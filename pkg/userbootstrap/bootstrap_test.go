package userbootstrap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	_ "modernc.org/sqlite"
)

func TestReconcileImportsLegacyUsersAndCreatesSeal(t *testing.T) {
	db, _ := openTestDatabase(t)
	seal := &memorySeal{}
	if _, err := db.Exec(`INSERT INTO o_users (username, password, role) VALUES ('legacy', 'hash', 'admin')`); err != nil {
		t.Fatal(err)
	}
	state, err := ReconcileState(context.Background(), db, seal)
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != StatusInitialized || seal.id != state.InstallationID {
		t.Fatalf("legacy state=%+v seal=%q", state, seal.id)
	}
	assertDatabaseState(t, db, StatusInitialized, state.InstallationID)
}

func TestReconcileFreshDatabaseIsPristineWithoutSeal(t *testing.T) {
	db, _ := openTestDatabase(t)
	seal := &memorySeal{}
	state, err := ReconcileState(context.Background(), db, seal)
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != StatusPristine || state.Initialized() || !state.SetupRequired() || seal.id != "" {
		t.Fatalf("fresh state=%+v seal=%q", state, seal.id)
	}
}

func TestDatabaseOnlyRestoreWithExistingSealLocksRecovery(t *testing.T) {
	firstDB, _ := openTestDatabase(t)
	seal := &memorySeal{}
	if _, err := CreateAdmin(context.Background(), firstDB, seal, "admin", "hash", nil); err != nil {
		t.Fatal(err)
	}

	restoredEmptyDB, _ := openTestDatabase(t)
	state, err := ReconcileState(context.Background(), restoredEmptyDB, seal)
	if !errors.Is(err, ErrRecoveryRequired) || state.Status != StatusRecovery {
		t.Fatalf("restored state=%+v err=%v", state, err)
	}
	assertDatabaseState(t, restoredEmptyDB, StatusRecovery, seal.id)
	if _, err := CreateAdmin(context.Background(), restoredEmptyDB, seal, "attacker", "hash", nil); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("bootstrap in recovery = %v", err)
	}
}

func TestDeletingAllUsersPermanentlyLocksRecovery(t *testing.T) {
	db, _ := openTestDatabase(t)
	seal := &memorySeal{}
	if _, err := CreateAdmin(context.Background(), db, seal, "admin", "hash", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM o_users`); err != nil {
		t.Fatal(err)
	}
	state, err := ReconcileState(context.Background(), db, seal)
	if !errors.Is(err, ErrRecoveryRequired) || state.Status != StatusRecovery {
		t.Fatalf("state after user deletion=%+v err=%v", state, err)
	}
	if _, err := CreateAdmin(context.Background(), db, seal, "replacement", "hash", nil); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("replay after deletion = %v", err)
	}
}

func TestCreateAdminIsExactlyOnceUnderConcurrency(t *testing.T) {
	db, _ := openTestDatabase(t)
	seal := &memorySeal{}
	const callers = 24
	start := make(chan struct{})
	errorsByCaller := make(chan error, callers)
	var callbackCount atomic.Int32
	var waitGroup sync.WaitGroup
	for index := 0; index < callers; index++ {
		index := index
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			_, err := CreateAdmin(context.Background(), db, seal, fmt.Sprintf("admin-%d", index), "argon2id-hash", func(int64) error {
				callbackCount.Add(1)
				return nil
			})
			errorsByCaller <- err
		}()
	}
	close(start)
	waitGroup.Wait()
	close(errorsByCaller)

	successes := 0
	alreadyInitialized := 0
	for err := range errorsByCaller {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrAlreadyInitialized):
			alreadyInitialized++
		default:
			t.Fatalf("unexpected concurrent bootstrap error: %v", err)
		}
	}
	if successes != 1 || alreadyInitialized != callers-1 {
		t.Fatalf("successes=%d already_initialized=%d", successes, alreadyInitialized)
	}
	if callbackCount.Load() != 1 {
		t.Fatalf("beforeCommit callback count = %d", callbackCount.Load())
	}
	assertUserCount(t, db, 1)
	assertDatabaseState(t, db, StatusInitialized, seal.id)
}

func TestCreateAdminRollsBackOnPreparationFailure(t *testing.T) {
	db, _ := openTestDatabase(t)
	seal := &memorySeal{}
	wantErr := errors.New("filesystem unavailable")
	if _, err := CreateAdmin(context.Background(), db, seal, "admin", "hash", func(int64) error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("CreateAdmin() error = %v", err)
	}
	assertUserCount(t, db, 0)
	assertDatabaseStatus(t, db, StatusPristine)
	if seal.id != "" {
		t.Fatalf("seal created after rollback: %q", seal.id)
	}
	if _, err := CreateAdmin(context.Background(), db, seal, "admin", "hash", nil); err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
}

func TestMissingSealAfterCommitIsRepairedWithoutSecondUser(t *testing.T) {
	db, _ := openTestDatabase(t)
	seal := &memorySeal{failCreates: 1}
	if _, err := CreateAdmin(context.Background(), db, seal, "admin", "hash", nil); err == nil {
		t.Fatal("CreateAdmin() unexpectedly ignored seal write failure")
	}
	assertUserCount(t, db, 1)
	assertDatabaseStatus(t, db, StatusInitialized)
	if seal.id != "" {
		t.Fatalf("failed seal was persisted: %q", seal.id)
	}
	if _, err := CreateAdmin(context.Background(), db, seal, "second", "hash", nil); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("retry error=%v, want ErrAlreadyInitialized", err)
	}
	assertUserCount(t, db, 1)
	if seal.id == "" {
		t.Fatal("retry did not repair the missing seal")
	}
}

func TestCreateAdminProcessDeathBeforeCommitRollsBack(t *testing.T) {
	db, databasePath := openTestDatabase(t)
	sealPath := filepath.Join(t.TempDir(), "bootstrap.seal")
	command := bootstrapHelperCommand("crash", databasePath, sealPath)
	err := command.Run()
	exitError := &exec.ExitError{}
	if !errors.As(err, &exitError) || exitError.ExitCode() != 23 {
		t.Fatalf("crash helper error = %v", err)
	}
	assertUserCount(t, db, 0)
	assertDatabaseStatus(t, db, StatusPristine)
	if _, err := os.Stat(sealPath); !os.IsNotExist(err) {
		t.Fatalf("seal exists after pre-commit crash: %v", err)
	}
}

func TestCreateAdminSerializesAcrossProcesses(t *testing.T) {
	db, databasePath := openTestDatabase(t)
	sealPath := filepath.Join(t.TempDir(), "bootstrap.seal")
	first := bootstrapHelperCommand("race", databasePath, sealPath)
	first.Env = append(first.Env, "RECASAOS_BOOTSTRAP_USERNAME=first")
	second := bootstrapHelperCommand("race", databasePath, sealPath)
	second.Env = append(second.Env, "RECASAOS_BOOTSTRAP_USERNAME=second")
	firstErrChannel := make(chan error, 1)
	secondErrChannel := make(chan error, 1)
	go func() { firstErrChannel <- first.Run() }()
	go func() { secondErrChannel <- second.Run() }()
	firstCode := exitCode(<-firstErrChannel)
	secondCode := exitCode(<-secondErrChannel)
	if !((firstCode == 0 && secondCode == 42) || (firstCode == 42 && secondCode == 0)) {
		t.Fatalf("helper exit codes = %d, %d", firstCode, secondCode)
	}
	assertUserCount(t, db, 1)
	seal := NewFileSeal(sealPath, uint32(os.Geteuid()))
	state, err := ReconcileState(context.Background(), db, seal)
	if err != nil || state.Status != StatusInitialized {
		t.Fatalf("post-race state=%+v err=%v", state, err)
	}
}

func TestBootstrapSubprocessHelper(t *testing.T) {
	mode := os.Getenv("RECASAOS_BOOTSTRAP_HELPER")
	if mode == "" {
		return
	}
	db := openHelperDatabase()
	seal := NewFileSeal(os.Getenv("RECASAOS_BOOTSTRAP_SEAL"), uint32(os.Geteuid()))
	switch mode {
	case "crash":
		_, _ = CreateAdmin(context.Background(), db, seal, "crash-admin", "hash", func(int64) error {
			os.Exit(23)
			return nil
		})
		os.Exit(72)
	case "race":
		username := os.Getenv("RECASAOS_BOOTSTRAP_USERNAME")
		_, err := CreateAdmin(context.Background(), db, seal, username, "hash", nil)
		if err == nil {
			os.Exit(0)
		}
		if errors.Is(err, ErrAlreadyInitialized) {
			os.Exit(42)
		}
		os.Exit(73)
	default:
		os.Exit(75)
	}
}

type memorySeal struct {
	mutex       sync.Mutex
	id          string
	failCreates int
}

func (seal *memorySeal) Load() (string, bool, error) {
	seal.mutex.Lock()
	defer seal.mutex.Unlock()
	return seal.id, seal.id != "", nil
}

func (seal *memorySeal) Create(id string) error {
	seal.mutex.Lock()
	defer seal.mutex.Unlock()
	if seal.failCreates > 0 {
		seal.failCreates--
		return errors.New("injected seal failure")
	}
	if seal.id != "" && seal.id != id {
		return errors.New("seal mismatch")
	}
	seal.id = id
	return nil
}

func openTestDatabase(t *testing.T) (*sql.DB, string) {
	t.Helper()
	databasePath := filepath.Join(t.TempDir(), "bootstrap.db")
	db, err := sql.Open("sqlite", databasePath+"?_pragma=busy_timeout%3d10000")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(32)
	t.Cleanup(func() { _ = db.Close() })
	createTestSchema(t, db)
	return db, databasePath
}

func createTestSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	statements := []string{
		`CREATE TABLE o_users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			password TEXT NOT NULL,
			role TEXT,
			created_at DATETIME,
			updated_at DATETIME
		)`,
		`CREATE UNIQUE INDEX idx_o_users_username ON o_users(username)`,
		`CREATE TABLE o_bootstrap_state (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			installation_id TEXT NOT NULL,
			status TEXT NOT NULL,
			admin_user_id INTEGER,
			initialized_at DATETIME,
			created_at DATETIME,
			updated_at DATETIME
		)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
}

func openHelperDatabase() *sql.DB {
	db, err := sql.Open("sqlite", os.Getenv("RECASAOS_BOOTSTRAP_DB")+"?_pragma=busy_timeout%3d10000")
	if err != nil {
		os.Exit(74)
	}
	db.SetMaxOpenConns(8)
	return db
}

func bootstrapHelperCommand(mode, databasePath, sealPath string) *exec.Cmd {
	command := exec.Command(os.Args[0], "-test.run=^TestBootstrapSubprocessHelper$")
	command.Env = append(os.Environ(),
		"RECASAOS_BOOTSTRAP_HELPER="+mode,
		"RECASAOS_BOOTSTRAP_DB="+databasePath,
		"RECASAOS_BOOTSTRAP_SEAL="+sealPath,
	)
	return command
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}

func assertUserCount(t *testing.T, db *sql.DB, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(`SELECT COUNT(*) FROM o_users`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("user count = %d, want %d", got, want)
	}
}

func assertDatabaseStatus(t *testing.T, db *sql.DB, want Status) {
	t.Helper()
	var got Status
	if err := db.QueryRow(`SELECT status FROM o_bootstrap_state WHERE id = 1`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("database status = %q, want %q", got, want)
	}
}

func assertDatabaseState(t *testing.T, db *sql.DB, wantStatus Status, wantID string) {
	t.Helper()
	var status Status
	var id string
	if err := db.QueryRow(`SELECT installation_id, status FROM o_bootstrap_state WHERE id = 1`).Scan(&id, &status); err != nil {
		t.Fatal(err)
	}
	if status != wantStatus || id != wantID {
		t.Fatalf("database state = (%q, %q), want (%q, %q)", id, status, wantID, wantStatus)
	}
}
