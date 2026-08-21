package sqlite

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	appmodel "github.com/EdmundFu-233/ReCasaOS-UserService/model"
	model2 "github.com/EdmundFu-233/ReCasaOS-UserService/service/model"
)

func TestGetDbCreatesOwnerOnlyDatabaseAndSchema(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "user-data")
	db, err := GetDb(directory)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	assertMode(t, directory, 0o700)
	assertMode(t, filepath.Join(directory, databaseFilename), 0o600)
	if !db.Migrator().HasTable(&model2.BootstrapStateDBModel{}) {
		t.Fatal("bootstrap state table was not migrated")
	}

	if err := db.Create(&model2.UserDBModel{Username: "same", Password: "hash", Role: "admin"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model2.UserDBModel{Username: "same", Password: "other", Role: "admin"}).Error; err == nil {
		t.Fatal("duplicate username unexpectedly succeeded")
	}
}

func TestGetExistingDbNeverCreatesMissingStorage(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "missing-user-data")
	if _, err := GetExistingDb(directory); err == nil {
		t.Fatal("GetExistingDb() created a missing database directory")
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatalf("missing database directory changed: %v", err)
	}

	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := GetExistingDb(directory); err == nil {
		t.Fatal("GetExistingDb() created a missing database file")
	}
	if _, err := os.Lstat(filepath.Join(directory, databaseFilename)); !os.IsNotExist(err) {
		t.Fatalf("missing database file changed: %v", err)
	}
}

func TestGetExistingDbDoesNotMigrateAnEmptyExistingFile(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "existing-user-data")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, databaseFilename)
	if err := os.WriteFile(databasePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := GetExistingDb(directory)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) != 0 {
		t.Fatalf("existing empty database was modified to %d bytes", len(contents))
	}
}

func TestGetBootstrapDbCreatesSchemaOnlyForANewDatabase(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "bootstrap-data")
	db, err := GetBootstrapDb(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !db.Migrator().HasTable(&model2.BootstrapStateDBModel{}) {
		t.Fatal("new bootstrap database did not receive the required schema")
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}

	databasePath := filepath.Join(directory, databaseFilename)
	before, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := GetBootstrapDb(directory)
	if err != nil {
		t.Fatal(err)
	}
	reopenedSQL, err := reopened.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := reopenedSQL.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("reopening a bootstrap database changed its bytes")
	}
}

func TestGetBootstrapDbDoesNotMigrateAnExistingEmptyFile(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "existing-bootstrap-data")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, databaseFilename)
	if err := os.WriteFile(databasePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := GetBootstrapDb(directory)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) != 0 {
		t.Fatalf("existing empty bootstrap database was modified to %d bytes", len(contents))
	}
}

func TestGetDbMigratesUpstreamLegacySchema(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "legacy-user-data")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, databaseFilename)
	if err := os.WriteFile(databasePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	legacy, err := GetExistingDb(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.AutoMigrate(&upstreamLegacyUserDBModel{}, &appmodel.EventModel{}); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Exec(`
		INSERT INTO o_users(id, username, password, role)
		VALUES(7, 'legacy-admin', 'legacy-verifier', 'admin');
		INSERT INTO events(uuid, source_id, name, properties, timestamp)
		VALUES('00000000-0000-4000-8000-000000000001', 'legacy-source', 'legacy-event', '"{}"', 1787184000000);
	`).Error; err != nil {
		t.Fatal(err)
	}
	legacySQL, err := legacy.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := legacySQL.Close(); err != nil {
		t.Fatal(err)
	}

	migrated, err := GetDb(directory)
	if err != nil {
		t.Fatal(err)
	}
	migratedSQL, err := migrated.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = migratedSQL.Close() })
	if !migrated.Migrator().HasTable(&model2.BootstrapStateDBModel{}) {
		t.Fatal("daemon migration did not create bootstrap state schema")
	}
	var uniqueIndexColumns int
	if err := migrated.Raw(`SELECT COUNT(*) FROM pragma_index_info('idx_o_users_username')
		WHERE seqno = 0 AND name = 'username'`).Scan(&uniqueIndexColumns).Error; err != nil {
		t.Fatal(err)
	}
	if uniqueIndexColumns != 1 {
		t.Fatal("daemon migration did not create the username uniqueness boundary")
	}
	var uniqueIndexes int
	if err := migrated.Raw(`SELECT COUNT(*) FROM pragma_index_list('o_users')
		WHERE name = 'idx_o_users_username' AND "unique" = 1 AND partial = 0`).Scan(&uniqueIndexes).Error; err != nil {
		t.Fatal(err)
	}
	if uniqueIndexes != 1 {
		t.Fatal("daemon migration did not create an exact unique username index")
	}
	var event appmodel.EventModel
	if err := migrated.First(&event, "uuid = ?", "00000000-0000-4000-8000-000000000001").Error; err != nil {
		t.Fatal(err)
	}
	if event.SourceID != "legacy-source" || event.Name != "legacy-event" || event.Properties != "{}" || event.Timestamp != 1787184000000 {
		t.Fatal("daemon migration did not preserve the legacy event record")
	}
}

// upstreamLegacyUserDBModel is the exact v0.4.17-alpha1 UserDBModel shape. It
// intentionally lacks the ReCasaOS username uniqueIndex tag so this test proves
// the daemon can migrate an authentic upstream-created schema.
type upstreamLegacyUserDBModel struct {
	Id          int `gorm:"column:id;primary_key"`
	Username    string
	Password    string
	Role        string
	Email       string
	Nickname    string
	Avatar      string
	Description string
	CreatedAt   time.Time `gorm:"<-:create;autoCreateTime"`
	UpdatedAt   time.Time `gorm:"<-:create;<-:update;autoUpdateTime"`
}

func (upstreamLegacyUserDBModel) TableName() string {
	return "o_users"
}

func TestGetDbRepairsExistingOverbroadModes(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "user-data")
	if err := os.Mkdir(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, databaseFilename)
	if err := os.WriteFile(databasePath, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(databasePath, 0o666); err != nil {
		t.Fatal(err)
	}

	db, err := GetDb(directory)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	assertMode(t, directory, 0o700)
	assertMode(t, databasePath, 0o600)
}

func TestGetDbDoesNotReuseAConnectionForAnotherDirectory(t *testing.T) {
	first, err := GetDb(filepath.Join(t.TempDir(), "first"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := GetDb(filepath.Join(t.TempDir(), "second"))
	if err != nil {
		t.Fatal(err)
	}
	firstSQL, _ := first.DB()
	secondSQL, _ := second.DB()
	t.Cleanup(func() {
		_ = firstSQL.Close()
		_ = secondSQL.Close()
	})
	if firstSQL == secondSQL {
		t.Fatal("GetDb reused the global database connection")
	}
}

func TestGetDbEscapesSpecialCharactersInPath(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "data ?# percent%")
	db, err := GetDb(directory)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if _, err := os.Stat(filepath.Join(directory, databaseFilename)); err != nil {
		t.Fatal(err)
	}
}

func TestGetDbRejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	t.Run("directory", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := GetDb(link); err == nil || !strings.Contains(err.Error(), "not a symlink") {
			t.Fatalf("GetDb() error = %v", err)
		}
	})

	t.Run("database file", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "data")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target.db")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(directory, databaseFilename)); err != nil {
			t.Fatal(err)
		}
		if _, err := GetDb(directory); err == nil || !strings.Contains(err.Error(), "not a symlink") {
			t.Fatalf("GetDb() error = %v", err)
		}
	})
}

func TestGetDbPropagatesInvalidDirectoryError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ordinary-file")
	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := GetDb(path); err == nil {
		t.Fatal("GetDb() unexpectedly accepted a file as its directory")
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %#o, want %#o", path, got, want)
	}
}
