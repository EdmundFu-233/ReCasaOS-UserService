package service

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	passwordutil "github.com/EdmundFu-233/ReCasaOS-UserService/pkg/password"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/sqlite"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/userbootstrap"
	"github.com/EdmundFu-233/ReCasaOS-UserService/service/model"
	"gorm.io/gorm"
)

func TestBootstrapAdminCreatesOnlyArgon2idAdministrator(t *testing.T) {
	db, seal := openSecurityTestDatabase(t)
	userID, err := BootstrapAdmin(context.Background(), db, seal, "local-admin", []byte("strong-bootstrap-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var user model.UserDBModel
	if err := db.First(&user, userID).Error; err != nil {
		t.Fatal(err)
	}
	if user.Role != "admin" || !passwordutil.IsArgon2id(user.Password) {
		t.Fatalf("created user role=%q argon2id=%v", user.Role, passwordutil.IsArgon2id(user.Password))
	}
	if _, err := BootstrapAdmin(context.Background(), db, seal, "second", []byte("another-strong-password"), nil); !errors.Is(err, userbootstrap.ErrAlreadyInitialized) {
		t.Fatalf("replayed BootstrapAdmin() = %v", err)
	}
}

func TestBootstrapReplayLeavesExistingDatabaseBytesUnchanged(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "db")
	seal := userbootstrap.NewFileSeal(filepath.Join(t.TempDir(), "seal", "bootstrap.seal"), uint32(os.Geteuid()))
	db, err := sqlite.GetBootstrapDb(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BootstrapAdmin(context.Background(), db, seal, "local-admin", []byte("strong-bootstrap-password"), nil); err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "user.db")
	before, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := sqlite.GetBootstrapDb(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BootstrapAdmin(context.Background(), reopened, seal, "second", []byte("another-strong-password"), nil); !errors.Is(err, userbootstrap.ErrAlreadyInitialized) {
		t.Fatalf("replayed BootstrapAdmin() = %v", err)
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
		t.Fatal("replayed bootstrap changed existing database bytes")
	}
}

func TestBootstrapAdminDoesNotMigrateOrMutateExistingLegacyDatabase(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "legacy-db")
	legacy, err := sqlite.GetDb(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Create(&model.UserDBModel{Username: "legacy-admin", Password: "legacy-verifier", Role: "admin"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := legacy.Migrator().DropTable(&model.BootstrapStateDBModel{}); err != nil {
		t.Fatal(err)
	}
	legacySQL, err := legacy.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := legacySQL.Close(); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "user.db")
	before, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal(err)
	}

	sealPath := filepath.Join(t.TempDir(), "seal", "bootstrap.seal")
	seal := userbootstrap.NewFileSeal(sealPath, uint32(os.Geteuid()))
	reopened, err := sqlite.GetBootstrapDb(directory)
	if err != nil {
		t.Fatal(err)
	}
	callbackCalled := false
	if _, err := BootstrapAdmin(context.Background(), reopened, seal, "new-admin", []byte("strong-bootstrap-password"), func(int64) error {
		callbackCalled = true
		return nil
	}); err == nil {
		t.Fatal("bootstrap unexpectedly migrated and accepted an existing legacy database")
	}
	if callbackCalled {
		t.Fatal("rejected legacy bootstrap created administrator resources")
	}
	if reopened.Migrator().HasTable(&model.BootstrapStateDBModel{}) {
		t.Fatal("rejected legacy bootstrap created bootstrap state schema")
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
		t.Fatal("rejected legacy bootstrap changed existing database bytes")
	}
	if _, err := os.Lstat(sealPath); !os.IsNotExist(err) {
		t.Fatalf("rejected legacy bootstrap changed the seal path: %v", err)
	}
}

func TestBootstrapAdminDoesNotPromoteAnExistingEmptyDatabaseFile(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "empty-db")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "user.db")
	if err := os.WriteFile(databasePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sealPath := filepath.Join(t.TempDir(), "seal", "bootstrap.seal")
	seal := userbootstrap.NewFileSeal(sealPath, uint32(os.Geteuid()))
	db, err := sqlite.GetBootstrapDb(directory)
	if err != nil {
		t.Fatal(err)
	}
	callbackCalled := false
	if _, err := BootstrapAdmin(context.Background(), db, seal, "new-admin", []byte("strong-bootstrap-password"), func(int64) error {
		callbackCalled = true
		return nil
	}); err == nil {
		t.Fatal("bootstrap unexpectedly accepted an existing empty database")
	}
	if callbackCalled {
		t.Fatal("rejected empty-database bootstrap created administrator resources")
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
		t.Fatalf("rejected empty-database bootstrap wrote %d bytes", len(contents))
	}
	if _, err := os.Lstat(sealPath); !os.IsNotExist(err) {
		t.Fatalf("rejected empty-database bootstrap changed the seal path: %v", err)
	}
}

func TestBootstrapAdminValidatesUsernameAndPasswordBeforeWriting(t *testing.T) {
	db, seal := openSecurityTestDatabase(t)
	tests := []struct {
		username string
		password string
		want     error
	}{
		{username: "../admin", password: "strong-bootstrap-password", want: ErrInvalidUsername},
		{username: "", password: "strong-bootstrap-password", want: ErrInvalidUsername},
		{username: "admin", password: "short", want: ErrWeakPassword},
		{username: "admin", password: "contains\nnewline", want: ErrWeakPassword},
	}
	for _, test := range tests {
		if _, err := BootstrapAdmin(context.Background(), db, seal, test.username, []byte(test.password), nil); !errors.Is(err, test.want) {
			t.Errorf("BootstrapAdmin(%q) error=%v, want %v", test.username, err, test.want)
		}
	}
	var count int64
	if err := db.Model(&model.UserDBModel{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("validation failures created %d users", count)
	}
}

func TestLegacyWeakLoginRequiresLocalArgon2idReset(t *testing.T) {
	db, seal := openSecurityTestDatabase(t)
	// Known legacy digest for "legacy-password"; no weak hash implementation is
	// imported or evaluated by the service.
	const legacyHash = "12121b2b7fdedd5ec5777926650d7119"
	legacy := model.UserDBModel{Username: "legacy", Password: legacyHash, Role: "admin"}
	if err := db.Create(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Migrator().DropTable(&model.BootstrapStateDBModel{}); err != nil {
		t.Fatal(err)
	}
	userService := NewUserService(db, userbootstrap.State{Status: userbootstrap.StatusInitialized})
	for _, candidate := range []string{"legacy-password", "wrong-legacy-password"} {
		if _, err := userService.AuthenticateUser("legacy", []byte(candidate)); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("legacy verifier was evaluated during login: %v", err)
		}
	}
	var rejected model.UserDBModel
	if err := db.First(&rejected, legacy.Id).Error; err != nil {
		t.Fatal(err)
	}
	if rejected.Password != legacyHash {
		t.Fatal("rejected legacy login modified the stored verifier")
	}
	newPassword := []byte("replacement-strong-password")
	if err := ResetAdminPassword(context.Background(), db, seal, "legacy", newPassword); err != nil {
		t.Fatal(err)
	}
	sealIDBefore, sealExists, err := seal.Load()
	if err != nil || !sealExists {
		t.Fatalf("load post-import seal: exists=%v err=%v", sealExists, err)
	}
	var markerBefore model.BootstrapStateDBModel
	if err := db.First(&markerBefore, 1).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := userService.AuthenticateUser("legacy", newPassword); err != nil {
		t.Fatalf("local reset password does not authenticate: %v", err)
	}
	if _, err := userService.AuthenticateUser("legacy", []byte("legacy-password")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password still authenticates after local reset: %v", err)
	}
	var reset model.UserDBModel
	if err := db.First(&reset, legacy.Id).Error; err != nil {
		t.Fatal(err)
	}
	if reset.Password == legacyHash || !passwordutil.IsArgon2id(reset.Password) {
		t.Fatalf("local reset stored legacy=%v argon2id=%v", reset.Password == legacyHash, passwordutil.IsArgon2id(reset.Password))
	}
	if reset.Id != legacy.Id || reset.Username != legacy.Username || reset.Role != legacy.Role {
		t.Fatal("local reset changed administrator identity or role")
	}
	var userCount int64
	if err := db.Model(&model.UserDBModel{}).Count(&userCount).Error; err != nil {
		t.Fatal(err)
	}
	if userCount != 1 {
		t.Fatalf("local reset changed user count to %d", userCount)
	}
	sealIDAfter, sealStillExists, err := seal.Load()
	if err != nil || !sealStillExists || sealIDAfter != sealIDBefore {
		t.Fatalf("local reset changed seal identity: exists=%v err=%v", sealStillExists, err)
	}
	var markerAfter model.BootstrapStateDBModel
	if err := db.First(&markerAfter, 1).Error; err != nil {
		t.Fatal(err)
	}
	if markerAfter.InstallationID != markerBefore.InstallationID || markerAfter.Status != markerBefore.Status ||
		markerAfter.AdminUserID == nil || markerBefore.AdminUserID == nil || *markerAfter.AdminUserID != *markerBefore.AdminUserID ||
		markerAfter.InitializedAt == nil || markerBefore.InitializedAt == nil ||
		!markerAfter.InitializedAt.Equal(*markerBefore.InitializedAt) || !markerAfter.CreatedAt.Equal(markerBefore.CreatedAt) ||
		!markerAfter.UpdatedAt.Equal(markerBefore.UpdatedAt) {
		t.Fatal("local reset changed bootstrap marker state")
	}
}

func TestLocalAdminResetRejectionsLeaveAllIdentityStateUnchanged(t *testing.T) {
	db, seal := openSecurityTestDatabase(t)
	if _, err := BootstrapAdmin(context.Background(), db, seal, "admin", []byte("initial-strong-password"), nil); err != nil {
		t.Fatal(err)
	}
	userHash, err := passwordutil.Hash([]byte("ordinary-user-password"))
	if err != nil {
		t.Fatal(err)
	}
	ordinary := model.UserDBModel{Username: "ordinary", Password: userHash, Role: "user"}
	if err := db.Create(&ordinary).Error; err != nil {
		t.Fatal(err)
	}
	var adminBefore, ordinaryBefore model.UserDBModel
	if err := db.Where("username = ?", "admin").First(&adminBefore).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Where("username = ?", "ordinary").First(&ordinaryBefore).Error; err != nil {
		t.Fatal(err)
	}
	var markerBefore model.BootstrapStateDBModel
	if err := db.First(&markerBefore, 1).Error; err != nil {
		t.Fatal(err)
	}
	sealIDBefore, exists, err := seal.Load()
	if err != nil || !exists {
		t.Fatalf("load seal before rejected resets: exists=%v err=%v", exists, err)
	}
	for _, invalid := range []string{"", "line\nbreak", strings.Repeat("x", 257)} {
		if err := ResetAdminPassword(context.Background(), db, seal, invalid, []byte("replacement-strong-password")); !errors.Is(err, ErrInvalidResetTarget) {
			t.Fatalf("invalid reset target error = %v", err)
		}
	}
	if err := ResetAdminPassword(context.Background(), db, seal, "ordinary", []byte("replacement-strong-password")); !errors.Is(err, ErrNotAdministrator) {
		t.Fatalf("non-admin reset error = %v", err)
	}
	if err := ResetAdminPassword(context.Background(), db, seal, "missing", []byte("replacement-strong-password")); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing-user reset error = %v", err)
	}
	if err := ResetAdminPassword(context.Background(), db, nil, "admin", []byte("replacement-strong-password")); !errors.Is(err, userbootstrap.ErrRecoveryRequired) {
		t.Fatalf("nil-seal reset error = %v", err)
	}
	mismatchedSeal := userbootstrap.NewFileSeal(filepath.Join(t.TempDir(), "mismatch", "seal"), uint32(os.Geteuid()))
	if err := mismatchedSeal.Create("123e4567-e89b-42d3-a456-426614174000"); err != nil {
		t.Fatal(err)
	}
	if err := ResetAdminPassword(context.Background(), db, mismatchedSeal, "admin", []byte("replacement-strong-password")); !errors.Is(err, userbootstrap.ErrRecoveryRequired) {
		t.Fatalf("mismatched-seal reset error = %v", err)
	}
	var adminAfter, ordinaryAfter model.UserDBModel
	if err := db.Where("username = ?", "admin").First(&adminAfter).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Where("username = ?", "ordinary").First(&ordinaryAfter).Error; err != nil {
		t.Fatal(err)
	}
	if !sameUserSecurityState(adminBefore, adminAfter) || !sameUserSecurityState(ordinaryBefore, ordinaryAfter) {
		t.Fatal("rejected local reset changed a user identity, role, profile, or verifier")
	}
	var userCount int64
	if err := db.Model(&model.UserDBModel{}).Count(&userCount).Error; err != nil {
		t.Fatal(err)
	}
	if userCount != 2 {
		t.Fatalf("rejected local reset changed user count to %d", userCount)
	}
	var markerAfter model.BootstrapStateDBModel
	if err := db.First(&markerAfter, 1).Error; err != nil {
		t.Fatal(err)
	}
	if !sameBootstrapState(markerBefore, markerAfter) {
		t.Fatal("rejected local reset changed bootstrap marker")
	}
	sealIDAfter, stillExists, err := seal.Load()
	if err != nil || !stillExists || sealIDAfter != sealIDBefore {
		t.Fatalf("rejected local reset changed seal: exists=%v err=%v", stillExists, err)
	}
}

func TestLocalAdminResetCASFailureRollsBack(t *testing.T) {
	db, seal := openSecurityTestDatabase(t)
	userID, err := BootstrapAdmin(context.Background(), db, seal, "admin", []byte("initial-strong-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var before model.UserDBModel
	if err := db.First(&before, userID).Error; err != nil {
		t.Fatal(err)
	}
	var markerBefore model.BootstrapStateDBModel
	if err := db.First(&markerBefore, 1).Error; err != nil {
		t.Fatal(err)
	}
	sealIDBefore, exists, err := seal.Load()
	if err != nil || !exists {
		t.Fatalf("load pre-CAS seal: exists=%v err=%v", exists, err)
	}
	if err := db.Exec(`CREATE TRIGGER ignore_password_reset
		BEFORE UPDATE OF password ON o_users
		BEGIN SELECT RAISE(IGNORE); END`).Error; err != nil {
		t.Fatal(err)
	}
	if err := ResetAdminPassword(context.Background(), db, seal, "admin", []byte("replacement-strong-password")); !errors.Is(err, ErrPasswordChanged) {
		t.Fatalf("CAS-zero reset error = %v", err)
	}
	var after model.UserDBModel
	if err := db.First(&after, userID).Error; err != nil {
		t.Fatal(err)
	}
	if !sameUserSecurityState(before, after) {
		t.Fatal("CAS-zero reset changed administrator state")
	}
	var markerAfter model.BootstrapStateDBModel
	if err := db.First(&markerAfter, 1).Error; err != nil {
		t.Fatal(err)
	}
	if !sameBootstrapState(markerBefore, markerAfter) {
		t.Fatal("CAS-zero reset changed bootstrap marker")
	}
	sealIDAfter, stillExists, err := seal.Load()
	if err != nil || !stillExists || sealIDAfter != sealIDBefore {
		t.Fatalf("CAS-zero reset changed seal: exists=%v err=%v", stillExists, err)
	}
}

func TestLegacyResetValidatesUniqueAdministratorBeforeStateMigration(t *testing.T) {
	const legacyHash = "12121b2b7fdedd5ec5777926650d7119"
	tests := []struct {
		name       string
		users      []model.UserDBModel
		target     string
		want       error
		duplicates bool
	}{
		{
			name:   "unknown target",
			users:  []model.UserDBModel{{Username: "admin", Password: legacyHash, Role: "admin"}},
			target: "typo",
			want:   ErrUserNotFound,
		},
		{
			name:   "non-administrator",
			users:  []model.UserDBModel{{Username: "ordinary", Password: legacyHash, Role: "user"}},
			target: "ordinary",
			want:   ErrNotAdministrator,
		},
		{
			name: "duplicate username",
			users: []model.UserDBModel{
				{Username: "duplicate", Password: legacyHash, Role: "admin"},
				{Username: "duplicate", Password: legacyHash, Role: "admin"},
			},
			target:     "duplicate",
			want:       ErrInvalidResetTarget,
			duplicates: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, seal := openSecurityTestDatabase(t)
			if test.duplicates {
				if err := db.Migrator().DropIndex(&model.UserDBModel{}, "idx_o_users_username"); err != nil {
					t.Fatal(err)
				}
			}
			for index := range test.users {
				if err := db.Create(&test.users[index]).Error; err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Migrator().DropTable(&model.BootstrapStateDBModel{}); err != nil {
				t.Fatal(err)
			}
			if err := ResetAdminPassword(context.Background(), db, seal, test.target, []byte("replacement-strong-password")); !errors.Is(err, test.want) {
				t.Fatalf("legacy reset error = %v, want %v", err, test.want)
			}
			if db.Migrator().HasTable(&model.BootstrapStateDBModel{}) {
				t.Fatal("rejected legacy reset created bootstrap state schema")
			}
			if _, exists, err := seal.Load(); err != nil || exists {
				t.Fatalf("rejected legacy reset created a seal: exists=%v err=%v", exists, err)
			}
			var count int64
			if err := db.Model(&model.UserDBModel{}).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if count != int64(len(test.users)) {
				t.Fatalf("rejected legacy reset changed user count to %d", count)
			}
			for _, original := range test.users {
				var stored model.UserDBModel
				if err := db.First(&stored, original.Id).Error; err != nil {
					t.Fatal(err)
				}
				if !sameUserSecurityState(original, stored) {
					t.Fatal("rejected legacy reset changed an existing user")
				}
			}
		})
	}
}

func TestLegacyResetRepairsSealPublicationCrashBeforeChangingPassword(t *testing.T) {
	db, _ := openSecurityTestDatabase(t)
	const legacyHash = "12121b2b7fdedd5ec5777926650d7119"
	legacy := model.UserDBModel{Username: "legacy", Password: legacyHash, Role: "admin"}
	if err := db.Create(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Migrator().DropTable(&model.BootstrapStateDBModel{}); err != nil {
		t.Fatal(err)
	}
	seal := &flakyMemorySeal{createFailures: 1}
	newPassword := []byte("replacement-strong-password")
	if err := ResetAdminPassword(context.Background(), db, seal, "legacy", newPassword); err == nil {
		t.Fatal("legacy reset succeeded despite injected seal publication failure")
	}
	var afterFailure model.UserDBModel
	if err := db.First(&afterFailure, legacy.Id).Error; err != nil {
		t.Fatal(err)
	}
	if afterFailure.Password != legacyHash || seal.exists {
		t.Fatal("failed seal publication changed password or published a seal")
	}
	var marker model.BootstrapStateDBModel
	if err := db.First(&marker, 1).Error; err != nil {
		t.Fatal(err)
	}
	if marker.Status != string(userbootstrap.StatusInitialized) || marker.InstallationID == "" {
		t.Fatal("failed seal publication did not preserve repairable initialized state")
	}
	if err := ResetAdminPassword(context.Background(), db, seal, "legacy", newPassword); err != nil {
		t.Fatalf("retry after seal publication failure: %v", err)
	}
	if !seal.exists || seal.id != marker.InstallationID {
		t.Fatal("retry did not publish the matching seal")
	}
	var afterRetry model.UserDBModel
	if err := db.First(&afterRetry, legacy.Id).Error; err != nil {
		t.Fatal(err)
	}
	if afterRetry.Password == legacyHash || !passwordutil.IsArgon2id(afterRetry.Password) {
		t.Fatal("retry did not replace the legacy verifier with Argon2id")
	}
}

func TestLocalAdminResetSupportsExistingLegacyUsernameAndRejectsRecoveryState(t *testing.T) {
	db, seal := openSecurityTestDatabase(t)
	userID, err := BootstrapAdmin(context.Background(), db, seal, "admin", []byte("initial-strong-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	const existingUsername = "legacy administrator ü"
	if err := db.Model(&model.UserDBModel{}).Where("id = ?", userID).Update("username", existingUsername).Error; err != nil {
		t.Fatal(err)
	}
	if err := ResetAdminPassword(context.Background(), db, seal, existingUsername, []byte("replacement-strong-password")); err != nil {
		t.Fatalf("reset existing legacy username: %v", err)
	}

	var beforeRecovery model.UserDBModel
	if err := db.First(&beforeRecovery, userID).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`UPDATE o_bootstrap_state SET status = ? WHERE id = 1`, userbootstrap.StatusRecovery).Error; err != nil {
		t.Fatal(err)
	}
	if err := ResetAdminPassword(context.Background(), db, seal, existingUsername, []byte("third-strong-password")); !errors.Is(err, userbootstrap.ErrRecoveryRequired) {
		t.Fatalf("recovery-state reset error = %v", err)
	}
	var afterRecovery model.UserDBModel
	if err := db.First(&afterRecovery, userID).Error; err != nil {
		t.Fatal(err)
	}
	if afterRecovery.Password != beforeRecovery.Password {
		t.Fatal("recovery-state reset modified the stored verifier")
	}
}

func TestAuthenticationRejectsOversizeInput(t *testing.T) {
	db, _ := openSecurityTestDatabase(t)
	userService := NewUserService(db, userbootstrap.State{Status: userbootstrap.StatusInitialized})
	if _, err := userService.AuthenticateUser("missing", bytes.Repeat([]byte{'x'}, 1025)); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("oversize password error=%v", err)
	}
	if _, err := userService.AuthenticateUser(strings.Repeat("u", 257), []byte("password")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("oversize username error=%v", err)
	}
}

func TestInitializationStatusUsesStartupSnapshotWithoutDatabaseLock(t *testing.T) {
	db, _ := openSecurityTestDatabase(t)
	want := userbootstrap.State{
		InstallationID: "123e4567-e89b-42d3-a456-426614174000",
		Status:         userbootstrap.StatusInitialized,
	}
	userService := NewUserService(db, want)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := userService.GetInitializationState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("initialization state = %+v, want %+v", got, want)
	}
}

func TestPasswordChangeAlwaysStoresArgon2idAndUsesCAS(t *testing.T) {
	db, seal := openSecurityTestDatabase(t)
	_, err := BootstrapAdmin(context.Background(), db, seal, "admin", []byte("original-strong-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	userService := NewUserService(db, userbootstrap.State{Status: userbootstrap.StatusInitialized})
	user := userService.GetUserAllInfoByName("admin")
	userID := strconv.Itoa(user.Id)
	if err := userService.ChangeUserPassword(userID, []byte("wrong-password"), []byte("replacement-strong-password")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong old password error=%v", err)
	}
	if err := userService.ChangeUserPassword(userID, []byte("original-strong-password"), []byte("replacement-strong-password")); err != nil {
		t.Fatal(err)
	}
	var changed model.UserDBModel
	if err := db.First(&changed, user.Id).Error; err != nil {
		t.Fatal(err)
	}
	if !passwordutil.IsArgon2id(changed.Password) {
		t.Fatal("changed password is not Argon2id")
	}
	if _, err := userService.AuthenticateUser("admin", []byte("original-strong-password")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password still authenticates: %v", err)
	}
	if _, err := userService.AuthenticateUser("admin", []byte("replacement-strong-password")); err != nil {
		t.Fatalf("new password does not authenticate: %v", err)
	}
}

func TestLastAdministratorAndBulkDeletionAreRejected(t *testing.T) {
	db, seal := openSecurityTestDatabase(t)
	firstID, err := BootstrapAdmin(context.Background(), db, seal, "first-admin", []byte("first-strong-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	userService := NewUserService(db, userbootstrap.State{Status: userbootstrap.StatusInitialized})
	if err := userService.DeleteUserById(strconv.FormatInt(firstID, 10)); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin deletion error=%v", err)
	}
	if err := userService.DeleteAllUser(); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("bulk deletion error=%v", err)
	}

	second := model.UserDBModel{Username: "second-admin", Password: "hash", Role: "admin"}
	if err := db.Create(&second).Error; err != nil {
		t.Fatal(err)
	}
	if err := userService.DeleteUserById(strconv.FormatInt(firstID, 10)); err != nil {
		t.Fatalf("delete one of two admins: %v", err)
	}
	var remaining int64
	if err := db.Model(&model.UserDBModel{}).Where("id = ?", firstID).Count(&remaining).Error; err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatal("deleted administrator remains")
	}
}

func TestUserUpdateCannotDemoteAdministrator(t *testing.T) {
	db, seal := openSecurityTestDatabase(t)
	userID, err := BootstrapAdmin(context.Background(), db, seal, "admin", []byte("strong-bootstrap-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	userService := NewUserService(db, userbootstrap.State{Status: userbootstrap.StatusInitialized})
	userService.UpdateUser(model.UserDBModel{Id: int(userID), Username: "admin", Role: "user", Nickname: "changed"})
	var stored model.UserDBModel
	if err := db.First(&stored, userID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Role != "admin" || stored.Nickname != "changed" {
		t.Fatalf("updated user role=%q nickname=%q", stored.Role, stored.Nickname)
	}
}

func openSecurityTestDatabase(t *testing.T) (*gorm.DB, userbootstrap.Seal) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "db")
	db, err := sqlite.GetDb(directory)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	seal := userbootstrap.NewFileSeal(filepath.Join(t.TempDir(), "seal", "bootstrap.seal"), uint32(os.Geteuid()))
	return db, seal
}

func sameUserSecurityState(first, second model.UserDBModel) bool {
	return first.Id == second.Id && first.Username == second.Username && first.Password == second.Password &&
		first.Role == second.Role && first.Email == second.Email && first.Nickname == second.Nickname &&
		first.Avatar == second.Avatar && first.Description == second.Description &&
		first.CreatedAt.Equal(second.CreatedAt) && first.UpdatedAt.Equal(second.UpdatedAt)
}

func sameBootstrapState(first, second model.BootstrapStateDBModel) bool {
	return first.ID == second.ID && first.InstallationID == second.InstallationID && first.Status == second.Status &&
		sameOptionalInt64(first.AdminUserID, second.AdminUserID) &&
		sameOptionalTime(first.InitializedAt, second.InitializedAt) &&
		first.CreatedAt.Equal(second.CreatedAt) && first.UpdatedAt.Equal(second.UpdatedAt)
}

func sameOptionalInt64(first, second *int64) bool {
	return (first == nil && second == nil) || (first != nil && second != nil && *first == *second)
}

func sameOptionalTime(first, second *time.Time) bool {
	return (first == nil && second == nil) || (first != nil && second != nil && first.Equal(*second))
}

type flakyMemorySeal struct {
	id             string
	exists         bool
	createFailures int
}

func (seal *flakyMemorySeal) Load() (string, bool, error) {
	return seal.id, seal.exists, nil
}

func (seal *flakyMemorySeal) Create(installationID string) error {
	if seal.createFailures > 0 {
		seal.createFailures--
		return errors.New("injected seal publication failure")
	}
	seal.id = installationID
	seal.exists = true
	return nil
}

func TestValidationErrorsDoNotContainSubmittedPasswords(t *testing.T) {
	db, seal := openSecurityTestDatabase(t)
	secret := "secret-that-must-not-appear"
	_, err := BootstrapAdmin(context.Background(), db, seal, "bad/name", []byte(secret), nil)
	if err == nil {
		t.Fatal("BootstrapAdmin() unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("error disclosed submitted password")
	}
}
