package service

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 -- constructs a legacy database fixture only.
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

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
		t.Fatalf("created user role=%q password=%q", user.Role, user.Password)
	}
	if _, err := BootstrapAdmin(context.Background(), db, seal, "second", []byte("another-strong-password"), nil); !errors.Is(err, userbootstrap.ErrAlreadyInitialized) {
		t.Fatalf("replayed BootstrapAdmin() = %v", err)
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

func TestLegacyMD5LoginCASMigratesToArgon2id(t *testing.T) {
	db, seal := openSecurityTestDatabase(t)
	plaintext := []byte("legacy-password")
	legacyDigest := md5.Sum(plaintext) // #nosec G401 -- legacy fixture.
	legacyHash := hex.EncodeToString(legacyDigest[:])
	legacy := model.UserDBModel{Username: "legacy", Password: legacyHash, Role: "admin"}
	if err := db.Create(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	userService := NewUserService(db, seal)

	const concurrentLogins = 4
	start := make(chan struct{})
	errorsByLogin := make(chan error, concurrentLogins)
	var waitGroup sync.WaitGroup
	for index := 0; index < concurrentLogins; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			_, err := userService.AuthenticateUser("legacy", plaintext)
			errorsByLogin <- err
		}()
	}
	close(start)
	waitGroup.Wait()
	close(errorsByLogin)
	for err := range errorsByLogin {
		if err != nil {
			t.Fatalf("concurrent legacy login: %v", err)
		}
	}

	var migrated model.UserDBModel
	if err := db.First(&migrated, legacy.Id).Error; err != nil {
		t.Fatal(err)
	}
	if migrated.Password == legacyHash || !passwordutil.IsArgon2id(migrated.Password) {
		t.Fatalf("legacy hash was not migrated: %q", migrated.Password)
	}
	if _, err := passwordutil.Verify(migrated.Password, plaintext); err != nil {
		t.Fatalf("migrated verifier rejected password: %v", err)
	}
	if _, err := userService.AuthenticateUser("legacy", []byte("wrong-password")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong login error=%v", err)
	}
	if _, err := userService.AuthenticateUser("missing", []byte("wrong-password")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown login error=%v", err)
	}
}

func TestAuthenticationRejectsOversizeInput(t *testing.T) {
	db, seal := openSecurityTestDatabase(t)
	userService := NewUserService(db, seal)
	if _, err := userService.AuthenticateUser("missing", bytes.Repeat([]byte{'x'}, 1025)); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("oversize password error=%v", err)
	}
	if _, err := userService.AuthenticateUser(strings.Repeat("u", 257), []byte("password")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("oversize username error=%v", err)
	}
}

func TestPasswordChangeAlwaysStoresArgon2idAndUsesCAS(t *testing.T) {
	db, seal := openSecurityTestDatabase(t)
	_, err := BootstrapAdmin(context.Background(), db, seal, "admin", []byte("original-strong-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	userService := NewUserService(db, seal)
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
		t.Fatalf("changed password is not Argon2id: %q", changed.Password)
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
	userService := NewUserService(db, seal)
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
	userService := NewUserService(db, seal)
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
