package sqlite

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	model2 "github.com/IceWhaleTech/CasaOS-UserService/service/model"
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
