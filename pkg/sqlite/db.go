/*
 * @Author: LinkLeong link@icewhale.com
 * @Date: 2022-05-13 18:15:46
 * @LastEditors: LinkLeong
 * @LastEditTime: 2022-07-11 18:10:53
 * @Description:
 * @Website: https://www.casaos.io
 * Copyright (c) 2022 by icewhale, All Rights Reserved.
 */
package sqlite

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/EdmundFu-233/ReCasaOS-UserService/model"
	model2 "github.com/EdmundFu-233/ReCasaOS-UserService/service/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

const databaseFilename = "user.db"

// GetDb opens and migrates an isolated user database. The directory and
// database contain password verifiers and are therefore always owner-only.
// Initialization errors are returned to the caller instead of being logged and
// ignored or panicking inside this package.
func GetDb(dbPath string) (*gorm.DB, error) {
	return openDb(dbPath, true, true)
}

// GetExistingDb opens an existing database without creating a directory or
// database file. Local recovery commands use it so a mistyped path cannot
// create a second empty user database.
func GetExistingDb(dbPath string) (*gorm.DB, error) {
	return openDb(dbPath, false, false)
}

func openDb(dbPath string, create, migrate bool) (*gorm.DB, error) {
	if strings.TrimSpace(dbPath) == "" {
		return nil, errors.New("database directory is empty")
	}
	if err := secureDirectory(dbPath, create); err != nil {
		return nil, err
	}

	databasePath := filepath.Join(dbPath, databaseFilename)
	if err := secureDatabaseFile(databasePath, create); err != nil {
		return nil, err
	}

	// _pragma is applied to every connection opened by modernc SQLite, which
	// gives concurrent BEGIN IMMEDIATE callers a bounded chance to serialize.
	dsnURL := &url.URL{Scheme: "file", Path: databasePath}
	query := dsnURL.Query()
	if !create {
		query.Add("mode", "rw")
	}
	query.Add("_pragma", "busy_timeout=5000")
	query.Add("_pragma", "foreign_keys=1")
	dsnURL.RawQuery = query.Encode()
	dsn := dsnURL.String()
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open user database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("access user database pool: %w", err)
	}
	sqlDB.SetMaxIdleConns(2)
	sqlDB.SetMaxOpenConns(8)
	sqlDB.SetConnMaxIdleTime(time.Second * 1000)

	closeOnError := func(err error) (*gorm.DB, error) {
		_ = sqlDB.Close()
		return nil, err
	}

	if migrate {
		if err := db.AutoMigrate(model2.UserDBModel{}, model2.BootstrapStateDBModel{}, model.EventModel{}); err != nil {
			return closeOnError(fmt.Errorf("migrate user database: %w", err))
		}
	}
	if err := os.Chmod(databasePath, 0o600); err != nil {
		return closeOnError(fmt.Errorf("secure user database: %w", err))
	}
	return db, nil
}

func secureDirectory(path string, create bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("inspect database directory: %w", err)
		}
		if !create {
			return errors.New("user database directory does not exist")
		}
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create database directory: %w", err)
		}
		info, err = os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect created database directory: %w", err)
		}
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("database directory must be a real directory, not a symlink")
	}
	if uid, ok := ownerUID(info); !ok || uid != uint32(os.Geteuid()) {
		return errors.New("database directory has an unexpected owner")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("secure database directory: %w", err)
	}
	return nil
}

func secureDatabaseFile(path string, create bool) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("user database must be a regular file, not a symlink")
		}
		if uid, ok := ownerUID(info); !ok || uid != uint32(os.Geteuid()) {
			return errors.New("user database has an unexpected owner")
		}
	} else {
		if !os.IsNotExist(err) {
			return fmt.Errorf("inspect user database: %w", err)
		}
		if !create {
			return errors.New("user database file does not exist")
		}
	}

	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return fmt.Errorf("open user database bootstrap file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close user database bootstrap file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure user database bootstrap file: %w", err)
	}
	return nil
}

func ownerUID(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}
