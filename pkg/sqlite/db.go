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
	"time"

	"github.com/IceWhaleTech/CasaOS-UserService/model"
	model2 "github.com/IceWhaleTech/CasaOS-UserService/service/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

const databaseFilename = "user.db"

// GetDb opens and migrates an isolated user database. The directory and
// database contain password verifiers and are therefore always owner-only.
// Initialization errors are returned to the caller instead of being logged and
// ignored or panicking inside this package.
func GetDb(dbPath string) (*gorm.DB, error) {
	if strings.TrimSpace(dbPath) == "" {
		return nil, errors.New("database directory is empty")
	}
	if err := secureDirectory(dbPath); err != nil {
		return nil, err
	}

	databasePath := filepath.Join(dbPath, databaseFilename)
	if err := secureDatabaseFile(databasePath); err != nil {
		return nil, err
	}

	// _pragma is applied to every connection opened by modernc SQLite, which
	// gives concurrent BEGIN IMMEDIATE callers a bounded chance to serialize.
	dsnURL := &url.URL{Scheme: "file", Path: databasePath}
	query := dsnURL.Query()
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

	if err := db.AutoMigrate(model2.UserDBModel{}, model2.BootstrapStateDBModel{}, model.EventModel{}); err != nil {
		return closeOnError(fmt.Errorf("migrate user database: %w", err))
	}
	if err := os.Chmod(databasePath, 0o600); err != nil {
		return closeOnError(fmt.Errorf("secure user database: %w", err))
	}
	return db, nil
}

func secureDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("inspect database directory: %w", err)
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
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("secure database directory: %w", err)
	}
	return nil
}

func secureDatabaseFile(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("user database must be a regular file, not a symlink")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect user database: %w", err)
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("create user database: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close user database bootstrap file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure user database bootstrap file: %w", err)
	}
	return nil
}
