/*
 * @Author: LinkLeong link@icewhale.com
 * @Date: 2022-03-18 11:40:55
 * @LastEditors: LinkLeong
 * @LastEditTime: 2022-07-12 10:05:37
 * @Description:
 * @Website: https://www.casaos.io
 * Copyright (c) 2022 by icewhale, All Rights Reserved.
 */
package service

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"regexp"

	passwordutil "github.com/EdmundFu-233/ReCasaOS-UserService/pkg/password"
	"github.com/EdmundFu-233/ReCasaOS-UserService/pkg/userbootstrap"
	"github.com/EdmundFu-233/ReCasaOS-UserService/service/model"
	"github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrPasswordChanged    = errors.New("password changed concurrently")
	ErrLastAdmin          = errors.New("refuse to delete the last administrator")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidUsername    = errors.New("username must be 1-64 characters and contain only letters, numbers, dot, underscore, or hyphen")
	ErrWeakPassword       = errors.New("password must be between 12 and 1024 bytes")
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type UserService interface {
	UpLoadFile(file multipart.File, name string) error
	UpdateUser(m model.UserDBModel)
	AuthenticateUser(username string, plaintext []byte) (model.UserDBModel, error)
	ChangeUserPassword(id string, oldPassword, newPassword []byte) error
	GetInitializationState(context.Context) (userbootstrap.State, error)
	GetUserInfoById(id string) (m model.UserDBModel)
	GetUserAllInfoById(id string) (m model.UserDBModel)
	GetUserAllInfoByName(userName string) (m model.UserDBModel)
	DeleteUserById(id string) error
	DeleteAllUser() error
	GetUserInfoByUserName(userName string) (m model.UserDBModel)
	GetAllUserName() (list []model.UserDBModel)

	GetKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey)
}

type userService struct {
	privateKey *ecdsa.PrivateKey // keep this private - NEVER expose it!!!
	publicKey  *ecdsa.PublicKey

	db                  *gorm.DB
	initializationState userbootstrap.State
}

func (u *userService) DeleteAllUser() error {
	return ErrLastAdmin
}

func (u *userService) DeleteUserById(id string) (err error) {
	db, err := u.db.DB()
	if err != nil {
		return fmt.Errorf("access user database pool: %w", err)
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("acquire user deletion connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), `BEGIN IMMEDIATE`); err != nil {
		return fmt.Errorf("begin user deletion transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()

	var role string
	if err := conn.QueryRowContext(context.Background(), `SELECT role FROM o_users WHERE id = ?`, id).Scan(&role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("load user for deletion: %w", err)
	}
	if role == "admin" {
		var administratorCount int64
		if err := conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM o_users WHERE role = 'admin'`).Scan(&administratorCount); err != nil {
			return fmt.Errorf("count administrators: %w", err)
		}
		if administratorCount <= 1 {
			return ErrLastAdmin
		}
	}
	result, err := conn.ExecContext(context.Background(), `DELETE FROM o_users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read user deletion result: %w", err)
	}
	if rows != 1 {
		return ErrUserNotFound
	}
	if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
		return fmt.Errorf("commit user deletion: %w", err)
	}
	committed = true
	return nil
}

func (u *userService) GetAllUserName() (list []model.UserDBModel) {
	u.db.Select("username").Find(&list)
	return
}

func (u *userService) UpdateUser(m model.UserDBModel) {
	u.db.Model(&m).Omit("password", "role").Updates(&m)
}

func (u *userService) AuthenticateUser(username string, plaintext []byte) (model.UserDBModel, error) {
	if len(username) == 0 || len(username) > 256 || len(plaintext) == 0 || len(plaintext) > 1024 {
		passwordutil.ConsumeUnknownUser([]byte("invalid-login-input"))
		return model.UserDBModel{}, ErrInvalidCredentials
	}
	var user model.UserDBModel
	if err := u.db.Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			passwordutil.ConsumeUnknownUser(plaintext)
			return model.UserDBModel{}, ErrInvalidCredentials
		}
		return model.UserDBModel{}, fmt.Errorf("load user for authentication: %w", err)
	}

	legacy, err := passwordutil.Verify(user.Password, plaintext)
	if err != nil {
		if errors.Is(err, passwordutil.ErrPassword) || errors.Is(err, passwordutil.ErrInvalidHash) {
			return model.UserDBModel{}, ErrInvalidCredentials
		}
		return model.UserDBModel{}, fmt.Errorf("verify password: %w", err)
	}
	if legacy || passwordutil.NeedsRehash(user.Password) {
		newHash, err := passwordutil.Hash(plaintext)
		if err != nil {
			return model.UserDBModel{}, fmt.Errorf("upgrade password hash: %w", err)
		}
		result := u.db.Model(&model.UserDBModel{}).
			Where("id = ? AND password = ?", user.Id, user.Password).
			Update("password", newHash)
		if result.Error != nil {
			return model.UserDBModel{}, fmt.Errorf("store upgraded password hash: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			var current model.UserDBModel
			if err := u.db.Where("id = ?", user.Id).First(&current).Error; err != nil {
				return model.UserDBModel{}, ErrInvalidCredentials
			}
			if _, err := passwordutil.Verify(current.Password, plaintext); err != nil {
				return model.UserDBModel{}, ErrInvalidCredentials
			}
			user = current
		} else {
			user.Password = newHash
		}
	}
	return user, nil
}

func (u *userService) ChangeUserPassword(id string, oldPassword, newPassword []byte) error {
	if err := ValidateNewPassword(newPassword); err != nil {
		return err
	}
	if len(oldPassword) == 0 || len(oldPassword) > 1024 {
		return ErrInvalidCredentials
	}

	var user model.UserDBModel
	if err := u.db.Where("id = ?", id).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrInvalidCredentials
		}
		return fmt.Errorf("load user for password change: %w", err)
	}
	if _, err := passwordutil.Verify(user.Password, oldPassword); err != nil {
		return ErrInvalidCredentials
	}
	newHash, err := passwordutil.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}
	result := u.db.Model(&model.UserDBModel{}).
		Where("id = ? AND password = ?", user.Id, user.Password).
		Update("password", newHash)
	if result.Error != nil {
		return fmt.Errorf("store new password: %w", result.Error)
	}
	if result.RowsAffected != 1 {
		return ErrPasswordChanged
	}
	return nil
}

func (u *userService) GetInitializationState(ctx context.Context) (userbootstrap.State, error) {
	if err := ctx.Err(); err != nil {
		return userbootstrap.State{}, err
	}
	return u.initializationState, nil
}

func (u *userService) GetUserAllInfoById(id string) (m model.UserDBModel) {
	u.db.Where("id= ?", id).First(&m)
	return
}

func (u *userService) GetUserAllInfoByName(userName string) (m model.UserDBModel) {
	u.db.Where("username= ?", userName).First(&m)
	return
}

func (u *userService) GetUserInfoById(id string) (m model.UserDBModel) {
	u.db.Select("username", "id", "role", "nickname", "description", "avatar", "email").Where("id= ?", id).First(&m)
	return
}

func (u *userService) GetUserInfoByUserName(userName string) (m model.UserDBModel) {
	u.db.Select("username", "id", "role", "nickname", "description", "avatar", "email").Where("username= ?", userName).First(&m)
	return
}

// 上传文件
func (c *userService) UpLoadFile(file multipart.File, url string) error {
	out, _ := os.OpenFile(url, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0o644)
	defer out.Close()
	io.Copy(out, file)
	return nil
}

func (u *userService) GetKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	return u.privateKey, u.publicKey
}

// 获取用户Service
func NewUserService(db *gorm.DB, initializationState userbootstrap.State) UserService {
	// DO NOT store private key anywhere - keep it in memory ONLY!!!
	privateKey, publicKey, err := jwt.GenerateKeyPair()
	if err != nil {
		logger.Error("failed to generate key pair for JWT", zap.Error(err))
		return nil
	}

	return &userService{
		privateKey:          privateKey,
		publicKey:           publicKey,
		db:                  db,
		initializationState: initializationState,
	}
}

// BootstrapAdmin hashes the password before entering the database write lock,
// then delegates the exactly-once state transition to userbootstrap.
func BootstrapAdmin(ctx context.Context, db *gorm.DB, seal userbootstrap.Seal, username string, plaintext []byte, beforeCommit func(int64) error) (int64, error) {
	if !usernamePattern.MatchString(username) {
		return 0, ErrInvalidUsername
	}
	if err := ValidateNewPassword(plaintext); err != nil {
		return 0, err
	}
	hash, err := passwordutil.Hash(plaintext)
	if err != nil {
		return 0, fmt.Errorf("hash bootstrap password: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return 0, fmt.Errorf("access user database pool: %w", err)
	}
	return userbootstrap.CreateAdmin(ctx, sqlDB, seal, username, hash, beforeCommit)
}

func ValidateNewPassword(plaintext []byte) error {
	if len(plaintext) < 12 || len(plaintext) > 1024 {
		return ErrWeakPassword
	}
	for _, character := range plaintext {
		if character == 0 || character == '\r' || character == '\n' {
			return ErrWeakPassword
		}
	}
	return nil
}
