package userconfig

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	// MaxKeyBytes keeps custom configuration names small enough for every
	// supported filesystem while preserving all keys used by the CasaOS UI.
	MaxKeyBytes = 64
	// MaxConfigBytes bounds both request memory use and files read back through
	// the authenticated API.
	MaxConfigBytes = 1 << 20
)

var (
	ErrInvalidKey      = errors.New("invalid custom configuration key")
	ErrInvalidUserID   = errors.New("invalid custom configuration user ID")
	ErrUnsafeStorage   = errors.New("unsafe custom configuration storage")
	ErrConfigTooLarge  = errors.New("custom configuration is too large")
	ErrTemporaryCreate = errors.New("create custom configuration temporary file")
)

// ValidateKey accepts one conservative, portable filename component. The
// explicit separator and parent-reference checks are security boundaries, not
// normalization: callers must never clean an attacker-controlled path into a
// different accepted path.
func ValidateKey(key string) error {
	if len(key) == 0 || len(key) > MaxKeyBytes || strings.Contains(key, "..") || strings.ContainsAny(key, "/\\") {
		return ErrInvalidKey
	}
	for index := 0; index < len(key); index++ {
		character := key[index]
		letter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
		digit := character >= '0' && character <= '9'
		if letter || digit || index > 0 && (character == '-' || character == '_' || character == '.') {
			continue
		}
		return ErrInvalidKey
	}
	return nil
}

// Read returns one authenticated user's custom configuration. All filesystem
// traversal is descriptor-relative beneath an owner-only data root.
func Read(rootPath string, userID int, key string) ([]byte, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	root, err := openUserRoot(rootPath, userID, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	file, err := openExistingRegularFile(root, key+".json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read custom configuration: %w", err)
	}
	if len(data) > MaxConfigBytes {
		return nil, ErrConfigTooLarge
	}
	return data, nil
}

// Write atomically replaces one authenticated user's custom configuration.
// Existing legacy files are accepted only when they are single-link regular
// files owned by this service; symbolic links and special files fail closed.
func Write(rootPath string, userID int, key string, data []byte) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	if len(data) > MaxConfigBytes {
		return ErrConfigTooLarge
	}
	root, err := openUserRoot(rootPath, userID, true)
	if err != nil {
		return err
	}
	defer root.Close()

	filename := key + ".json"
	if info, err := root.Lstat(filename); err == nil {
		if err := validateRegularFile(info); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect custom configuration: %w", err)
	}

	temporaryName, temporary, err := createTemporaryFile(root)
	if err != nil {
		return err
	}
	keepTemporary := true
	defer func() {
		if temporary != nil {
			_ = temporary.Close()
		}
		if keepTemporary {
			_ = root.Remove(temporaryName)
		}
	}()

	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write custom configuration: %w", err)
	}
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure custom configuration: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync custom configuration: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close custom configuration: %w", err)
	}
	temporary = nil
	if err := root.Rename(temporaryName, filename); err != nil {
		return fmt.Errorf("install custom configuration: %w", err)
	}
	keepTemporary = false
	return syncRoot(root)
}

// Delete removes one authenticated user's custom configuration without ever
// following a final symbolic link.
func Delete(rootPath string, userID int, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	root, err := openUserRoot(rootPath, userID, false)
	if err != nil {
		return err
	}
	defer root.Close()

	filename := key + ".json"
	info, err := root.Lstat(filename)
	if err != nil {
		return err
	}
	if err := validateRegularFile(info); err != nil {
		return err
	}
	if err := root.Remove(filename); err != nil {
		return fmt.Errorf("remove custom configuration: %w", err)
	}
	return syncRoot(root)
}

func openUserRoot(rootPath string, userID int, create bool) (*os.Root, error) {
	if userID <= 0 {
		return nil, ErrInvalidUserID
	}
	if strings.TrimSpace(rootPath) == "" || !filepath.IsAbs(rootPath) {
		return nil, ErrUnsafeStorage
	}
	rootInfo, err := os.Lstat(rootPath)
	if err != nil {
		return nil, fmt.Errorf("inspect custom configuration root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || !ownedByCurrentUser(rootInfo) || rootInfo.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%w: unsafe shared data root", ErrUnsafeStorage)
	}

	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open custom configuration root: %w", err)
	}
	closeOnError := func(err error) (*os.Root, error) {
		_ = root.Close()
		return nil, err
	}
	openedRootInfo, err := root.Stat(".")
	if err != nil {
		return closeOnError(fmt.Errorf("inspect opened custom configuration root: %w", err))
	}
	if !os.SameFile(rootInfo, openedRootInfo) || !openedRootInfo.IsDir() ||
		!ownedByCurrentUser(openedRootInfo) || openedRootInfo.Mode().Perm()&0o022 != 0 {
		return closeOnError(fmt.Errorf("%w: shared data root changed during open", ErrUnsafeStorage))
	}

	userDirectory := strconv.Itoa(userID)
	if create {
		if err := root.Mkdir(userDirectory, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return closeOnError(fmt.Errorf("create custom configuration directory: %w", err))
		}
	}
	userInfo, err := root.Lstat(userDirectory)
	if err != nil {
		return closeOnError(err)
	}
	if userInfo.Mode()&os.ModeSymlink != 0 || !userInfo.IsDir() || !ownedByCurrentUser(userInfo) {
		return closeOnError(ErrUnsafeStorage)
	}

	userRoot, err := root.OpenRoot(userDirectory)
	_ = root.Close()
	if err != nil {
		return nil, fmt.Errorf("open custom configuration directory: %w", err)
	}
	openedUserInfo, err := userRoot.Stat(".")
	if err != nil {
		_ = userRoot.Close()
		return nil, fmt.Errorf("inspect opened custom configuration directory: %w", err)
	}
	if !os.SameFile(userInfo, openedUserInfo) || !openedUserInfo.IsDir() || !ownedByCurrentUser(openedUserInfo) {
		_ = userRoot.Close()
		return nil, fmt.Errorf("%w: user directory changed during open", ErrUnsafeStorage)
	}
	userDirectoryHandle, err := userRoot.Open(".")
	if err != nil {
		_ = userRoot.Close()
		return nil, fmt.Errorf("open custom configuration directory handle: %w", err)
	}
	if err := userDirectoryHandle.Chmod(0o700); err != nil {
		_ = userDirectoryHandle.Close()
		_ = userRoot.Close()
		return nil, fmt.Errorf("secure custom configuration directory: %w", err)
	}
	if err := userDirectoryHandle.Close(); err != nil {
		_ = userRoot.Close()
		return nil, fmt.Errorf("close custom configuration directory handle: %w", err)
	}
	return userRoot, nil
}

func openExistingRegularFile(root *os.Root, filename string) (*os.File, error) {
	before, err := root.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if err := validateRegularFile(before); err != nil {
		return nil, err
	}
	file, err := root.Open(filename)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect opened custom configuration: %w", err)
	}
	if err := validateRegularFile(after); err != nil || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, ErrUnsafeStorage
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure opened custom configuration: %w", err)
	}
	return file, nil
}

func validateRegularFile(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: symbolic link", ErrUnsafeStorage)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: non-regular file", ErrUnsafeStorage)
	}
	if !ownedByCurrentUser(info) {
		return fmt.Errorf("%w: unexpected owner", ErrUnsafeStorage)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: unavailable file identity", ErrUnsafeStorage)
	}
	// A zero link count is possible for an already-open inode while another
	// authenticated request atomically replaces the pathname. It is not an
	// alias to another pathname; only multiple links create that risk.
	if stat.Nlink > 1 {
		return fmt.Errorf("%w: unexpected link count", ErrUnsafeStorage)
	}
	return nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func createTemporaryFile(root *os.Root) (string, *os.File, error) {
	for attempt := 0; attempt < 16; attempt++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", nil, fmt.Errorf("%w: generate name: %v", ErrTemporaryCreate, err)
		}
		name := ".recasaos-custom-" + hex.EncodeToString(nonce[:])
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return name, file, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", nil, fmt.Errorf("%w: %v", ErrTemporaryCreate, err)
		}
	}
	return "", nil, ErrTemporaryCreate
}

func syncRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open custom configuration directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync custom configuration directory: %w", err)
	}
	return nil
}
