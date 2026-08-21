package userbootstrap

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const sealFormatPrefix = "recasaos-user-bootstrap-v1:"

type FileSeal struct {
	path     string
	ownerUID uint32
}

func NewFileSeal(path string, ownerUID uint32) *FileSeal {
	return &FileSeal{path: path, ownerUID: ownerUID}
}

func (seal *FileSeal) Load() (string, bool, error) {
	if seal == nil || !filepath.IsAbs(seal.path) {
		return "", false, errors.New("bootstrap seal path must be absolute")
	}
	if err := validateExistingSealDirectory(filepath.Dir(seal.path), seal.ownerUID); err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	info, err := os.Lstat(seal.path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("inspect bootstrap seal: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", false, errors.New("bootstrap seal must be a regular file, not a symlink")
	}
	if info.Mode().Perm() != 0o600 {
		return "", false, errors.New("bootstrap seal must have mode 0600")
	}
	if uid, ok := fileOwnerUID(info); !ok || uid != seal.ownerUID {
		return "", false, errors.New("bootstrap seal has an unexpected owner")
	}

	fd, err := unix.Open(seal.path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", false, fmt.Errorf("open bootstrap seal: %w", err)
	}
	file := os.NewFile(uintptr(fd), seal.path)
	if file == nil {
		_ = unix.Close(fd)
		return "", false, errors.New("open bootstrap seal")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return "", false, fmt.Errorf("inspect open bootstrap seal: %w", err)
	}
	if !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() {
		return "", false, errors.New("bootstrap seal changed while opening")
	}
	contents, err := io.ReadAll(io.LimitReader(file, 128))
	if err != nil {
		return "", false, fmt.Errorf("read bootstrap seal: %w", err)
	}
	value := strings.TrimSuffix(string(contents), "\n")
	if !strings.HasPrefix(value, sealFormatPrefix) || strings.Contains(value, "\n") {
		return "", false, errors.New("bootstrap seal has an invalid format")
	}
	installationID := strings.TrimPrefix(value, sealFormatPrefix)
	if !validInstallationID(installationID) {
		return "", false, errors.New("bootstrap seal has an invalid installation id")
	}
	return installationID, true, nil
}

func (seal *FileSeal) Create(installationID string) error {
	if !validInstallationID(installationID) {
		return errors.New("refuse to create a seal with an invalid installation id")
	}
	if existingID, exists, err := seal.Load(); err != nil {
		return err
	} else if exists {
		if existingID != installationID {
			return errors.New("bootstrap seal belongs to another installation")
		}
		return nil
	}

	directory := filepath.Dir(seal.path)
	if err := ensureSealDirectory(directory, seal.ownerUID); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".recasaos-bootstrap-seal-*")
	if err != nil {
		return fmt.Errorf("create temporary bootstrap seal: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	closeTemporary := func() {
		_ = temporary.Close()
	}
	defer closeTemporary()

	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary bootstrap seal: %w", err)
	}
	if info, err := temporary.Stat(); err != nil {
		return fmt.Errorf("inspect temporary bootstrap seal: %w", err)
	} else if uid, ok := fileOwnerUID(info); !ok || uid != seal.ownerUID {
		return errors.New("temporary bootstrap seal has an unexpected owner")
	}
	if _, err := io.WriteString(temporary, sealFormatPrefix+installationID+"\n"); err != nil {
		return fmt.Errorf("write temporary bootstrap seal: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary bootstrap seal: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary bootstrap seal: %w", err)
	}

	if err := os.Link(temporaryPath, seal.path); err != nil {
		if existingID, exists, loadErr := seal.Load(); loadErr == nil && exists && existingID == installationID {
			return nil
		}
		return fmt.Errorf("publish bootstrap seal: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open bootstrap seal directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync bootstrap seal directory: %w", err)
	}
	return nil
}

func ensureSealDirectory(path string, ownerUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("inspect bootstrap seal directory: %w", err)
		}
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create bootstrap seal directory: %w", err)
		}
		info, err = os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect created bootstrap seal directory: %w", err)
		}
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("bootstrap seal directory must be a real directory, not a symlink")
	}
	if uid, ok := fileOwnerUID(info); !ok || uid != ownerUID {
		return errors.New("bootstrap seal directory has an unexpected owner")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("bootstrap seal directory must not be writable by group or other users")
	}
	return nil
}

func validateExistingSealDirectory(path string, ownerUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("bootstrap seal directory must be a real directory, not a symlink")
	}
	if uid, ok := fileOwnerUID(info); !ok || uid != ownerUID {
		return errors.New("bootstrap seal directory has an unexpected owner")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("bootstrap seal directory must not be writable by group or other users")
	}
	return nil
}

func fileOwnerUID(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}
