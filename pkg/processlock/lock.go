// Package processlock provides the non-blocking filesystem lock shared by the
// daemon and local bootstrap command.
package processlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

var ErrAlreadyLocked = errors.New("user service or bootstrap is already running")

type Lock struct {
	file *os.File
}

func Acquire(path string, ownerUID uint32) (*Lock, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("process lock path must be absolute")
	}
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("inspect process lock directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("process lock directory must be a real directory, not a symlink")
	}
	if uid, ok := ownerUIDOf(info); !ok || uid != ownerUID {
		return nil, errors.New("process lock directory has an unexpected owner")
	}

	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open process lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open process lock")
	}
	closeOnError := func(err error) (*Lock, error) {
		_ = file.Close()
		return nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return closeOnError(fmt.Errorf("inspect process lock: %w", err))
	}
	if !openedInfo.Mode().IsRegular() {
		return closeOnError(errors.New("process lock must be a regular file"))
	}
	if uid, ok := ownerUIDOf(openedInfo); !ok || uid != ownerUID {
		return closeOnError(errors.New("process lock has an unexpected owner"))
	}
	if err := file.Chmod(0o600); err != nil {
		return closeOnError(fmt.Errorf("secure process lock: %w", err))
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return closeOnError(ErrAlreadyLocked)
		}
		return closeOnError(fmt.Errorf("acquire process lock: %w", err))
	}
	return &Lock{file: file}, nil
}

func (lock *Lock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	fd := int(lock.file.Fd())
	unlockErr := unix.Flock(fd, unix.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if unlockErr != nil {
		return fmt.Errorf("unlock process lock: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close process lock: %w", closeErr)
	}
	return nil
}

func ownerUIDOf(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}
