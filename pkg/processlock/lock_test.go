package processlock

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestAcquireIsExclusiveAndOwnerOnly(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "user-service.lock")
	uid := uint32(os.Geteuid())
	first, err := Acquire(path, uid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	if _, err := Acquire(path, uid); !errors.Is(err, ErrAlreadyLocked) {
		t.Fatalf("second Acquire() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode = %#o", info.Mode().Perm())
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Acquire(path, uid)
	if err != nil {
		t.Fatalf("Acquire() after release: %v", err)
	}
	_ = second.Close()
}

func TestAcquireRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "lock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(link, uint32(os.Geteuid())); err == nil {
		t.Fatal("Acquire() unexpectedly followed a symlink")
	}
}

func TestAcquireRejectsUnexpectedOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test requires an unprivileged owner mismatch")
	}
	path := filepath.Join(t.TempDir(), "lock")
	if _, err := Acquire(path, uint32(os.Geteuid()+1)); err == nil {
		t.Fatal("Acquire() unexpectedly accepted the wrong owner")
	}
}

func currentUID(t *testing.T, path string) uint32 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("missing syscall.Stat_t")
	}
	return stat.Uid
}
