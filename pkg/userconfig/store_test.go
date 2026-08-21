package userconfig

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestValidateKey(t *testing.T) {
	t.Parallel()
	valid := []string{
		"system",
		"link",
		"shortcut",
		"wallpaper",
		"notFirstOpenMergerStorage",
		"widgets_config",
		"app_order",
		"shared_init_data",
		"new_app_ids",
		"tips_state",
		"app-order.v2",
	}
	for _, key := range valid {
		if err := ValidateKey(key); err != nil {
			t.Errorf("ValidateKey(%q) = %v", key, err)
		}
	}
	invalid := []string{
		"",
		".",
		"..",
		"../outside",
		"inside/../../outside",
		`inside\outside`,
		"%2foutside",
		" leading",
		"trailing ",
		"line\nfeed",
		"nul\x00byte",
		"unicodé",
		strings.Repeat("a", MaxKeyBytes+1),
	}
	for _, key := range invalid {
		if err := ValidateKey(key); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("ValidateKey(%q) = %v, want ErrInvalidKey", key, err)
		}
	}
}

func TestRoundTripUsesOwnerOnlyLegacyCompatibleLayout(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"theme":"dark"}`)
	if err := Write(root, 7, "system", payload); err != nil {
		t.Fatal(err)
	}
	assertMode(t, root, 0o755)
	userDirectory := filepath.Join(root, "7")
	filename := filepath.Join(userDirectory, "system.json")
	assertMode(t, userDirectory, 0o700)
	assertMode(t, filename, 0o600)
	data, err := Read(root, 7, "system")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("Read() = %q, want %q", data, payload)
	}
	if err := Delete(root, 7, "system"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filename); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("configuration still exists: %v", err)
	}
}

func TestWritableSharedRootFailsClosedWithoutChangingPermissions(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := Write(root, 7, "system", []byte("changed")); !errors.Is(err, ErrUnsafeStorage) {
		t.Fatalf("Write() error = %v, want ErrUnsafeStorage", err)
	}
	assertMode(t, root, 0o777)
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatalf("unsafe shared root changed: entries=%v err=%v", entries, err)
	}
}

func TestSharedRootSymlinkFailsClosed(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	target := t.TempDir()
	root := filepath.Join(parent, "data")
	if err := os.Symlink(target, root); err != nil {
		t.Fatal(err)
	}
	if err := Write(root, 7, "system", []byte("changed")); !errors.Is(err, ErrUnsafeStorage) {
		t.Fatalf("Write() error = %v, want ErrUnsafeStorage", err)
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Fatalf("symlink target changed: entries=%v err=%v", entries, err)
	}
}

func TestLegacyDirectoryAndFileAreTightenedWithoutChangingBytes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	userDirectory := filepath.Join(root, "11")
	if err := os.Mkdir(userDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(userDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(userDirectory, "link.json")
	want := []byte(`{"items":[1,2,3]}`)
	if err := os.WriteFile(filename, want, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, 0o666); err != nil {
		t.Fatal(err)
	}
	got, err := Read(root, 11, "link")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Read() = %q, want %q", got, want)
	}
	assertMode(t, root, 0o755)
	assertMode(t, userDirectory, 0o700)
	assertMode(t, filename, 0o600)
}

func TestUserDirectorySymlinkFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "3")); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []struct {
		name string
		call func() error
	}{
		{name: "read", call: func() error { _, err := Read(root, 3, "system"); return err }},
		{name: "write", call: func() error { return Write(root, 3, "system", []byte("changed")) }},
		{name: "delete", call: func() error { return Delete(root, 3, "system") }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.call(); !errors.Is(err, ErrUnsafeStorage) {
				t.Fatalf("error = %v, want ErrUnsafeStorage", err)
			}
		})
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("outside directory changed: entries=%v err=%v", entries, err)
	}
}

func TestConfigurationSymlinkFailsClosedWithoutChangingTarget(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	userDirectory := filepath.Join(root, "5")
	if err := os.Mkdir(userDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside.json")
	want := []byte("outside-sentinel")
	if err := os.WriteFile(target, want, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(userDirectory, "system.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []struct {
		name string
		call func() error
	}{
		{name: "read", call: func() error { _, err := Read(root, 5, "system"); return err }},
		{name: "write", call: func() error { return Write(root, 5, "system", []byte("changed")) }},
		{name: "delete", call: func() error { return Delete(root, 5, "system") }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.call(); !errors.Is(err, ErrUnsafeStorage) {
				t.Fatalf("error = %v, want ErrUnsafeStorage", err)
			}
		})
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("outside target = %q, want %q", got, want)
	}
}

func TestHardLinkAndFIFOFailClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	userDirectory := filepath.Join(root, "9")
	if err := os.Mkdir(userDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, filepath.Join(userDirectory, "hardlink.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(root, 9, "hardlink"); !errors.Is(err, ErrUnsafeStorage) {
		t.Fatalf("hardlink read error = %v, want ErrUnsafeStorage", err)
	}
	if err := Write(root, 9, "hardlink", []byte("changed")); !errors.Is(err, ErrUnsafeStorage) {
		t.Fatalf("hardlink write error = %v, want ErrUnsafeStorage", err)
	}
	if err := Delete(root, 9, "hardlink"); !errors.Is(err, ErrUnsafeStorage) {
		t.Fatalf("hardlink delete error = %v, want ErrUnsafeStorage", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("sentinel")) {
		t.Fatalf("hardlink target changed: %q", got)
	}
	if err := syscall.Mkfifo(filepath.Join(userDirectory, "pipe.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(root, 9, "pipe"); !errors.Is(err, ErrUnsafeStorage) {
		t.Fatalf("FIFO read error = %v, want ErrUnsafeStorage", err)
	}
	if err := Delete(root, 9, "pipe"); !errors.Is(err, ErrUnsafeStorage) {
		t.Fatalf("FIFO delete error = %v, want ErrUnsafeStorage", err)
	}
}

func TestOversizedLegacyConfigurationReadFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	userDirectory := filepath.Join(root, "15")
	if err := os.Mkdir(userDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(userDirectory, "system.json")
	want := bytes.Repeat([]byte{'x'}, MaxConfigBytes+1)
	if err := os.WriteFile(filename, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(root, 15, "system"); !errors.Is(err, ErrConfigTooLarge) {
		t.Fatalf("Read() error = %v, want ErrConfigTooLarge", err)
	}
	got, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("oversized legacy configuration changed")
	}
}

func TestSizeLimitAndConcurrentAtomicWrites(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := Write(root, 13, "system", bytes.Repeat([]byte{'x'}, MaxConfigBytes+1)); !errors.Is(err, ErrConfigTooLarge) {
		t.Fatalf("oversized write error = %v, want ErrConfigTooLarge", err)
	}
	payloads := [][]byte{
		bytes.Repeat([]byte{'a'}, 8192),
		bytes.Repeat([]byte{'b'}, 16384),
	}
	var wait sync.WaitGroup
	errorsByWriter := make(chan error, 32)
	for index := 0; index < 32; index++ {
		wait.Add(1)
		payload := payloads[index%len(payloads)]
		go func() {
			defer wait.Done()
			errorsByWriter <- Write(root, 13, "system", payload)
		}()
	}
	wait.Wait()
	close(errorsByWriter)
	for err := range errorsByWriter {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := Read(root, 13, "system")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payloads[0]) && !bytes.Equal(got, payloads[1]) {
		t.Fatalf("final data is not one complete payload: len=%d", len(got))
	}
	entries, err := os.ReadDir(filepath.Join(root, "13"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".recasaos-custom-") {
			t.Fatalf("temporary file was not removed: %s", entry.Name())
		}
	}
}

func assertMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode(%s) = %#o, want %#o", path, got, want)
	}
}
