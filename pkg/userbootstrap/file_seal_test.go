package userbootstrap

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const testInstallationID = "7bc942d6-25ef-4af8-8f0f-f9ddd90942cc"

func TestFileSealCreateLoadAndIdempotence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "bootstrap.seal")
	seal := NewFileSeal(path, uint32(os.Geteuid()))
	if err := seal.Create(testInstallationID); err != nil {
		t.Fatal(err)
	}
	id, exists, err := seal.Load()
	if err != nil || !exists || id != testInstallationID {
		t.Fatalf("Load() = %q, %v, %v", id, exists, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("seal mode = %#o", info.Mode().Perm())
	}
	if err := seal.Create(testInstallationID); err != nil {
		t.Fatalf("idempotent Create(): %v", err)
	}
	if err := seal.Create("02bb57a8-0bb2-4266-bf99-ae81f37c09a4"); err == nil {
		t.Fatal("Create() accepted another installation id")
	}
}

func TestFileSealConcurrentCreatePublishesOneMatchingValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap.seal")
	seal := NewFileSeal(path, uint32(os.Geteuid()))
	const callers = 12
	var waitGroup sync.WaitGroup
	errorsByCaller := make(chan error, callers)
	for index := 0; index < callers; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			errorsByCaller <- seal.Create(testInstallationID)
		}()
	}
	waitGroup.Wait()
	close(errorsByCaller)
	for err := range errorsByCaller {
		if err != nil {
			t.Fatalf("concurrent Create(): %v", err)
		}
	}
	if id, exists, err := seal.Load(); err != nil || !exists || id != testInstallationID {
		t.Fatalf("Load() = %q, %v, %v", id, exists, err)
	}
}

func TestFileSealRejectsUnsafeOrMalformedFiles(t *testing.T) {
	tests := []struct {
		name    string
		content string
		mode    os.FileMode
	}{
		{name: "overbroad mode", content: sealFormatPrefix + testInstallationID + "\n", mode: 0o644},
		{name: "malformed", content: "not-a-seal\n", mode: 0o600},
		{name: "trailing data", content: sealFormatPrefix + testInstallationID + "\nextra", mode: 0o600},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "seal")
			if err := os.WriteFile(path, []byte(test.content), test.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			seal := NewFileSeal(path, uint32(os.Geteuid()))
			if _, _, err := seal.Load(); err == nil {
				t.Fatal("Load() unexpectedly accepted unsafe seal")
			}
		})
	}
}

func TestFileSealRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte(sealFormatPrefix+testInstallationID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "seal")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	seal := NewFileSeal(link, uint32(os.Geteuid()))
	if _, _, err := seal.Load(); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Load() error = %v", err)
	}
}
