package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadCredentialAcceptsOnlyOwnerPrivateRegularFile(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "credentials")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, passwordCredentialName)
	if err := os.WriteFile(path, []byte("strong-password\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	credential, err := readCredential(directory, passwordCredentialName, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer erase(credential)
	if string(credential) != "strong-password" {
		t.Fatalf("credential = %q", credential)
	}
}

func TestReadCredentialRejectsUnsafeInputs(t *testing.T) {
	t.Run("overbroad directory", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "credentials")
		if err := os.Mkdir(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := readCredential(directory, passwordCredentialName, uint32(os.Geteuid())); err == nil {
			t.Fatal("readCredential() accepted overbroad directory")
		}
	})

	t.Run("overbroad file", func(t *testing.T) {
		directory := privateCredentialDirectory(t)
		path := filepath.Join(directory, passwordCredentialName)
		if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readCredential(directory, passwordCredentialName, uint32(os.Geteuid())); err == nil {
			t.Fatal("readCredential() accepted overbroad file")
		}
	})

	t.Run("embedded newline", func(t *testing.T) {
		directory := privateCredentialDirectory(t)
		path := filepath.Join(directory, passwordCredentialName)
		if err := os.WriteFile(path, []byte("first\nsecond"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readCredential(directory, passwordCredentialName, uint32(os.Geteuid())); err == nil {
			t.Fatal("readCredential() accepted embedded newline")
		}
	})

	t.Run("oversize", func(t *testing.T) {
		directory := privateCredentialDirectory(t)
		path := filepath.Join(directory, passwordCredentialName)
		if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maximumCredentialBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readCredential(directory, passwordCredentialName, uint32(os.Geteuid())); err == nil {
			t.Fatal("readCredential() accepted oversize input")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink semantics differ on Windows")
		}
		directory := privateCredentialDirectory(t)
		target := filepath.Join(directory, "target")
		if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(directory, passwordCredentialName)); err != nil {
			t.Fatal(err)
		}
		if _, err := readCredential(directory, passwordCredentialName, uint32(os.Geteuid())); err == nil {
			t.Fatal("readCredential() followed a symlink")
		}
	})
}

func TestBootstrapCLIRejectsNonRootAndPasswordArgumentsWithoutDisclosure(t *testing.T) {
	secret := "never-print-this-password"
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	err := run([]string{"bootstrap-admin", "-password=" + secret}, stdout, stderr, 0, func(string) string {
		t.Fatal("environment should not be read after argument parse failure")
		return ""
	})
	if err == nil {
		t.Fatal("bootstrap-admin accepted a password argument")
	}
	if strings.Contains(err.Error()+stdout.String()+stderr.String(), secret) {
		t.Fatal("bootstrap argument error disclosed password value")
	}

	err = run([]string{"bootstrap-admin"}, stdout, stderr, 1, func(string) string {
		t.Fatal("non-root bootstrap should fail before reading credentials")
		return ""
	})
	if err == nil || !strings.Contains(err.Error(), "effective uid 0") {
		t.Fatalf("non-root bootstrap error = %v", err)
	}
}

func TestPasswordResetCLIRejectsNonRootAndPasswordArgumentsWithoutDisclosure(t *testing.T) {
	secret := "never-print-this-reset-password"
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	err := run([]string{"reset-admin-password", "-password=" + secret}, stdout, stderr, 0, func(string) string {
		t.Fatal("environment should not be read after argument parse failure")
		return ""
	})
	if err == nil {
		t.Fatal("reset-admin-password accepted a password argument")
	}
	if strings.Contains(err.Error()+stdout.String()+stderr.String(), secret) {
		t.Fatal("reset argument error disclosed password value")
	}

	err = run([]string{"reset-admin-password"}, stdout, stderr, 1, func(string) string {
		t.Fatal("non-root reset should fail before reading credentials")
		return ""
	})
	if err == nil || !strings.Contains(err.Error(), "effective uid 0") {
		t.Fatalf("non-root reset error = %v", err)
	}
}

func TestLegacyResetIsDisabledWithoutPrintingCredentials(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	err := run([]string{"-ru", "-user", "admin"}, stdout, stderr, os.Geteuid(), os.Getenv)
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("legacy reset error = %v", err)
	}
	combined := stdout.String() + stderr.String()
	for _, forbidden := range []string{"Password:", "UserName:"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("legacy reset output contains %q: %s", forbidden, combined)
		}
	}
}

func TestBootstrapSealMustBeOutsideDatabaseDirectory(t *testing.T) {
	database := filepath.Join(t.TempDir(), "db")
	if err := requireSealOutsideDatabase(database, filepath.Join(database, "seal")); err == nil {
		t.Fatal("seal inside database directory was accepted")
	}
	if err := requireSealOutsideDatabase(database, filepath.Join(filepath.Dir(database), "seal")); err != nil {
		t.Fatalf("seal outside database directory was rejected: %v", err)
	}
}

func TestBootstrapSealRejectsAncestorSymlinkIntoDatabase(t *testing.T) {
	root := t.TempDir()
	database := filepath.Join(root, "database")
	if err := os.Mkdir(database, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "apparently-external")
	if err := os.Symlink(database, alias); err != nil {
		t.Fatal(err)
	}
	if err := requireSealOutsideDatabase(database, filepath.Join(alias, "seal")); err == nil {
		t.Fatal("seal physically inside database through ancestor symlink was accepted")
	}
}

func TestSystemdBootstrapUnitIsOneShotAndConflictsWithDaemon(t *testing.T) {
	unit, err := os.ReadFile("build/sysroot/usr/lib/systemd/system/recasaos-user-bootstrap.service")
	if err != nil {
		t.Fatal(err)
	}
	text := string(unit)
	for _, required := range []string{
		"Conflicts=casaos-user-service.service",
		"Type=oneshot",
		"LoadCredential=recasaos.admin.username:/run/recasaos-user-bootstrap/username",
		"LoadCredential=recasaos.admin.password:/run/recasaos-user-bootstrap/password",
		"ExecStart=/usr/bin/casaos-user-service bootstrap-admin",
		"ExecStopPost=-/usr/bin/rm -f -- /run/recasaos-user-bootstrap/username /run/recasaos-user-bootstrap/password",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("bootstrap unit is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"LoadCredential=recasaos.admin.username\n",
		"LoadCredential=recasaos.admin.password\n",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("bootstrap unit contains unsupported bare credential directive %q", forbidden)
		}
	}
}

func TestSystemdPasswordResetUnitIsLocalOneShot(t *testing.T) {
	unit, err := os.ReadFile("build/sysroot/usr/lib/systemd/system/recasaos-user-password-reset.service")
	if err != nil {
		t.Fatal(err)
	}
	text := string(unit)
	for _, required := range []string{
		"Conflicts=casaos-user-service.service recasaos-user-bootstrap.service",
		"Type=oneshot",
		"LoadCredential=recasaos.admin.username:/run/recasaos-user-password-reset/username",
		"LoadCredential=recasaos.admin.new-password:/run/recasaos-user-password-reset/new-password",
		"ExecStart=/usr/bin/casaos-user-service reset-admin-password",
		"ExecStopPost=-/usr/bin/rm -f -- /run/recasaos-user-password-reset/username /run/recasaos-user-password-reset/new-password",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("password reset unit is missing %q", required)
		}
	}
	for _, forbidden := range []string{"[Install]", "Environment=", "recasaos.admin.password:", "LoadCredential=recasaos.admin.new-password\n"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("password reset unit contains forbidden directive %q", forbidden)
		}
	}
}

func privateCredentialDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "credentials")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}
