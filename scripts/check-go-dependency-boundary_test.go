package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDependencyBoundaryAllowsArgon2(t *testing.T) {
	input := strings.NewReader(
		"{\"ImportPath\":\"golang.org/x/crypto/argon2\"}\n" +
			"{\"ImportPath\":\"example.com/safe\",\"Doc\":\"golang.org/x/crypto/openpgp\"}\n",
	)
	count, forbidden, err := inspect(input)
	if err != nil {
		t.Fatalf("inspect allowed graph: %v", err)
	}
	if count != 2 {
		t.Fatalf("record count = %d, want 2", count)
	}
	if len(forbidden) != 0 {
		t.Fatalf("allowed graph reported forbidden packages: %v", forbidden)
	}
}

func TestDependencyBoundaryRejectsOpenPGP(t *testing.T) {
	tests := []struct {
		name       string
		importPath string
	}{
		{name: "root", importPath: "golang.org/x/crypto/openpgp"},
		{name: "subpackage", importPath: "golang.org/x/crypto/openpgp/packet"},
		{name: "test variant", importPath: "golang.org/x/crypto/openpgp/armor [example.com/project.test]"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := strings.NewReader("{\"ImportPath\":\"" + test.importPath + "\"}\n")
			_, forbidden, err := inspect(input)
			if err != nil {
				t.Fatalf("inspect forbidden graph: %v", err)
			}
			if len(forbidden) != 1 || !strings.HasPrefix(forbidden[0], forbiddenOpenPGPPackage) {
				t.Fatalf("forbidden packages = %v, want OpenPGP rejection", forbidden)
			}
		})
	}
}

func TestDependencyBoundaryFailsClosed(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "incomplete", input: "{\"ImportPath\":\"example.com/incomplete\",\"Incomplete\":true}\n"},
		{name: "load error", input: "{\"ImportPath\":\"example.com/error\",\"Error\":{\"Err\":\"failure\"}}\n"},
		{name: "duplicate path", input: "{\"ImportPath\":\"example.com/a\",\"ImportPath\":\"example.com/b\"}\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := inspect(strings.NewReader(test.input)); err == nil {
				t.Fatal("inspect accepted an invalid or incomplete graph")
			}
		})
	}
}

func TestSourceImportBoundaryRejectsWeakHashes(t *testing.T) {
	root := t.TempDir()
	safe := filepath.Join(root, "safe.go")
	if err := os.WriteFile(safe, []byte("package safe\nimport _ \"crypto/sha256\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	count, violations, err := inspectSourceImports(root)
	if err != nil || count != 1 || len(violations) != 0 {
		t.Fatalf("safe source inspection count=%d violations=%v err=%v", count, violations, err)
	}

	weak := filepath.Join(root, "weak.go")
	if err := os.WriteFile(weak, []byte("package safe\nimport legacy `crypto/md5`\nvar _ = legacy.Size\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, violations, err = inspectSourceImports(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 1 || !strings.Contains(violations[0], "crypto/md5") {
		t.Fatalf("weak hash violations = %v", violations)
	}
}

func TestSourceImportBoundaryRejectsRemovedPathHelper(t *testing.T) {
	t.Run("legacy import", func(t *testing.T) {
		root := t.TempDir()
		source := []byte("package safe\nimport _ \"" + forbiddenLegacyFilePackage + "\"\n")
		if err := os.WriteFile(filepath.Join(root, "unsafe.go"), source, 0o600); err != nil {
			t.Fatal(err)
		}
		_, violations, err := inspectSourceImports(root)
		if err != nil {
			t.Fatal(err)
		}
		if len(violations) != 1 || !strings.Contains(violations[0], "removed unsafe path helper") {
			t.Fatalf("legacy import violations = %v", violations)
		}
	})

	t.Run("legacy package directory", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(root, filepath.FromSlash(forbiddenLegacyFileSourcePath))
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "file.go"), []byte("package file\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, violations, err := inspectSourceImports(root)
		if err != nil {
			t.Fatal(err)
		}
		if len(violations) != 1 || !strings.Contains(violations[0], forbiddenLegacyFileSourcePath) {
			t.Fatalf("legacy package violations = %v", violations)
		}
	})
}

func TestSourceImportBoundaryFailsClosed(t *testing.T) {
	root := t.TempDir()
	if _, _, err := inspectSourceImports(root); err == nil {
		t.Fatal("empty source root was accepted")
	}

	target := filepath.Join(t.TempDir(), "target.go")
	if err := os.WriteFile(target, []byte("package target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "linked.go")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inspectSourceImports(root); err == nil {
		t.Fatal("symbolic Go source was accepted")
	}
}
