package main

import (
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
