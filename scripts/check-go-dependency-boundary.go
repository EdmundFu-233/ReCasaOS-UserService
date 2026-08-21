package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	forbiddenOpenPGPPackage       = "golang.org/x/crypto/openpgp"
	forbiddenLegacyFilePackage    = "github.com/EdmundFu-233/ReCasaOS-UserService/pkg/utils/file"
	forbiddenLegacyFileSourcePath = "pkg/utils/file"
	maximumGraphBytes             = 64 << 20
	maximumSourceFileBytes        = 4 << 20
	maximumSourceFiles            = 4096
)

var forbiddenSourceImports = map[string]string{
	"crypto/md5":               "weak hash",
	"crypto/sha1":              "weak hash",
	forbiddenLegacyFilePackage: "removed unsafe path helper",
}

type packageRecord struct {
	ImportPath string          `json:"ImportPath"`
	Incomplete bool            `json:"Incomplete"`
	Error      json.RawMessage `json:"Error"`
	DepsErrors json.RawMessage `json:"DepsErrors"`
}

func (record *packageRecord) UnmarshalJSON(payload []byte) error {
	if !utf8.Valid(payload) {
		return errors.New("package record is not valid UTF-8")
	}
	*record = packageRecord{}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return errors.New("package record is not a JSON object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("package record contains a non-string key")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("package record contains duplicate key %q", key)
		}
		seen[key] = struct{}{}
		switch key {
		case "ImportPath":
			err = decoder.Decode(&record.ImportPath)
		case "Incomplete":
			err = decoder.Decode(&record.Incomplete)
		case "Error":
			err = decoder.Decode(&record.Error)
		case "DepsErrors":
			err = decoder.Decode(&record.DepsErrors)
		default:
			var ignored json.RawMessage
			err = decoder.Decode(&ignored)
		}
		if err != nil {
			return fmt.Errorf("decode package record key %q: %w", key, err)
		}
	}
	token, err = decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok = token.(json.Delim)
	if !ok || delimiter != '}' {
		return errors.New("package record has no closing object delimiter")
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("package record contains trailing JSON")
		}
		return err
	}
	return nil
}

func fail(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "Go dependency boundary check failed: "+format+"\n", arguments...)
	os.Exit(1)
}

func canonicalImportPath(importPath string) (string, error) {
	if importPath == "" {
		return "", errors.New("package record has an empty ImportPath")
	}
	if !utf8.ValidString(importPath) {
		return "", fmt.Errorf("package record has an invalid ImportPath %q", importPath)
	}
	for _, character := range importPath {
		if character < 0x20 || character > 0x7e {
			return "", fmt.Errorf("package record has a non-ASCII ImportPath %q", importPath)
		}
	}
	if strings.ContainsAny(importPath, "\t\r\n") {
		return "", fmt.Errorf("package record has an invalid ImportPath %q", importPath)
	}

	// With `go list -test`, a package rebuilt for a test binary is reported as
	// "package/path [package/path.test]". Inspect the selected package itself,
	// not the synthetic test-context suffix.
	if marker := strings.Index(importPath, " ["); marker >= 0 {
		if marker == 0 || !strings.HasSuffix(importPath, "]") ||
			strings.Count(importPath, " [") != 1 {
			return "", fmt.Errorf("package record has a malformed test ImportPath %q", importPath)
		}
		testContext := importPath[marker+2 : len(importPath)-1]
		if testContext == "" || !strings.HasSuffix(testContext, ".test") ||
			strings.ContainsAny(testContext, "[] ") {
			return "", fmt.Errorf("package record has a malformed test ImportPath %q", importPath)
		}
		importPath = importPath[:marker]
	}

	if strings.Contains(importPath, " ") {
		return "", fmt.Errorf("package record has an invalid ImportPath %q", importPath)
	}
	return importPath, nil
}

func rawJSONIs(raw json.RawMessage, allowed ...string) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return true
	}
	for _, value := range allowed {
		if bytes.Equal(trimmed, []byte(value)) {
			return true
		}
	}
	return false
}

func isForbidden(importPath string) bool {
	return importPath == forbiddenOpenPGPPackage ||
		strings.HasPrefix(importPath, forbiddenOpenPGPPackage+"/")
}

func inspect(input io.Reader) (int, []string, error) {
	decoder := json.NewDecoder(input)
	seen := 0
	violations := make(map[string]struct{})

	for {
		var record packageRecord
		err := decoder.Decode(&record)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return seen, nil, fmt.Errorf("decode package record %d: %w", seen+1, err)
		}
		seen++

		importPath, err := canonicalImportPath(record.ImportPath)
		if err != nil {
			return seen, nil, fmt.Errorf("package record %d: %w", seen, err)
		}
		if record.Incomplete {
			return seen, nil, fmt.Errorf("selected package graph is incomplete at %q", importPath)
		}
		if !rawJSONIs(record.Error, "null") {
			return seen, nil, fmt.Errorf("selected package %q contains a load error", importPath)
		}
		if !rawJSONIs(record.DepsErrors, "null", "[]") {
			return seen, nil, fmt.Errorf("selected package %q contains dependency load errors", importPath)
		}
		if isForbidden(importPath) {
			violations[importPath] = struct{}{}
		}
	}

	if seen == 0 {
		return 0, nil, errors.New("selected package graph is empty")
	}

	forbidden := make([]string, 0, len(violations))
	for importPath := range violations {
		forbidden = append(forbidden, importPath)
	}
	sort.Strings(forbidden)
	return seen, forbidden, nil
}

func readBounded(input io.Reader) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(input, maximumGraphBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > maximumGraphBytes {
		return nil, fmt.Errorf("selected package graph exceeds %d bytes", maximumGraphBytes)
	}
	return payload, nil
}

func enforce(label string, payload []byte) {
	count, forbidden, err := inspect(bytes.NewReader(payload))
	if err != nil {
		fail("%s: %v", label, err)
	}
	if len(forbidden) != 0 {
		for _, importPath := range forbidden {
			fmt.Fprintf(os.Stderr, "Go dependency boundary violation (%s): forbidden selected package: %s\n", label, importPath)
		}
		os.Exit(1)
	}
	fmt.Printf("Go dependency boundary check passed (%s): %d selected package records\n", label, count)
}

func inspectSourceImports(root string) (int, []string, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return 0, nil, fmt.Errorf("inspect source root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, nil, errors.New("source root must be a real directory, not a symlink")
	}

	files := 0
	violations := make([]string, 0)
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if filepath.Ext(entry.Name()) == ".go" {
				return fmt.Errorf("Go source file is symbolic: %s", path)
			}
			return nil
		}
		if filepath.Ext(entry.Name()) != ".go" {
			return nil
		}
		sourceInfo, infoErr := entry.Info()
		if infoErr != nil {
			return fmt.Errorf("inspect Go source file %s: %w", path, infoErr)
		}
		if !sourceInfo.Mode().IsRegular() {
			return fmt.Errorf("Go source file is not regular: %s", path)
		}
		if sourceInfo.Size() > maximumSourceFileBytes {
			return fmt.Errorf("Go source file exceeds %d bytes: %s", maximumSourceFileBytes, path)
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		relative = filepath.ToSlash(relative)
		if relative == forbiddenLegacyFileSourcePath || strings.HasPrefix(relative, forbiddenLegacyFileSourcePath+"/") {
			violations = append(violations, relative+": removed unsafe path helper package")
		}
		files++
		if files > maximumSourceFiles {
			return fmt.Errorf("source root exceeds %d Go files", maximumSourceFiles)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parse Go imports in %s: %w", path, err)
		}
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return fmt.Errorf("decode Go import in %s: %w", path, err)
			}
			if reason, forbidden := forbiddenSourceImports[importPath]; forbidden {
				violations = append(violations, relative+": "+importPath+" ("+reason+")")
			}
		}
		return nil
	})
	if err != nil {
		return files, nil, err
	}
	if files == 0 {
		return 0, nil, errors.New("source root contains no Go files")
	}
	sort.Strings(violations)
	return files, violations, nil
}

func enforceSourceImports(root string) {
	count, violations, err := inspectSourceImports(root)
	if err != nil {
		fail("source import policy: %v", err)
	}
	if len(violations) != 0 {
		for _, violation := range violations {
			fmt.Fprintf(os.Stderr, "Go dependency boundary violation (source imports): forbidden source dependency: %s\n", violation)
		}
		os.Exit(1)
	}
	fmt.Printf("Go source import boundary check passed: %d Go files\n", count)
}

func main() {
	label := flag.String("label", "unlabelled", "human-readable dependency graph label")
	sourceRoot := flag.String("source-root", "", "repository source root to inspect")
	sourceOnly := flag.Bool("source-only", false, "inspect source imports without reading a package graph")
	flag.Parse()
	if *sourceRoot != "" {
		enforceSourceImports(*sourceRoot)
	}
	if *sourceOnly {
		if *sourceRoot == "" {
			fail("source-only mode requires -source-root")
		}
		if flag.NArg() != 0 {
			fail("source-only mode accepts no package graph")
		}
		return
	}
	if flag.NArg() != 1 {
		fail("usage: check-go-dependency-boundary [-label LABEL] PACKAGE_GRAPH_JSON")
	}

	graphPath := flag.Arg(0)
	if graphPath == "-" {
		payload, err := readBounded(os.Stdin)
		if err != nil {
			fail("read package graph from standard input: %v", err)
		}
		enforce(*label, payload)
		return
	}
	info, err := os.Lstat(graphPath)
	if err != nil {
		fail("inspect package graph %q: %v", graphPath, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		fail("package graph is not a regular non-symbolic file: %q", graphPath)
	}

	graph, err := os.Open(graphPath)
	if err != nil {
		fail("open package graph %q: %v", graphPath, err)
	}
	defer graph.Close()
	openedInfo, err := graph.Stat()
	if err != nil {
		fail("inspect opened package graph %q: %v", graphPath, err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		fail("package graph identity changed while opening: %q", graphPath)
	}
	payload, err := readBounded(graph)
	if err != nil {
		fail("read package graph %q: %v", graphPath, err)
	}
	afterReadInfo, err := graph.Stat()
	if err != nil {
		fail("reinspect opened package graph %q: %v", graphPath, err)
	}
	if !os.SameFile(openedInfo, afterReadInfo) ||
		afterReadInfo.Size() != int64(len(payload)) ||
		!afterReadInfo.ModTime().Equal(openedInfo.ModTime()) {
		fail("package graph metadata changed while reading: %q", graphPath)
	}
	if _, err = graph.Seek(0, io.SeekStart); err != nil {
		fail("rewind package graph %q: %v", graphPath, err)
	}
	verification, err := readBounded(graph)
	if err != nil {
		fail("reread package graph %q: %v", graphPath, err)
	}
	if !bytes.Equal(payload, verification) {
		fail("package graph bytes changed while reading: %q", graphPath)
	}
	enforce(*label, payload)
}
