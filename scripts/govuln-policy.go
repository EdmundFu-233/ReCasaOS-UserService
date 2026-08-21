//go:build ignore

// govuln-policy enforces a narrow, explicit allowlist for reachable findings
// emitted by govulncheck's JSON protocol.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type scanConfig struct {
	ProtocolVersion string `json:"protocol_version"`
	ScannerName     string `json:"scanner_name"`
	ScannerVersion  string `json:"scanner_version"`
	GoVersion       string `json:"go_version"`
	ScanLevel       string `json:"scan_level"`
	ScanMode        string `json:"scan_mode"`
}

type scanSBOM struct {
	GoVersion string `json:"go_version"`
	Modules   []struct {
		Path string `json:"path"`
	} `json:"modules"`
}

type progress struct {
	Message string `json:"message"`
}

type finding struct {
	OSV   string       `json:"osv"`
	Trace []traceEntry `json:"trace"`
}

type traceEntry struct {
	Function string `json:"function"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: govuln-policy <allowlist>")
		os.Exit(2)
	}

	allowed, err := readAllowlist(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read vulnerability allowlist: %v\n", err)
		os.Exit(2)
	}

	reachable, err := readReachableFindings(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read govulncheck output: %v\n", err)
		os.Exit(2)
	}

	unexpected := difference(reachable, allowed)
	stale := difference(allowed, reachable)
	if len(unexpected) != 0 || len(stale) != 0 {
		if len(unexpected) != 0 {
			fmt.Fprintf(os.Stderr, "unexpected reachable vulnerabilities: %s\n", strings.Join(unexpected, ", "))
		}
		if len(stale) != 0 {
			fmt.Fprintf(os.Stderr, "stale vulnerability allowlist entries: %s\n", strings.Join(stale, ", "))
		}
		os.Exit(1)
	}

	fmt.Printf("reachable vulnerability policy passed (%d explicitly held)\n", len(allowed))
}

func readAllowlist(path string) (map[string]struct{}, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	allowed := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 1 || !strings.HasPrefix(fields[0], "GO-") {
			return nil, fmt.Errorf("invalid allowlist line %q", scanner.Text())
		}
		if _, exists := allowed[fields[0]]; exists {
			return nil, fmt.Errorf("duplicate allowlist entry %s", fields[0])
		}
		allowed[fields[0]] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return allowed, nil
}

func readReachableFindings(reader io.Reader) (map[string]struct{}, error) {
	reachable := make(map[string]struct{})
	decoder := json.NewDecoder(reader)
	configCount := 0
	sbomCount := 0
	checkingProgress := false
	for {
		var raw map[string]json.RawMessage
		err := decoder.Decode(&raw)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(raw) != 1 {
			return nil, errors.New("govulncheck message must contain exactly one top-level field")
		}
		for kind, payload := range raw {
			switch kind {
			case "config":
				configCount++
				var config scanConfig
				if err := json.Unmarshal(payload, &config); err != nil {
					return nil, fmt.Errorf("decode govulncheck config: %w", err)
				}
				if config.ProtocolVersion != "v1.0.0" || config.ScannerName != "govulncheck" ||
					config.ScannerVersion == "" || config.GoVersion == "" ||
					config.ScanLevel != "symbol" || config.ScanMode != "source" {
					return nil, errors.New("govulncheck config is not a source symbol scan")
				}
			case "SBOM":
				sbomCount++
				var sbom scanSBOM
				if err := json.Unmarshal(payload, &sbom); err != nil {
					return nil, fmt.Errorf("decode govulncheck SBOM: %w", err)
				}
				if sbom.GoVersion == "" || len(sbom.Modules) == 0 {
					return nil, errors.New("govulncheck SBOM is empty")
				}
				rootFound := false
				for _, module := range sbom.Modules {
					if module.Path == "github.com/EdmundFu-233/ReCasaOS-UserService" {
						rootFound = true
					}
				}
				if !rootFound {
					return nil, errors.New("govulncheck SBOM does not contain the root module")
				}
			case "progress":
				var progress progress
				if err := json.Unmarshal(payload, &progress); err != nil {
					return nil, fmt.Errorf("decode govulncheck progress: %w", err)
				}
				if progress.Message == "Checking the code against the vulnerabilities..." {
					checkingProgress = true
				}
			case "osv":
				if len(payload) == 0 || string(payload) == "null" {
					return nil, errors.New("govulncheck OSV message is empty")
				}
			case "finding":
				var finding finding
				if err := json.Unmarshal(payload, &finding); err != nil {
					return nil, fmt.Errorf("decode govulncheck finding: %w", err)
				}
				if finding.OSV == "" {
					return nil, errors.New("govulncheck finding is missing an OSV identifier")
				}
				if len(finding.Trace) != 0 && finding.Trace[0].Function != "" {
					reachable[finding.OSV] = struct{}{}
				}
			default:
				return nil, fmt.Errorf("unknown govulncheck message type %q", kind)
			}
		}
	}
	if configCount != 1 || sbomCount != 1 || !checkingProgress {
		return nil, errors.New("govulncheck stream is incomplete or duplicated")
	}
	return reachable, nil
}

func difference(left, right map[string]struct{}) []string {
	var result []string
	for id := range left {
		if _, ok := right[id]; !ok {
			result = append(result, id)
		}
	}
	sort.Strings(result)
	return result
}
