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

type message struct {
	Finding *finding `json:"finding"`
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
	for {
		var event message
		err := decoder.Decode(&event)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if event.Finding == nil || len(event.Finding.Trace) == 0 {
			continue
		}
		if event.Finding.Trace[0].Function != "" {
			reachable[event.Finding.OSV] = struct{}{}
		}
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
