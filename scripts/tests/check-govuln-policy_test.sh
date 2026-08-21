#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "$script_dir/../.." && pwd -P)
policy="$repo_root/scripts/govuln-policy.go"
allowlist="$repo_root/security/govuln-allowlist.txt"
workspace=$(mktemp -d "${TMPDIR:-/tmp}/recasaos-govuln-policy-test.XXXXXX")
trap 'rm -rf -- "$workspace"' EXIT HUP INT TERM

valid_stream='{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.1.4","go_version":"go1.26.6","scan_level":"symbol","scan_mode":"source"}}
{"SBOM":{"go_version":"go1.26.6","modules":[{"path":"github.com/EdmundFu-233/ReCasaOS-UserService"}]}}
{"progress":{"message":"Checking the code against the vulnerabilities..."}}'

run_policy() {
	printf '%s\n' "$1" | go run "$policy" "$allowlist"
}

expect_reject() {
	label=$1
	content=$2
	if run_policy "$content" >"$workspace/stdout" 2>"$workspace/stderr"; then
		printf 'expected govuln policy rejection: %s\n' "$label" >&2
		exit 1
	fi
}

run_policy "$valid_stream" >/dev/null
expect_reject "empty stream" ""
expect_reject "empty object" '{}'
expect_reject "config only" '{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.1.4","go_version":"go1.26.6","scan_level":"symbol","scan_mode":"source"}}'
expect_reject "wrong scanner" "${valid_stream/govulncheck/not-govulncheck}"
expect_reject "module scan" "${valid_stream/\"scan_level\":\"symbol\"/\"scan_level\":\"module\"}"
expect_reject "binary scan" "${valid_stream/\"scan_mode\":\"source\"/\"scan_mode\":\"binary\"}"
expect_reject "duplicate config" "$valid_stream
{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.1.4","go_version":"go1.26.6","scan_level":"symbol","scan_mode":"source"}}"
expect_reject "unexpected reachable finding" "$valid_stream
{"finding":{"osv":"GO-2099-0001","trace":[{"function":"example.Vulnerable"}]}}"

printf 'govuln policy negative tests passed\n'
