#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
checker=$(cd "$script_dir/.." && pwd)/check-workflow-policy.sh
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/recasaos-workflow-policy-test.XXXXXX")
workflow_dir="$fixture_root/workflows"

cleanup() {
  rm -f "$workflow_dir/test.yml" "$fixture_root/policy-output"
  rmdir "$workflow_dir" "$fixture_root" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$workflow_dir"

write_fixture() {
  printf '%s\n' "$1" >"$workflow_dir/test.yml"
}

expect_reject() {
  label=$1
  content=$2
  expected=$3
  write_fixture "$content"
  if bash "$checker" "$workflow_dir" >"$fixture_root/policy-output" 2>&1; then
    echo "expected rejection: $label" >&2
    exit 1
  fi
  if ! grep -Fq "$expected" "$fixture_root/policy-output"; then
    echo "unexpected rejection reason for $label; wanted: $expected" >&2
    sed -n '1,8p' "$fixture_root/policy-output" >&2
    exit 1
  fi
}

run_workflow() {
  printf '%s\n' 'name: bad' 'on: push' 'permissions:' '  contents: read' 'jobs:' '  test:' \
    '    runs-on: ubuntu-24.04' '    timeout-minutes: 5' '    steps:' '      - shell: bash' "        run: $1"
}

action_workflow() {
  printf '%s\n' 'name: bad' 'on: push' 'permissions:' '  contents: read' 'jobs:' '  test:' \
    '    runs-on: ubuntu-24.04' '    timeout-minutes: 5' '    steps:' "      - uses: $1"
}

safe_workflow='name: safe
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
        with:
          persist-credentials: false
      - uses: actions/setup-go@2222222222222222222222222222222222222222
        with:
          go-version: "1.26.6"
          check-latest: false
          cache: false'

write_fixture "$safe_workflow"
bash "$checker" "$workflow_dir" >/dev/null

expect_reject "mutable action" "${safe_workflow/@1111111111111111111111111111111111111111/@main}" "mutable or malformed action"
expect_reject "secret reference" "$(run_workflow 'echo \"${{ secrets.TOKEN }}\"')" "workflow references the secrets context"
expect_reject "whole secrets context" "$(run_workflow 'echo \"${{ toJSON(secrets) }}\"')" "workflow references the secrets context"

expect_reject "quoted uses key" 'name: bad
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - "uses": attacker/action@main' "mutable or malformed action"
expect_reject "spaced uses key" 'name: bad
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses : attacker/action@main' "mutable or malformed action"

expect_reject "sshpass" "$(run_workflow 'sshpass -p password true')" "run command is not allowlisted"
expect_reject "ZeroTier" "$(run_workflow 'ZeroTier-cli info')" "run command is not allowlisted"
expect_reject "host key bypass" "$(run_workflow 'ssh -o StrictHostKeyChecking=no host')" "run command is not allowlisted"
expect_reject "npm publish" "$(run_workflow 'npm publish')" "run command is not allowlisted"
expect_reject "decoded deployment primitive" "$(run_workflow '\"ssh\u0070ass -p password true\"')" "run command is not allowlisted"
expect_reject "absolute network primitive" "$(run_workflow '/usr/bin/ssh host.example')" "run command is not allowlisted"
expect_reject "shell-token deployment primitive" "$(run_workflow 's\"\"shpass -p password true')" "run command is not allowlisted"

expect_reject "non-allowlisted action" "$(action_workflow 'attacker/action@4444444444444444444444444444444444444444')" "non-allowlisted action"
expect_reject "checkout credential persistence default" "$(action_workflow 'actions/checkout@1111111111111111111111111111111111111111')" "persist-credentials"
expect_reject "setup-go cache default" "$(action_workflow 'actions/setup-go@2222222222222222222222222222222222222222')" "cache to boolean false"
expect_reject "privileged trigger" 'name: bad
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps: []' "outside pull_request and push"
expect_reject "write permission" 'name: bad
on: push
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps: []' "forbidden contents: write permission"
expect_reject "decoded quoted write permission" 'name: bad
on: push
permissions:
  "contents": write
jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps: []' "forbidden contents: write permission"
expect_reject "decoded privileged trigger" 'name: bad
"on":
  "pull_request_t\u0061rget":
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps: []' "outside pull_request and push"

expect_reject "step environment injection" 'name: bad
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - shell: bash
        env:
          PATH: ./attacker-bin
        run: go vet ./...' "unsupported keys"

echo "workflow policy negative tests passed"
