#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
checker=$(cd "$script_dir/.." && pwd)/check-workflow-policy.sh
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/recasaos-workflow-policy-test.XXXXXX")
workflow_dir="$fixture_root/workflows"

cleanup() {
  rm -f "$workflow_dir/test.yml"
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
  write_fixture "$content"
  if bash "$checker" "$workflow_dir" >/dev/null 2>&1; then
    echo "expected rejection: $label" >&2
    exit 1
  fi
}

safe_workflow='name: safe
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
        with:
          persist-credentials: false
      - uses: actions/setup-go@2222222222222222222222222222222222222222
        with:
          cache: false
      - uses: github/codeql-action/init@3333333333333333333333333333333333333333'

write_fixture "$safe_workflow"
bash "$checker" "$workflow_dir" >/dev/null

expect_reject "mutable action" "${safe_workflow/@1111111111111111111111111111111111111111/@main}"
expect_reject "secret reference" 'name: bad
on: push
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - run: echo "${{ secrets.TOKEN }}"'
expect_reject "whole secrets context" 'name: bad
on: push
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - run: echo "${{ toJSON(secrets) }}"'
expect_reject "quoted uses key" 'name: bad
on: push
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - "uses": attacker/action@main'
expect_reject "spaced uses key" 'name: bad
on: push
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses : attacker/action@main'
expect_reject "sshpass" 'name: bad
on: push
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - run: sshpass -p password true'
expect_reject "ZeroTier" 'name: bad
on: push
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - run: ZeroTier-cli info'
expect_reject "host key bypass" 'name: bad
on: push
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - run: ssh -o StrictHostKeyChecking=no host'
expect_reject "npm publish" 'name: bad
on: push
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - run: npm publish'
expect_reject "non-allowlisted action" 'name: bad
on: push
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: attacker/action@4444444444444444444444444444444444444444'
expect_reject "checkout credential persistence default" 'name: bad
on: push
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111'
expect_reject "setup-go cache default" 'name: bad
on: push
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/setup-go@2222222222222222222222222222222222222222'
expect_reject "privileged trigger" 'name: bad
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-24.04
    steps: []'
expect_reject "write permission" 'name: bad
on: push
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-24.04
    steps: []'

echo "workflow policy negative tests passed"
