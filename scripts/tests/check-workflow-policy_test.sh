#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
checker=$(cd "$script_dir/.." && pwd)/check-workflow-policy.sh
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/recasaos-workflow-policy-test.XXXXXX")
workflow_dir="$fixture_root/workflows"
policy_repo="$fixture_root/repo"
repo_root=$(cd "$script_dir/../.." && pwd)
ci_source="$repo_root/.github/workflows/ci.yml"
codeql_source="$repo_root/.github/workflows/codeql.yml"
trusted_source="$repo_root/.github/workflows/trusted-attestor.yml"

cleanup() {
  rm -f "$workflow_dir/test.yml" "$workflow_dir/ci.yml" "$workflow_dir/codeql.yml" \
    "$workflow_dir/trusted-attestor.yml" \
    "$workflow_dir/trusted-attestor.yaml" "$workflow_dir/ci.yaml" \
    "$workflow_dir/extra.yml" "$workflow_dir/.hidden.yml" \
    "$fixture_root/policy-output"
  rm -rf "$policy_repo"
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
  if RECASAOS_WORKFLOW_POLICY_FIXTURE_MODE=1 bash "$checker" "$workflow_dir" >"$fixture_root/policy-output" 2>&1; then
    echo "expected rejection: $label" >&2
    exit 1
  fi
  if ! grep -Fq "$expected" "$fixture_root/policy-output"; then
    echo "unexpected rejection reason for $label; wanted: $expected" >&2
    sed -n '1,8p' "$fixture_root/policy-output" >&2
    exit 1
  fi
}

expect_ci_reject() {
  label=$1
  old=$2
  new=$3
  expected=$4
  rm -f "$workflow_dir/test.yml"
  ruby - "$ci_source" "$workflow_dir/ci.yml" "$old" "$new" <<'RUBY'
source, destination, old, replacement = ARGV
text = File.read(source, encoding: "UTF-8")
raise "CI mutation target is not unique" unless text.scan(old).length == 1
File.write(destination, text.sub(old, replacement), mode: "w", encoding: "UTF-8")
RUBY
  if RECASAOS_WORKFLOW_POLICY_FIXTURE_MODE=1 bash "$checker" "$workflow_dir" >"$fixture_root/policy-output" 2>&1; then
    echo "expected CI rejection: $label" >&2
    exit 1
  fi
  if ! grep -Fq "$expected" "$fixture_root/policy-output"; then
    echo "unexpected CI rejection reason for $label; wanted: $expected" >&2
    sed -n '1,8p' "$fixture_root/policy-output" >&2
    exit 1
  fi
  rm -f "$workflow_dir/ci.yml"
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
RECASAOS_WORKFLOW_POLICY_FIXTURE_MODE=1 bash "$checker" "$workflow_dir" >/dev/null

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
expect_reject "security-events write outside exact CodeQL job" 'name: bad
on: push
permissions:
  contents: read
jobs:
  test:
    name: Analyze Go
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    permissions:
      security-events: write
    steps:
      - name: Analyze
        uses: github/codeql-action/analyze@ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd' "forbidden security-events: write permission"

expect_ci_reject "shortened VM job budget" \
  'timeout-minutes: 60' 'timeout-minutes: 59' \
  'CI Go 1.26.6 job metadata is not exact'
expect_ci_reject "renamed CI workflow identity" \
  'name: CI' 'name: renamed-ci' \
  'CI workflow name is not exact'
expect_ci_reject "removed CI pull request trigger" \
  $'  pull_request:\n    branches:\n      - main\n  push:' \
  '  push:' \
  'CI workflow triggers are not exact'
expect_ci_reject "expanded CI root read permissions" \
  $'permissions:\n  contents: read\n\njobs:' \
  $'permissions:\n  contents: read\n  packages: read\n\njobs:' \
  'CI workflow root permissions are not exact'
expect_ci_reject "replaced policy enforcement with allowed no-op" \
  'run: bash scripts/check-workflow-policy.sh' 'run: go build ./...' \
  'CI Workflow policy step sequence is not exact'
expect_ci_reject "removed systemd lifecycle" \
  'run: bash scripts/tests/check-debian11-systemd-vm.sh' 'run: go vet ./...' \
  'CI Go 1.26.6 step sequence is not exact'
expect_ci_reject "changed early VM step identity" \
  '      - name: Install isolated Debian VM tools' '      - name: Renamed isolated Debian VM tools' \
  'CI Go 1.26.6 step sequence is not exact'
expect_ci_reject "removed same-runner VM digest verification" \
  '186a91e596aba93a23364d260e5b640b04409dae263840f2399c7be41cc4db46' \
  '286a91e596aba93a23364d260e5b640b04409dae263840f2399c7be41cc4db46' \
  'run command is not allowlisted'
expect_ci_reject "mutable setup-go identity" \
  'actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e' \
  'actions/setup-go@1111111111111111111111111111111111111111' \
  'CI Go 1.26.6 step sequence is not exact'
expect_ci_reject "required check display-name impersonator" \
  $'jobs:\n  workflow-policy:' $'jobs:\n  analyze-impostor:\n    name: Analyze Go\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - name: No-op build\n        shell: bash\n        run: go build ./...\n  workflow-policy:' \
  'CI workflow must contain exactly workflow-policy and go jobs'

rm -f "$workflow_dir/test.yml" "$workflow_dir/ci.yml" "$workflow_dir/codeql.yml" "$workflow_dir/trusted-attestor.yml" "$workflow_dir/ci.yaml" "$workflow_dir/extra.yml"
cp "$ci_source" "$workflow_dir/ci.yaml"
cp "$codeql_source" "$workflow_dir/codeql.yml"
cp "$trusted_source" "$workflow_dir/trusted-attestor.yml"
if bash "$checker" "$workflow_dir" >"$fixture_root/policy-output" 2>&1; then
  echo "expected rejection: renamed CI workflow" >&2
  exit 1
fi
grep -Fq 'unsupported filename' "$fixture_root/policy-output" || {
  echo "unexpected renamed-workflow rejection reason" >&2
  exit 1
}
rm -f "$workflow_dir/ci.yaml" "$workflow_dir/codeql.yml"
cp "$ci_source" "$workflow_dir/ci.yml"
cp "$codeql_source" "$workflow_dir/codeql.yml"
cp "$codeql_source" "$workflow_dir/extra.yml"
if bash "$checker" "$workflow_dir" >"$fixture_root/policy-output" 2>&1; then
  echo "expected rejection: extra workflow" >&2
  exit 1
fi
grep -Fq 'exactly ci.yml, codeql.yml, and trusted-attestor.yml' "$fixture_root/policy-output" || {
  echo "unexpected extra-workflow rejection reason" >&2
  exit 1
}

rm -f "$workflow_dir/extra.yml"
cp "$codeql_source" "$workflow_dir/.hidden.yml"
if bash "$checker" "$workflow_dir" >"$fixture_root/policy-output" 2>&1; then
  echo "expected rejection: hidden extra workflow" >&2
  exit 1
fi
grep -Fq 'exactly ci.yml, codeql.yml, and trusted-attestor.yml' "$fixture_root/policy-output" || {
  echo "unexpected hidden-workflow rejection reason" >&2
  exit 1
}

rm -f "$workflow_dir/.hidden.yml"
rm -f "$workflow_dir/trusted-attestor.yml"
if bash "$checker" "$workflow_dir" >"$fixture_root/policy-output" 2>&1; then
  echo "expected rejection: missing trusted attestor workflow" >&2
  exit 1
fi
grep -Fq 'exactly ci.yml, codeql.yml, and trusted-attestor.yml' "$fixture_root/policy-output" || {
  echo "unexpected missing-attestor rejection reason" >&2
  exit 1
}

ln -s "$trusted_source" "$workflow_dir/trusted-attestor.yml"
if bash "$checker" "$workflow_dir" >"$fixture_root/policy-output" 2>&1; then
  echo "expected rejection: symbolic trusted attestor workflow" >&2
  exit 1
fi
grep -Fq 'regular and non-symbolic' "$fixture_root/policy-output" || {
  echo "unexpected symbolic-attestor rejection reason" >&2
  exit 1
}
rm -f "$workflow_dir/trusted-attestor.yml"

mkfifo "$workflow_dir/trusted-attestor.yml"
if bash "$checker" "$workflow_dir" >"$fixture_root/policy-output" 2>&1; then
  echo "expected rejection: FIFO trusted attestor workflow" >&2
  exit 1
fi
grep -Fq 'regular and non-symbolic' "$fixture_root/policy-output" || {
  echo "unexpected FIFO-attestor rejection reason" >&2
  exit 1
}
rm -f "$workflow_dir/trusted-attestor.yml"

cp "$trusted_source" "$workflow_dir/trusted-attestor.yaml"
if bash "$checker" "$workflow_dir" >"$fixture_root/policy-output" 2>&1; then
  echo "expected rejection: renamed trusted attestor workflow" >&2
  exit 1
fi
grep -Fq 'unsupported filename' "$fixture_root/policy-output" || {
  echo "unexpected renamed-attestor rejection reason" >&2
  exit 1
}
rm -f "$workflow_dir/trusted-attestor.yaml"
cp "$trusted_source" "$workflow_dir/trusted-attestor.yml"

ruby - "$codeql_source" "$workflow_dir/codeql.yml" <<'RUBY'
source, destination = ARGV
text = File.read(source, encoding: "UTF-8")
old = "      - name: Analyze\n        uses: github/codeql-action/analyze@ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd # v4.37.7\n"
replacement = "      - name: Analyze\n        shell: bash\n        run: go build ./...\n"
raise "CodeQL mutation target is not unique" unless text.scan(old).length == 1
File.write(destination, text.sub(old, replacement), mode: "w", encoding: "UTF-8")
RUBY
if bash "$checker" "$workflow_dir" >"$fixture_root/policy-output" 2>&1; then
  echo "expected rejection: CodeQL analyze no-op" >&2
  exit 1
fi
grep -Fq 'forbidden security-events: write permission' "$fixture_root/policy-output" || {
  echo "unexpected CodeQL no-op rejection reason" >&2
  exit 1
}

ruby - "$codeql_source" "$workflow_dir/codeql.yml" <<'RUBY'
source, destination = ARGV
text = File.read(source, encoding: "UTF-8")
old = "      - name: Build\n        shell: bash\n        run: go build ./...\n"
replacement = "      - name: Build\n        shell: bash\n        run: go generate ./...\n"
raise "CodeQL build mutation target is not unique" unless text.scan(old).length == 1
File.write(destination, text.sub(old, replacement), mode: "w", encoding: "UTF-8")
RUBY
if bash "$checker" "$workflow_dir" >"$fixture_root/policy-output" 2>&1; then
  echo "expected rejection: generic-valid CodeQL step substitution" >&2
  exit 1
fi
grep -Fq 'CodeQL analyze step sequence is not exact' "$fixture_root/policy-output" || {
  echo "unexpected CodeQL step-sequence rejection reason" >&2
  exit 1
}

ruby - "$codeql_source" "$workflow_dir/codeql.yml" <<'RUBY'
source, destination = ARGV
text = File.read(source, encoding: "UTF-8")
raise "CodeQL name target is not unique" unless text.scan("name: CodeQL").length == 1
File.write(destination, text.sub("name: CodeQL", "name: renamed-codeql"), mode: "w", encoding: "UTF-8")
RUBY
if bash "$checker" "$workflow_dir" >"$fixture_root/policy-output" 2>&1; then
  echo "expected rejection: renamed CodeQL workflow" >&2
  exit 1
fi
grep -Fq 'CodeQL workflow name is not exact' "$fixture_root/policy-output" || {
  echo "unexpected CodeQL name rejection reason" >&2
  exit 1
}

ruby - "$codeql_source" "$workflow_dir/codeql.yml" <<'RUBY'
source, destination = ARGV
text = File.read(source, encoding: "UTF-8")
old = "  pull_request:\n    branches:\n      - main\n  push:"
raise "CodeQL trigger target is not unique" unless text.scan(old).length == 1
File.write(destination, text.sub(old, "  push:"), mode: "w", encoding: "UTF-8")
RUBY
if bash "$checker" "$workflow_dir" >"$fixture_root/policy-output" 2>&1; then
  echo "expected rejection: CodeQL pull request trigger removed" >&2
  exit 1
fi
grep -Fq 'CodeQL workflow triggers are not exact' "$fixture_root/policy-output" || {
  echo "unexpected CodeQL trigger rejection reason" >&2
  exit 1
}

mkdir -p "$policy_repo/.github/workflows" "$policy_repo/scripts/tests"
cp "$ci_source" "$policy_repo/.github/workflows/ci.yml"
cp "$repo_root/scripts/tests/check-debian11-systemd-vm.sh" "$policy_repo/scripts/tests/check-debian11-systemd-vm.sh"
cp "$repo_root/scripts/tests/test-systemd-lifecycle.sh" "$policy_repo/scripts/tests/test-systemd-lifecycle.sh"
ruby "$repo_root/scripts/check-workflow-structure.rb" \
  "$policy_repo/.github/workflows/ci.yml" "$policy_repo" >/dev/null
printf '\n# host tamper\n' >>"$policy_repo/scripts/tests/check-debian11-systemd-vm.sh"
if ruby "$repo_root/scripts/check-workflow-structure.rb" \
  "$policy_repo/.github/workflows/ci.yml" "$policy_repo" >"$fixture_root/policy-output" 2>&1
then
  echo "expected rejection: host VM script tamper" >&2
  exit 1
fi
grep -Fq 'reviewed VM script digest does not match policy' "$fixture_root/policy-output" || {
  echo "unexpected host VM script tamper rejection reason" >&2
  exit 1
}
cp "$repo_root/scripts/tests/check-debian11-systemd-vm.sh" "$policy_repo/scripts/tests/check-debian11-systemd-vm.sh"
printf '\n# guest tamper\n' >>"$policy_repo/scripts/tests/test-systemd-lifecycle.sh"
if ruby "$repo_root/scripts/check-workflow-structure.rb" \
  "$policy_repo/.github/workflows/ci.yml" "$policy_repo" >"$fixture_root/policy-output" 2>&1
then
  echo "expected rejection: guest lifecycle script tamper" >&2
  exit 1
fi
grep -Fq 'reviewed VM script digest does not match policy' "$fixture_root/policy-output" || {
  echo "unexpected guest VM script tamper rejection reason" >&2
  exit 1
}

bash "$repo_root/scripts/tests/check-trusted-attestor-policy_test.sh"
echo "workflow policy negative tests passed"
