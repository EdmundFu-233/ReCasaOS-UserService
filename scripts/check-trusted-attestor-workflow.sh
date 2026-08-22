#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'trusted attestor workflow policy: %s\n' "$*" >&2
  exit 1
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
workflow=${1:-"$repo_root/.github/workflows/trusted-attestor.yml"}

expected_workflow_sha256=acd189aec833fc369cae5ea2b22f5062797feb5c96ba6b8cd9bb527e1807d396
expected_validator_sha256=8114a162fc4bb5fe74f56ffd2810077d53baed22c4dd03a27f938c982a537cc0
expected_sarif_checker_sha256=d0ab7cc61d4cd24214be471c33030d1249ba239c0730fd327a078cfbe008e27d
expected_vm_host_sha256=186a91e596aba93a23364d260e5b640b04409dae263840f2399c7be41cc4db46
expected_vm_guest_sha256=32c8a77d66ef4953355338c4fc532f9bf94e39f469b4ac5ef11d627f9a9e8519

[[ "$(basename -- "$workflow")" == trusted-attestor.yml ]] ||
  fail "workflow filename is not exact"
[[ -f "$workflow" && ! -L "$workflow" ]] ||
  fail "workflow must be a regular non-symbolic file"
workflow_size=$(wc -c <"$workflow" | tr -d '[:space:]')
[[ "$workflow_size" =~ ^[0-9]+$ && "$workflow_size" -ge 10000 && "$workflow_size" -le 100000 ]] ||
  fail "workflow size is outside the reviewed bound"

actual_workflow_sha256=$(sha256sum "$workflow" | awk '{print $1}')
[[ "$actual_workflow_sha256" == "$expected_workflow_sha256" ]] ||
  fail "workflow digest does not match the exact reviewed policy"

for relative_path in \
  scripts/check-codeql-sarif.py \
  scripts/trusted_attestor.py \
  scripts/tests/check-debian11-systemd-vm.sh \
  scripts/tests/test-systemd-lifecycle.sh
do
  candidate="$repo_root/$relative_path"
  [[ -f "$candidate" && ! -L "$candidate" ]] ||
    fail "reviewed trust root is missing or symbolic: $relative_path"
done

actual_validator_sha256=$(sha256sum "$repo_root/scripts/trusted_attestor.py" | awk '{print $1}')
actual_sarif_checker_sha256=$(sha256sum "$repo_root/scripts/check-codeql-sarif.py" | awk '{print $1}')
actual_vm_host_sha256=$(sha256sum "$repo_root/scripts/tests/check-debian11-systemd-vm.sh" | awk '{print $1}')
actual_vm_guest_sha256=$(sha256sum "$repo_root/scripts/tests/test-systemd-lifecycle.sh" | awk '{print $1}')
[[ "$actual_validator_sha256" == "$expected_validator_sha256" ]] ||
  fail "trusted validator digest drifted"
[[ "$actual_sarif_checker_sha256" == "$expected_sarif_checker_sha256" ]] ||
  fail "trusted SARIF checker digest drifted"
[[ "$actual_vm_host_sha256" == "$expected_vm_host_sha256" ]] ||
  fail "VM host harness digest drifted"
[[ "$actual_vm_guest_sha256" == "$expected_vm_guest_sha256" ]] ||
  fail "VM guest harness digest drifted"

[[ "$(grep -Fc "$expected_validator_sha256" "$workflow")" == 2 ]] ||
  fail "workflow does not verify the trusted validator in both API jobs"
[[ "$(grep -Fc "$expected_sarif_checker_sha256" "$workflow")" == 2 ]] ||
  fail "automatic and diagnostic analyses do not verify the exact SARIF checker"
[[ "$(grep -Fc 'needs.prepare-promotion.outputs.sarif_checker_sha256' "$workflow")" == 3 ]] ||
  fail "manual promotion does not propagate the exact reviewed SARIF checker"
[[ "$(grep -Fc 'needs.promoted-qa.outputs.verified_sarif_checker_sha256' "$workflow")" == 1 ]] ||
  fail "manual publisher does not consume the QA-verified SARIF checker identity"
[[ "$(grep -Fc 'upload: never' "$workflow")" == 3 ]] ||
  fail "independent CodeQL upload prohibition is not exact"
[[ "$(grep -Fc 'tools: linked' "$workflow")" == 3 ]] ||
  fail "independent CodeQL bundle linkage is not exact"
[[ "$(grep -Fc "run: test \"\$ACTUAL_CODEQL_VERSION\" = '2.26.3'" "$workflow")" == 3 ]] ||
  fail "independent CodeQL runtime version proof is not exact"
[[ "$(grep -Fc 'trap-caching: false' "$workflow")" == 3 ]] ||
  fail "independent CodeQL TRAP cache prohibition is not exact"
[[ "$(grep -Fc 'dependency-caching: false' "$workflow")" == 3 ]] ||
  fail "independent CodeQL dependency cache prohibition is not exact"
[[ "$(grep -Fc 'CODEQL_OVERLAY_DATABASE_MODE: none' "$workflow")" == 3 ]] ||
  fail "independent CodeQL overlay cache prohibition is not exact"
! grep -Fq 'security-events: write' "$workflow" ||
  fail "trusted workflow grants a forbidden SARIF upload permission"
[[ "$(grep -Fc 'environment: trusted-attestor' "$workflow")" == 2 ]] ||
  fail "protected environment boundary is not exact"
[[ "$(grep -Fc 'actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1' "$workflow")" == 2 ]] ||
  fail "trusted App token action identity is not exact"
[[ "$(grep -Fc 'ReCasaOS-UserService / trusted exact-SHA' "$workflow")" == 1 ]] ||
  fail "trusted status context is not exact"
! grep -Eq '__[A-Z0-9_]+SHA256__' "$workflow" || fail "workflow retains an unresolved digest placeholder"

ruby -e '
  require "yaml"
  stream = Psych.parse_stream(File.read(ARGV.fetch(0), encoding: "UTF-8"))
  abort "trusted workflow is not exactly one YAML document" unless stream.children.length == 1
  YAML.safe_load(File.read(ARGV.fetch(0), encoding: "UTF-8"), permitted_classes: [], permitted_symbols: [], aliases: false)
' "$workflow" >/dev/null || fail "workflow YAML is invalid or ambiguous"

printf 'trusted attestor workflow policy passed\n'
