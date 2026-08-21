#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
workflow_dir=${1:-"$repo_root/.github/workflows"}
structure_checker="$script_dir/check-workflow-structure.rb"
fixture_mode=${RECASAOS_WORKFLOW_POLICY_FIXTURE_MODE:-0}

fail() {
  echo "workflow policy: $*" >&2
  exit 1
}

[ -d "$workflow_dir" ] || fail "workflow directory does not exist: $workflow_dir"
command -v ruby >/dev/null 2>&1 || fail "ruby is unavailable"
[ -f "$structure_checker" ] && [ ! -L "$structure_checker" ] || fail "workflow structure checker is missing or symbolic"

workflow_dir=$(cd "$workflow_dir" && pwd -P)
default_workflow_dir=$(cd "$repo_root/.github/workflows" && pwd -P)
case "$fixture_mode" in
  0) ;;
  1)
    [ "$workflow_dir" != "$default_workflow_dir" ] ||
      fail "fixture mode cannot disable the real repository workflow set"
    ;;
  *) fail "workflow fixture mode is malformed" ;;
esac

shopt -s nullglob dotglob
workflow_files=("$workflow_dir"/*.yml "$workflow_dir"/*.yaml)
if [ "$fixture_mode" = 0 ]; then
  [ "${#workflow_files[@]}" -eq 2 ] || fail "workflow set must contain exactly ci.yml and codeql.yml"
  found_ci=0
  found_codeql=0
  for workflow in "${workflow_files[@]}"; do
    [ -f "$workflow" ] && [ ! -L "$workflow" ] || fail "workflow files must be regular and non-symbolic"
    case "$(basename "$workflow")" in
      ci.yml) found_ci=1 ;;
      codeql.yml) found_codeql=1 ;;
      *) fail "workflow set contains an unsupported filename" ;;
    esac
  done
  [ "$found_ci" = 1 ] && [ "$found_codeql" = 1 ] ||
    fail "workflow set must contain exactly ci.yml and codeql.yml"
fi

workflow_count=0
for workflow in "${workflow_files[@]}"; do
	[ -f "$workflow" ] && [ ! -L "$workflow" ] || fail "workflow files must be regular and non-symbolic"
	workflow_count=$((workflow_count + 1))

	ruby "$structure_checker" "$workflow" "$repo_root" || fail "$workflow failed structured workflow validation"

	if grep -Eiq '\$\{\{[^}]*secrets([^[:alnum:]_]|$)' "$workflow"; then
    fail "$workflow references repository or environment secrets"
  fi
  if grep -Eiq 'pull_request_target|workflow_run|workflow_call' "$workflow"; then
    fail "$workflow uses a forbidden privileged or reusable trigger"
  fi
  if grep -Eiq 'write-all|^[[:space:]]*(actions|checks|contents|deployments|discussions|id-token|issues|packages|pages|pull-requests|repository-projects|statuses):[[:space:]]*write([[:space:]]|$)' "$workflow"; then
    fail "$workflow requests a forbidden write permission"
  fi
  if grep -Eiq 'sshpass|zerotier|stricthostkeychecking[[:space:]]*=[[:space:]]*no|npm[[:space:]]+publish|yarn[[:space:]]+publish|pnpm[[:space:]]+publish|(^|[[:space:];|&])(curl|wget|scp|ssh|rsync|nc|ncat)([[:space:]]|$)' "$workflow"; then
    fail "$workflow contains a forbidden network-egress or deployment primitive"
  fi

  while IFS= read -r uses_line; do
    uses_value=$(printf '%s\n' "$uses_line" | sed -E "s/^[[:space:]-]*uses:[[:space:]]*//; s/[[:space:]]+#.*$//; s/^[\"']//; s/[\"']$//")
    action=${uses_value%@*}
    ref=${uses_value##*@}
    if ! printf '%s\n' "$ref" | grep -Eq '^[0-9a-f]{40}$'; then
      fail "$workflow has a mutable or malformed uses reference: $uses_value"
    fi
    case "$action" in
      actions/checkout|actions/setup-go|github/codeql-action/*)
        ;;
      *)
        fail "$workflow uses a non-allowlisted action: $action"
        ;;
    esac
  done < <(grep -E '^[[:space:]-]*uses:' "$workflow" || true)

  awk -v file="$workflow" '
    function finish() {
      if (action == "checkout" && safe != 1) {
        print "workflow policy: " file " checkout must set persist-credentials: false" > "/dev/stderr"
        bad = 1
      }
      if (action == "setup-go" && safe != 1) {
        print "workflow policy: " file " setup-go must set cache: false" > "/dev/stderr"
        bad = 1
      }
      action = ""
      safe = 0
    }
    /^[[:space:]]*-[[:space:]]*(name|uses):/ {
      if (action != "") {
        finish()
      }
    }
    /uses:[[:space:]]*actions\/checkout@/ {
      action = "checkout"
      safe = 0
    }
    /uses:[[:space:]]*actions\/setup-go@/ {
      action = "setup-go"
      safe = 0
    }
    action == "checkout" && /persist-credentials:[[:space:]]*false([[:space:]]|$)/ {
      safe = 1
    }
    action == "setup-go" && /cache:[[:space:]]*false([[:space:]]|$)/ {
      safe = 1
    }
    END {
      if (action != "") {
        finish()
      }
      exit bad
    }
  ' "$workflow" || fail "$workflow has unsafe action inputs"
done

[ "$workflow_count" -gt 0 ] || fail "no workflow files found"
echo "workflow policy passed for $workflow_count file(s)"
