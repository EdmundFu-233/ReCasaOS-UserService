#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'trusted attestor policy negative tests: %s\n' "$*" >&2
  exit 1
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/../.." && pwd -P)
checker="$repo_root/scripts/check-trusted-attestor-workflow.sh"
workflow="$repo_root/.github/workflows/trusted-attestor.yml"
fixture=$(mktemp -d "${TMPDIR:-/tmp}/recasaos-userservice-attestor-policy.XXXXXX")
candidate_dir="$fixture/.github/workflows"
candidate="$candidate_dir/trusted-attestor.yml"

cleanup() {
  rm -rf -- "$fixture"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$candidate_dir"

[[ -x "$checker" ]] || fail "checker is not executable"
[[ -f "$workflow" && ! -L "$workflow" ]] || fail "reviewed workflow is missing"
"$checker" "$workflow" >/dev/null

replace_once() {
  local source=$1
  local destination=$2
  local needle=$3
  local replacement=$4
  ruby - "$source" "$destination" "$needle" "$replacement" <<'RUBY'
source, destination, needle, replacement = ARGV
text = File.read(source, encoding: "UTF-8")
raise "mutation target is not unique" unless text.scan(needle).length == 1
File.write(destination, text.sub(needle, replacement), mode: "w", encoding: "UTF-8")
RUBY
}

expect_reject() {
  local label=$1
  local needle=$2
  local replacement=$3
  printf 'trusted attestor mutation: %s\n' "$label"
  replace_once "$workflow" "$candidate" "$needle" "$replacement"
  if "$checker" "$candidate" >"$fixture/$label.log" 2>&1; then
    fail "unsafe mutation was accepted: $label"
  fi
  grep -Fq 'workflow digest does not match the exact reviewed policy' "$fixture/$label.log" ||
    fail "unexpected rejection for $label"
}

expect_reject workflow-name \
  'name: Trusted exact-SHA attestor' \
  'name: Untrusted exact-SHA attestor'
expect_reject pull-request-target \
  $'  workflow_run:\n    workflows:' \
  $'  pull_request_target:\n  workflow_run:\n    workflows:'
expect_reject caller-selected-ref \
  '  repository_dispatch:' \
  $'  workflow_dispatch:\n  repository_dispatch:'
expect_reject root-token-permission \
  $'permissions: {}\n\nenv:' \
  $'permissions:\n  statuses: write\n\nenv:'
expect_reject cancellation-race \
  '  cancel-in-progress: false' \
  '  cancel-in-progress: true'
expect_reject automatic-pr-checkout \
  $'      default_tree: ${{ steps.validate.outputs.default_tree }}\n    steps:\n      - name: Check out only the protected default branch\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          ref: main' \
  $'      default_tree: ${{ steps.validate.outputs.default_tree }}\n    steps:\n      - name: Check out only the protected default branch\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          ref: ${{ github.event.workflow_run.head_sha }}'
expect_reject independent-codeql-upload \
  $'          upload: never\n          upload-database: false\n          output: ${{ runner.temp }}/trusted-codeql-sarif' \
  $'          upload: always\n          upload-database: false\n          output: ${{ runner.temp }}/trusted-codeql-sarif'
expect_reject independent-codeql-unlinked \
  $'      - name: Initialize independent CodeQL without upload permission\n        id: independent-init\n        uses: github/codeql-action/init@ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd # v4.37.7\n        with:\n          languages: go\n          build-mode: manual\n          tools: linked' \
  $'      - name: Initialize independent CodeQL without upload permission\n        id: independent-init\n        uses: github/codeql-action/init@ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd # v4.37.7\n        with:\n          languages: go\n          build-mode: manual\n          tools: toolcache'
expect_reject independent-codeql-version-unproved \
  $'      - name: Prove exact independent CodeQL CLI\n        shell: bash\n        env:\n          ACTUAL_CODEQL_VERSION: ${{ steps.independent-init.outputs.codeql-version }}\n        run: test "$ACTUAL_CODEQL_VERSION" = '\''2.26.3'\''' \
  $'      - name: Prove exact independent CodeQL CLI\n        shell: bash\n        env:\n          ACTUAL_CODEQL_VERSION: ${{ steps.independent-init.outputs.codeql-version }}\n        run: test -n "$ACTUAL_CODEQL_VERSION"'
expect_reject promoted-codeql-upload \
  $'          upload: never\n          upload-database: false\n          output: ${{ runner.temp }}/trusted-promoted-codeql-sarif' \
  $'          upload: always\n          upload-database: false\n          output: ${{ runner.temp }}/trusted-promoted-codeql-sarif'
expect_reject independent-codeql-write-token \
  $'  independent-codeql:\n    name: Independently reject High-or-higher CodeQL results\n    needs:\n      - validate-automatic\n    if: needs.validate-automatic.result == \'success\'\n    runs-on: ubuntu-24.04\n    timeout-minutes: 30\n    permissions:\n      actions: read\n      contents: read' \
  $'  independent-codeql:\n    name: Independently reject High-or-higher CodeQL results\n    needs:\n      - validate-automatic\n    if: needs.validate-automatic.result == \'success\'\n    runs-on: ubuntu-24.04\n    timeout-minutes: 30\n    permissions:\n      actions: read\n      contents: read\n      security-events: write'
expect_reject publisher-skips-independent-codeql \
  $'    needs:\n      - validate-automatic\n      - independent-codeql\n    if: >-\n      needs.validate-automatic.result == \'success\' &&\n      needs.independent-codeql.result == \'success\'' \
  $'    needs:\n      - validate-automatic\n    if: needs.validate-automatic.result == \'success\''
expect_reject validator-write-token \
  $'      checks: read\n      contents: read\n      pull-requests: read' \
  $'      checks: read\n      contents: write\n      pull-requests: read'
expect_reject app-action-mutable \
  $'  publish-automatic:\n    name: Publish App-backed automatic status' \
  $'  publish-automatic:\n    # actions/create-github-app-token@main\n    name: Publish App-backed automatic status'
expect_reject app-id-unbound \
  $'          app-id: ${{ vars.TRUSTED_ATTESTOR_APP_ID }}\n          private-key: ${{ secrets.TRUSTED_ATTESTOR_PRIVATE_KEY }}\n          owner: EdmundFu-233\n          repositories: ReCasaOS-UserService\n          skip-token-revoke: false\n          permission-actions: read\n          permission-contents: read\n          permission-pull-requests: read\n          permission-statuses: write\n      - name: Revalidate live identities and publish exact-head success' \
  $'          app-id: 1\n          private-key: ${{ secrets.TRUSTED_ATTESTOR_PRIVATE_KEY }}\n          owner: EdmundFu-233\n          repositories: ReCasaOS-UserService\n          skip-token-revoke: false\n          permission-actions: read\n          permission-contents: read\n          permission-pull-requests: read\n          permission-statuses: write\n      - name: Revalidate live identities and publish exact-head success'
expect_reject app-key-name \
  $'          private-key: ${{ secrets.TRUSTED_ATTESTOR_PRIVATE_KEY }}\n          owner: EdmundFu-233\n          repositories: ReCasaOS-UserService\n          skip-token-revoke: false\n          permission-actions: read\n          permission-contents: read\n          permission-pull-requests: read\n          permission-statuses: write\n      - name: Revalidate live identities and publish exact-head success' \
  $'          private-key: ${{ secrets.GENERIC_PRIVATE_KEY }}\n          owner: EdmundFu-233\n          repositories: ReCasaOS-UserService\n          skip-token-revoke: false\n          permission-actions: read\n          permission-contents: read\n          permission-pull-requests: read\n          permission-statuses: write\n      - name: Revalidate live identities and publish exact-head success'
expect_reject app-status-permission \
  $'          permission-statuses: write\n      - name: Revalidate live identities and publish exact-head success' \
  $'          permission-statuses: read\n      - name: Revalidate live identities and publish exact-head success'
expect_reject app-token-in-qa \
  $'  promoted-qa:\n    name: Run promoted exact-SHA Go and Debian QA' \
  $'  promoted-qa:\n    environment: trusted-attestor\n    name: Run promoted exact-SHA Go and Debian QA'
expect_reject qa-write-token \
  $'    timeout-minutes: 60\n    permissions:\n      actions: read\n      contents: read\n    env:\n      CODEQL_OVERLAY_DATABASE_MODE: none\n      GOTOOLCHAIN: local' \
  $'    timeout-minutes: 60\n    permissions:\n      actions: read\n      contents: write\n    env:\n      CODEQL_OVERLAY_DATABASE_MODE: none\n      GOTOOLCHAIN: local'
expect_reject publish-before-cleanup \
  $'      - promoted-qa\n      - cleanup-promotion\n    if: >-\n      always() &&' \
  $'      - promoted-qa\n    if: >-\n      always() &&'
expect_reject weakened-publish-condition \
  "      needs.cleanup-promotion.outputs.removed == 'true'" \
  "      github.actor == github.repository_owner"
expect_reject cleanup-after-failed-prepare \
  $'      always() &&\n      needs.prepare-promotion.result == \'success\' &&\n      github.event_name == \'repository_dispatch\'' \
  $'      always() &&\n      github.event_name == \'repository_dispatch\''
expect_reject moved-ref-tolerated \
  '          [[ "${exact_shas[0]}" == "$EXPECTED_SHA" ]] || fail "trusted ref moved"' \
  '          [[ -n "${exact_shas[0]}" ]] || fail "trusted ref moved"'
expect_reject no-delete-readback \
  $'          remaining="$(\n            gh api -X GET "repos/$REPOSITORY/git/matching-refs/heads/$TRUSTED_BRANCH" \\\n              -f per_page=100 -f page=1\n          )"\n          [[ "$(jq \'length\' <<<"$remaining")" -lt 100 ]] ||\n            fail "post-delete matching refs exceed one complete bounded page"\n          [[ "$(jq --arg ref "$trusted_ref" \'[.[] | select(.ref == $ref)] | length\' <<<"$remaining")" == 0 ]] ||' \
  $'          remaining="[]"\n          [[ "$(jq \'length\' <<<"$remaining")" -lt 100 ]] ||\n            fail "post-delete matching refs exceed one complete bounded page"\n          [[ "$(jq --arg ref "$trusted_ref" \'[.[] | select(.ref == $ref)] | length\' <<<"$remaining")" == 0 ]] ||'
expect_reject status-context \
  '  STATUS_CONTEXT: ReCasaOS-UserService / trusted exact-SHA' \
  '  STATUS_CONTEXT: Workflow policy'
expect_reject wrong-status-sha \
  $'          gh api --method POST "repos/$REPOSITORY/statuses/$EXPECTED_SHA" \\\n            -f state=success \\\n            -f "context=$STATUS_CONTEXT" \\\n            -f description='\''Trusted App verified CI, independent CodeQL, policy, and SHA'\''' \
  $'          gh api --method POST "repos/$REPOSITORY/statuses/$DEFAULT_SHA" \\\n            -f state=success \\\n            -f "context=$STATUS_CONTEXT" \\\n            -f description='\''Trusted App verified CI, independent CodeQL, policy, and SHA'\'''
expect_reject duplicate-yaml-key \
  $'permissions: {}\n\nenv:' \
  $'permissions: {}\npermissions: {}\n\nenv:'
expect_reject yaml-alias \
  $'permissions: {}\n\nenv:' \
  $'permissions: &root_permissions {}\nunsafe: *root_permissions\n\nenv:'
expect_reject second-document \
  'name: Trusted exact-SHA attestor' \
  $'---\nname: injected\n---\nname: Trusted exact-SHA attestor'

fixture_repo="$fixture/repo"
mkdir -p "$fixture_repo/.github/workflows" "$fixture_repo/scripts/tests"
cp "$checker" "$fixture_repo/scripts/check-trusted-attestor-workflow.sh"
cp "$workflow" "$fixture_repo/.github/workflows/trusted-attestor.yml"
cp "$repo_root/scripts/check-codeql-sarif.py" "$fixture_repo/scripts/check-codeql-sarif.py"
cp "$repo_root/scripts/trusted_attestor.py" "$fixture_repo/scripts/trusted_attestor.py"
cp "$repo_root/scripts/tests/check-debian11-systemd-vm.sh" "$fixture_repo/scripts/tests/check-debian11-systemd-vm.sh"
cp "$repo_root/scripts/tests/test-systemd-lifecycle.sh" "$fixture_repo/scripts/tests/test-systemd-lifecycle.sh"
printf '\n# tamper\n' >>"$fixture_repo/scripts/trusted_attestor.py"
if "$fixture_repo/scripts/check-trusted-attestor-workflow.sh" \
  "$fixture_repo/.github/workflows/trusted-attestor.yml" >"$fixture/runtime-tamper.log" 2>&1
then
  fail "tampered validator was accepted"
fi
grep -Fq 'trusted validator digest drifted' "$fixture/runtime-tamper.log" ||
  fail "tampered validator had an unexpected rejection"

cp "$repo_root/scripts/trusted_attestor.py" "$fixture_repo/scripts/trusted_attestor.py"
printf '\n# tamper\n' >>"$fixture_repo/scripts/check-codeql-sarif.py"
if "$fixture_repo/scripts/check-trusted-attestor-workflow.sh" \
  "$fixture_repo/.github/workflows/trusted-attestor.yml" >"$fixture/sarif-runtime-tamper.log" 2>&1
then
  fail "tampered SARIF checker was accepted"
fi
grep -Fq 'trusted SARIF checker digest drifted' "$fixture/sarif-runtime-tamper.log" ||
  fail "tampered SARIF checker had an unexpected rejection"

python3 -B "$repo_root/scripts/tests/trusted_attestor_test.py"
python3 -B "$repo_root/scripts/tests/check-codeql-sarif_test.py"
printf 'trusted attestor policy negative tests passed\n'
