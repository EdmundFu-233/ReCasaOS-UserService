#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"
require "digest"

VM_INSTALL_RUN = "sudo apt-get update\nsudo apt-get install --yes --no-install-recommends cloud-image-utils qemu-system-x86 qemu-utils".freeze
VM_LIFECYCLE_RUN = "bash scripts/tests/check-debian11-systemd-vm.sh".freeze
VM_SCRIPT_VERIFY_RUN = <<~'BASH'.strip.freeze
  printf '%s  %s\n' \
    'bffb4639af8268725b636a94c0bf096835addfd2c70da5eddf87c015867adb68' 'scripts/tests/check-debian11-systemd-vm.sh' \
    'e08a2181f7709e2b59917c442b4b1bb8a79bf20612436fa71c3b2ca2784523a1' 'scripts/tests/test-systemd-lifecycle.sh' |
    sha256sum --check --strict
  test -z "$(git status --porcelain --untracked-files=all)"
BASH

ALLOWED_RUNS = [
  "bash scripts/tests/check-workflow-policy_test.sh",
  "bash scripts/check-workflow-policy.sh",
  VM_INSTALL_RUN,
  VM_SCRIPT_VERIFY_RUN,
  VM_LIFECYCLE_RUN,
  "go mod tidy -diff",
  "bash scripts/check-go-dependency-boundary.sh --tools-only",
  "go generate ./...\ngit diff --exit-code -- codegen/\ntest -z \"$(git status --porcelain --untracked-files=all)\"",
  "bash scripts/check-go-dependency-boundary.sh --all",
  "go tool go-licenses check --include_tests ./... tool",
  "go test -race -count=1 ./...",
  "go vet ./...",
  "bash scripts/tests/check-govuln-policy_test.sh\nset -o pipefail\ngo tool govulncheck -json ./... |\n  go run ./scripts/govuln-policy.go security/govuln-allowlist.txt",
  "go generate ./...",
  "go build ./..."
].freeze

EXPECTED_CI_POLICY_STEPS = [
  ["Checkout", "uses", "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"],
  ["Test policy checker", "run", "bash scripts/tests/check-workflow-policy_test.sh"],
  ["Enforce repository workflow policy", "run", "bash scripts/check-workflow-policy.sh"]
].freeze

EXPECTED_CI_GO_STEPS = [
  ["Checkout", "uses", "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"],
  ["Set up Go", "uses", "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e"],
  ["Install isolated Debian VM tools", "run", VM_INSTALL_RUN],
  ["Verify reviewed VM harness before executing pull request code", "run", VM_SCRIPT_VERIFY_RUN],
  ["Exercise local administrator lifecycle under systemd 247 PID 1", "run", VM_LIFECYCLE_RUN],
  ["Verify module graph", "run", "go mod tidy -diff"],
  ["Preflight selected Go tool package boundary", "run", "bash scripts/check-go-dependency-boundary.sh --tools-only"],
  ["Generate APIs and verify tracked outputs", "run", "go generate ./...\ngit diff --exit-code -- codegen/\ntest -z \"$(git status --porcelain --untracked-files=all)\""],
  ["Enforce Linux test, release, and tool package boundaries", "run", "bash scripts/check-go-dependency-boundary.sh --all"],
  ["Enforce dependency license policy", "run", "go tool go-licenses check --include_tests ./... tool"],
  ["Race tests", "run", "go test -race -count=1 ./..."],
  ["Vet", "run", "go vet ./..."],
  ["Reachable vulnerability policy", "run", "bash scripts/tests/check-govuln-policy_test.sh\nset -o pipefail\ngo tool govulncheck -json ./... |\n  go run ./scripts/govuln-policy.go security/govuln-allowlist.txt"]
].freeze

EXPECTED_CODEQL_STEPS = [
  ["Checkout", "uses", "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"],
  ["Set up Go", "uses", "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e"],
  ["Initialize CodeQL", "uses", "github/codeql-action/init@ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd"],
  ["Preflight selected Go tool package boundary", "run", "bash scripts/check-go-dependency-boundary.sh --tools-only"],
  ["Generate APIs", "run", "go generate ./..."],
  ["Build", "run", "go build ./..."],
  ["Analyze", "uses", "github/codeql-action/analyze@ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd"]
].freeze

EXPECTED_VM_SCRIPT_SHA256 = {
  "scripts/tests/check-debian11-systemd-vm.sh" => "bffb4639af8268725b636a94c0bf096835addfd2c70da5eddf87c015867adb68",
  "scripts/tests/test-systemd-lifecycle.sh" => "e08a2181f7709e2b59917c442b4b1bb8a79bf20612436fa71c3b2ca2784523a1"
}.freeze

def reject(message)
  warn "workflow structure policy: #{message}"
  exit 1
end

def workflow_triggers(document)
  if document.key?("on") && document.key?(true)
    reject("workflow declares the on key more than once")
  end
  value = document.key?("on") ? document["on"] : document[true]
  reject("workflow trigger is missing") if value.nil?

  case value
  when String
    [value]
  when Array
    value
  when Hash
    value.keys
  else
    reject("workflow trigger must be a string, array, or mapping")
  end
end

def validate_exact_main_triggers(document, context)
  value = document.key?("on") ? document["on"] : document[true]
  expected = {
    "pull_request" => { "branches" => ["main"] },
    "push" => { "branches" => ["main"] }
  }
  reject("#{context} triggers are not exact") unless value == expected
end

def validate_permissions(value, context, allow_security_events_write)
  reject("#{context} permissions must be a mapping") unless value.is_a?(Hash)
  value.each do |name, level|
    reject("#{context} permission names and levels must be strings") unless name.is_a?(String) && level.is_a?(String)
    unless ["none", "read", "write"].include?(level)
      reject("#{context} permission #{name} has an unsupported level")
    end
    next unless level == "write"
    next if allow_security_events_write && name == "security-events"

    reject("#{context} requests forbidden #{name}: write permission")
  end
end

def validate_run(run, context)
  reject("#{context} run must be a string") unless run.is_a?(String)
  reject("#{context} run command is not allowlisted") unless ALLOWED_RUNS.include?(run.strip)
end

path = ARGV.fetch(0) { reject("missing workflow path") }
repository_root_argument = ARGV.fetch(1) { reject("missing repository root") }
begin
  repository_root = File.realpath(repository_root_argument)
rescue SystemCallError
  reject("repository root is unavailable")
end
reject("repository root must be an absolute directory") unless File.directory?(repository_root) && repository_root.start_with?(File::SEPARATOR)
document = YAML.safe_load(
  File.read(path, encoding: "UTF-8"),
  permitted_classes: [],
  permitted_symbols: [],
  aliases: false
)
reject("workflow root must be a mapping") unless document.is_a?(Hash)
allowed_root_keys = ["name", "on", true, "permissions", "jobs"]
unknown_root_keys = document.keys.reject { |key| allowed_root_keys.include?(key) }
reject("workflow contains unsupported root keys") unless unknown_root_keys.empty?
reject("workflow name must be a string") unless document["name"].is_a?(String)

triggers = workflow_triggers(document)
unless triggers.all? { |trigger| trigger.is_a?(String) && ["pull_request", "push"].include?(trigger) }
  reject("workflow uses a trigger outside pull_request and push")
end

validate_permissions(document.fetch("permissions") { reject("workflow permissions are missing") }, "workflow", false)

visit = lambda do |value|
  case value
  when Hash
    value.each do |key, child|
      visit.call(key)
      visit.call(child)
    end
  when Array
    value.each { |child| visit.call(child) }
  when String
    if value.match?(/\$\{\{[^}]*\bsecrets\b[^}]*\}\}/im)
      reject("workflow references the secrets context")
    end
  end
end
visit.call(document)

jobs = document["jobs"]
reject("jobs must be a non-empty mapping") unless jobs.is_a?(Hash) && !jobs.empty?

allowed_actions = [
  "actions/checkout",
  "actions/setup-go",
  "github/codeql-action/init",
  "github/codeql-action/analyze"
].freeze

jobs.each do |job_name, job|
	reject("job name must be a string") unless job_name.is_a?(String)
  reject("job #{job_name} must be a mapping") unless job.is_a?(Hash)
	allowed_job_keys = ["name", "needs", "runs-on", "timeout-minutes", "env", "permissions", "steps"]
	unknown_job_keys = job.keys - allowed_job_keys
	reject("job #{job_name} contains unsupported keys") unless unknown_job_keys.empty?
	reject("job #{job_name} must use ubuntu-24.04") unless job["runs-on"] == "ubuntu-24.04"
	timeout = job["timeout-minutes"]
	maximum_timeout = File.basename(path) == "ci.yml" && job_name == "go" ? 60 : 30
	reject("job #{job_name} must have a bounded timeout") unless timeout.is_a?(Integer) && timeout.between?(1, maximum_timeout)
	if job.key?("env") && job["env"] != { "GOTOOLCHAIN" => "local" }
		reject("job #{job_name} has an unsupported environment")
	end
  steps = job["steps"]
  reject("job #{job_name} steps must be an array") unless steps.is_a?(Array)
  codeql_analyze = steps.any? do |step|
    step.is_a?(Hash) && step["uses"].is_a?(String) && step["uses"].start_with?("github/codeql-action/analyze@")
  end
  if job.key?("permissions")
    allow_security_events_write = File.basename(path) == "codeql.yml" && job_name == "analyze" && codeql_analyze
    validate_permissions(job["permissions"], "job #{job_name}", allow_security_events_write)
  end
  steps.each_with_index do |step, index|
    reject("job #{job_name} step #{index + 1} must be a mapping") unless step.is_a?(Hash)
	allowed_step_keys = ["name", "uses", "with", "run", "shell"]
	unknown_step_keys = step.keys - allowed_step_keys
	reject("job #{job_name} step #{index + 1} contains unsupported keys") unless unknown_step_keys.empty?
	reject("job #{job_name} step #{index + 1} name must be a string") if step.key?("name") && !step["name"].is_a?(String)
	if step.key?("run")
		reject("job #{job_name} step #{index + 1} cannot combine run and uses") if step.key?("uses")
		reject("job #{job_name} step #{index + 1} must use shell bash") unless step["shell"] == "bash"
		reject("job #{job_name} step #{index + 1} cannot declare action inputs") if step.key?("with")
		validate_run(step["run"], "job #{job_name} step #{index + 1}")
		next
	end
    next unless step.key?("uses")

    uses = step["uses"]
    reject("job #{job_name} step #{index + 1} uses must be a string") unless uses.is_a?(String)
    match = uses.match(/\A([^@\s]+)@([0-9a-f]{40})\z/)
    reject("job #{job_name} step #{index + 1} has a mutable or malformed action") unless match
    action = match[1]
    unless allowed_actions.include?(action)
      reject("job #{job_name} step #{index + 1} uses a non-allowlisted action")
    end
	reject("job #{job_name} step #{index + 1} action cannot declare shell") if step.key?("shell")

    inputs = step.fetch("with", {})
    reject("job #{job_name} step #{index + 1} with must be a mapping") unless inputs.is_a?(Hash)
    if action == "actions/checkout" && inputs["persist-credentials"] != false
      reject("checkout must set persist-credentials to boolean false")
    end
    if action == "actions/setup-go" && inputs["cache"] != false
      reject("setup-go must set cache to boolean false")
    end
	case action
	when "actions/checkout"
		reject("checkout inputs are not exact") unless inputs == { "persist-credentials" => false }
	when "actions/setup-go"
		expected = { "go-version" => "1.26.6", "check-latest" => false, "cache" => false }
		reject("setup-go inputs are not exact") unless inputs == expected
	when "github/codeql-action/init"
		reject("CodeQL init inputs are not exact") unless inputs == { "languages" => "go" }
	when "github/codeql-action/analyze"
		reject("CodeQL analyze must not have inputs") unless inputs.empty?
	end
  end
end

if File.basename(path) == "ci.yml"
  reject("CI workflow name is not exact") unless document["name"] == "CI"
  validate_exact_main_triggers(document, "CI workflow")
  reject("CI workflow root permissions are not exact") unless document["permissions"] == { "contents" => "read" }
  reject("CI workflow must contain exactly workflow-policy and go jobs") unless jobs.keys == ["workflow-policy", "go"]
  policy_job = jobs["workflow-policy"]
  expected_policy_metadata = {
    "name" => "Workflow policy",
    "runs-on" => "ubuntu-24.04",
    "timeout-minutes" => 5
  }
  actual_policy_metadata = policy_job.reject { |key, _value| key == "steps" }
  reject("CI Workflow policy job metadata is not exact") unless actual_policy_metadata == expected_policy_metadata
  policy_signatures = policy_job.fetch("steps", []).map do |step|
    kind = step.key?("uses") ? "uses" : "run"
    payload = step[kind]
    payload = payload.strip if kind == "run" && payload.is_a?(String)
    [step["name"], kind, payload]
  end
  reject("CI Workflow policy step sequence is not exact") unless policy_signatures == EXPECTED_CI_POLICY_STEPS
  go_job = jobs["go"]
  reject("CI Go 1.26.6 job is missing") unless go_job.is_a?(Hash)
  expected_metadata = {
    "name" => "Go 1.26.6",
    "needs" => ["workflow-policy"],
    "runs-on" => "ubuntu-24.04",
    "timeout-minutes" => 60,
    "env" => { "GOTOOLCHAIN" => "local" }
  }
  actual_metadata = go_job.reject { |key, _value| key == "steps" }
  reject("CI Go 1.26.6 job metadata is not exact") unless actual_metadata == expected_metadata
  signatures = go_job.fetch("steps", []).map do |step|
    kind = step.key?("uses") ? "uses" : "run"
    payload = step[kind]
    payload = payload.strip if kind == "run" && payload.is_a?(String)
    [step["name"], kind, payload]
  end
  reject("CI Go 1.26.6 step sequence is not exact") unless signatures == EXPECTED_CI_GO_STEPS
  EXPECTED_VM_SCRIPT_SHA256.each do |relative_path, expected_digest|
    script_path = File.join(repository_root, relative_path)
    begin
      info = File.lstat(script_path)
    rescue SystemCallError
      reject("reviewed VM script is missing")
    end
    unless info.file? && !info.symlink? && info.size.between?(1024, 131_072)
      reject("reviewed VM script is not a bounded regular file")
    end
    reject("reviewed VM script digest does not match policy") unless Digest::SHA256.file(script_path).hexdigest == expected_digest
  end
end

if File.basename(path) == "codeql.yml"
  reject("CodeQL workflow name is not exact") unless document["name"] == "CodeQL"
  validate_exact_main_triggers(document, "CodeQL workflow")
  reject("CodeQL workflow root permissions are not exact") unless document["permissions"] == { "contents" => "read" }
  reject("CodeQL workflow must contain only the analyze job") unless jobs.keys == ["analyze"]
  analyze_job = jobs["analyze"]
  expected_metadata = {
    "name" => "Analyze Go",
    "runs-on" => "ubuntu-24.04",
    "timeout-minutes" => 30,
    "permissions" => {
      "actions" => "read",
      "contents" => "read",
      "security-events" => "write"
    },
    "env" => { "GOTOOLCHAIN" => "local" }
  }
  actual_metadata = analyze_job.reject { |key, _value| key == "steps" }
  reject("CodeQL analyze job metadata is not exact") unless actual_metadata == expected_metadata
  signatures = analyze_job.fetch("steps", []).map do |step|
    kind = step.key?("uses") ? "uses" : "run"
    payload = step[kind]
    payload = payload.strip if kind == "run" && payload.is_a?(String)
    [step["name"], kind, payload]
  end
  reject("CodeQL analyze step sequence is not exact") unless signatures == EXPECTED_CODEQL_STEPS
end
