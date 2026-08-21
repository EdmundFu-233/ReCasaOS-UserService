#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

ALLOWED_RUNS = [
  "bash scripts/tests/check-workflow-policy_test.sh",
  "bash scripts/check-workflow-policy.sh",
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
	reject("job #{job_name} must have a bounded timeout") unless timeout.is_a?(Integer) && timeout.between?(1, 30)
	if job.key?("env") && job["env"] != { "GOTOOLCHAIN" => "local" }
		reject("job #{job_name} has an unsupported environment")
	end
  steps = job["steps"]
  reject("job #{job_name} steps must be an array") unless steps.is_a?(Array)
  codeql_analyze = steps.any? do |step|
    step.is_a?(Hash) && step["uses"].is_a?(String) && step["uses"].start_with?("github/codeql-action/analyze@")
  end
  if job.key?("permissions")
    validate_permissions(job["permissions"], "job #{job_name}", codeql_analyze)
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
