#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

def reject(message)
  warn "workflow structure policy: #{message}"
  exit 1
end

path = ARGV.fetch(0) { reject("missing workflow path") }
document = YAML.safe_load(
  File.read(path, encoding: "UTF-8"),
  permitted_classes: [],
  permitted_symbols: [],
  aliases: false
)
reject("workflow root must be a mapping") unless document.is_a?(Hash)

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
  "actions/setup-go"
].freeze

jobs.each do |job_name, job|
  reject("job #{job_name} must be a mapping") unless job.is_a?(Hash)
  steps = job["steps"]
  reject("job #{job_name} steps must be an array") unless steps.is_a?(Array)
  steps.each_with_index do |step, index|
    reject("job #{job_name} step #{index + 1} must be a mapping") unless step.is_a?(Hash)
    next unless step.key?("uses")

    uses = step["uses"]
    reject("job #{job_name} step #{index + 1} uses must be a string") unless uses.is_a?(String)
    match = uses.match(/\A([^@\s]+)@([0-9a-f]{40})\z/)
    reject("job #{job_name} step #{index + 1} has a mutable or malformed action") unless match
    action = match[1]
    unless allowed_actions.include?(action) || action.start_with?("github/codeql-action/")
      reject("job #{job_name} step #{index + 1} uses a non-allowlisted action")
    end

    inputs = step.fetch("with", {})
    reject("job #{job_name} step #{index + 1} with must be a mapping") unless inputs.is_a?(Hash)
    if action == "actions/checkout" && inputs["persist-credentials"] != false
      reject("checkout must set persist-credentials to boolean false")
    end
    if action == "actions/setup-go" && inputs["cache"] != false
      reject("setup-go must set cache to boolean false")
    end
  end
end
