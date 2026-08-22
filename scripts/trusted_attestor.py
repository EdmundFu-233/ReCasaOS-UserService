#!/usr/bin/env python3
"""Fail-closed validation for the independent exact-SHA attestor.

This module is executed only from a checkout of the protected default branch.
It never publishes a status and never receives the dedicated GitHub App key or
installation token.  The protected publisher independently re-reads the
immutable identities before it uses the App token.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


REPOSITORY = "EdmundFu-233/ReCasaOS-UserService"
REPOSITORY_ID = 1_341_287_306
REPOSITORY_OWNER = "EdmundFu-233"
DEFAULT_BRANCH = "main"
CI_WORKFLOW_NAME = "CI"
CI_WORKFLOW_ID = 339_058_307
CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
PROMOTION_EVENT = "trusted-attestor-promote"
STATUS_CONTEXT = "ReCasaOS-UserService / trusted exact-SHA"
GITHUB_ACTIONS_APP_ID = 15_368
CODEQL_APP_ID = 57_789
VM_HOST_PATH = "scripts/tests/check-debian11-systemd-vm.sh"
VM_GUEST_PATH = "scripts/tests/test-systemd-lifecycle.sh"
SARIF_CHECKER_PATH = "scripts/check-codeql-sarif.py"

SHA1_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
SAFE_REF_RE = re.compile(r"[A-Za-z0-9._/-]{1,240}\Z")
VALID_TREE_MODE_TYPES = frozenset(
    {
        ("040000", "tree"),
        ("100644", "blob"),
        ("100755", "blob"),
        ("120000", "blob"),
        ("160000", "commit"),
    }
)

FROZEN_ROOTS = (
    ".github",
    "api",
    "build",
    "codegen",
    "scripts",
    "security",
    "vendor",
)
FROZEN_FILES = frozenset(
    {
        ".gitattributes",
        ".gitignore",
        ".gitmodules",
        ".goreleaser.debug.yaml",
        ".goreleaser.yaml",
        "CODEOWNERS",
        "SECURITY.md",
        "UPSTREAM.md",
        "docs/CODEOWNERS",
        "docs/trusted-attestor.md",
        "go.mod",
        "go.sum",
        "go.work",
        "go.work.sum",
        "main.go",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "tools.go",
        "tsconfig.json",
        "yarn.lock",
    }
)

REQUIRED_FROZEN_PATHS = frozenset(
    {
        ".github/workflows/ci.yml",
        ".github/workflows/codeql.yml",
        ".github/workflows/trusted-attestor.yml",
        "scripts/check-go-dependency-boundary.go",
        "scripts/check-go-dependency-boundary.sh",
        "scripts/check-codeql-sarif.py",
        "scripts/check-trusted-attestor-workflow.sh",
        "scripts/check-workflow-policy.sh",
        "scripts/check-workflow-structure.rb",
        "scripts/generate-api.sh",
        "scripts/govuln-policy.go",
        "scripts/trusted_attestor.py",
        "scripts/tests/check-debian11-systemd-vm.sh",
        "scripts/tests/check-codeql-sarif_test.py",
        "scripts/tests/check-govuln-policy_test.sh",
        "scripts/tests/check-trusted-attestor-policy_test.sh",
        "scripts/tests/check-workflow-policy_test.sh",
        "scripts/tests/test-systemd-lifecycle.sh",
        "scripts/tests/trusted_attestor_test.py",
        "security/govuln-allowlist.txt",
        "docs/trusted-attestor.md",
    }
)
REQUIRED_EXECUTABLE_PATHS = frozenset(
    {
        "scripts/check-go-dependency-boundary.sh",
        "scripts/check-codeql-sarif.py",
        "scripts/check-trusted-attestor-workflow.sh",
        "scripts/check-workflow-policy.sh",
        "scripts/check-workflow-structure.rb",
        "scripts/generate-api.sh",
        "scripts/trusted_attestor.py",
        "scripts/tests/check-debian11-systemd-vm.sh",
        "scripts/tests/check-codeql-sarif_test.py",
        "scripts/tests/check-govuln-policy_test.sh",
        "scripts/tests/check-trusted-attestor-policy_test.sh",
        "scripts/tests/check-workflow-policy_test.sh",
        "scripts/tests/test-systemd-lifecycle.sh",
        "scripts/tests/trusted_attestor_test.py",
    }
)

REQUIRED_CHECKS = (
    ("Workflow policy", GITHUB_ACTIONS_APP_ID),
    ("Go 1.26.6", GITHUB_ACTIONS_APP_ID),
    ("Analyze Go", GITHUB_ACTIONS_APP_ID),
    ("CodeQL", CODEQL_APP_ID),
)

REQUIRED_JOB_STEPS = {
    "Workflow policy": (
        "Checkout",
        "Test policy checker",
        "Enforce repository workflow policy",
    ),
    "Go 1.26.6": (
        "Checkout",
        "Set up Go",
        "Install isolated Debian VM tools",
        "Verify reviewed VM harness before executing pull request code",
        "Exercise local administrator lifecycle under systemd 247 PID 1",
        "Verify module graph",
        "Preflight selected Go tool package boundary",
        "Generate APIs and verify tracked outputs",
        "Enforce Linux test, release, and tool package boundaries",
        "Enforce dependency license policy",
        "Race tests",
        "Vet",
        "Reachable vulnerability policy",
    ),
}


class AttestorError(RuntimeError):
    """A validation refusal that must withhold trusted success."""


def refuse(condition: bool, message: str) -> None:
    if not condition:
        raise AttestorError(message)


def exact_sha1(value: Any, label: str) -> str:
    refuse(isinstance(value, str) and SHA1_RE.fullmatch(value) is not None, f"{label} is not an exact lowercase SHA-1")
    return value


def exact_sha256(value: Any, label: str) -> str:
    refuse(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None, f"{label} is not an exact lowercase SHA-256")
    return value


def exact_positive_int(value: Any, label: str, maximum: int = 10**18) -> int:
    refuse(isinstance(value, int) and not isinstance(value, bool) and 0 < value <= maximum, f"{label} is not a bounded positive integer")
    return value


def mapping(value: Any, label: str) -> Mapping[str, Any]:
    refuse(isinstance(value, dict) and all(isinstance(key, str) for key in value), f"{label} is not a string-keyed object")
    return value


def sequence(value: Any, label: str) -> Sequence[Any]:
    refuse(isinstance(value, list), f"{label} is not an array")
    return value


def nested(value: Mapping[str, Any], path: str, label: str) -> Any:
    current: Any = value
    for component in path.split("."):
        refuse(isinstance(current, dict) and component in current, f"{label} is missing {path}")
        current = current[component]
    return current


def load_json_file(path: str, label: str, maximum: int = 2_000_000) -> Mapping[str, Any]:
    candidate = Path(path)
    refuse(candidate.is_absolute(), f"{label} path is not absolute")
    info = candidate.lstat()
    refuse(candidate.is_file() and not candidate.is_symlink() and 0 < info.st_size <= maximum, f"{label} is not a bounded regular file")
    try:
        value = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AttestorError(f"{label} is not valid JSON: {error}") from error
    return mapping(value, label)


class GitHubAPI:
    def __init__(self, token: str, repository: str = REPOSITORY, api_url: str = "https://api.github.com") -> None:
        refuse(bool(token) and "\n" not in token and "\r" not in token, "GitHub token is missing or malformed")
        refuse(repository == REPOSITORY, "repository identity is not trusted")
        refuse(api_url == "https://api.github.com", "GitHub API origin is not trusted")
        self._token = token
        self._root = f"{api_url}/repos/{repository}"

    def _request(self, method: str, path: str, body: Mapping[str, Any] | None = None, query: Mapping[str, Any] | None = None) -> Any:
        refuse(path.startswith("/") and not path.startswith("//"), "API path is malformed")
        url = self._root + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "ReCasaOS-UserService-trusted-attestor",
                "X-GitHub-Api-Version": "2026-03-10",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read(8_000_001)
                refuse(len(payload) <= 8_000_000, "GitHub API response is too large")
                if not payload:
                    return None
                return json.loads(payload.decode("utf-8"))
        except urllib.error.HTTPError as error:
            detail = error.read(512).decode("utf-8", errors="replace")
            raise AttestorError(f"GitHub API {method} {path} returned {error.code}: {detail}") from error
        except (urllib.error.URLError, TimeoutError, UnicodeError, json.JSONDecodeError) as error:
            raise AttestorError(f"GitHub API {method} {path} failed: {error}") from error

    def get(self, path: str, query: Mapping[str, Any] | None = None) -> Any:
        return self._request("GET", path, query=query)

    def post(self, path: str, body: Mapping[str, Any]) -> Any:
        return self._request("POST", path, body=body)

    def delete(self, path: str) -> Any:
        return self._request("DELETE", path)


def is_frozen_path(path: str) -> bool:
    basename = path.rsplit("/", 1)[-1]
    components = path.split("/")
    if path in FROZEN_FILES or basename in {"go.mod", "go.sum", "go.work", "go.work.sum", "tools.go"}:
        return True
    if path.endswith("_test.go"):
        return True
    if any(component in {"testdata", "fixtures", "test-fixtures", "test_fixtures", "golden", "snapshots"} for component in components):
        return True
    if basename in {"Dockerfile", "Makefile", "GNUmakefile", "Taskfile.yml", "Taskfile.yaml"}:
        return True
    if basename.startswith("Dockerfile.") or basename.endswith(".Dockerfile"):
        return True
    if any(path.endswith(suffix) for suffix in (".sh", ".bash", ".zsh", ".py", ".rb", ".pl", ".ps1")):
        return True
    if path == "docs/security-bootstrap.md" or path == "docs/security-custom-config.md":
        return True
    return any(path == root or path.startswith(root + "/") for root in FROZEN_ROOTS)


def validated_tree(tree_document: Any, label: str) -> dict[str, tuple[str, str, str]]:
    document = mapping(tree_document, label)
    refuse(document.get("truncated") is False, f"{label} is truncated or lacks an exact truncation marker")
    entries = sequence(document.get("tree"), f"{label}.tree")
    refuse(len(entries) <= 100_000, f"{label} has too many entries")
    result: dict[str, tuple[str, str, str]] = {}
    seen: set[str] = set()
    for index, raw_entry in enumerate(entries):
        entry = mapping(raw_entry, f"{label}.tree[{index}]")
        path = entry.get("path")
        refuse(
            isinstance(path, str)
            and 0 < len(path.encode("utf-8")) <= 4096
            and not path.startswith("/")
            and not path.endswith("/")
            and re.search(r"[\x00-\x1f\x7f-\x9f]", path) is None
            and all(component not in ("", ".", "..") for component in path.split("/")),
            f"{label} contains a malformed path",
        )
        refuse(path not in seen, f"{label} contains duplicate path {path}")
        seen.add(path)
        mode = entry.get("mode")
        kind = entry.get("type")
        sha = entry.get("sha")
        refuse(
            isinstance(mode, str)
            and isinstance(kind, str)
            and (mode, kind) in VALID_TREE_MODE_TYPES,
            f"{label} has an invalid mode/type pair for {path}",
        )
        result[path] = (mode, kind, exact_sha1(sha, f"{label} object {path}"))
    return result


def frozen_tree(tree_document: Any, label: str) -> dict[str, tuple[str, str, str]]:
    return {path: signature for path, signature in validated_tree(tree_document, label).items() if is_frozen_path(path)}


def validate_required_trust_roots(
    entries: Mapping[str, tuple[str, str, str]], label: str
) -> None:
    missing = sorted(path for path in REQUIRED_FROZEN_PATHS if path not in entries)
    refuse(not missing, f"{label} is missing required trust roots: " + ", ".join(missing[:12]))
    for path in REQUIRED_FROZEN_PATHS:
        expected_mode = "100755" if path in REQUIRED_EXECUTABLE_PATHS else "100644"
        signature = entries[path]
        refuse(
            signature[0] == expected_mode and signature[1] == "blob",
            f"{label} trust root has unsafe type or mode: {path}",
        )


def compare_frozen_trees(base_document: Any, head_document: Any) -> list[str]:
    base = validated_tree(base_document, "default tree")
    head = validated_tree(head_document, "head tree")
    validate_required_trust_roots(base, "default tree")
    validate_required_trust_roots(head, "head tree")
    dangerous_modes = {"100755", "120000", "160000"}
    changed: list[str] = []
    for path in base.keys() | head.keys():
        before = base.get(path)
        after = head.get(path)
        if before == after:
            continue
        before_mode = before[0] if before else None
        after_mode = after[0] if after else None
        before_type = before[1] if before else None
        after_type = after[1] if after else None
        type_changed = before is not None and after is not None and before_type != after_type
        if is_frozen_path(path) or before_mode in dangerous_modes or after_mode in dangerous_modes or type_changed:
            changed.append(path)
    return sorted(changed)


def blob_bytes(api: Any, sha: str, label: str) -> bytes:
    document = mapping(api.get(f"/git/blobs/{sha}"), label)
    refuse(document.get("sha") == sha and document.get("encoding") == "base64", f"{label} identity or encoding is invalid")
    size = document.get("size")
    refuse(
        isinstance(size, int) and not isinstance(size, bool) and 0 <= size <= 1_000_000,
        f"{label} size is invalid",
    )
    encoded = document.get("content")
    refuse(isinstance(encoded, str) and len(encoded) <= 2_000_000, f"{label} is too large")
    compact = "".join(encoded.splitlines())
    refuse(re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact) is not None, f"{label} has malformed base64 characters")
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise AttestorError(f"{label} has invalid base64 content") from error
    refuse(len(decoded) <= 1_000_000, f"{label} decoded content is too large")
    refuse(size == len(decoded), f"{label} declared size does not match decoded content")
    object_bytes = b"blob " + str(len(decoded)).encode("ascii") + b"\0" + decoded
    actual_sha = hashlib.sha1(object_bytes, usedforsecurity=False).hexdigest()
    refuse(actual_sha == sha, f"{label} content does not match the requested Git blob SHA")
    return decoded


def changed_go_generate_paths(api: Any, base_document: Any, head_document: Any) -> list[str]:
    base = validated_tree(base_document, "default tree")
    head = validated_tree(head_document, "head tree")
    changed: list[str] = []
    for path in sorted(base.keys() | head.keys()):
        before = base.get(path)
        after = head.get(path)
        if before == after or not path.endswith(".go") or path.endswith("_test.go"):
            continue
        for label, signature in (("default", before), ("head", after)):
            if signature is None or signature[1] != "blob":
                continue
            content = blob_bytes(api, signature[2], f"{label} Go blob {path}")
            if re.search(br"(?m)^//go:generate[ \t]", content):
                changed.append(path)
                break
    return changed


def repository_from_event(event: Mapping[str, Any]) -> Mapping[str, Any]:
    repository = mapping(event.get("repository"), "event repository")
    refuse(repository.get("id") == REPOSITORY_ID, "event repository id is not trusted")
    refuse(repository.get("full_name") == REPOSITORY, "event repository name is not trusted")
    refuse(repository.get("default_branch") == DEFAULT_BRANCH, "event default branch is not exact")
    owner = mapping(repository.get("owner"), "event repository owner")
    refuse(owner.get("login") == REPOSITORY_OWNER, "event repository owner is not trusted")
    return repository


def validate_pr(pr_value: Any, head_sha: str, base_sha: str | None = None) -> int:
    pr = mapping(pr_value, "pull request")
    number = exact_positive_int(pr.get("number"), "pull request number", 999_999_999)
    refuse(pr.get("state") == "open", "pull request is not open")
    refuse(nested(pr, "base.repo.id", "pull request") == REPOSITORY_ID, "pull request base repository id is not trusted")
    refuse(nested(pr, "base.repo.full_name", "pull request") == REPOSITORY, "pull request base repository is not trusted")
    refuse(nested(pr, "base.ref", "pull request") == DEFAULT_BRANCH, "pull request base branch is not exact")
    current_base_sha = exact_sha1(nested(pr, "base.sha", "pull request"), "pull request base SHA")
    if base_sha is not None:
        refuse(current_base_sha == base_sha, "pull request base SHA is stale")
    refuse(nested(pr, "head.repo.id", "pull request") == REPOSITORY_ID, "pull request head repository id is not trusted")
    refuse(nested(pr, "head.repo.full_name", "pull request") == REPOSITORY, "pull request head is not in the trusted repository")
    refuse(nested(pr, "head.sha", "pull request") == head_sha, "pull request head SHA is stale")
    refuse(pr.get("author_association") in ("OWNER", "MEMBER", "COLLABORATOR"), "pull request author association is not trusted")
    return number


def paginated_array(api: Any, path: str, label: str, maximum_pages: int = 10) -> list[Any]:
    values: list[Any] = []
    for page in range(1, maximum_pages + 1):
        current = sequence(api.get(path, {"per_page": 100, "page": page}), f"{label} page {page}")
        values.extend(current)
        refuse(len(values) <= maximum_pages * 100, f"{label} is too large")
        if len(current) < 100:
            return values
    raise AttestorError(f"{label} exceeded the bounded pagination limit")


def resolve_exact_pr(api: Any, head_sha: str, base_sha: str | None = None) -> tuple[int, Mapping[str, Any]]:
    associated = paginated_array(api, f"/commits/{head_sha}/pulls", "associated pull requests")
    matches: list[tuple[int, Mapping[str, Any]]] = []
    for candidate_value in associated:
        try:
            candidate = mapping(candidate_value, "associated pull request")
            number = validate_pr(candidate, head_sha, base_sha)
        except AttestorError:
            continue
        matches.append((number, candidate))
    refuse(len(matches) == 1, "run head is not bound to exactly one current same-repository pull request")
    number, _ = matches[0]
    current = mapping(api.get(f"/pulls/{number}"), "current pull request")
    refuse(validate_pr(current, head_sha, base_sha) == number, "current pull request number changed")
    return number, current


def commit_tree_sha(api: Any, commit_sha: str, label: str) -> str:
    commit = mapping(api.get(f"/git/commits/{commit_sha}"), f"{label} commit")
    refuse(commit.get("sha") == commit_sha, f"{label} commit response identity changed")
    return exact_sha1(nested(commit, "tree.sha", f"{label} commit"), f"{label} tree SHA")


def current_default_sha(api: Any) -> str:
    ref = mapping(api.get(f"/git/ref/heads/{DEFAULT_BRANCH}"), "default branch ref")
    refuse(ref.get("ref") == f"refs/heads/{DEFAULT_BRANCH}", "default branch ref identity is not exact")
    refuse(nested(ref, "object.type", "default branch ref") == "commit", "default branch does not point to a commit")
    return exact_sha1(nested(ref, "object.sha", "default branch ref"), "default branch SHA")


def validate_run_jobs(api: Any, run_id: int, head_sha: str) -> None:
    document = mapping(api.get(f"/actions/runs/{run_id}/jobs", {"filter": "latest", "per_page": 100}), "workflow jobs")
    jobs = sequence(document.get("jobs"), "workflow jobs.jobs")
    refuse(document.get("total_count") == len(jobs) and len(jobs) == len(REQUIRED_JOB_STEPS), "workflow run does not contain the exact two jobs")
    by_name: dict[str, list[Mapping[str, Any]]] = {}
    for job_value in jobs:
        job = mapping(job_value, "workflow job")
        name = job.get("name")
        refuse(isinstance(name, str), "workflow job name is malformed")
        by_name.setdefault(name, []).append(job)
    refuse(set(by_name) == set(REQUIRED_JOB_STEPS), "workflow run job identities are not exact")
    for name, required_steps in REQUIRED_JOB_STEPS.items():
        refuse(len(by_name[name]) == 1, f"workflow job {name} is duplicated")
        job = by_name[name][0]
        refuse(job.get("conclusion") == "success", f"workflow job {name} did not succeed")
        refuse(job.get("head_sha") == head_sha, f"workflow job {name} is not bound to the exact head")
        refuse(job.get("run_id") == run_id, f"workflow job {name} belongs to another run")
        steps = sequence(job.get("steps"), f"workflow job {name} steps")
        for required_step in required_steps:
            matches = [step for step in steps if isinstance(step, dict) and step.get("name") == required_step]
            refuse(len(matches) == 1 and matches[0].get("conclusion") == "success", f"required workflow step did not pass exactly once: {name} / {required_step}")


def checks_are_exact(document_value: Any, head_sha: str) -> bool:
    document = mapping(document_value, "check runs")
    checks = sequence(document.get("check_runs"), "check runs.check_runs")
    if document.get("total_count") != len(checks) or len(checks) > 100:
        return False
    for required_name, required_app in REQUIRED_CHECKS:
        same_name = [check for check in checks if isinstance(check, dict) and check.get("name") == required_name]
        if len(same_name) != 1:
            return False
        check = same_name[0]
        app = check.get("app")
        if not isinstance(app, dict) or app.get("id") != required_app:
            return False
        if check.get("head_sha") != head_sha or check.get("status") != "completed" or check.get("conclusion") != "success":
            return False
    return True


def wait_for_required_checks(api: Any, head_sha: str, attempts: int, delay_seconds: float) -> None:
    for attempt in range(attempts):
        document = api.get(f"/commits/{head_sha}/check-runs", {"filter": "latest", "per_page": 100})
        if checks_are_exact(document, head_sha):
            return
        if attempt + 1 < attempts:
            time.sleep(delay_seconds)
    raise AttestorError("required exact-name, exact-App checks did not all succeed")


@dataclass(frozen=True)
class AutomaticEvidence:
    run_id: int
    run_url: str
    pull_request: int
    head_sha: str
    head_tree: str
    default_sha: str
    default_tree: str

    def outputs(self) -> dict[str, str]:
        return {
            "run_id": str(self.run_id),
            "run_url": self.run_url,
            "pull_request": str(self.pull_request),
            "head_sha": self.head_sha,
            "head_tree": self.head_tree,
            "default_sha": self.default_sha,
            "default_tree": self.default_tree,
        }


def validate_automatic(event: Mapping[str, Any], api: Any, attempts: int = 1, delay_seconds: float = 0.0) -> AutomaticEvidence:
    repository_from_event(event)
    refuse(event.get("action") == "completed", "workflow_run action is not completed")
    event_run = mapping(event.get("workflow_run"), "event workflow run")
    run_id = exact_positive_int(event_run.get("id"), "workflow run id")
    head_sha = exact_sha1(event_run.get("head_sha"), "workflow run head SHA")
    refuse(event_run.get("name") == CI_WORKFLOW_NAME, "workflow run name is not exact")
    refuse(event_run.get("workflow_id") == CI_WORKFLOW_ID, "workflow run id is not the trusted CI workflow")
    refuse(event_run.get("path") == CI_WORKFLOW_PATH, "workflow run path is not exact")
    refuse(event_run.get("event") == "pull_request", "workflow run was not triggered by pull_request")
    refuse(event_run.get("status") == "completed" and event_run.get("conclusion") == "success", "workflow run did not complete successfully")
    refuse(nested(event_run, "head_repository.id", "event workflow run") == REPOSITORY_ID, "workflow run head repository id is not trusted")
    refuse(nested(event_run, "head_repository.full_name", "event workflow run") == REPOSITORY, "workflow run head repository is not trusted")

    run = mapping(api.get(f"/actions/runs/{run_id}"), "current workflow run")
    refuse(run.get("id") == run_id, "workflow run API id changed")
    refuse(run.get("name") == CI_WORKFLOW_NAME and run.get("workflow_id") == CI_WORKFLOW_ID, "workflow run API identity is not exact")
    refuse(run.get("path") == CI_WORKFLOW_PATH, "workflow run API path is not exact")
    refuse(run.get("event") == "pull_request", "workflow run API event is not pull_request")
    refuse(run.get("status") == "completed" and run.get("conclusion") == "success", "workflow run API result is not successful")
    refuse(run.get("head_sha") == head_sha, "workflow run API head SHA changed")
    refuse(nested(run, "repository.id", "current workflow run") == REPOSITORY_ID, "workflow run repository id is not trusted")
    refuse(nested(run, "repository.full_name", "current workflow run") == REPOSITORY, "workflow run repository is not trusted")
    refuse(nested(run, "head_repository.id", "current workflow run") == REPOSITORY_ID, "workflow run head repository id changed")
    refuse(nested(run, "head_repository.full_name", "current workflow run") == REPOSITORY, "workflow run head repository changed")
    run_url = run.get("html_url")
    refuse(isinstance(run_url, str) and run_url == f"https://github.com/{REPOSITORY}/actions/runs/{run_id}", "workflow run URL is not exact")

    default_sha = current_default_sha(api)
    refuse(default_sha != head_sha, "pull request head unexpectedly equals the default branch")
    pull_request, _ = resolve_exact_pr(api, head_sha, default_sha)
    head_tree = commit_tree_sha(api, head_sha, "head")
    default_tree = commit_tree_sha(api, default_sha, "default")
    default_tree_document = api.get(f"/git/trees/{default_tree}", {"recursive": 1})
    head_tree_document = api.get(f"/git/trees/{head_tree}", {"recursive": 1})
    refuse(mapping(default_tree_document, "default tree response").get("sha") == default_tree, "default tree response identity changed")
    refuse(mapping(head_tree_document, "head tree response").get("sha") == head_tree, "head tree response identity changed")
    changes = compare_frozen_trees(default_tree_document, head_tree_document)
    changes.extend(changed_go_generate_paths(api, default_tree_document, head_tree_document))
    changes = sorted(set(changes))
    refuse(not changes, "pull request changes frozen trust roots: " + ", ".join(changes[:12]))
    validate_run_jobs(api, run_id, head_sha)
    wait_for_required_checks(api, head_sha, attempts, delay_seconds)

    refuse(current_default_sha(api) == default_sha, "default branch moved during automatic validation")
    final_pull_request, _ = resolve_exact_pr(api, head_sha, default_sha)
    refuse(final_pull_request == pull_request, "pull request identity changed before validation completed")
    refuse(commit_tree_sha(api, head_sha, "final head") == head_tree, "head tree identity changed")
    refuse(commit_tree_sha(api, default_sha, "final default") == default_tree, "default tree identity changed")
    refuse(current_default_sha(api) == default_sha, "default branch moved before automatic evidence was emitted")
    return AutomaticEvidence(run_id, run_url, pull_request, head_sha, head_tree, default_sha, default_tree)


def harness_bytes(
    api: Any, entries: Mapping[str, tuple[str, str, str]], path: str
) -> bytes:
    signature = entries[path]
    content = blob_bytes(api, signature[2], f"reviewed harness blob {path}")
    refuse(0 < len(content) <= 500_000, f"{path} content has an unsafe size")
    return content


@dataclass(frozen=True)
class ManualEvidence:
    pull_request: int
    head_sha: str
    head_tree: str
    default_sha: str
    default_tree: str
    trusted_branch: str
    host_sha256: str
    guest_sha256: str
    sarif_checker_sha256: str

    def outputs(self) -> dict[str, str]:
        return {
            "pull_request": str(self.pull_request),
            "head_sha": self.head_sha,
            "head_tree": self.head_tree,
            "default_sha": self.default_sha,
            "default_tree": self.default_tree,
            "trusted_branch": self.trusted_branch,
            "host_sha256": self.host_sha256,
            "guest_sha256": self.guest_sha256,
            "sarif_checker_sha256": self.sarif_checker_sha256,
        }


def matching_exact_refs(api: Any, trusted_branch: str, trusted_ref: str, label: str) -> list[Mapping[str, Any]]:
    existing = sequence(
        api.get(f"/git/matching-refs/heads/{trusted_branch}", {"per_page": 100, "page": 1}),
        label,
    )
    refuse(len(existing) < 100, f"{label} exceed one complete bounded page")
    return [item for item in existing if isinstance(item, dict) and item.get("ref") == trusted_ref]


def rollback_created_ref(api: Any, trusted_branch: str, trusted_ref: str, head_sha: str) -> None:
    exact = matching_exact_refs(api, trusted_branch, trusted_ref, "rollback matching refs")
    if not exact:
        return
    refuse(len(exact) == 1, "rollback found duplicate exact refs")
    refuse(nested(exact[0], "object.type", "rollback ref") == "commit", "rollback ref is not a commit")
    refuse(nested(exact[0], "object.sha", "rollback ref") == head_sha, "rollback ref moved")
    api.delete(f"/git/refs/heads/{trusted_branch}")
    refuse(not matching_exact_refs(api, trusted_branch, trusted_ref, "post-rollback matching refs"), "rollback did not remove the created ref")


def validate_manual_prepare(
    event: Mapping[str, Any],
    api: Any,
    actor: str,
    github_ref: str,
    github_sha: str,
    nonce: str | None = None,
) -> ManualEvidence:
    repository_from_event(event)
    refuse(event.get("action") == PROMOTION_EVENT, "repository_dispatch action is not exact")
    refuse(actor == REPOSITORY_OWNER, "manual promotion actor is not the repository owner")
    sender = mapping(event.get("sender"), "repository_dispatch sender")
    refuse(sender.get("login") == REPOSITORY_OWNER, "manual promotion sender is not the repository owner")
    refuse(github_ref == f"refs/heads/{DEFAULT_BRANCH}", "manual promotion did not load from the default branch")
    github_sha = exact_sha1(github_sha, "repository_dispatch workflow SHA")

    payload = mapping(event.get("client_payload"), "repository_dispatch payload")
    expected_keys = {"pull_request", "head_sha", "tree_sha", "vm_host_sha256", "vm_guest_sha256"}
    refuse(set(payload) == expected_keys, "repository_dispatch payload keys are not exact")
    pull_request = exact_positive_int(payload.get("pull_request"), "payload pull request", 999_999_999)
    head_sha = exact_sha1(payload.get("head_sha"), "payload head SHA")
    head_tree = exact_sha1(payload.get("tree_sha"), "payload tree SHA")
    host_sha256 = exact_sha256(payload.get("vm_host_sha256"), "payload VM host SHA-256")
    guest_sha256 = exact_sha256(payload.get("vm_guest_sha256"), "payload VM guest SHA-256")

    default_sha = current_default_sha(api)
    refuse(default_sha == github_sha, "default branch moved after repository_dispatch began")
    resolved_pull_request, _ = resolve_exact_pr(api, head_sha, default_sha)
    refuse(resolved_pull_request == pull_request, "payload pull request is not the unique exact pull request for this head")
    refuse(commit_tree_sha(api, head_sha, "manual head") == head_tree, "payload tree SHA does not match the exact commit")
    head_tree_document = api.get(f"/git/trees/{head_tree}", {"recursive": 1})
    refuse(mapping(head_tree_document, "manual head tree response").get("sha") == head_tree, "manual head tree response identity changed")
    head_entries = validated_tree(head_tree_document, "manual head tree")
    validate_required_trust_roots(head_entries, "manual head tree")
    actual_host = hashlib.sha256(harness_bytes(api, head_entries, VM_HOST_PATH)).hexdigest()
    actual_guest = hashlib.sha256(harness_bytes(api, head_entries, VM_GUEST_PATH)).hexdigest()
    refuse(actual_host == host_sha256, "payload VM host hash was not reviewed for this head")
    refuse(actual_guest == guest_sha256, "payload VM guest hash was not reviewed for this head")
    sarif_signature = head_entries[SARIF_CHECKER_PATH]
    sarif_checker = blob_bytes(api, sarif_signature[2], f"reviewed SARIF checker blob {SARIF_CHECKER_PATH}")
    refuse(0 < len(sarif_checker) <= 500_000, "reviewed SARIF checker has an unsafe size")
    sarif_checker_sha256 = hashlib.sha256(sarif_checker).hexdigest()

    default_tree = commit_tree_sha(api, default_sha, "manual default")
    nonce = nonce or secrets.token_hex(16)
    refuse(isinstance(nonce, str) and re.fullmatch(r"[0-9a-f]{32}", nonce) is not None, "trusted ref nonce is malformed")
    trusted_branch = f"ci/trusted-pr-{pull_request}-{head_sha}-{nonce}"
    refuse(SAFE_REF_RE.fullmatch(trusted_branch) is not None, "trusted branch name is malformed")
    trusted_ref = f"refs/heads/{trusted_branch}"
    exact_existing = matching_exact_refs(api, trusted_branch, trusted_ref, "matching trusted refs")
    refuse(not exact_existing, "one-time trusted ref already exists")
    try:
        api.post("/git/refs", {"ref": trusted_ref, "sha": head_sha})
        pinned = mapping(api.get(f"/git/ref/heads/{trusted_branch}"), "created trusted ref")
        refuse(pinned.get("ref") == trusted_ref, "created trusted ref name changed")
        refuse(nested(pinned, "object.type", "created trusted ref") == "commit", "created trusted ref is not a commit")
        refuse(nested(pinned, "object.sha", "created trusted ref") == head_sha, "created trusted ref did not pin the expected SHA")
        final_pull_request, _ = resolve_exact_pr(api, head_sha, default_sha)
        refuse(final_pull_request == pull_request, "manual pull request identity changed while the trusted ref was created")
        refuse(current_default_sha(api) == default_sha, "default branch moved while the trusted ref was created")
    except Exception:
        rollback_created_ref(api, trusted_branch, trusted_ref, head_sha)
        raise
    return ManualEvidence(
        pull_request,
        head_sha,
        head_tree,
        default_sha,
        default_tree,
        trusted_branch,
        host_sha256,
        guest_sha256,
        sarif_checker_sha256,
    )


def write_outputs(path: str, values: Mapping[str, str]) -> None:
    candidate = Path(path)
    refuse(candidate.is_absolute(), "GITHUB_OUTPUT is not absolute")
    with candidate.open("a", encoding="utf-8", newline="\n") as output:
        for key, value in values.items():
            refuse(re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key) is not None, "output key is malformed")
            refuse(isinstance(value, str) and value and "\n" not in value and "\r" not in value, f"output {key} is malformed")
            output.write(f"{key}={value}\n")


def run_automatic() -> None:
    event = load_json_file(os.environ.get("GITHUB_EVENT_PATH", ""), "GitHub event")
    api = GitHubAPI(os.environ.get("GITHUB_TOKEN", ""))
    evidence = validate_automatic(event, api, attempts=31, delay_seconds=10.0)
    write_outputs(os.environ.get("GITHUB_OUTPUT", ""), evidence.outputs())
    print(f"Validated automatic exact-SHA evidence for {evidence.head_sha}")


def run_manual_prepare() -> None:
    event = load_json_file(os.environ.get("GITHUB_EVENT_PATH", ""), "GitHub event")
    api = GitHubAPI(os.environ.get("GITHUB_TOKEN", ""))
    evidence = validate_manual_prepare(
        event,
        api,
        os.environ.get("GITHUB_ACTOR", ""),
        os.environ.get("GITHUB_REF", ""),
        os.environ.get("GITHUB_SHA", ""),
    )
    write_outputs(os.environ.get("GITHUB_OUTPUT", ""), evidence.outputs())
    print(f"Created one-time trusted ref {evidence.trusted_branch}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("automatic", "manual-prepare"))
    arguments = parser.parse_args()
    try:
        if arguments.command == "automatic":
            run_automatic()
        else:
            run_manual_prepare()
    except (AttestorError, OSError) as error:
        print(f"trusted attestor refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
