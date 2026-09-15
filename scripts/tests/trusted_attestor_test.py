#!/usr/bin/env python3

import base64
import copy
import hashlib
import importlib.util
import pathlib
import sys
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "trusted_attestor.py"
SPEC = importlib.util.spec_from_file_location("trusted_attestor", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
attestor = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = attestor
SPEC.loader.exec_module(attestor)


HEAD = "a" * 40
HEAD_TREE = "b" * 40
DEFAULT = "c" * 40
DEFAULT_TREE = "d" * 40
MOVED = "e" * 40


class Queue:
    def __init__(self, *values):
        self.values = list(values)


class FakeAPI:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []
        self.posts = []

    def get(self, path, query=None):
        self.calls.append(("GET", path, copy.deepcopy(query)))
        key = (path, tuple(sorted((query or {}).items())))
        response_key = key if key in self.responses else path
        if response_key not in self.responses:
            raise AssertionError(f"unexpected GET {path}")
        value = self.responses[response_key]
        if isinstance(value, Queue):
            if not value.values:
                raise AssertionError(f"exhausted GET {path}")
            value = value.values.pop(0)
        return copy.deepcopy(value)

    def post(self, path, body):
        self.calls.append(("POST", path, copy.deepcopy(body)))
        self.posts.append((path, copy.deepcopy(body)))
        return copy.deepcopy(self.responses.get(("POST", path), {}))

    def delete(self, path):
        self.calls.append(("DELETE", path, None))
        return copy.deepcopy(self.responses.get(("DELETE", path)))


def object_sha(path):
    return hashlib.sha1(path.encode("utf-8"), usedforsecurity=False).hexdigest()


def git_blob_sha(data):
    object_bytes = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    return hashlib.sha1(object_bytes, usedforsecurity=False).hexdigest()


def tree(extra=None, root_sha=DEFAULT_TREE):
    paths = sorted(attestor.REQUIRED_FROZEN_PATHS | {"go.mod", "pkg/service.go"})
    entries = [
        {
            "path": path,
            "mode": "100755" if path in attestor.REQUIRED_EXECUTABLE_PATHS else "100644",
            "type": "blob",
            "sha": object_sha(path),
        }
        for path in paths
    ]
    if extra:
        entries.extend(copy.deepcopy(extra))
    return {"sha": root_sha, "truncated": False, "tree": entries}


def repository():
    return {
        "id": attestor.REPOSITORY_ID,
        "full_name": attestor.REPOSITORY,
        "default_branch": attestor.DEFAULT_BRANCH,
        "owner": {"login": attestor.REPOSITORY_OWNER},
    }


def pull_request(
    number=7,
    head=HEAD,
    state="open",
    head_repo=None,
    base="main",
    base_sha=DEFAULT,
    association="OWNER",
):
    repo = repository()
    return {
        "number": number,
        "state": state,
        "author_association": association,
        "base": {
            "ref": base,
            "sha": base_sha,
            "repo": {"id": repo["id"], "full_name": repo["full_name"]},
        },
        "head": {
            "sha": head,
            "repo": head_repo or {"id": repo["id"], "full_name": repo["full_name"]},
        },
    }


def workflow_event():
    return {
        "action": "completed",
        "repository": repository(),
        "workflow_run": {
            "id": 1234,
            "name": attestor.CI_WORKFLOW_NAME,
            "workflow_id": attestor.CI_WORKFLOW_ID,
            "path": attestor.CI_WORKFLOW_PATH,
            "event": "pull_request",
            "status": "completed",
            "conclusion": "success",
            "head_sha": HEAD,
            "head_repository": {"id": attestor.REPOSITORY_ID, "full_name": attestor.REPOSITORY},
        },
    }


def jobs():
    values = []
    for name, names in attestor.REQUIRED_JOB_STEPS.items():
        values.append(
            {
                "name": name,
                "run_id": 1234,
                "head_sha": HEAD,
                "conclusion": "success",
                "steps": [{"name": step, "conclusion": "success"} for step in names],
            }
        )
    return {"total_count": len(values), "jobs": values}


def checks():
    values = [
        {
            "name": name,
            "app": {"id": app_id},
            "head_sha": HEAD,
            "status": "completed",
            "conclusion": "success",
        }
        for name, app_id in attestor.REQUIRED_CHECKS
    ]
    return {"total_count": len(values), "check_runs": values}


def automatic_api():
    pr = pull_request()
    default_tree_document = tree(root_sha=DEFAULT_TREE)
    head_tree_document = tree(root_sha=HEAD_TREE)
    run = {
        "id": 1234,
        "name": attestor.CI_WORKFLOW_NAME,
        "workflow_id": attestor.CI_WORKFLOW_ID,
        "path": attestor.CI_WORKFLOW_PATH,
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "head_sha": HEAD,
        "html_url": f"https://github.com/{attestor.REPOSITORY}/actions/runs/1234",
        "repository": {"id": attestor.REPOSITORY_ID, "full_name": attestor.REPOSITORY},
        "head_repository": {"id": attestor.REPOSITORY_ID, "full_name": attestor.REPOSITORY},
    }
    ref = {"ref": "refs/heads/main", "object": {"type": "commit", "sha": DEFAULT}}
    return FakeAPI(
        {
            "/actions/runs/1234": run,
            f"/commits/{HEAD}/pulls": [pr],
            "/pulls/7": pr,
            "/git/ref/heads/main": ref,
            f"/git/commits/{HEAD}": {"sha": HEAD, "tree": {"sha": HEAD_TREE}},
            f"/git/commits/{DEFAULT}": {"sha": DEFAULT, "tree": {"sha": DEFAULT_TREE}},
            f"/git/trees/{HEAD_TREE}": head_tree_document,
            f"/git/trees/{DEFAULT_TREE}": default_tree_document,
            "/actions/runs/1234/jobs": jobs(),
            f"/commits/{HEAD}/check-runs": checks(),
        }
    )


class FrozenTreeTests(unittest.TestCase):
    def test_equal_complete_frozen_trees_pass(self):
        self.assertEqual(attestor.compare_frozen_trees(tree(), tree()), [])

    def test_add_delete_content_mode_and_type_changes_are_frozen(self):
        cases = []
        added = tree([{"path": ".github/workflows/.evil.yml", "mode": "100644", "type": "blob", "sha": "1" * 40}])
        cases.append((tree(), added, ".github/workflows/.evil.yml"))
        deleted = tree()
        deleted["tree"] = [entry for entry in deleted["tree"] if entry["path"] != "security/govuln-allowlist.txt"]
        with self.assertRaises(attestor.AttestorError):
            attestor.compare_frozen_trees(tree(), deleted)
        content = tree()
        next(entry for entry in content["tree"] if entry["path"] == "go.mod")["sha"] = "2" * 40
        cases.append((tree(), content, "go.mod"))
        mode = tree()
        next(entry for entry in mode["tree"] if entry["path"] == "pkg/service.go")["mode"] = "100755"
        cases.append((tree(), mode, "pkg/service.go"))
        kind = tree()
        target = next(entry for entry in kind["tree"] if entry["path"] == "pkg/service.go")
        target["mode"], target["type"] = "120000", "blob"
        cases.append((tree(), kind, "pkg/service.go"))
        for base, head, expected in cases:
            with self.subTest(expected=expected):
                self.assertIn(expected, attestor.compare_frozen_trees(base, head))

    def test_truncated_duplicate_and_missing_required_trees_refuse(self):
        truncated = tree()
        truncated["truncated"] = True
        duplicate = tree()
        duplicate["tree"].append(copy.deepcopy(duplicate["tree"][0]))
        missing = tree()
        missing["tree"] = [entry for entry in missing["tree"] if entry["path"] != ".github/workflows/trusted-attestor.yml"]
        for candidate in (truncated, duplicate, missing):
            with self.subTest(candidate=candidate):
                with self.assertRaises(attestor.AttestorError):
                    attestor.compare_frozen_trees(tree(), candidate)

    def test_invalid_mode_type_pairs_and_control_paths_refuse(self):
        malformed_entries = (
            {"path": "pkg/invalid-mode", "mode": "100700", "type": "blob", "sha": "7" * 40},
            {"path": "pkg/invalid-kind", "mode": "100644", "type": "tree", "sha": "8" * 40},
        )
        for entry in malformed_entries:
            with self.subTest(entry=entry):
                with self.assertRaises(attestor.AttestorError):
                    attestor.compare_frozen_trees(tree(), tree([entry]))

        for codepoint in (*range(0x20), *range(0x7F, 0xA0)):
            entry = {
                "path": f"pkg/bad{chr(codepoint)}name",
                "mode": "100644",
                "type": "blob",
                "sha": "9" * 40,
            }
            with self.subTest(control=codepoint):
                with self.assertRaises(attestor.AttestorError):
                    attestor.compare_frozen_trees(tree(), tree([entry]))

    def test_all_legal_mode_type_pairs_are_accepted(self):
        entries = [
            {
                "path": f"objects/{index}",
                "mode": mode,
                "type": kind,
                "sha": f"{index + 1:x}" * 40,
            }
            for index, (mode, kind) in enumerate(sorted(attestor.VALID_TREE_MODE_TYPES))
        ]
        self.assertEqual(
            set(attestor.validated_tree({"truncated": False, "tree": entries}, "legal tree").values()),
            {(mode, kind, f"{index + 1:x}" * 40) for index, (mode, kind) in enumerate(sorted(attestor.VALID_TREE_MODE_TYPES))},
        )

    def test_required_trust_root_mode_is_exact(self):
        candidate = tree()
        target = next(entry for entry in candidate["tree"] if entry["path"] == "scripts/trusted_attestor.py")
        target["mode"] = "100644"
        with self.assertRaises(attestor.AttestorError):
            attestor.compare_frozen_trees(tree(), candidate)

    def test_prefix_boundary_and_global_test_fixture_rules(self):
        self.assertFalse(attestor.is_frozen_path("scripts-evil/ordinary.txt"))
        self.assertTrue(attestor.is_frozen_path("pkg/nested/policy_test.go"))
        self.assertTrue(attestor.is_frozen_path("pkg/testdata/config.json"))
        self.assertTrue(attestor.is_frozen_path("nested/go.mod"))

    def test_ordinary_file_add_and_delete_are_not_frozen(self):
        added = tree([{"path": "pkg/new.go", "mode": "100644", "type": "blob", "sha": "3" * 40}])
        self.assertEqual(attestor.compare_frozen_trees(tree(), added), [])
        self.assertEqual(attestor.compare_frozen_trees(added, tree()), [])

    def test_executable_symlink_and_gitlink_additions_are_frozen(self):
        candidates = (
            {"path": "pkg/tool", "mode": "100755", "type": "blob", "sha": "4" * 40},
            {"path": "pkg/link", "mode": "120000", "type": "blob", "sha": "5" * 40},
            {"path": "pkg/module", "mode": "160000", "type": "commit", "sha": "6" * 40},
        )
        for entry in candidates:
            with self.subTest(entry=entry):
                changed = attestor.compare_frozen_trees(tree(), tree([entry]))
                self.assertEqual(changed, [entry["path"]])

    def test_new_go_generate_directive_is_frozen(self):
        base = tree()
        head = tree()
        base_content = b"package pkg\n"
        head_content = b"package pkg\n//go:generate sh attack.sh\n"
        base_entry = next(entry for entry in base["tree"] if entry["path"] == "pkg/service.go")
        head_entry = next(entry for entry in head["tree"] if entry["path"] == "pkg/service.go")
        base_entry["sha"] = git_blob_sha(base_content)
        head_entry["sha"] = git_blob_sha(head_content)
        api = FakeAPI(
            {
                f"/git/blobs/{base_entry['sha']}": blob(base_entry["sha"], base_content),
                f"/git/blobs/{head_entry['sha']}": blob(head_entry["sha"], head_content),
            }
        )
        self.assertEqual(attestor.changed_go_generate_paths(api, base, head), ["pkg/service.go"])

    def test_blob_declared_size_and_git_object_identity_refuse(self):
        content = b"good"
        sha = git_blob_sha(content)
        wrong_size = blob(sha, content)
        wrong_size["size"] += 1
        wrong_content = blob(sha, b"evil")
        for document in (wrong_size, wrong_content):
            api = FakeAPI({f"/git/blobs/{sha}": document})
            with self.subTest(document=document):
                with self.assertRaises(attestor.AttestorError):
                    attestor.blob_bytes(api, sha, "test blob")


class AutomaticValidationTests(unittest.TestCase):
    def test_success_is_read_only_and_returns_exact_evidence(self):
        api = automatic_api()
        result = attestor.validate_automatic(workflow_event(), api)
        self.assertEqual((result.pull_request, result.head_sha, result.head_tree), (7, HEAD, HEAD_TREE))
        self.assertEqual(api.posts, [])

    def test_wrong_run_path_refuses(self):
        event = workflow_event()
        event["workflow_run"]["path"] = ".github/workflows/evil.yml"
        with self.assertRaises(attestor.AttestorError):
            attestor.validate_automatic(event, automatic_api())

    def test_wrong_tree_response_identity_refuses(self):
        api = automatic_api()
        api.responses[f"/git/trees/{HEAD_TREE}"]["sha"] = MOVED
        with self.assertRaises(attestor.AttestorError):
            attestor.validate_automatic(workflow_event(), api)

    def test_wrong_commit_response_identity_refuses(self):
        api = automatic_api()
        api.responses[f"/git/commits/{HEAD}"]["sha"] = MOVED
        with self.assertRaises(attestor.AttestorError):
            attestor.validate_automatic(workflow_event(), api)

    def test_zero_or_two_current_prs_refuse(self):
        for associated in ([], [pull_request(7), pull_request(8)]):
            api = automatic_api()
            api.responses[f"/commits/{HEAD}/pulls"] = associated
            with self.subTest(count=len(associated)):
                with self.assertRaises(attestor.AttestorError):
                    attestor.validate_automatic(workflow_event(), api)

    def test_duplicate_same_pr_entry_refuses(self):
        api = automatic_api()
        api.responses[f"/commits/{HEAD}/pulls"] = [pull_request(7), pull_request(7)]
        with self.assertRaises(attestor.AttestorError):
            attestor.validate_automatic(workflow_event(), api)

    def test_second_valid_pr_on_next_full_page_refuses(self):
        api = automatic_api()
        invalid = [pull_request(number=1000 + index, state="closed") for index in range(99)]
        api.responses[(f"/commits/{HEAD}/pulls", (("page", 1), ("per_page", 100)))] = [pull_request(7), *invalid]
        api.responses[(f"/commits/{HEAD}/pulls", (("page", 2), ("per_page", 100)))] = [pull_request(8)]
        with self.assertRaises(attestor.AttestorError):
            attestor.validate_automatic(workflow_event(), api)

    def test_second_valid_pr_appearing_during_validation_refuses(self):
        api = automatic_api()
        first_page = (f"/commits/{HEAD}/pulls", (("page", 1), ("per_page", 100)))
        api.responses[first_page] = Queue([pull_request(7)], [pull_request(7), pull_request(8)])
        with self.assertRaises(attestor.AttestorError):
            attestor.validate_automatic(workflow_event(), api)

    def test_fork_wrong_base_closed_and_stale_prs_refuse(self):
        variants = (
            pull_request(head_repo={"id": 99, "full_name": "attacker/fork"}),
            pull_request(base="release"),
            pull_request(state="closed"),
            pull_request(head=MOVED),
        )
        for candidate in variants:
            api = automatic_api()
            api.responses[f"/commits/{HEAD}/pulls"] = [candidate]
            with self.subTest(candidate=candidate):
                with self.assertRaises(attestor.AttestorError):
                    attestor.validate_automatic(workflow_event(), api)

    def test_initial_and_final_base_sha_mismatches_refuse(self):
        api = automatic_api()
        api.responses[f"/commits/{HEAD}/pulls"] = [pull_request(base_sha=MOVED)]
        with self.assertRaises(attestor.AttestorError):
            attestor.validate_automatic(workflow_event(), api)

        api = automatic_api()
        api.responses["/pulls/7"] = Queue(pull_request(), pull_request(base_sha=MOVED))
        with self.assertRaises(attestor.AttestorError):
            attestor.validate_automatic(workflow_event(), api)

    def test_wrong_app_duplicate_missing_or_failed_check_refuses(self):
        mutations = []
        wrong_app = checks()
        wrong_app["check_runs"][0]["app"]["id"] = 1
        mutations.append(wrong_app)
        duplicate = checks()
        duplicate["check_runs"].append(copy.deepcopy(duplicate["check_runs"][0]))
        duplicate["total_count"] += 1
        mutations.append(duplicate)
        missing = checks()
        missing["check_runs"].pop()
        missing["total_count"] -= 1
        mutations.append(missing)
        failed = checks()
        failed["check_runs"][1]["conclusion"] = "failure"
        mutations.append(failed)
        for document in mutations:
            api = automatic_api()
            api.responses[f"/commits/{HEAD}/check-runs"] = document
            with self.subTest(document=document):
                with self.assertRaises(attestor.AttestorError):
                    attestor.validate_automatic(workflow_event(), api)
            self.assertEqual(api.posts, [])

    def test_stale_final_head_and_moved_default_refuse(self):
        api = automatic_api()
        api.responses["/pulls/7"] = Queue(pull_request(), pull_request(head=MOVED))
        with self.assertRaises(attestor.AttestorError):
            attestor.validate_automatic(workflow_event(), api)
        api = automatic_api()
        good_ref = api.responses["/git/ref/heads/main"]
        moved_ref = {"ref": "refs/heads/main", "object": {"type": "commit", "sha": MOVED}}
        api.responses["/git/ref/heads/main"] = Queue(good_ref, moved_ref)
        with self.assertRaises(attestor.AttestorError):
            attestor.validate_automatic(workflow_event(), api)


def promotion_event(host, guest):
    return {
        "action": attestor.PROMOTION_EVENT,
        "repository": repository(),
        "sender": {"login": attestor.REPOSITORY_OWNER},
        "client_payload": {
            "pull_request": 7,
            "head_sha": HEAD,
            "tree_sha": HEAD_TREE,
            "vm_host_sha256": hashlib.sha256(host).hexdigest(),
            "vm_guest_sha256": hashlib.sha256(guest).hexdigest(),
        },
    }


def blob(sha, data):
    return {
        "sha": sha,
        "encoding": "base64",
        "size": len(data),
        "content": base64.b64encode(data).decode(),
    }


NONCE = "1" * 32


def manual_api(host=b"host", guest=b"guest", existing=None, head_tree_document=None, sarif_checker=b"checker"):
    pr = pull_request()
    ref = {"ref": "refs/heads/main", "object": {"type": "commit", "sha": DEFAULT}}
    branch = f"ci/trusted-pr-7-{HEAD}-{NONCE}"
    trusted = f"refs/heads/{branch}"
    head_tree_document = copy.deepcopy(head_tree_document or tree(root_sha=HEAD_TREE))
    by_path = {
        entry.get("path"): entry
        for entry in head_tree_document.get("tree", [])
        if isinstance(entry, dict)
    }
    for path, data in (
        (attestor.VM_HOST_PATH, host),
        (attestor.VM_GUEST_PATH, guest),
        (attestor.SARIF_CHECKER_PATH, sarif_checker),
    ):
        if path in by_path:
            by_path[path]["sha"] = git_blob_sha(data)
    host_blob_sha = by_path.get(attestor.VM_HOST_PATH, {}).get("sha", git_blob_sha(host))
    guest_blob_sha = by_path.get(attestor.VM_GUEST_PATH, {}).get("sha", git_blob_sha(guest))
    sarif_blob_sha = by_path.get(attestor.SARIF_CHECKER_PATH, {}).get("sha", git_blob_sha(sarif_checker))
    return FakeAPI(
        {
            "/pulls/7": pr,
            f"/commits/{HEAD}/pulls": [pr],
            f"/git/commits/{HEAD}": {"sha": HEAD, "tree": {"sha": HEAD_TREE}},
            f"/git/trees/{HEAD_TREE}": head_tree_document,
            f"/git/blobs/{host_blob_sha}": blob(host_blob_sha, host),
            f"/git/blobs/{guest_blob_sha}": blob(guest_blob_sha, guest),
            f"/git/blobs/{sarif_blob_sha}": blob(sarif_blob_sha, sarif_checker),
            "/git/ref/heads/main": ref,
            f"/git/commits/{DEFAULT}": {"sha": DEFAULT, "tree": {"sha": DEFAULT_TREE}},
            f"/git/matching-refs/heads/{branch}": existing or [],
            f"/git/ref/heads/{branch}": {
                "ref": trusted,
                "object": {"type": "commit", "sha": HEAD},
            },
            ("POST", "/git/refs"): {"ref": trusted, "object": {"sha": HEAD}},
        }
    )


class ManualPreparationTests(unittest.TestCase):
    def test_owner_can_pin_exact_reviewed_ref(self):
        host, guest, sarif_checker = b"host", b"guest", b"checker"
        api = manual_api(host, guest, sarif_checker=sarif_checker)
        result = attestor.validate_manual_prepare(
            promotion_event(host, guest), api, attestor.REPOSITORY_OWNER, "refs/heads/main", DEFAULT, NONCE
        )
        self.assertEqual(result.trusted_branch, f"ci/trusted-pr-7-{HEAD}-{NONCE}")
        self.assertEqual(result.sarif_checker_sha256, hashlib.sha256(sarif_checker).hexdigest())
        self.assertEqual(result.outputs()["sarif_checker_sha256"], hashlib.sha256(sarif_checker).hexdigest())
        self.assertEqual(api.posts, [("/git/refs", {"ref": f"refs/heads/ci/trusted-pr-7-{HEAD}-{NONCE}", "sha": HEAD})])
        self.assertIn(("GET", f"/git/trees/{HEAD_TREE}", {"recursive": 1}), api.calls)
        self.assertIn(("GET", f"/git/blobs/{git_blob_sha(host)}", None), api.calls)
        self.assertIn(("GET", f"/git/blobs/{git_blob_sha(sarif_checker)}", None), api.calls)
        self.assertFalse(any(call[1].startswith("/contents/") for call in api.calls if call[0] == "GET"))

    def test_sarif_checker_blob_identity_and_size_refuse_without_write(self):
        host, guest, sarif_checker = b"host", b"guest", b"checker"
        sarif_blob_path = f"/git/blobs/{git_blob_sha(sarif_checker)}"
        mutations = (
            lambda document: document.update({"sha": MOVED}),
            lambda document: document.update({"size": len(sarif_checker) + 1}),
        )
        for mutate in mutations:
            api = manual_api(host, guest, sarif_checker=sarif_checker)
            mutate(api.responses[sarif_blob_path])
            with self.subTest(document=api.responses[sarif_blob_path]):
                with self.assertRaises(attestor.AttestorError):
                    attestor.validate_manual_prepare(
                        promotion_event(host, guest),
                        api,
                        attestor.REPOSITORY_OWNER,
                        "refs/heads/main",
                        DEFAULT,
                        NONCE,
                    )
                self.assertEqual(api.posts, [])

    def test_non_owner_and_unreviewed_hash_refuse_without_write(self):
        host, guest = b"host", b"guest"
        api = manual_api(host, guest)
        with self.assertRaises(attestor.AttestorError):
            attestor.validate_manual_prepare(promotion_event(host, guest), api, "attacker", "refs/heads/main", DEFAULT, NONCE)
        self.assertEqual(api.posts, [])
        api = manual_api(host, guest)
        event = promotion_event(host, guest)
        event["client_payload"]["vm_host_sha256"] = "0" * 64
        with self.assertRaises(attestor.AttestorError):
            attestor.validate_manual_prepare(event, api, attestor.REPOSITORY_OWNER, "refs/heads/main", DEFAULT, NONCE)
        self.assertEqual(api.posts, [])

    def test_existing_one_time_ref_refuses_without_write(self):
        host, guest = b"host", b"guest"
        existing = [{"ref": f"refs/heads/ci/trusted-pr-7-{HEAD}-{NONCE}", "object": {"type": "commit", "sha": HEAD}}]
        api = manual_api(host, guest, existing)
        with self.assertRaises(attestor.AttestorError):
            attestor.validate_manual_prepare(
                promotion_event(host, guest), api, attestor.REPOSITORY_OWNER, "refs/heads/main", DEFAULT, NONCE
            )
        self.assertEqual(api.posts, [])

    def test_manual_requires_payload_pr_to_be_the_unique_exact_match(self):
        host, guest = b"host", b"guest"
        for associated in ([pull_request(7), pull_request(8)], [pull_request(8)]):
            api = manual_api(host, guest)
            api.responses[f"/commits/{HEAD}/pulls"] = associated
            api.responses["/pulls/8"] = pull_request(8)
            with self.subTest(associated=associated):
                with self.assertRaises(attestor.AttestorError):
                    attestor.validate_manual_prepare(
                        promotion_event(host, guest),
                        api,
                        attestor.REPOSITORY_OWNER,
                        "refs/heads/main",
                        DEFAULT,
                        NONCE,
                    )
                self.assertEqual(api.posts, [])

    def test_second_pr_during_ref_creation_refuses_and_rolls_back(self):
        host, guest = b"host", b"guest"
        api = manual_api(host, guest)
        branch = f"ci/trusted-pr-7-{HEAD}-{NONCE}"
        trusted_ref = f"refs/heads/{branch}"
        exact_ref = {"ref": trusted_ref, "object": {"type": "commit", "sha": HEAD}}
        api.responses[f"/commits/{HEAD}/pulls"] = Queue(
            [pull_request(7)],
            [pull_request(7), pull_request(8)],
        )
        api.responses[f"/git/matching-refs/heads/{branch}"] = Queue([], [exact_ref], [])
        with self.assertRaises(attestor.AttestorError):
            attestor.validate_manual_prepare(
                promotion_event(host, guest),
                api,
                attestor.REPOSITORY_OWNER,
                "refs/heads/main",
                DEFAULT,
                NONCE,
            )
        self.assertEqual(api.posts, [("/git/refs", {"ref": trusted_ref, "sha": HEAD})])
        self.assertIn(("DELETE", f"/git/refs/heads/{branch}", None), api.calls)

    def test_manual_tree_identity_completeness_and_required_modes_refuse(self):
        host, guest = b"host", b"guest"
        wrong_root = tree(root_sha=MOVED)
        truncated = tree(root_sha=HEAD_TREE)
        truncated["truncated"] = True
        missing = tree(root_sha=HEAD_TREE)
        missing["tree"] = [entry for entry in missing["tree"] if entry["path"] != attestor.VM_HOST_PATH]
        wrong_mode = tree(root_sha=HEAD_TREE)
        next(entry for entry in wrong_mode["tree"] if entry["path"] == attestor.VM_HOST_PATH)["mode"] = "100644"
        symlink = tree(root_sha=HEAD_TREE)
        next(entry for entry in symlink["tree"] if entry["path"] == attestor.VM_HOST_PATH)["mode"] = "120000"
        wrong_type = tree(root_sha=HEAD_TREE)
        wrong_type_entry = next(entry for entry in wrong_type["tree"] if entry["path"] == attestor.VM_HOST_PATH)
        wrong_type_entry["mode"], wrong_type_entry["type"] = "040000", "tree"
        for candidate in (wrong_root, truncated, missing, wrong_mode, symlink, wrong_type):
            api = manual_api(host, guest, head_tree_document=candidate)
            with self.subTest(candidate=candidate):
                with self.assertRaises(attestor.AttestorError):
                    attestor.validate_manual_prepare(
                        promotion_event(host, guest),
                        api,
                        attestor.REPOSITORY_OWNER,
                        "refs/heads/main",
                        DEFAULT,
                        NONCE,
                    )
                self.assertEqual(api.posts, [])

    def test_manual_invalid_harness_base64_refuses_without_write(self):
        host, guest = b"host", b"guest"
        api = manual_api(host, guest)
        api.responses[f"/git/blobs/{git_blob_sha(host)}"]["content"] = "not!base64"
        with self.assertRaises(attestor.AttestorError):
            attestor.validate_manual_prepare(
                promotion_event(host, guest),
                api,
                attestor.REPOSITORY_OWNER,
                "refs/heads/main",
                DEFAULT,
                NONCE,
            )
        self.assertEqual(api.posts, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
