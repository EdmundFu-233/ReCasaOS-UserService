# Independent exact-SHA attestation

The required status `ReCasaOS-UserService / trusted exact-SHA` is published
only with an installation token from a dedicated GitHub App. Pull-request
workflows use the GitHub Actions App and cannot impersonate this App identity.
The repository must bind the required status to the dedicated App ID, not only
to its context string.

## App and environment boundary

Create a private GitHub App owned by `EdmundFu-233` and install it only on the
repository whose numeric ID is `1341287306` (`ReCasaOS-UserService`). Grant
only these repository permissions:

- Actions: read;
- Contents: read;
- Pull requests: read; and
- Commit statuses: read and write.

Metadata read access is implicit. Do not grant Checks write, Contents write,
Administration, Workflows, Secrets, OIDC, or organization permissions.

Create the protected environment `trusted-attestor` with no wait timer, no
self-review bypass, custom deployment branches enabled, and one exact branch
policy for `main`. Disable the UI option that permits administrators to bypass
environment protection. Store:

- environment secret `TRUSTED_ATTESTOR_PRIVATE_KEY`;
- environment variable `TRUSTED_ATTESTOR_APP_ID` containing the dedicated
  App's numeric ID.

The private key must never be committed, printed, copied into an issue, or
placed in a repository-level secret. Both publisher jobs have `permissions:
{}`, use the protected environment, never check out pull-request code, and
mint a repository-scoped token with the pinned official token action. The
validation, promotion, QA, and cleanup jobs cannot access the environment.

## Automatic path

The default-branch `workflow_run` validator accepts only the exact `CI`
workflow and a successful pull-request run. It resolves exactly one current,
open, same-repository PR from the immutable run head. It then verifies the
current base and head, complete Git tree identities, exact CI jobs and steps,
and these current check identities:

| Check | App ID |
| --- | ---: |
| `Workflow policy` | 15368 |
| `Go 1.26.6` | 15368 |
| `Analyze Go` | 15368 |
| `CodeQL` | 57789 |

All four must be completed successfully and must occur exactly once by name.
The validator compares complete recursive Git trees and rejects truncated,
duplicate, malformed, added, removed, content-changed, mode-changed, or
type-changed frozen paths. The first policy freezes `.github`, `api`, `build`,
`codegen`, `scripts`, `security`, `vendor`, dependency and release manifests, security
documents, all Go tests and test fixtures, executable or symbolic changes, and
production Go files that add or change a `//go:generate` directive.

The remote CodeQL status remains required, but it is not accepted as the sole
proof of alert severity because a repository writer can upload replacement
SARIF for a commit. After the validator succeeds, a separate read-only job
checks out the exact validated head, runs the pinned CodeQL action with
its linked CodeQL bundle, proves the exact CLI version, uses `upload: never`
with no `security-events: write` permission, and fails on any
local SARIF result whose security score is 7.0 or higher. It uploads neither
SARIF nor a CodeQL database, explicitly disables TRAP, dependency, and overlay
database caching, and cannot access the protected environment.

The publisher runs only after that independent gate succeeds. It uses the App
token to re-read the run, exactly-one current PR, base/head identities, default
branch, and both commit trees. It publishes success only when those identities
still equal the validator's immutable evidence.

## Maintainer-reviewed promotion

A change to any frozen trust root deliberately receives no automatic trusted
status. After reviewing the exact PR commit, tree, and both VM harnesses, the
repository owner may send this event from the protected default branch:

```json
{
  "event_type": "trusted-attestor-promote",
  "client_payload": {
    "pull_request": 123,
    "head_sha": "<40-lowercase-hex>",
    "tree_sha": "<40-lowercase-hex>",
    "vm_host_sha256": "<64-lowercase-hex>",
    "vm_guest_sha256": "<64-lowercase-hex>"
  }
}
```

Obtain all values from GitHub's API and the exact reviewed blobs. Do not use a
moving branch name or a local unpushed checkout as evidence. The event payload
accepts exactly those five keys and only the repository owner may initiate it.

Promotion is ordered `prepare -> QA -> cleanup -> publish`:

1. prepare revalidates the open same-repository PR, commit tree, both
   reviewed harness hashes, and the exact SARIF-checker blob, then creates and reads back the one-time ref
   `refs/heads/ci/trusted-pr-<PR>-<full-SHA>-<32-hex-random-nonce>` after first
   proving that exact unpredictable ref is absent;
2. QA checks out only that ref with a read-only workflow token, proves its
   commit/tree/checker/harness identities, and runs workflow-policy tests, exact Go
   1.26.6 QA, the same local no-upload High-or-higher CodeQL gate, and the
   Debian 11/systemd 247 PID 1 lifecycle;
3. cleanup runs only after prepare succeeds, refuses a missing, duplicate, or
   moved prepared ref, deletes only the exact returned random ref, and proves
   it is absent; and
4. the protected App publisher revalidates the PR, default branch, commit
   trees, QA outputs, the checker and harness blobs, and ref absence before publishing.

QA receives no App credentials, secrets, OIDC, status write, or contents
write. Cleanup runs even when QA fails. A moved ref or failed deletion leaves
the required status absent.

The automatic path keeps the default-branch checker pinned to a reviewed digest.
The promotion path derives the checker digest from the owner-reviewed exact head
tree, propagates it through QA, and re-reads it before publishing. This preserves
the fail-closed gate while allowing a reviewed checker and workflow update after
the trusted context becomes required.

Upgrade a pinned CodeQL Action or bundle in three promoted changes. First, keep
the current Action and update only the checker to accept the current and proposed
exact CLI versions. Second, retain that dual-version checker while moving the
workflow to the proposed pinned Action and linked bundle. After it merges, use
an ordinary non-frozen test PR to prove the new exact CLI and raw-SARIF gate in
the default-branch workflow. Third, remove the old accepted version. Do not jump
directly from an old-only checker to a new-only checker: promotion jobs are
defined by the protected default branch and would correctly fail closed on that
incompatible transition.

## One-time bootstrap and branch protection

The first merge is a manual root-of-trust operation because the App-backed
context cannot exist before the workflow and App exist. Keep the existing
required checks and CodeQL high-or-higher ruleset active throughout bootstrap.
Those four checks are defense in depth, not the new attestor root, during this
gap.

Treat steps 1 through 5 below as one exclusive owner maintenance window. Before
step 1, inventory every actor with write or merge authority, disable concurrent
and automatic merges, and temporarily make `main` owner-only by an exact push
restriction/ruleset or by removing or downgrading every non-owner write grant.
Record the reviewed pre-merge SHA and tree. After step 1, pin the attestor merge
SHA and tree; read both back before and after every remaining bootstrap mutation.
If `main` leaves that exact reviewed identity before the new App-bound context is
required, stop on security hold and audit the intervening commits. Do not rely on
the old four checks to close this window.

Use this order:

1. merge the reviewed attestor under the existing four checks and record its
   exact merge SHA and tree;
2. allow only
   `actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1`
   in the repository's selected-actions policy;
3. create/install the minimum-permission App and configure the exact-main
   protected environment without exposing its key;
4. open an ordinary non-frozen test PR and verify that the status is attributed
   to the dedicated App on that exact head;
5. retain the four existing app-bound checks and add
   `ReCasaOS-UserService / trusted exact-SHA`, bound to the dedicated numeric
   App ID, to strict branch protection; and
6. prove the required check is strict and bound to that exact App ID, then
   restore only the reviewed collaborator/merge settings and re-read them; and
7. record settings, run, status, PR-head, merge-SHA, maintenance-window, and
   post-merge evidence in Issue #6 before closing it.

Never bind the new context before the first real App-backed status proves the
App ID and workflow path. Never substitute a `GITHUB_TOKEN` status during
bootstrap. If the App, environment, secret, action allowlist, or required check
is unavailable, the repository remains on security hold.
