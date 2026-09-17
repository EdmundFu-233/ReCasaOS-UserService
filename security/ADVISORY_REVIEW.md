# Authentication Advisory Review

Reviewed revision: `1ce4d9d` (2026-09-17), ReCasaOS-UserService `main`.
Method: source review of the fork baseline, the four inherited upstream
security merges, and the ReCasaOS hardening layers, with the cited tests
executed in CI. This record maps each known CasaOS authentication advisory
to its code, test, and deployment mitigation, or documents why it does not
apply. It contains no exploit details.

## CVE-2024-24765 / GHSA-h5gf-cmm8-cg7c — arbitrary file read via avatar path

- Upstream fix `3f4558e` (ancestor of the fork baseline `800c630`).
- The fork additionally disables every path-based image endpoint: avatar
  upload, image get/put/delete, and file-image handlers all answer
  `410 Gone` without touching the filesystem
  (`route/v1/user.go`, via `legacyImageEndpointGone`; e.g. the
  `PutUserImage`, `PostUserUploadImage`, `GetUserImage`, `DeleteUserImage`
  handlers).
- Custom per-user configuration I/O is confined with descriptor-relative
  `os.Root` operations, bounded reads, and atomic temporary-file
  publication (`pkg/userconfig/store.go`, `Read`/`openUserRoot`/
  `openExistingRegularFile`/`createTemporaryFile`/`syncRoot`).
- Tests: `TestLegacyImageHandlersFailClosedWithoutTouchingPaths`
  (`route/v1/user_auth_security_test.go`) asserts 410 responses, `no-store`
  headers, and no path reflection;
  `TestCustomConfigRouterContainsPathsAndUsesAuthenticatedIdentity`
  (`route/custom_config_security_test.go`) asserts traversal rejection and
  authenticated identity.
- Residual: none known. Custom configuration remains authenticated-only.

## CVE-2024-24766 / GHSA-c967-2652-gfjm — username enumeration, and its bypass CVE-2024-28232 / GHSA-hcw2-2r9c-gc6p

- Upstream fixes `c75063d` and `dd927fe` (ancestors of the fork baseline).
- The fork returns one uniform credential error for unknown users, wrong
  passwords, and malformed input (`service/user.go`, `AuthenticateUser`),
  and runs a dummy Argon2id verification for unknown usernames
  (`pkg/password`, `ConsumeUnknownUser`) so the missing-user path performs
  comparable key-derivation work.
- Tests cover uniform responses; timing parity between the dummy and real
  verification paths has been code-reviewed but not measured on target
  hardware, so it is a review observation rather than a tested claim.

## CVE-2024-24767 / GHSA-c69x-5xmw-v44x — unlimited login attempts

- Upstream fix `62006f6` (ancestor of the fork baseline) added a
  process-global login limiter.
- The fork replaces the single global bucket with per-username lockout
  plus process-global backstops: five consecutive failures lock the exact
  username key for fifteen minutes with a `Retry-After` hint and an audit
  event; success clears the budget; locks never extend
  (`service/session.go`, `RecordLoginFailure`/`CheckLoginLockout`; login
  and refresh backstops in `route/v1/user.go`).
- Refresh attempts carry their own per-user budget inside session issuance
  (`service/session_issue.go`).
- Tests: `TestLoginIssuesSessionAndEnforcesLockout`
  (`route/v1/user_auth_security_test.go`) proves five failures lock with
  `Retry-After` and emit failure/lockout/success audit events;
  `TestLoginLockoutLifecycle` (`service/session_test.go`) proves the
  budget, expiry, non-extension, and clearing semantics.
- Residual: a distributed attacker can still burn per-username budgets
  (targeted lockout) and aggregate CPU (Argon2) up to the global backstop;
  there is no per-IP signal because the service sits behind the gateway.

## CVE-2025-34171 / GHSA-9w9c-6cc9-mc59 — rejected CVE, root management plane scope

- The CVE identifier was rejected (reserved but not used for a disclosure).
  The associated third-party advisory describes unauthenticated file and
  debug-data exposure in the CasaOS root management plane. It has no
  UserService package mapping, and no exploit detail is recorded here.
- The fork's posture for this class: the loopback authentication bypass
  was removed from the management middleware (all requests require a
  session token), debug and avatar paths are gone, and `govulncheck` gates
  the module graph (below). No UserService code change was required.

## Dependency and supply-chain posture

- `govulncheck` runs in CI with an empty reachable-finding allowlist
  (`security/govuln-allowlist.txt`, `.github/workflows/ci.yml`).
- The selected-package boundary rejects `golang.org/x/crypto/openpgp`
  and every subpackage across Linux test, release, and tool graphs
  (`scripts/check-go-dependency-boundary.sh`, `security/DEPENDENCY_BOUNDARY.md`).
- The Go toolchain and generator inputs are pinned (`go.mod`,
  `scripts/generate-api.sh`); `go mod tidy` drift fails CI.

## Session credential posture (this revision)

- Access/refresh tokens carry `jti` and `token_version` claims; tokens
  without an identifier fail closed.
- Refresh sessions rotate atomically with reuse detection that revokes the
  session family and advances the credential generation; password change,
  resets, logout-all, and account deletion retire sessions; single logout
  retires the pair through a pruned denylist.
- Credential lifecycle operations append secret-free audit events readable
  by their owner (administrators may read all).
- Evidence: `service/session_test.go` (rotation, reuse, concurrency,
  lockout, caps, pruning), `route/v1/user_auth_security_test.go`
  (login/lockout/refresh/logout/events flows), `route/auth_test.go`
  (middleware acceptance and denial matrix), and the Debian 11/systemd 247
  lifecycle lane in CI.

## Open items (not advisories)

- MFA and account-recovery design, an offline legacy-verifier migration
  command, and measured timing parity for enumeration resistance remain
  future work and are tracked separately from these advisories.
