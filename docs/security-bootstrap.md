# Secure local administrator bootstrap

ReCasaOS never sends or accepts an administrator setup secret over HTTP. The
`POST /v1/users/register` compatibility route always returns `410 Gone`, and
`GET /v1/users/status` returns only an `initialized` boolean.

The first administrator is created with the local `bootstrap-admin` command.
The command:

- requires effective UID 0;
- refuses to run while the user-service daemon holds its process lock;
- reads `recasaos.admin.username` and `recasaos.admin.password` only from the
  service-private directory named by systemd's `CREDENTIALS_DIRECTORY`;
- never accepts a password through command arguments or environment variables;
- stores only an Argon2id password verifier; and
- commits the administrator and initialized marker atomically.

The packaged `recasaos-user-bootstrap.service` is a disabled oneshot unit that
conflicts with `casaos-user-service.service`. Its explicit `LoadCredential`
source paths are compatible with the supported systemd 247 and newer targets:

- `/run/recasaos-user-bootstrap/username`
- `/run/recasaos-user-bootstrap/password`

Before starting it, a local administrator must create that directory as
root-owned mode `0700` and both source files as root-owned mode `0600`. Capture
the password from a secure local TTY without placing it in command arguments,
environment variables, shell history, journal messages, or issue reports.
The unit removes both source files after the oneshot exits; the administrator
must verify their absence and remove them manually if credential loading itself
failed before the service process was started.

Use this explicit lifecycle: stop `casaos-user-service.service`, start and wait
for `recasaos-user-bootstrap.service`, verify its successful result and the
absence of both source files, then start `casaos-user-service.service` again.
Do not use the network registration endpoint as a recovery fallback.

The database marker is paired with
`/etc/casaos/recasaos-user-bootstrap.seal`. The seal is deliberately outside
the database directory. Never include it in a database-only restore and never
delete it to retry setup. A mismatched database/seal pair, or an initialized
database with no users, enters fail-closed `recovery` state. A valid initialized
marker with no seal may republish only the same installation ID; this narrowly
recovers the deliberate database-commit-before-seal crash window and never
creates another administrator.

On success the command prints only:

```text
administrator bootstrap completed
```

It never prints the username or password.

## Existing installations with legacy password verifiers

ReCasaOS never evaluates legacy weak password hashes during login. Before
promoting this fork on an existing installation, use the disabled
`recasaos-user-password-reset.service` to replace the selected existing
administrator's verifier with Argon2id.

Create root-owned mode `0600` sources at
`/run/recasaos-user-password-reset/username` and
`/run/recasaos-user-password-reset/new-password` under that root-owned mode
`0700` directory. They are loaded as `recasaos.admin.username` and
`recasaos.admin.new-password`. Then use
the same explicit stop → start/wait/verify oneshot → verify source deletion →
start daemon lifecycle described above. The reset command:

- requires effective UID 0 and the same daemon-exclusion process lock;
- refuses to create a missing database or database directory;
- imports an unmodified legacy database only when it already has users and has
  neither a bootstrap-state row nor an external seal;
- otherwise requires an initialized database and either its matching external
  seal or the narrowly repairable missing-seal crash state described above;
- requires the selected existing account to have the `admin` role;
- never evaluates or logs the old verifier; and
- replaces only that administrator's password in one immediate transaction.

Restarting the daemon after the reset generates a new in-memory signing key,
invalidating access and refresh tokens issued by the stopped process. The reset
unit is not a network recovery API and is intentionally never enabled. Legacy
non-administrator accounts remain locked until a separately reviewed
administrator-driven reset flow exists; this command never promotes them.

## Authentication compatibility hold

The preferred request form is `Authorization: Bearer <access-token>`. The
currently deployed CasaOS UI still sends a compact access JWT directly in the
single `Authorization` header, so this fork temporarily accepts that exact raw
header form as a migration compatibility exception. It does not inspect query
parameters, cookies, form bodies, proxy headers, or loopback source addresses
for authentication evidence. Duplicate, comma-joined, oversized, malformed,
and refresh-token authorization headers fail closed.

This exception must be removed after a ReCasaOS UI build that always sends the
Bearer scheme is immutably pinned. Until then, the raw-header compatibility is
an explicit release hold tracked by Issue #2, not a general token transport
mechanism. Tokens must never be placed in URLs.

## Debian 11 systemd qualification

The required `Go 1.26.6` CI job also boots a checksum-pinned Debian 11 image
under QEMU with systemd 247 as PID 1. It installs the exact checked-out,
host-built static binary and the packaged units, then verifies:

- systemd credential loading and source cleanup on success and failure;
- exactly-once local bootstrap, replay rejection, and a usable administrator;
- an upstream-shaped legacy database reset without unrelated schema drift;
- daemon/reset lock exclusion and zero mutation on lock failure;
- authenticated v1/v2 and refresh flows, with query/cookie/form tokens rejected;
- password rotation followed by a new process and canonical public P-256 JWKS;
- rejection of every access and refresh token issued by the stopped process;
- exact Gateway/MessageBus registration through a body-free loopback stub; and
- absence of passwords, verifiers, and all captured JWTs after daemon shutdown
  and journal synchronization.

This lane proves compatibility with the legacy systemd 247 target. The
loopback dependency stub is not a full CasaOS stack, the host-built binary is
not a final GoReleaser artifact, and Debian 11 is not declared the recommended
new-deployment baseline. Full-stack UI, gateway, packaging, upgrade, and
rollback qualification remain separate release gates.
