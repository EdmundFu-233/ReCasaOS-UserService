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
delete it to retry setup. A missing or mismatched database/seal pair, or an
initialized database with no users, enters fail-closed `recovery` state. It
cannot create another administrator through the bootstrap command; investigate
and restore a consistent backup instead.

On success the command prints only:

```text
administrator bootstrap completed
```

It never prints the username or password.
