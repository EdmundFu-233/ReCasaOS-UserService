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
conflicts with `casaos-user-service.service`. Before starting it, a local
administrator must provide both `LoadCredential` sources in a root-only
drop-in or through an equivalent transient systemd unit. Credential source
files must be regular root-owned files with mode `0600`, preferably on a
temporary filesystem. Remove those source files immediately after the oneshot
finishes. Do not put either credential in a shell command line, unit
`Environment=`, journal message, or issue report.

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
