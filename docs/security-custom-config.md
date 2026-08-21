# Authenticated custom-configuration storage

The legacy custom-configuration API remains available at
`/v1/users/current/custom/:key`, but path selection is deliberately narrow:

- the normal access-token middleware must authenticate the request;
- the storage directory is selected from the database result's numeric user
  ID, never from an untrusted request header or path;
- `key` is one ASCII component of at most 64 bytes matching
  `[A-Za-z0-9][A-Za-z0-9._-]*`, and parent references are rejected rather than
  normalized; and
- request and response files are limited to 1 MiB.

The configured shared data root must already be an absolute, real directory
owned by the service account and must not be group- or world-writable. The API
does not change that shared root's permissions. It opens and verifies the root
identity before using a descriptor-relative `os.Root`; a numeric user
subdirectory is then verified and tightened to mode `0700` through an opened
directory descriptor.

Configuration files must be regular, service-owned files without another hard
link. Symbolic links, FIFOs, devices, unexpected owners, and directory identity
changes fail closed. Existing legacy files are tightened to mode `0600`.
Writes use a random mode-`0600` temporary file in the same user directory,
followed by file synchronization, atomic rename, and directory synchronization.
Reads are bounded and deletes never follow a final symbolic link.

For compatibility, valid JSON remains JSON in both POST and GET response data;
object, array, and boolean values are not converted to strings. A missing key
continues to return successful empty-string data. Saving the `system` key still
publishes the existing MessageBus event with the original JSON bytes.

Tests exercise the real Echo router and access-token middleware, raw and
encoded traversal, a forged `user_id` header, symlinks, hard links, special
files, concurrent replacement, size limits, legacy permissions, JSON response
types, and the `system` event. CodeQL must report no open path-injection alert
on the exact pull-request head and on the post-merge default branch; alerts are
never dismissed merely because a unit test passes.
