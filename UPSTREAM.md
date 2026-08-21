# Fork provenance

## User Service baseline

- Fork: <https://github.com/EdmundFu-233/ReCasaOS-UserService>
- Upstream: <https://github.com/IceWhaleTech/CasaOS-UserService>
- Upstream branch: `main`
- Baseline tag: `v0.4.17-alpha1`
- Baseline commit: `800c630c3443364cde142a9aadea0dc3880e6232`

The initial ReCasaOS branch was created from that exact commit. Future upstream
imports must identify the upstream commit and use an ordinary reviewable merge
or cherry-pick; do not regenerate from a moving branch reference.

## MessageBus generation input

The MessageBus OpenAPI source is vendored at
`api/message-bus/openapi.yaml`. Its provenance and checksum are documented in
`api/message-bus/README.md`. Generation refuses a missing or altered snapshot.

## Security maintenance

Fork hardening is tracked in
[issue #1](https://github.com/EdmundFu-233/ReCasaOS-UserService/issues/1).
Security findings are not considered fixed merely because a workflow is green;
the relevant code, tests, and deployment boundary must be verified.
