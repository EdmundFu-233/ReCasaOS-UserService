# ReCasaOS User Service

> Security-maintained ReCasaOS fork of
> [IceWhaleTech/CasaOS-UserService](https://github.com/IceWhaleTech/CasaOS-UserService).
> The exact fork baseline is upstream commit
> `800c630c3443364cde142a9aadea0dc3880e6232`
> (`v0.4.17-alpha1`). See [UPSTREAM.md](UPSTREAM.md).

[![CI](https://github.com/EdmundFu-233/ReCasaOS-UserService/actions/workflows/ci.yml/badge.svg)](https://github.com/EdmundFu-233/ReCasaOS-UserService/actions/workflows/ci.yml)
[![CodeQL](https://github.com/EdmundFu-233/ReCasaOS-UserService/actions/workflows/codeql.yml/badge.svg)](https://github.com/EdmundFu-233/ReCasaOS-UserService/actions/workflows/codeql.yml)

ReCasaOS User Service provides CasaOS-compatible local user-management APIs.
The Go module path remains `github.com/IceWhaleTech/CasaOS-UserService` for
source compatibility while the fork is hardened.

## Security status

Hardening is in progress under
[issue #1](https://github.com/EdmundFu-233/ReCasaOS-UserService/issues/1).
This repository does **not** yet claim that the service is ready for direct
public-Internet exposure. Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md); never put credentials or exploit details in a
public issue.

## Reproducible checks

The supported CI toolchain is exactly Go 1.26.6. GitHub Actions disables
dependency caching, uses read-only permissions except for CodeQL result upload,
and pins every action to a full commit SHA.

```bash
go generate ./...
git diff --exit-code -- codegen/
bash scripts/check-go-dependency-boundary.sh --all
go test -race -count=1 ./...
go vet ./...
```

The generated APIs are tracked. The MessageBus input is a local vendored
snapshot whose upstream commit and SHA-256 are checked before generation; the
generator itself is version-pinned. See
[api/message-bus/README.md](api/message-bus/README.md).
The structured dependency boundary rejects selected OpenPGP packages while
allowing reviewed packages such as `golang.org/x/crypto/argon2`; see
[security/DEPENDENCY_BOUNDARY.md](security/DEPENDENCY_BOUNDARY.md).

## Release boundary

Automatic test-server deployment, npm publishing, OpenAPI synchronization, and
tag-triggered release workflows are disabled. The npm package is marked
`private`. GoReleaser metadata targets this fork and creates drafts, but its
configuration does not authorize or trigger a release.

## License

This fork preserves the upstream Apache License 2.0. ReCasaOS modifications are
documented in Git history.
