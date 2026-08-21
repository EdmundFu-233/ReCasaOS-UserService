# Selected Go package boundary

`govulncheck` distinguishes reachable symbol findings from imported-package
and module-only findings. A module-only result is not described as fixed merely
because no vulnerable symbol is currently reachable.

The repository therefore also inspects structured
`go list -deps -json=ImportPath,Incomplete,Error,DepsErrors` output. CI checks:

- Linux amd64 test graphs with CGO disabled and enabled;
- the Linux amd64 race-test graph;
- Linux amd64, arm64, armv7, and riscv64 release-tag graphs with both CGO
  settings; and
- pinned generator, license, and vulnerability-scanner tool graphs.

The checker rejects `golang.org/x/crypto/openpgp` and every subpackage by
decoded canonical import path. It deliberately permits reviewed non-OpenPGP
packages such as `golang.org/x/crypto/argon2`. Invalid, empty, incomplete, or
dependency-error graph records fail closed. Unit tests prove both the negative
and allowed cases.

The remaining module-only OpenPGP advisory context is tracked in
[issue #1](https://github.com/EdmundFu-233/ReCasaOS-UserService/issues/1);
it has not been dismissed.
