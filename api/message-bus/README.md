# Vendored MessageBus OpenAPI provenance

- Source repository: <https://github.com/IceWhaleTech/CasaOS-MessageBus>
- Source commit: `ba87168fcfa4ac5ff7a114f66a139eb5fe427646`
- Source path: `api/message_bus/openapi.yaml`
- Git blob: `15f66aa673029479f706e962c1edb1480e856657`
- Vendored SHA-256:
  `1fad6851af193a1b8681b1e6c288e26078125f6f9d5dccb067be1569a24e0b20`
- Vendored size: 23,492 bytes
- Generated MessageBus client SHA-256:
  `5b0511aa93a01f94160ec55c507a9c39b95f165453a60e4906a5a2fe92606c7e`
- Generated User Service API SHA-256:
  `c00a58be9d23b3dde61e412874cfc2011957ff0eb6be6e991a86beeed3c80bef`

This commit was the MessageBus `main` commit paired with the exact User
Service fork baseline. `scripts/generate-api.sh` validates the SHA-256 before
invoking `github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen` pinned at
`v2.8.0` by the Go tool directive. It never reads a moving remote branch.

To update the schema, review an exact upstream commit, replace the vendored
file, update the checksum and provenance together, run `go generate ./...`,
and commit the reviewed generated-code diff. A network or checksum failure must
stop generation; there is no fallback to `main`.
