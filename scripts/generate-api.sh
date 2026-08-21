#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
message_bus_spec="$repo_root/api/message-bus/openapi.yaml"
message_bus_sha256="1fad6851af193a1b8681b1e6c288e26078125f6f9d5dccb067be1569a24e0b20"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
    return
  fi
  echo "No SHA-256 implementation found (need sha256sum or shasum)." >&2
  return 127
}

if [ ! -f "$message_bus_spec" ]; then
  echo "Vendored MessageBus schema is missing: $message_bus_spec" >&2
  exit 1
fi

actual_sha256=$(sha256_file "$message_bus_spec")
if [ "$actual_sha256" != "$message_bus_sha256" ]; then
  echo "Vendored MessageBus schema checksum mismatch." >&2
  echo "Expected: $message_bus_sha256" >&2
  echo "Actual:   $actual_sha256" >&2
  exit 1
fi

temp_root=$(mktemp -d "${TMPDIR:-/tmp}/recasaos-userservice-codegen.XXXXXX")
temp_user="$temp_root/user_service_api.go"
temp_message_bus="$temp_root/message_bus_api.go"

cleanup() {
  rm -f "$temp_user" "$temp_message_bus"
  rmdir "$temp_root" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

cd "$repo_root"
go tool oapi-codegen -generate types,server,spec -package codegen api/user-service/openapi.yaml >"$temp_user"
go tool oapi-codegen -package message_bus "$message_bus_spec" >"$temp_message_bus"

mkdir -p codegen/user_service codegen/message_bus
mv "$temp_user" codegen/user_service/user_service_api.go
mv "$temp_message_bus" codegen/message_bus/api.go
