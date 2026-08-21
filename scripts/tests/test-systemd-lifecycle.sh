#!/usr/bin/env bash

set -Eeuo pipefail
set +x
IFS=$'\n\t'

fail() {
  printf 'UserService systemd lifecycle test failed: %s\n' "$*" >&2
  exit 1
}

phase() {
  printf 'UserService systemd lifecycle phase passed: %s\n' "$1"
}

assert_secret_absent_from_file() {
  local secret=$1
  local path=$2
  local result
  if grep -Fq -- "$secret" "$path"; then
    fail "credential, token, or verifier material reached the system journal"
  else
    result=$?
    [[ "$result" == 1 ]] || fail "could not complete the system-journal secret scan"
  fi
}

assert_secret_absent_from_logs() {
  local secret=$1
  local result
  [[ -d /var/log/casaos && ! -L /var/log/casaos ]] || fail "the application log directory is unsafe"
  if grep -R -Fq -- "$secret" /var/log/casaos; then
    fail "credential, token, or verifier material reached the service log directory"
  else
    result=$?
    [[ "$result" == 1 ]] || fail "could not complete the application-log secret scan"
  fi
}

[[ "$(id -u)" == 0 ]] || fail "the guest lifecycle test must run as root"
[[ "$(cat /proc/1/comm)" == systemd ]] || fail "guest PID 1 is not systemd"
[[ "$(systemd --version | awk 'NR == 1 { print $2 }')" == 247 ]] ||
  fail "guest systemd is not exact version 247"
[[ "$(systemctl show --property=Version --value)" == 247* ]] ||
  fail "the running systemd manager is not version 247"
[[ "$(systemd-detect-virt --vm)" == qemu ]] || fail "guest virtualization is not QEMU"
[[ -f /root/RECASAOS_DISPOSABLE_E2E_VM ]] ||
  fail "the disposable-VM marker is missing"
[[ "${RECASAOS_USERSERVICE_SYSTEMD_CI:-}" == 1 ]] ||
  fail "explicit UserService systemd CI opt-in is missing"
[[ "${RECASAOS_USERSERVICE_EXPECTED_SHA:-}" =~ ^[0-9a-f]{40}$ ]] ||
  fail "the expected source SHA is missing or malformed"
[[ "${RECASAOS_USERSERVICE_BINARY_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] ||
  fail "the expected binary digest is missing or malformed"

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
[[ "$repo_root" == /opt/recasaos-userservice-src ]] ||
  fail "the source archive is not installed at the reviewed guest path"
[[ -f "$repo_root/.git-archive-sha" ]] || fail "the source archive identity file is missing"
[[ "$(<"$repo_root/.git-archive-sha")" == "$RECASAOS_USERSERVICE_EXPECTED_SHA" ]] ||
  fail "the source archive identity does not match the expected SHA"

candidate=${1:-}
[[ "$candidate" =~ ^/tmp/recasaos-userservice-vm-payload-[0-9]+-[0-9]+/casaos-user-service$ ]] ||
  fail "the release-candidate path is unsafe"
[[ -f "$candidate" && ! -L "$candidate" ]] || fail "the release candidate is not a regular file"
[[ "$(sha256sum "$candidate" | awk '{ print $1 }')" == "$RECASAOS_USERSERVICE_BINARY_SHA256" ]] ||
  fail "the release candidate digest does not match the host-built artifact"

for required_tool in awk curl grep install jq journalctl readlink runuser sha256sum sqlite3 stat systemctl systemd-analyze; do
  command -v "$required_tool" >/dev/null 2>&1 || fail "required guest tool is unavailable: $required_tool"
done

run_key="${GITHUB_RUN_ID:-}-${GITHUB_RUN_ATTEMPT:-}"
[[ "$run_key" =~ ^[0-9]+-[0-9]+$ ]] || fail "the GitHub run identity is missing or unsafe"
evidence_dir="/run/recasaos-userservice-e2e-${run_key}"
case "$evidence_dir" in
  /run/recasaos-userservice-e2e-[0-9]*-[0-9]*) ;;
  *) fail "refusing unsafe evidence directory: $evidence_dir" ;;
esac
[[ ! -e "$evidence_dir" && ! -L "$evidence_dir" ]] || fail "the evidence directory already exists"
install -d -o root -g root -m 0700 "$evidence_dir"

cleanup() {
  status=$?
  trap - EXIT
  set +e
  systemctl stop casaos-user-service.service recasaos-user-password-reset.service \
    recasaos-user-bootstrap.service casaos-message-bus.service >/dev/null 2>&1
  rm -f -- /run/casaos/user-service.url /run/casaos/management.url /run/casaos/message-bus.url \
    /run/casaos/recasaos-userservice-e2e-stub-state.json
  rm -rf -- /run/recasaos-user-bootstrap /run/recasaos-user-password-reset
  case "$evidence_dir" in
    /run/recasaos-userservice-e2e-[0-9]*-[0-9]*)
      [[ ! -L "$evidence_dir" ]] && rm -rf -- "$evidence_dir"
      ;;
  esac
  exit "$status"
}
trap cleanup EXIT

database_dir=/var/lib/casaos/db
database_path=$database_dir/user.db
seal_path=/etc/casaos/recasaos-user-bootstrap.seal
bootstrap_source=/run/recasaos-user-bootstrap
reset_source=/run/recasaos-user-password-reset
service_address_file=/run/casaos/user-service.url

[[ ! -e "$database_path" && ! -L "$database_path" ]] || fail "the guest already contains a user database"
[[ ! -e "$seal_path" && ! -L "$seal_path" ]] || fail "the guest already contains a bootstrap seal"
[[ ! -e "$bootstrap_source" && ! -L "$bootstrap_source" ]] || fail "bootstrap credential source already exists"
[[ ! -e "$reset_source" && ! -L "$reset_source" ]] || fail "reset credential source already exists"
for install_target in \
  /usr/bin/casaos-user-service \
  /usr/local/libexec/recasaos-e2e-casaos-stub \
  /etc/casaos/user-service.conf \
  /etc/systemd/system/casaos-message-bus.service \
  /etc/systemd/system/casaos-user-service.service \
  /etc/systemd/system/recasaos-user-bootstrap.service \
  /etc/systemd/system/recasaos-user-password-reset.service
do
  [[ ! -e "$install_target" && ! -L "$install_target" ]] || fail "guest install target already exists"
done

install -d -o root -g root -m 0755 /etc/casaos /usr/local/libexec /var/lib/casaos /var/log/casaos /run/casaos
install -o root -g root -m 0755 "$candidate" /usr/bin/casaos-user-service
install -o root -g root -m 0644 \
  "$repo_root/build/sysroot/etc/casaos/user-service.conf.sample" \
  /etc/casaos/user-service.conf
install -o root -g root -m 0644 \
  "$repo_root/build/sysroot/usr/lib/systemd/system/casaos-user-service.service" \
  /etc/systemd/system/casaos-user-service.service
install -o root -g root -m 0644 \
  "$repo_root/build/sysroot/usr/lib/systemd/system/recasaos-user-bootstrap.service" \
  /etc/systemd/system/recasaos-user-bootstrap.service
install -o root -g root -m 0644 \
  "$repo_root/build/sysroot/usr/lib/systemd/system/recasaos-user-password-reset.service" \
  /etc/systemd/system/recasaos-user-password-reset.service

install -o root -g root -m 0600 /dev/null "$evidence_dir/stub-ready"
cat >"$evidence_dir/fake-casaos.py" <<'PYTHON'
#!/usr/bin/env python3
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EXPECTED_ROUTES = {
    "/v1/users",
    "/v2/users",
    "/doc/v2/users",
    "/.well-known/jwks.json",
}
STATE_PATH = "/run/casaos/recasaos-userservice-e2e-stub-state.json"
STATE_LOCK = threading.Lock()
STATE = {
    "routes": {path: 0 for path in sorted(EXPECTED_ROUTES)},
    "event_type": 0,
}

def publish_state():
    temporary = STATE_PATH + ".tmp"
    with open(temporary, "w", encoding="ascii") as destination:
        json.dump(STATE, destination, sort_keys=True, separators=(",", ":"))
        destination.flush()
        os.fsync(destination.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, STATE_PATH)

class Handler(BaseHTTPRequestHandler):
    server_version = "ReCasaOS-E2E"
    sys_version = ""

    def log_message(self, _format, *_args):
        return

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > 65536:
            return None
        return self.rfile.read(length)

    def do_GET(self):
        if self.path == "/ping":
            self.send_response(200)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        body = self._body()
        if body is None:
            self.send_response(413)
            self.end_headers()
            return
        try:
            decoded = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_response(400)
            self.end_headers()
            return
        if self.path == "/v1/gateway/routes":
            path = decoded.get("path") if isinstance(decoded, dict) else None
            target = decoded.get("target") if isinstance(decoded, dict) else None
            if path not in EXPECTED_ROUTES or not isinstance(target, str) or not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", target):
                self.send_response(400)
                self.end_headers()
                return
            with STATE_LOCK:
                STATE["routes"][path] += 1
                publish_state()
            self.send_response(201)
            self.end_headers()
            return
        if self.path == "/v2/message_bus/event_type" and isinstance(decoded, list):
            with STATE_LOCK:
                STATE["event_type"] += 1
                publish_state()
            self.send_response(200)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

server = ThreadingHTTPServer(("127.0.0.1", 18771), Handler)
runtime = "/run/casaos"
os.makedirs(runtime, mode=0o755, exist_ok=True)
publish_state()
for name in ("management.url", "message-bus.url"):
    temporary = os.path.join(runtime, "." + name + ".tmp")
    with open(temporary, "w", encoding="ascii") as destination:
        destination.write("http://127.0.0.1:18771")
        destination.flush()
        os.fsync(destination.fileno())
    os.chmod(temporary, 0o644)
    os.replace(temporary, os.path.join(runtime, name))
server.serve_forever()
PYTHON
chmod 0755 "$evidence_dir/fake-casaos.py"
install -o root -g root -m 0755 "$evidence_dir/fake-casaos.py" /usr/local/libexec/recasaos-e2e-casaos-stub
cat >/etc/systemd/system/casaos-message-bus.service <<'UNIT'
[Unit]
Description=ReCasaOS UserService isolated CI dependency stub

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/libexec/recasaos-e2e-casaos-stub
Restart=no
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
UMask=0077
UNIT

systemctl daemon-reload
systemd-analyze verify \
  /etc/systemd/system/casaos-message-bus.service \
  /etc/systemd/system/casaos-user-service.service \
  /etc/systemd/system/recasaos-user-bootstrap.service \
  /etc/systemd/system/recasaos-user-password-reset.service
[[ "$(systemctl show recasaos-user-bootstrap.service --property=UnitFileState --value)" == static ]] ||
  fail "bootstrap unit is unexpectedly enableable"
[[ "$(systemctl show recasaos-user-password-reset.service --property=UnitFileState --value)" == static ]] ||
  fail "password-reset unit is unexpectedly enableable"
systemctl start casaos-message-bus.service
stub_deadline=$((SECONDS + 20))
until [[ -s /run/casaos/management.url && -s /run/casaos/message-bus.url ]] &&
  [[ "$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' http://127.0.0.1:18771/ping)" == 200 ]]
do
  systemctl is-active --quiet casaos-message-bus.service || fail "the isolated dependency stub stopped"
  ((SECONDS < stub_deadline)) || fail "timed out waiting for the isolated dependency stub"
  sleep 0.2
done
phase "systemd 247 units and isolated dependencies"

bootstrap_username='bootstrap-admin-e2e'
bootstrap_password='ReCasaOS-E2E-bootstrap-password-01'
legacy_username='legacy-admin-e2e'
first_password='ReCasaOS-E2E-reset-password-01'
second_password='ReCasaOS-E2E-reset-password-02'
lock_password='ReCasaOS-E2E-lock-candidate-03'
missing_username='missing-admin-e2e'
legacy_verifier='12121b2b7fdedd5ec5777926650d7119'

write_private() {
  local path=$1
  local value=$2
  umask 077
  printf '%s' "$value" >"$path"
  chmod 0600 "$path"
}

prepare_bootstrap_source() {
  rm -rf -- "$bootstrap_source"
  install -d -o root -g root -m 0700 "$bootstrap_source"
  write_private "$bootstrap_source/username" "$bootstrap_username"
  write_private "$bootstrap_source/password" "$bootstrap_password"
}

prepare_reset_source() {
  local username=$1
  local password=$2
  rm -rf -- "$reset_source"
  install -d -o root -g root -m 0700 "$reset_source"
  write_private "$reset_source/username" "$username"
  write_private "$reset_source/new-password" "$password"
}

assert_oneshot_success() {
  local unit=$1
  [[ "$(systemctl show "$unit" --property=ActiveState --value)" == inactive ]] || fail "$unit did not return to inactive"
  [[ "$(systemctl show "$unit" --property=SubState --value)" == dead ]] || fail "$unit did not return to dead"
  [[ "$(systemctl show "$unit" --property=Result --value)" == success ]] || fail "$unit did not report success"
  [[ "$(systemctl show "$unit" --property=ExecMainStatus --value)" == 0 ]] || fail "$unit main process did not exit zero"
}

assert_oneshot_failure() {
  local unit=$1
  [[ "$(systemctl show "$unit" --property=ActiveState --value)" == failed ]] || fail "$unit did not enter failed state"
  [[ "$(systemctl show "$unit" --property=Result --value)" == exit-code ]] || fail "$unit did not report an exit-code failure"
  [[ "$(systemctl show "$unit" --property=ExecMainStatus --value)" != 0 ]] || fail "$unit unexpectedly exited zero"
}

assert_sources_removed() {
  local directory=$1
  shift
  local name
  for name in "$@"; do
    [[ ! -e "$directory/$name" && ! -L "$directory/$name" ]] || fail "credential source cleanup did not remove $name"
  done
}

read_seal_id() {
  local raw
  raw=$(<"$seal_path")
  [[ "$raw" == recasaos-user-bootstrap-v1:* ]] || return 1
  raw=${raw#recasaos-user-bootstrap-v1:}
  [[ "$raw" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || return 1
  printf '%s\n' "$raw"
}

assert_compact_token_file() {
  local path=$1
  local token
  [[ -f "$path" && ! -L "$path" && "$(stat -c '%a:%u:%g' "$path")" == 600:0:0 ]] ||
    fail "token evidence is not a root-only regular file"
  token=$(<"$path")
  [[ "$token" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]] ||
    fail "token evidence is not a compact JWT"
  [[ "$(stat -c %s "$path")" == "${#token}" ]] ||
    fail "token evidence contains trailing or non-ASCII bytes"
}

process_start_time() {
  local pid=$1
  local stat_line
  local -a fields=()
  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 && -r "/proc/$pid/stat" ]] || return 1
  stat_line=$(<"/proc/$pid/stat")
  [[ "$stat_line" == *') '* ]] || return 1
  IFS=' ' read -r -a fields <<<"${stat_line##*) }"
  [[ "${#fields[@]}" -gt 19 && "${fields[19]}" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${fields[19]}"
}

exact_process_live() {
  local pid=$1
  local expected_start=$2
  local actual_start
  actual_start=$(process_start_time "$pid" 2>/dev/null) || return 1
  [[ "$actual_start" == "$expected_start" ]]
}

validated_jwks_material() {
  local path=$1
  python3 - "$path" <<'PYTHON'
import base64
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    document = json.load(source)
if not isinstance(document, dict) or set(document) != {"keys"}:
    raise SystemExit("JWKS root is not exact")
keys = document["keys"]
if not isinstance(keys, list) or len(keys) != 1:
    raise SystemExit("JWKS must contain exactly one key")
key = keys[0]
if not isinstance(key, dict) or set(key) != {"kty", "crv", "x", "y"}:
    raise SystemExit("JWK fields are not exact")
if key["kty"] != "EC" or key["crv"] != "P-256":
    raise SystemExit("JWK is not a P-256 public key")

def coordinate(name):
    value = key[name]
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise SystemExit(f"JWK {name} is not strict base64url")
    try:
        decoded = base64.b64decode(
            value + "=" * ((4 - len(value) % 4) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, base64.binascii.Error) as error:
        raise SystemExit(f"JWK {name} is malformed") from error
    if len(decoded) != 32:
        raise SystemExit(f"JWK {name} is not an exact P-256 coordinate")
    return int.from_bytes(decoded, "big")

x = coordinate("x")
y = coordinate("y")
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
if not 0 < x < p or not 0 < y < p or (y * y - (x * x * x - 3 * x + b)) % p != 0:
    raise SystemExit("JWK coordinates are not a P-256 curve point")
print(f"{x:064x}|{y:064x}", end="")
PYTHON
}

prepare_bootstrap_source
systemctl start recasaos-user-bootstrap.service
assert_oneshot_success recasaos-user-bootstrap.service
assert_sources_removed "$bootstrap_source" username password
[[ "$(stat -c '%a:%u:%g' "$database_dir")" == 700:0:0 ]] || fail "bootstrap database directory permissions are unsafe"
[[ "$(stat -c '%a:%u:%g' "$database_path")" == 600:0:0 ]] || fail "bootstrap database permissions are unsafe"
[[ "$(stat -c '%a:%u:%g' "$seal_path")" == 600:0:0 ]] || fail "bootstrap seal permissions are unsafe"
bootstrap_record=$(sqlite3 -batch -noheader "$database_path" \
  "SELECT id || '|' || username || '|' || role || '|' || password FROM o_users ORDER BY id;")
[[ "$(sqlite3 -batch -noheader "$database_path" 'SELECT COUNT(*) FROM o_users;')" == 1 ]] ||
  fail "bootstrap did not create exactly one user"
[[ "$bootstrap_record" == 1\|bootstrap-admin-e2e\|admin\|\$argon2id\$* ]] ||
  fail "bootstrap did not create exactly one Argon2id administrator"
bootstrap_state=$(sqlite3 -batch -noheader "$database_path" \
  "SELECT installation_id || '|' || status || '|' || admin_user_id || '|' || (initialized_at IS NOT NULL) FROM o_bootstrap_state WHERE id = 1;")
[[ "$(sqlite3 -batch -noheader "$database_path" 'SELECT COUNT(*) FROM o_bootstrap_state;')" == 1 ]] ||
  fail "bootstrap state is not a singleton"
[[ "$bootstrap_state" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\|initialized\|1\|1$ ]] ||
  fail "bootstrap state is not initialized"
bootstrap_seal_id=$(read_seal_id) || fail "bootstrap seal format is invalid"
[[ "$bootstrap_seal_id|initialized|1|1" == "$bootstrap_state" ]] || fail "bootstrap seal does not match the database marker"
bootstrap_database_hash=$(sha256sum "$database_path" | awk '{ print $1 }')
bootstrap_seal_snapshot=$(<"$seal_path")
bootstrap_user_snapshot=$(sqlite3 -batch -noheader "$database_path" \
  "SELECT id || '|' || username || '|' || role || '|' || email || '|' || nickname || '|' || avatar || '|' || description || '|' || password FROM o_users ORDER BY id;")
[[ "$(stat -c '%a:%u:%g' /var/lib/casaos/1)" == 700:0:0 ]] ||
  fail "bootstrap administrator data directory permissions are unsafe"
bootstrap_data_stat=$(stat -c '%a:%u:%g:%i' /var/lib/casaos/1)

prepare_bootstrap_source
if systemctl start recasaos-user-bootstrap.service >"$evidence_dir/bootstrap-replay.out" 2>&1; then
  fail "bootstrap replay unexpectedly succeeded"
fi
assert_oneshot_failure recasaos-user-bootstrap.service
assert_sources_removed "$bootstrap_source" username password
[[ "$(sqlite3 -batch -noheader "$database_path" 'SELECT COUNT(*) FROM o_users;')" == 1 ]] ||
  fail "bootstrap replay changed the user count"
[[ "$(sha256sum "$database_path" | awk '{ print $1 }')" == "$bootstrap_database_hash" ]] ||
  fail "bootstrap replay changed the database bytes"
[[ "$(<"$seal_path")" == "$bootstrap_seal_snapshot" ]] || fail "bootstrap replay changed the seal"
[[ "$(sqlite3 -batch -noheader "$database_path" \
  "SELECT id || '|' || username || '|' || role || '|' || email || '|' || nickname || '|' || avatar || '|' || description || '|' || password FROM o_users ORDER BY id;")" == "$bootstrap_user_snapshot" ]] ||
  fail "bootstrap replay changed the administrator record"
[[ "$(stat -c '%a:%u:%g:%i' /var/lib/casaos/1)" == "$bootstrap_data_stat" ]] ||
  fail "bootstrap replay changed the administrator data directory"
systemctl reset-failed recasaos-user-bootstrap.service
phase "local exactly-once administrator bootstrap and replay rejection"

write_private "$evidence_dir/bootstrap-username" "$bootstrap_username"
write_private "$evidence_dir/bootstrap-password" "$bootstrap_password"
jq -n --rawfile username "$evidence_dir/bootstrap-username" \
  --rawfile password "$evidence_dir/bootstrap-password" \
  '{username: $username, password: $password}' >"$evidence_dir/bootstrap-login-request.json"
chmod 0600 "$evidence_dir/bootstrap-login-request.json"
systemctl start casaos-user-service.service
bootstrap_daemon_deadline=$((SECONDS + 45))
bootstrap_ready=0
while ((SECONDS < bootstrap_daemon_deadline)); do
  if systemctl is-active --quiet casaos-user-service.service && [[ -s "$service_address_file" ]]; then
    bootstrap_address=$(<"$service_address_file")
    if [[ "$bootstrap_address" =~ ^http://127\.0\.0\.1:([0-9]{1,5})$ ]] &&
      ((10#${BASH_REMATCH[1]} >= 1 && 10#${BASH_REMATCH[1]} <= 65535)) &&
      [[ "$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "$bootstrap_address/v1/users/status")" == 200 ]]
    then
      bootstrap_ready=1
      break
    fi
  fi
  sleep 0.2
done
[[ "$bootstrap_ready" == 1 ]] ||
  fail "the bootstrap-backed daemon did not become ready"
bootstrap_daemon_pid=$(systemctl show casaos-user-service.service --property=MainPID --value)
[[ "$bootstrap_daemon_pid" =~ ^[0-9]+$ && "$bootstrap_daemon_pid" -gt 1 ]] ||
  fail "the bootstrap-backed daemon PID is invalid"
bootstrap_daemon_start=$(process_start_time "$bootstrap_daemon_pid") ||
  fail "could not record the bootstrap-backed daemon identity"
[[ "$(curl --silent --show-error --output "$evidence_dir/bootstrap-noauth-v1.json" \
  --write-out '%{http_code}' "$bootstrap_address/v1/users/current")" == 401 ]] ||
  fail "bootstrap-backed v1 accepted a request without Authorization"
[[ "$(curl --silent --show-error --output "$evidence_dir/bootstrap-noauth-v2.json" \
  --write-out '%{http_code}' "$bootstrap_address/v2/users/events")" == 401 ]] ||
  fail "bootstrap-backed v2 accepted a request without Authorization"
bootstrap_login_status=$(curl --silent --show-error --request POST \
  --header 'Content-Type: application/json' \
  --data-binary "@$evidence_dir/bootstrap-login-request.json" \
  --output "$evidence_dir/bootstrap-login-response.json" \
  --write-out '%{http_code}' "$bootstrap_address/v1/users/login")
[[ "$bootstrap_login_status" == 200 ]] || fail "the bootstrap administrator could not log in"
jq -e '.success == 200 and .data.user.id == 1 and .data.user.username == "bootstrap-admin-e2e" and (.data.user | has("password") | not) and (.data.token.access_token | type == "string" and length > 0) and (.data.token.refresh_token | type == "string" and length > 0)' \
  "$evidence_dir/bootstrap-login-response.json" >/dev/null || fail "the bootstrap login response is malformed"
jq -rj '.data.token.access_token' "$evidence_dir/bootstrap-login-response.json" >"$evidence_dir/bootstrap-access-token"
jq -rj '.data.token.refresh_token' "$evidence_dir/bootstrap-login-response.json" >"$evidence_dir/bootstrap-refresh-token"
chmod 0600 "$evidence_dir/bootstrap-access-token" "$evidence_dir/bootstrap-refresh-token"
assert_compact_token_file "$evidence_dir/bootstrap-access-token"
assert_compact_token_file "$evidence_dir/bootstrap-refresh-token"
bootstrap_access=$(<"$evidence_dir/bootstrap-access-token")
printf 'header = "Authorization: Bearer %s"\n' "$bootstrap_access" >"$evidence_dir/bootstrap-bearer.config"
printf 'header = "Authorization: %s"\n' "$bootstrap_access" >"$evidence_dir/bootstrap-raw.config"
chmod 0600 "$evidence_dir/bootstrap-bearer.config" "$evidence_dir/bootstrap-raw.config"
[[ "$(curl --silent --show-error --config "$evidence_dir/bootstrap-bearer.config" \
  --output "$evidence_dir/bootstrap-v1.json" --write-out '%{http_code}' \
  "$bootstrap_address/v1/users/current")" == 200 ]] || fail "bootstrap access token failed the v1 boundary"
jq -e '.data.id == 1 and .data.username == "bootstrap-admin-e2e" and (.data | has("password") | not)' \
  "$evidence_dir/bootstrap-v1.json" >/dev/null || fail "bootstrap v1 identity response is malformed"
[[ "$(curl --silent --show-error --config "$evidence_dir/bootstrap-raw.config" \
  --output "$evidence_dir/bootstrap-v2.json" --write-out '%{http_code}' \
  "$bootstrap_address/v2/users/events")" == 200 ]] || fail "bootstrap access token failed the v2 boundary"
jq -e 'type == "array"' "$evidence_dir/bootstrap-v2.json" >/dev/null || fail "bootstrap v2 response is malformed"
printf 'url = "%s/v1/users/current?token=%s"\n' "$bootstrap_address" "$bootstrap_access" \
  >"$evidence_dir/bootstrap-query.config"
chmod 0600 "$evidence_dir/bootstrap-query.config"
[[ "$(curl --silent --show-error --config "$evidence_dir/bootstrap-query.config" \
  --output "$evidence_dir/bootstrap-query-rejected.json" --write-out '%{http_code}')" == 401 ]] ||
  fail "v1 accepted an access token from the query string"
printf 'url = "%s/v1/users/current"\ncookie = "token=%s"\n' "$bootstrap_address" "$bootstrap_access" \
  >"$evidence_dir/bootstrap-cookie.config"
chmod 0600 "$evidence_dir/bootstrap-cookie.config"
[[ "$(curl --silent --show-error --config "$evidence_dir/bootstrap-cookie.config" \
  --output "$evidence_dir/bootstrap-cookie-rejected.json" --write-out '%{http_code}')" == 401 ]] ||
  fail "v1 accepted an access token from a cookie"
printf 'token=%s' "$bootstrap_access" >"$evidence_dir/bootstrap-form-body"
chmod 0600 "$evidence_dir/bootstrap-form-body"
[[ "$(curl --silent --show-error --request GET \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary "@$evidence_dir/bootstrap-form-body" \
  --output "$evidence_dir/bootstrap-form-rejected.json" --write-out '%{http_code}' \
  "$bootstrap_address/v1/users/current")" == 401 ]] ||
  fail "v1 accepted an access token from a form body"
: >"$evidence_dir/bootstrap-bearer.config"
: >"$evidence_dir/bootstrap-raw.config"
: >"$evidence_dir/bootstrap-query.config"
: >"$evidence_dir/bootstrap-cookie.config"
: >"$evidence_dir/bootstrap-form-body"
systemctl stop casaos-user-service.service
[[ "$(systemctl show casaos-user-service.service --property=ActiveState --value)" == inactive ]] ||
  fail "the bootstrap-backed daemon did not stop"
bootstrap_stop_deadline=$((SECONDS + 10))
while exact_process_live "$bootstrap_daemon_pid" "$bootstrap_daemon_start" &&
  ((SECONDS < bootstrap_stop_deadline)); do sleep 0.1; done
exact_process_live "$bootstrap_daemon_pid" "$bootstrap_daemon_start" &&
  fail "the bootstrap-backed daemon process remained live"
rm -f -- "$service_address_file"
phase "bootstrap administrator authentication on v1 and v2"

install -d -o root -g root -m 0700 /var/lib/casaos/e2e-bootstrap-evidence
[[ ! -e /var/lib/casaos/e2e-bootstrap-evidence/db ]] || fail "bootstrap evidence database already exists"
mv -- "$database_dir" /var/lib/casaos/e2e-bootstrap-evidence/db
[[ ! -e /var/lib/casaos/e2e-bootstrap-evidence/user-data ]] || fail "bootstrap evidence user data already exists"
mv -- /var/lib/casaos/1 /var/lib/casaos/e2e-bootstrap-evidence/user-data
mv -- "$seal_path" /var/lib/casaos/e2e-bootstrap-evidence/seal

install -d -o root -g root -m 0700 "$database_dir"
sqlite3 "$database_path" <<'SQL'
PRAGMA journal_mode=DELETE;
CREATE TABLE o_users (
  id integer PRIMARY KEY AUTOINCREMENT,
  username text,
  password text,
  role text,
  email text,
  nickname text,
  avatar text,
  description text,
  created_at datetime,
  updated_at datetime
);
CREATE TABLE events (
  uuid text PRIMARY KEY,
  source_id text,
  name text,
  properties text,
  timestamp integer
);
CREATE INDEX idx_events_source_id ON events(source_id);
INSERT INTO o_users(id, username, password, role, email, nickname, avatar, description, created_at, updated_at)
VALUES(7, 'legacy-admin-e2e', '12121b2b7fdedd5ec5777926650d7119', 'admin',
  'legacy-admin@example.invalid', 'Legacy Admin', 'avatar-marker', 'profile-marker',
  '2026-08-20 00:00:00', '2026-08-20 00:00:00');
INSERT INTO events(uuid, source_id, name, properties, timestamp)
VALUES('00000000-0000-4000-8000-000000000001', 'legacy-source', 'legacy-event', '"{}"', 1787184000000);
SQL
chmod 0600 "$database_path"
[[ "$(sqlite3 -batch -noheader "$database_path" \
  "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'o_bootstrap_state';")" == 0 ]] ||
  fail "legacy fixture unexpectedly contains initialization state"
[[ ! -e "$seal_path" && ! -L "$seal_path" ]] || fail "legacy fixture unexpectedly contains a seal"
legacy_db_hash=$(sha256sum "$database_path" | awk '{ print $1 }')

install -d -o root -g root -m 0700 "$evidence_dir/nonroot-credentials"
write_private "$evidence_dir/nonroot-credentials/recasaos.admin.username" "$legacy_username"
write_private "$evidence_dir/nonroot-credentials/recasaos.admin.new-password" "$first_password"
if runuser -u nobody -- env CREDENTIALS_DIRECTORY="$evidence_dir/nonroot-credentials" \
  /usr/bin/casaos-user-service reset-admin-password -c /etc/casaos/user-service.conf \
  >"$evidence_dir/nonroot-reset.out" 2>&1
then
  fail "non-root password reset unexpectedly succeeded"
fi
grep -Fq 'reset-admin-password requires effective uid 0' "$evidence_dir/nonroot-reset.out" ||
  fail "non-root reset did not fail at the effective-UID boundary"
[[ "$(sha256sum "$database_path" | awk '{ print $1 }')" == "$legacy_db_hash" ]] ||
  fail "non-root reset changed the legacy database"
[[ ! -e "$seal_path" && ! -L "$seal_path" ]] || fail "non-root reset created a seal"

prepare_reset_source "$missing_username" "$first_password"
if systemctl start recasaos-user-password-reset.service >"$evidence_dir/missing-reset.out" 2>&1; then
  fail "password reset for a missing administrator unexpectedly succeeded"
fi
assert_oneshot_failure recasaos-user-password-reset.service
assert_sources_removed "$reset_source" username new-password
[[ "$(sqlite3 -batch -noheader "$database_path" \
  "SELECT password FROM o_users WHERE id = 7;")" == "$legacy_verifier" ]] ||
  fail "failed reset changed the legacy verifier"
[[ "$(sqlite3 -batch -noheader "$database_path" \
  "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'o_bootstrap_state';")" == 0 ]] ||
  fail "failed reset created initialization state"
[[ ! -e "$seal_path" && ! -L "$seal_path" ]] || fail "failed reset created a seal"
[[ "$(sha256sum "$database_path" | awk '{ print $1 }')" == "$legacy_db_hash" ]] ||
  fail "failed reset changed the legacy database bytes"
systemctl reset-failed recasaos-user-password-reset.service

prepare_reset_source "$legacy_username" "$first_password"
systemctl start recasaos-user-password-reset.service
assert_oneshot_success recasaos-user-password-reset.service
assert_sources_removed "$reset_source" username new-password
legacy_record=$(sqlite3 -batch -noheader "$database_path" \
  "SELECT id || '|' || username || '|' || role || '|' || email || '|' || nickname || '|' || avatar || '|' || description || '|' || password FROM o_users ORDER BY id;")
[[ "$(sqlite3 -batch -noheader "$database_path" 'SELECT COUNT(*) FROM o_users;')" == 1 ]] ||
  fail "legacy reset changed the user count"
[[ "$legacy_record" == 7\|legacy-admin-e2e\|admin\|legacy-admin@example.invalid\|Legacy\ Admin\|avatar-marker\|profile-marker\|\$argon2id\$* ]] ||
  fail "legacy reset changed identity/profile data or did not store Argon2id"
legacy_state=$(sqlite3 -batch -noheader "$database_path" \
  "SELECT installation_id || '|' || status || '|' || admin_user_id || '|' || (initialized_at IS NOT NULL) FROM o_bootstrap_state WHERE id = 1;")
[[ "$(sqlite3 -batch -noheader "$database_path" 'SELECT COUNT(*) FROM o_bootstrap_state;')" == 1 ]] ||
  fail "legacy reset initialization state is not a singleton"
[[ "$legacy_state" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\|initialized\|7\|1$ ]] ||
  fail "legacy reset did not initialize state"
legacy_seal_id=$(read_seal_id) || fail "legacy reset seal format is invalid"
[[ "$legacy_seal_id|initialized|7|1" == "$legacy_state" ]] || fail "legacy reset seal does not match the database marker"
[[ "$(stat -c '%a:%u:%g' "$seal_path")" == 600:0:0 ]] || fail "legacy reset seal permissions are unsafe"
[[ "$(sqlite3 -batch -noheader "$database_path" \
  "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'events';")" == 1 &&
  "$(sqlite3 -batch -noheader "$database_path" \
  "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_events_source_id';")" == 1 &&
  "$(sqlite3 -batch -noheader "$database_path" \
  "SELECT uuid || '|' || source_id || '|' || name || '|' || properties || '|' || timestamp FROM events;")" == \
  '00000000-0000-4000-8000-000000000001|legacy-source|legacy-event|"{}"|1787184000000' ]] ||
  fail "legacy reset changed the existing event schema or record"
[[ "$(sqlite3 -batch -noheader "$database_path" \
  "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_o_users_username';")" == 0 ]] ||
  fail "legacy reset migrated the daemon-owned username index"
phase "root-only legacy administrator reset and fail-closed error paths"

wait_for_daemon() {
  local deadline=$((SECONDS + 45))
  local address
  while ((SECONDS < deadline)); do
    if systemctl is-active --quiet casaos-user-service.service && [[ -s "$service_address_file" ]]; then
      address=$(<"$service_address_file")
      if [[ "$address" =~ ^http://127\.0\.0\.1:([0-9]{1,5})$ ]] &&
        ((10#${BASH_REMATCH[1]} >= 1 && 10#${BASH_REMATCH[1]} <= 65535)) &&
        [[ "$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "$address/v1/users/status")" == 200 ]]
      then
        printf '%s' "$address" >"$evidence_dir/service-address"
        chmod 0600 "$evidence_dir/service-address"
        return 0
      fi
    fi
    sleep 0.2
  done
  return 1
}

build_login_body() {
  local password_file=$1
  local output=$2
  jq -n --rawfile username "$evidence_dir/legacy-username" --rawfile password "$password_file" \
    '{username: $username, password: $password}' >"$output"
  chmod 0600 "$output"
}

login_success() {
  local password_file=$1
  local prefix=$2
  build_login_body "$password_file" "$evidence_dir/${prefix}-login-request.json"
  local address status
  address=$(<"$evidence_dir/service-address")
  status=$(curl --silent --show-error --request POST \
    --header 'Content-Type: application/json' \
    --data-binary "@$evidence_dir/${prefix}-login-request.json" \
    --output "$evidence_dir/${prefix}-login-response.json" \
    --write-out '%{http_code}' "$address/v1/users/login")
  [[ "$status" == 200 ]] || fail "expected a successful login"
  jq -e '.success == 200 and (.data.token.access_token | type == "string" and length > 0) and (.data.token.refresh_token | type == "string" and length > 0) and (.data.user | has("password") | not)' \
    "$evidence_dir/${prefix}-login-response.json" >/dev/null || fail "successful login response is malformed"
  jq -rj '.data.token.access_token' "$evidence_dir/${prefix}-login-response.json" >"$evidence_dir/${prefix}-access-token"
  jq -rj '.data.token.refresh_token' "$evidence_dir/${prefix}-login-response.json" >"$evidence_dir/${prefix}-refresh-token"
  chmod 0600 "$evidence_dir/${prefix}-access-token" "$evidence_dir/${prefix}-refresh-token"
  assert_compact_token_file "$evidence_dir/${prefix}-access-token"
  assert_compact_token_file "$evidence_dir/${prefix}-refresh-token"
}

login_failure() {
  local password_file=$1
  local prefix=$2
  build_login_body "$password_file" "$evidence_dir/${prefix}-login-request.json"
  local address status
  address=$(<"$evidence_dir/service-address")
  status=$(curl --silent --show-error --request POST \
    --header 'Content-Type: application/json' \
    --data-binary "@$evidence_dir/${prefix}-login-request.json" \
    --output "$evidence_dir/${prefix}-login-response.json" \
    --write-out '%{http_code}' "$address/v1/users/login")
  [[ "$status" == 400 ]] || fail "rejected password did not return HTTP 400"
  jq -e '.success == 10013 and (.data == null)' "$evidence_dir/${prefix}-login-response.json" >/dev/null ||
    fail "rejected password response is malformed"
}

authenticated_get() {
  local token_file=$1
  local path=$2
  local expected=$3
  local output=$4
  local config="$evidence_dir/curl-auth.config"
  local token
  assert_compact_token_file "$token_file"
  token=$(<"$token_file")
  printf 'header = "Authorization: Bearer %s"\n' "$token" >"$config"
  chmod 0600 "$config"
  local address status
  address=$(<"$evidence_dir/service-address")
  status=$(curl --silent --show-error --config "$config" \
    --output "$output" --write-out '%{http_code}' "$address$path")
  : >"$config"
  [[ "$status" == "$expected" ]] || fail "authenticated request to $path returned an unexpected status"
}

refresh_request() {
  local token_file=$1
  local expected=$2
  local output=$3
  assert_compact_token_file "$token_file"
  jq -n --rawfile refresh "$token_file" '{refresh_token: $refresh}' >"$evidence_dir/refresh-request.json"
  chmod 0600 "$evidence_dir/refresh-request.json"
  local address status
  address=$(<"$evidence_dir/service-address")
  status=$(curl --silent --show-error --request POST \
    --header 'Content-Type: application/json' \
    --data-binary "@$evidence_dir/refresh-request.json" \
    --output "$output" --write-out '%{http_code}' "$address/v1/users/refresh")
  [[ "$status" == "$expected" ]] || fail "refresh request returned an unexpected status"
}

extract_refresh_pair() {
  local response=$1
  local prefix=$2
  jq -e '.success == 200 and (.data.access_token | type == "string" and length > 0) and (.data.refresh_token | type == "string" and length > 0)' \
    "$response" >/dev/null || fail "successful refresh response is malformed"
  jq -rj '.data.access_token' "$response" >"$evidence_dir/${prefix}-access-token"
  jq -rj '.data.refresh_token' "$response" >"$evidence_dir/${prefix}-refresh-token"
  chmod 0600 "$evidence_dir/${prefix}-access-token" "$evidence_dir/${prefix}-refresh-token"
  assert_compact_token_file "$evidence_dir/${prefix}-access-token"
  assert_compact_token_file "$evidence_dir/${prefix}-refresh-token"
}

assert_unauthenticated_private_routes_rejected() {
  local prefix=$1
  local address status
  address=$(<"$evidence_dir/service-address")
  status=$(curl --silent --show-error --output "$evidence_dir/${prefix}-noauth-v1.json" \
    --write-out '%{http_code}' "$address/v1/users/current")
  [[ "$status" == 401 ]] || fail "v1 accepted a request without Authorization"
  status=$(curl --silent --show-error --output "$evidence_dir/${prefix}-noauth-v2.json" \
    --write-out '%{http_code}' "$address/v2/users/events")
  [[ "$status" == 401 ]] || fail "v2 accepted a request without Authorization"
}

write_private "$evidence_dir/legacy-username" "$legacy_username"
write_private "$evidence_dir/first-password" "$first_password"
write_private "$evidence_dir/second-password" "$second_password"
write_private "$evidence_dir/lock-password" "$lock_password"

systemctl start casaos-user-service.service
wait_for_daemon || fail "the UserService daemon did not become ready"
assert_unauthenticated_private_routes_rejected initial
[[ "$(sqlite3 -batch -noheader "$database_path" \
  "SELECT COUNT(*) FROM pragma_index_list('o_users') WHERE name = 'idx_o_users_username' AND \"unique\" = 1 AND partial = 0;")" == 1 ]] ||
  fail "the daemon did not migrate the legacy username uniqueness boundary"
[[ "$(sqlite3 -batch -noheader "$database_path" \
  "SELECT COUNT(*) FROM pragma_index_info('idx_o_users_username') WHERE seqno = 0 AND name = 'username';")" == 1 &&
  "$(sqlite3 -batch -noheader "$database_path" \
  "SELECT COUNT(*) FROM pragma_index_info('idx_o_users_username');")" == 1 ]] ||
  fail "the daemon username uniqueness index targets an unexpected column set"
old_pid=$(systemctl show casaos-user-service.service --property=MainPID --value)
old_start=$(process_start_time "$old_pid") || fail "could not record the initial daemon identity"
[[ "$(readlink -f "/proc/$old_pid/exe")" == /usr/bin/casaos-user-service ]] ||
  fail "the initial daemon is not the exact installed candidate"
login_success "$evidence_dir/first-password" old
authenticated_get "$evidence_dir/old-access-token" /v1/users/current 200 "$evidence_dir/old-v1.json"
jq -e '.data.id == 7 and .data.username == "legacy-admin-e2e" and (.data | has("password") | not)' \
  "$evidence_dir/old-v1.json" >/dev/null || fail "authenticated v1 identity response is malformed"
authenticated_get "$evidence_dir/old-access-token" /v2/users/events 200 "$evidence_dir/old-v2.json"
jq -e 'type == "array" and length == 1 and .[0].uuid == "00000000-0000-4000-8000-000000000001" and .[0].source_id == "legacy-source" and .[0].name == "legacy-event" and .[0].properties == "{}" and .[0].timestamp == 1787184000000' \
  "$evidence_dir/old-v2.json" >/dev/null || fail "authenticated v2 response did not preserve the legacy event"
refresh_request "$evidence_dir/old-refresh-token" 200 "$evidence_dir/old-refresh.json"
extract_refresh_pair "$evidence_dir/old-refresh.json" old-refreshed
authenticated_get "$evidence_dir/old-refreshed-access-token" /v1/users/current 200 "$evidence_dir/old-refreshed-v1.json"
authenticated_get "$evidence_dir/old-refreshed-access-token" /v2/users/events 200 "$evidence_dir/old-refreshed-v2.json"
refresh_request "$evidence_dir/old-refreshed-refresh-token" 200 "$evidence_dir/old-refresh-chain.json"
extract_refresh_pair "$evidence_dir/old-refresh-chain.json" old-chain
address=$(<"$evidence_dir/service-address")
[[ "$(curl --silent --show-error --output "$evidence_dir/old-jwks.json" --write-out '%{http_code}' "$address/.well-known/jwks.json")" == 200 ]] ||
  fail "could not read the initial JWKS"
old_jwks_material=$(validated_jwks_material "$evidence_dir/old-jwks.json") ||
  fail "the initial JWKS is not an exact public P-256 key set"
phase "initial daemon authentication on v1, v2, refresh, and JWKS"

install -d -o root -g root -m 0700 "$evidence_dir/lock-credentials"
write_private "$evidence_dir/lock-credentials/recasaos.admin.username" "$legacy_username"
write_private "$evidence_dir/lock-credentials/recasaos.admin.new-password" "$lock_password"
verifier_before_lock=$(sqlite3 -batch -noheader "$database_path" "SELECT password FROM o_users WHERE id = 7;")
profile_before_lock=$(sqlite3 -batch -noheader "$database_path" \
  "SELECT id || '|' || username || '|' || role || '|' || email || '|' || nickname || '|' || avatar || '|' || description FROM o_users ORDER BY id;")
account_before_lock=$(sqlite3 -batch -noheader "$database_path" \
  "SELECT id || '|' || username || '|' || role || '|' || email || '|' || nickname || '|' || avatar || '|' || description || '|' || quote(created_at) || '|' || quote(updated_at) FROM o_users ORDER BY id;")
state_before_lock=$(sqlite3 -batch -noheader "$database_path" \
  "SELECT installation_id || '|' || status || '|' || admin_user_id || '|' || quote(initialized_at) || '|' || quote(created_at) || '|' || quote(updated_at) FROM o_bootstrap_state WHERE id = 1;")
seal_before_lock=$(<"$seal_path")
if CREDENTIALS_DIRECTORY="$evidence_dir/lock-credentials" \
  /usr/bin/casaos-user-service reset-admin-password -c /etc/casaos/user-service.conf \
  >"$evidence_dir/locked-reset.out" 2>&1
then
  fail "password reset unexpectedly bypassed the running-daemon lock"
fi
grep -Fq 'user service or bootstrap is already running' "$evidence_dir/locked-reset.out" ||
  fail "running-daemon password reset did not fail at the shared lock"
exact_process_live "$old_pid" "$old_start" || fail "lock contention changed the daemon identity"
systemctl is-active --quiet casaos-user-service.service || fail "lock contention stopped the daemon"
[[ "$(sqlite3 -batch -noheader "$database_path" "SELECT password FROM o_users WHERE id = 7;")" == "$verifier_before_lock" ]] ||
  fail "lock contention changed the password verifier"
[[ "$(sqlite3 -batch -noheader "$database_path" \
  "SELECT id || '|' || username || '|' || role || '|' || email || '|' || nickname || '|' || avatar || '|' || description || '|' || quote(created_at) || '|' || quote(updated_at) FROM o_users ORDER BY id;")" == "$account_before_lock" ]] ||
  fail "lock contention changed the account record"
[[ "$(sqlite3 -batch -noheader "$database_path" \
  "SELECT installation_id || '|' || status || '|' || admin_user_id || '|' || quote(initialized_at) || '|' || quote(created_at) || '|' || quote(updated_at) FROM o_bootstrap_state WHERE id = 1;")" == "$state_before_lock" ]] ||
  fail "lock contention changed initialization state"
[[ "$(<"$seal_path")" == "$seal_before_lock" ]] || fail "lock contention changed the seal"
authenticated_get "$evidence_dir/old-access-token" /v1/users/current 200 "$evidence_dir/post-lock-v1.json"
phase "daemon/reset mutual exclusion and zero database mutation"

prepare_reset_source "$legacy_username" "$second_password"
systemctl start recasaos-user-password-reset.service
assert_oneshot_success recasaos-user-password-reset.service
assert_sources_removed "$reset_source" username new-password
systemctl is-active --quiet casaos-user-service.service && fail "password-reset conflict did not stop the daemon"
exact_process_live "$old_pid" "$old_start" && fail "the old daemon remained live after password reset"
verifier_after_reset=$(sqlite3 -batch -noheader "$database_path" "SELECT password FROM o_users WHERE id = 7;")
[[ "$verifier_after_reset" == \$argon2id\$* && "$verifier_after_reset" != "$verifier_before_lock" ]] ||
  fail "second password reset did not replace the Argon2id verifier"
[[ "$(sqlite3 -batch -noheader "$database_path" \
  "SELECT id || '|' || username || '|' || role || '|' || email || '|' || nickname || '|' || avatar || '|' || description FROM o_users ORDER BY id;")" == "$profile_before_lock" ]] ||
  fail "second password reset changed account identity or profile"
[[ "$(sqlite3 -batch -noheader "$database_path" \
  "SELECT installation_id || '|' || status || '|' || admin_user_id || '|' || quote(initialized_at) || '|' || quote(created_at) || '|' || quote(updated_at) FROM o_bootstrap_state WHERE id = 1;")" == "$state_before_lock" ]] ||
  fail "second password reset changed initialization state"
[[ "$(<"$seal_path")" == "$seal_before_lock" ]] || fail "second password reset changed the seal"

rm -f -- "$service_address_file"
systemctl start casaos-user-service.service
wait_for_daemon || fail "the UserService daemon did not restart after password reset"
assert_unauthenticated_private_routes_rejected restarted
new_pid=$(systemctl show casaos-user-service.service --property=MainPID --value)
new_start=$(process_start_time "$new_pid") || fail "could not record the restarted daemon identity"
[[ "$new_pid:$new_start" != "$old_pid:$old_start" ]] || fail "daemon restart reused the old process identity"
address=$(<"$evidence_dir/service-address")
[[ "$(curl --silent --show-error --output "$evidence_dir/new-jwks.json" --write-out '%{http_code}' "$address/.well-known/jwks.json")" == 200 ]] ||
  fail "could not read the restarted JWKS"
new_jwks_material=$(validated_jwks_material "$evidence_dir/new-jwks.json") ||
  fail "the restarted JWKS is not an exact public P-256 key set"
[[ "$new_jwks_material" != "$old_jwks_material" ]] || fail "daemon restart did not rotate its signing key"

authenticated_get "$evidence_dir/old-access-token" /v1/users/current 401 "$evidence_dir/revoked-v1.json"
authenticated_get "$evidence_dir/old-access-token" /v2/users/events 401 "$evidence_dir/revoked-v2.json"
refresh_request "$evidence_dir/old-refresh-token" 401 "$evidence_dir/revoked-refresh.json"
authenticated_get "$evidence_dir/old-refreshed-access-token" /v1/users/current 401 "$evidence_dir/revoked-refreshed-v1.json"
authenticated_get "$evidence_dir/old-refreshed-access-token" /v2/users/events 401 "$evidence_dir/revoked-refreshed-v2.json"
refresh_request "$evidence_dir/old-refreshed-refresh-token" 401 "$evidence_dir/revoked-refreshed-refresh.json"
authenticated_get "$evidence_dir/old-chain-access-token" /v1/users/current 401 "$evidence_dir/revoked-chain-v1.json"
refresh_request "$evidence_dir/old-chain-refresh-token" 401 "$evidence_dir/revoked-chain-refresh.json"
login_failure "$evidence_dir/first-password" stale
login_success "$evidence_dir/second-password" new
authenticated_get "$evidence_dir/new-access-token" /v1/users/current 200 "$evidence_dir/new-v1.json"
authenticated_get "$evidence_dir/new-access-token" /v2/users/events 200 "$evidence_dir/new-v2.json"
jq -e 'type == "array" and length == 1 and .[0].uuid == "00000000-0000-4000-8000-000000000001" and .[0].source_id == "legacy-source" and .[0].name == "legacy-event" and .[0].properties == "{}" and .[0].timestamp == 1787184000000' \
  "$evidence_dir/new-v2.json" >/dev/null || fail "restarted v2 response did not preserve the legacy event"
refresh_request "$evidence_dir/new-refresh-token" 200 "$evidence_dir/new-refresh.json"
extract_refresh_pair "$evidence_dir/new-refresh.json" new-refreshed
authenticated_get "$evidence_dir/new-refreshed-access-token" /v1/users/current 200 "$evidence_dir/new-refreshed-v1.json"
authenticated_get "$evidence_dir/new-refreshed-access-token" /v2/users/events 200 "$evidence_dir/new-refreshed-v2.json"
refresh_request "$evidence_dir/new-refreshed-refresh-token" 200 "$evidence_dir/new-refresh-chain.json"
extract_refresh_pair "$evidence_dir/new-refresh-chain.json" new-chain
phase "password rotation, explicit restart, and old access/refresh revocation"

systemctl stop casaos-user-service.service
[[ "$(systemctl show casaos-user-service.service --property=ActiveState --value)" == inactive ]] ||
  fail "the final daemon did not stop before diagnostic inspection"
final_stop_deadline=$((SECONDS + 10))
while exact_process_live "$new_pid" "$new_start" && ((SECONDS < final_stop_deadline)); do sleep 0.1; done
exact_process_live "$new_pid" "$new_start" && fail "the final daemon process remained live"
rm -f -- "$service_address_file"
journalctl --sync

journalctl --boot --no-pager --output=cat \
  -u casaos-user-service.service \
  -u recasaos-user-bootstrap.service \
  -u recasaos-user-password-reset.service \
  >"$evidence_dir/service-journal"
chmod 0600 "$evidence_dir/service-journal"
for secret_file in \
  "$evidence_dir/first-password" \
  "$evidence_dir/second-password" \
  "$evidence_dir/lock-password" \
  "$evidence_dir/bootstrap-access-token" \
  "$evidence_dir/bootstrap-refresh-token" \
  "$evidence_dir/old-access-token" \
  "$evidence_dir/old-refresh-token" \
  "$evidence_dir/old-refreshed-access-token" \
  "$evidence_dir/old-refreshed-refresh-token" \
  "$evidence_dir/old-chain-access-token" \
  "$evidence_dir/old-chain-refresh-token" \
  "$evidence_dir/new-access-token" \
  "$evidence_dir/new-refresh-token" \
  "$evidence_dir/new-refreshed-access-token" \
  "$evidence_dir/new-refreshed-refresh-token" \
  "$evidence_dir/new-chain-access-token" \
  "$evidence_dir/new-chain-refresh-token"
do
  secret=$(<"$secret_file")
  [[ -n "$secret" ]] || fail "a secret audit input is empty"
  assert_secret_absent_from_file "$secret" "$evidence_dir/service-journal"
  assert_secret_absent_from_logs "$secret"
done
assert_secret_absent_from_file "$bootstrap_password" "$evidence_dir/service-journal"
assert_secret_absent_from_file "$legacy_verifier" "$evidence_dir/service-journal"
assert_secret_absent_from_file '$argon2id$' "$evidence_dir/service-journal"
assert_secret_absent_from_logs "$bootstrap_password"
assert_secret_absent_from_logs "$legacy_verifier"
assert_secret_absent_from_logs '$argon2id$'
phase "credential-safe systemd and application diagnostics"

[[ -f /run/casaos/recasaos-userservice-e2e-stub-state.json &&
  ! -L /run/casaos/recasaos-userservice-e2e-stub-state.json ]] ||
  fail "the isolated dependency stub state is missing or unsafe"
jq -e '
  .event_type == 3 and
  .routes == {
    "/.well-known/jwks.json": 3,
    "/doc/v2/users": 3,
    "/v1/users": 3,
    "/v2/users": 3
  }
' /run/casaos/recasaos-userservice-e2e-stub-state.json >/dev/null ||
  fail "the daemon did not register every reviewed gateway/message-bus route exactly once per start"
phase "exact gateway and message-bus registration across all three daemon starts"

systemctl stop casaos-message-bus.service
printf 'UserService Debian 11 systemd 247 lifecycle passed for %s\n' \
  "$RECASAOS_USERSERVICE_EXPECTED_SHA"
