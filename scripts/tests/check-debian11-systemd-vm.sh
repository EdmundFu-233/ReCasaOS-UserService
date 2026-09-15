#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

fail() {
  printf 'UserService Debian 11 VM test failed: %s\n' "$*" >&2
  exit 1
}

[[ "${GITHUB_ACTIONS:-}" == true ]] || fail "this VM test is restricted to GitHub Actions"
[[ "${GITHUB_REPOSITORY:-}" == EdmundFu-233/ReCasaOS-UserService ]] ||
  fail "the repository identity is not the trusted UserService repository"
[[ "${RUNNER_OS:-}" == Linux ]] || fail "the runner is not Linux"
[[ -d /opt/hostedtoolcache ]] || fail "the GitHub-hosted runner marker is missing"
[[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ ]] || fail "GITHUB_RUN_ID is missing or unsafe"
[[ "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ ]] || fail "GITHUB_RUN_ATTEMPT is missing or unsafe"
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || fail "GITHUB_SHA is missing or unsafe"
[[ "${GITHUB_EVENT_PATH:-}" == /* && -f "${GITHUB_EVENT_PATH:-}" && ! -L "${GITHUB_EVENT_PATH:-}" ]] ||
  fail "GITHUB_EVENT_PATH is not a safe regular file"

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd -- "$repo_root"
[[ "$(git rev-parse --show-toplevel)" == "$repo_root" ]] || fail "the script is not running from the exact repository root"
actual_sha=$(git rev-parse HEAD) || fail "could not inspect the checkout SHA"
actual_tree=$(git show -s --format=%T HEAD) || fail "could not inspect the checkout tree"
[[ "$actual_sha" =~ ^[0-9a-f]{40}$ && "$actual_tree" =~ ^[0-9a-f]{40}$ ]] ||
  fail "checkout identity is malformed"
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || fail "the exact checkout is not clean"

/usr/bin/python3 - "$GITHUB_EVENT_PATH" "$actual_sha" "$actual_tree" <<'PYTHON'
import json
import os
import re
import subprocess
import sys

event_path, actual, actual_tree = sys.argv[1:]
with open(event_path, encoding="utf-8") as source:
    event = json.load(source)
repository = event.get("repository") or {}
if (
    repository.get("id") != 1341287306
    or repository.get("full_name") != "EdmundFu-233/ReCasaOS-UserService"
    or (repository.get("owner") or {}).get("login") != "EdmundFu-233"
):
    raise SystemExit("event repository identity is not trusted")
event_name = event.get("action")
pull_request = event.get("pull_request")
promotion_names = (
    "RECASAOS_TRUSTED_PROMOTION_SHA",
    "RECASAOS_TRUSTED_PROMOTION_TREE",
    "RECASAOS_TRUSTED_PROMOTION_HOST_SHA256",
    "RECASAOS_TRUSTED_PROMOTION_GUEST_SHA256",
)
promotion_values = {name: os.environ.get(name, "") for name in promotion_names}
if event_name == "trusted-attestor-promote":
    if (event.get("sender") or {}).get("login") != "EdmundFu-233":
        raise SystemExit("trusted promotion sender is not the repository owner")
    payload = event.get("client_payload") or {}
    if set(payload) != {
        "pull_request",
        "head_sha",
        "tree_sha",
        "vm_host_sha256",
        "vm_guest_sha256",
    }:
        raise SystemExit("trusted promotion payload keys are not exact")
    expected_sha = promotion_values["RECASAOS_TRUSTED_PROMOTION_SHA"]
    expected_tree = promotion_values["RECASAOS_TRUSTED_PROMOTION_TREE"]
    expected_host = promotion_values["RECASAOS_TRUSTED_PROMOTION_HOST_SHA256"]
    expected_guest = promotion_values["RECASAOS_TRUSTED_PROMOTION_GUEST_SHA256"]
    if not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (expected_sha, expected_tree)):
        raise SystemExit("trusted promotion commit identity is malformed")
    if not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in (expected_host, expected_guest)):
        raise SystemExit("trusted promotion harness identity is malformed")
    if (
        payload.get("head_sha") != expected_sha
        or payload.get("tree_sha") != expected_tree
        or payload.get("vm_host_sha256") != expected_host
        or payload.get("vm_guest_sha256") != expected_guest
        or actual != expected_sha
        or actual_tree != expected_tree
    ):
        raise SystemExit("trusted promotion payload does not bind the checkout")
elif any(promotion_values.values()):
    raise SystemExit("trusted promotion environment appeared outside its exact event")
elif isinstance(pull_request, dict):
    head = pull_request.get("head") or {}
    base = pull_request.get("base") or {}
    head_repo = head.get("repo") or {}
    base_repo = base.get("repo") or {}
    if not isinstance(head_repo.get("full_name"), str) or "/" not in head_repo.get("full_name"):
        raise SystemExit("pull request head repository identity is malformed")
    if base_repo.get("full_name") != repository.get("full_name"):
        raise SystemExit("pull request base repository identity is not trusted")
    head_sha = head.get("sha")
    base_sha = base.get("sha")
    if not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) for value in (head_sha, base_sha)):
        raise SystemExit("pull request source identity is malformed")
    commit_object = subprocess.check_output(
        ["git", "cat-file", "commit", actual],
        text=True,
    )
    parents = []
    for line in commit_object.splitlines():
        if not line:
            break
        if line.startswith("parent "):
            parents.append(line.removeprefix("parent "))
    if parents != [base_sha, head_sha]:
        raise SystemExit("checked-out pull request merge does not bind the event base and head")
else:
    if actual != os.environ.get("GITHUB_SHA"):
        raise SystemExit("checkout SHA does not match GITHUB_SHA")
    if event.get("ref") != "refs/heads/main" or event.get("after") != actual:
        raise SystemExit("push event is not the exact main commit")
PYTHON

for required_tool in cloud-localds curl file git go qemu-img qemu-system-x86_64 scp sha256sum sha512sum ssh ssh-keygen stat tar timeout; do
  command -v "$required_tool" >/dev/null 2>&1 || fail "required host tool is unavailable: $required_tool"
done
[[ "$(go version)" == "go version go1.26.6 linux/amd64" ]] ||
  fail "the host Go toolchain is not exact Go 1.26.6 linux/amd64"
/usr/bin/python3 -c '
import os
import signal
if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
    raise SystemExit(1)
' || fail "host Python pidfd signaling support is unavailable"

runner_temp=$(cd -- "${RUNNER_TEMP:?RUNNER_TEMP is missing}" && pwd -P)
[[ "$runner_temp" == /* && -d "$runner_temp" && ! -L "$runner_temp" ]] ||
  fail "RUNNER_TEMP is not a safe physical directory"
workspace=$(mktemp -d "$runner_temp/recasaos-userservice-debian11-vm.XXXXXX")
case "$workspace" in
  "$runner_temp"/recasaos-userservice-debian11-vm.[A-Za-z0-9]*) ;;
  *) fail "refusing unsafe VM workspace path: $workspace" ;;
esac

base_image=$workspace/debian-11-generic-amd64.qcow2
overlay_image=$workspace/debian-11-overlay.qcow2
seed_image=$workspace/debian-11-seed.img
user_data=$workspace/user-data
meta_data=$workspace/meta-data
private_key=$workspace/guest-key
known_hosts=$workspace/known-hosts
serial_log=$workspace/serial.log
qemu_log=$workspace/qemu.log
repo_archive=$workspace/recasaos-userservice.tar
source_identity=$workspace/source.sha
candidate=$workspace/casaos-user-service
build_info=$workspace/candidate-build-info
payload_manifest=$workspace/payload.sha256
run_key=${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}
guest_payload=/tmp/recasaos-userservice-vm-payload-${run_key}
image_url='https://cloud.debian.org/images/cloud/bullseye/20260728-2553/debian-11-generic-amd64-20260728-2553.qcow2'
image_sha512='67dcf10dc67b807596c21b36fcd0a752838c124420774737d4badc46cb115b88cc879fac91a22d149d74b2ecd9600a7b4761690900348726e718f501a8564131'
qemu_pid=
qemu_start_time=

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

qemu_process_is_live() {
  local current_start
  [[ "$qemu_pid" =~ ^[0-9]+$ && "$qemu_pid" -gt 1 && "$qemu_start_time" =~ ^[0-9]+$ ]] || return 1
  current_start=$(process_start_time "$qemu_pid" 2>/dev/null) || return 1
  [[ "$current_start" == "$qemu_start_time" ]]
}

signal_exact_process() {
  local pid=$1
  local start_time=$2
  local signal_number=$3
  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 && "$start_time" =~ ^[0-9]+$ ]] || return 1
  [[ "$signal_number" == 9 || "$signal_number" == 15 ]] || return 1
  /usr/bin/python3 - "$pid" "$start_time" "$signal_number" <<'PYTHON'
import os
import signal
import sys

pid = int(sys.argv[1])
expected_start = sys.argv[2].encode("ascii")
signal_number = int(sys.argv[3])
try:
    pidfd = os.pidfd_open(pid, 0)
except ProcessLookupError:
    raise SystemExit(0)
try:
    try:
        with open(f"/proc/{pid}/stat", "rb") as source:
            stat_data = source.read()
    except FileNotFoundError:
        raise SystemExit(0)
    marker = stat_data.rfind(b") ")
    fields = stat_data[marker + 2:].split() if marker >= 0 else []
    if len(fields) <= 19 or not fields[19].isdigit():
        raise RuntimeError("could not parse exact process start time")
    if fields[19] != expected_start:
        raise SystemExit(0)
    try:
        signal.pidfd_send_signal(pidfd, signal_number, None, 0)
    except ProcessLookupError:
        pass
finally:
    os.close(pidfd)
PYTHON
}

cleanup() {
  status=$?
  cleanup_status=0
  trap - EXIT
  set +e
  if qemu_process_is_live; then
    signal_exact_process "$qemu_pid" "$qemu_start_time" 15 || cleanup_status=1
    deadline=$((SECONDS + 10))
    while qemu_process_is_live && ((SECONDS < deadline)); do sleep 0.1; done
  fi
  if qemu_process_is_live; then
    signal_exact_process "$qemu_pid" "$qemu_start_time" 9 || cleanup_status=1
    deadline=$((SECONDS + 5))
    while qemu_process_is_live && ((SECONDS < deadline)); do sleep 0.1; done
  fi
  if qemu_process_is_live; then
    printf 'VM cleanup could not stop the exact QEMU process\n' >&2
    cleanup_status=1
  elif [[ "$qemu_pid" =~ ^[0-9]+$ ]]; then
    wait "$qemu_pid" 2>/dev/null || true
  fi
  if [[ "$status" != 0 ]]; then
    if [[ -s "$qemu_log" ]]; then
      printf 'QEMU diagnostics (credential-free host log):\n' >&2
      tail -n 120 "$qemu_log" >&2
    fi
    if [[ -s "$serial_log" ]]; then
      printf 'Debian guest serial diagnostics (no application journal):\n' >&2
      tail -n 200 "$serial_log" >&2
    fi
  fi
  case "$workspace" in
    "$runner_temp"/recasaos-userservice-debian11-vm.[A-Za-z0-9]*)
      if [[ -d "$workspace" && ! -L "$workspace" ]]; then
        rm -rf -- "$workspace" || cleanup_status=1
      elif [[ -e "$workspace" || -L "$workspace" ]]; then
        printf 'refusing unsafe VM workspace cleanup: %s\n' "$workspace" >&2
        cleanup_status=1
      fi
      ;;
    *)
      printf 'refusing unsafe VM workspace cleanup: %s\n' "$workspace" >&2
      cleanup_status=1
      ;;
  esac
  if [[ "$status" == 0 && "$cleanup_status" != 0 ]]; then status=1; fi
  exit "$status"
}
trap cleanup EXIT

GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -buildvcs=false -o "$candidate" .
[[ -x "$candidate" ]] || fail "the host did not build an executable release candidate"
candidate_description=$(file -b "$candidate")
[[ "$candidate_description" == *'ELF 64-bit LSB executable'* &&
  "$candidate_description" == *'x86-64'* &&
  "$candidate_description" == *'statically linked'* ]] ||
  fail "the release candidate is not a static linux/amd64 ELF binary"
go version -m "$candidate" >"$build_info"
grep -Fq $'path\tgithub.com/EdmundFu-233/ReCasaOS-UserService' "$build_info" ||
  fail "the release candidate module path is unexpected"
grep -Fq $'build\tCGO_ENABLED=0' "$build_info" || fail "the release candidate unexpectedly enables CGO"
grep -Fq $'build\tGOARCH=amd64' "$build_info" || fail "the release candidate architecture is unexpected"
grep -Fq $'build\tGOOS=linux' "$build_info" || fail "the release candidate operating system is unexpected"
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || fail "building the release candidate changed the checkout"

git archive --format=tar --prefix=recasaos-userservice-src/ --output="$repo_archive" "$actual_sha"
printf '%s' "$actual_sha" >"$source_identity"
candidate_hash=$(sha256sum "$candidate" | awk '{ print $1 }')
repo_hash=$(sha256sum "$repo_archive" | awk '{ print $1 }')
source_hash=$(sha256sum "$source_identity" | awk '{ print $1 }')
[[ "$candidate_hash" =~ ^[0-9a-f]{64}$ && "$repo_hash" =~ ^[0-9a-f]{64}$ && "$source_hash" =~ ^[0-9a-f]{64}$ ]] ||
  fail "could not hash the exact VM payload"
printf '%s  casaos-user-service\n%s  recasaos-userservice.tar\n%s  source.sha\n' \
  "$candidate_hash" "$repo_hash" "$source_hash" >"$payload_manifest"

curl --fail --location --proto '=https' --tlsv1.2 \
  --retry 3 --retry-all-errors --connect-timeout 20 --max-time 600 --max-filesize 400000000 \
  --output "$base_image" "$image_url"
base_image_bytes=$(stat -c %s "$base_image")
[[ "$base_image_bytes" =~ ^[0-9]+$ && "$base_image_bytes" -ge 300000000 &&
  "$base_image_bytes" -le 400000000 ]] || fail "Debian cloud image byte size is outside the reviewed bound"
printf '%s  %s\n' "$image_sha512" "$base_image" | sha512sum --check --status ||
  fail "Debian cloud image checksum mismatch"
qemu-img info --output=json "$base_image" >"$workspace/base-image.json"
/usr/bin/python3 - "$workspace/base-image.json" <<'PYTHON'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    info = json.load(source)
if info.get("format") != "qcow2" or info.get("backing-filename") is not None:
    raise SystemExit("base image format or backing chain is unsafe")
size = info.get("virtual-size")
if not isinstance(size, int) or not 1_000_000_000 <= size <= 20_000_000_000:
    raise SystemExit("base image virtual size is outside the reviewed bound")
PYTHON
qemu-img create -f qcow2 -F qcow2 -b "$base_image" "$overlay_image"
qemu-img resize "$overlay_image" 8G
qemu-img info --output=json "$overlay_image" >"$workspace/overlay-image.json"
/usr/bin/python3 - "$workspace/overlay-image.json" "$base_image" <<'PYTHON'
import json
import os
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    info = json.load(source)
if info.get("format") != "qcow2":
    raise SystemExit("overlay image is not qcow2")
backing = info.get("full-backing-filename")
if backing is None or os.path.realpath(backing) != os.path.realpath(sys.argv[2]):
    raise SystemExit("overlay does not use the reviewed base image")
if info.get("virtual-size") != 8 * 1024 * 1024 * 1024:
    raise SystemExit("overlay virtual size is not exactly 8 GiB")
PYTHON

umask 077
ssh-keygen -q -t ed25519 -N '' -f "$private_key"
guest_public_key=$(<"${private_key}.pub")
[[ "$guest_public_key" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+\ .+$ ]] || fail "generated guest SSH public key is malformed"
cat >"$user_data" <<EOF
#cloud-config
users:
  - name: debian
    gecos: ReCasaOS UserService CI
    groups: [adm, sudo]
    shell: /bin/bash
    lock_passwd: true
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $guest_public_key
ssh_pwauth: false
disable_root: true
package_update: true
package_upgrade: false
packages:
  - ca-certificates
  - curl
  - file
  - jq
  - procps
  - python3
  - sqlite3
  - sudo
  - util-linux
EOF
cat >"$meta_data" <<EOF
instance-id: recasaos-userservice-${run_key}
local-hostname: recasaos-userservice-debian11-ci
EOF
cloud-localds "$seed_image" "$user_data" "$meta_data"

ssh_port=$(/usr/bin/python3 - <<'PYTHON'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PYTHON
)
[[ "$ssh_port" =~ ^[0-9]+$ && "$ssh_port" -ge 1024 && "$ssh_port" -le 65535 ]] ||
  fail "could not allocate a safe SSH port"

env -i \
  HOME="$workspace" \
  PATH=/usr/bin:/bin \
  TMPDIR="$workspace" \
  qemu-system-x86_64 \
  -name recasaos-userservice-debian11-ci \
  -machine pc \
  -accel tcg,thread=multi \
  -cpu max \
  -smp 2 \
  -m 2048 \
  -display none \
  -monitor none \
  -nodefaults \
  -no-user-config \
  -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
  -serial "file:$serial_log" \
  -no-reboot \
  -drive "if=virtio,format=qcow2,file=$overlay_image" \
  -drive "if=virtio,format=raw,readonly=on,file=$seed_image" \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${ssh_port}-:22" \
  -device virtio-net-pci,netdev=net0 \
  -device virtio-rng-pci \
  >"$qemu_log" 2>&1 &
qemu_pid=$!
qemu_start_time=$(process_start_time "$qemu_pid") || fail "could not record the exact QEMU process identity"

ssh_common=(
  -F /dev/null
  -i "$private_key"
  -o BatchMode=yes
  -o ConnectTimeout=5
  -o ConnectionAttempts=1
  -o IdentitiesOnly=yes
  -o LogLevel=ERROR
  -o ClearAllForwardings=yes
  -o ForwardAgent=no
  -o ForwardX11=no
  -o PermitLocalCommand=no
  -o ProxyCommand=none
  -o StrictHostKeyChecking=accept-new
  -o "UserKnownHostsFile=$known_hosts"
)
ssh_deadline=$((SECONDS + 600))
until ssh "${ssh_common[@]}" -p "$ssh_port" debian@127.0.0.1 true >/dev/null 2>&1; do
  qemu_process_is_live || fail "QEMU exited before SSH became ready"
  ((SECONDS < ssh_deadline)) || fail "timed out waiting for guest SSH"
  sleep 2
done

timeout --signal=TERM --kill-after=10s 10m \
  ssh "${ssh_common[@]}" -p "$ssh_port" debian@127.0.0.1 \
    'sudo cloud-init status --wait --long' || {
      ssh "${ssh_common[@]}" -p "$ssh_port" debian@127.0.0.1 \
        'sudo cloud-init status --long || true; sudo journalctl --no-pager -u cloud-final.service -n 120 || true' >&2 || true
      fail "cloud-init did not complete successfully"
    }

guest_identity=$(ssh "${ssh_common[@]}" -p "$ssh_port" debian@127.0.0.1 '
  set -eu
  . /etc/os-release
  printf "%s:%s\n" "${ID:-}" "${VERSION_ID:-}"
  cat /proc/1/comm
  systemd --version | sed -n "1p"
  systemctl show --property=Version --value
  systemd-detect-virt --vm
  stat -fc %T /sys/fs/cgroup
  df -B1 --output=size / | awk "NR == 2 { gsub(/[[:space:]]/, \"\"); print }"
') || fail "could not verify the guest platform identity"
guest_release=$(sed -n '1p' <<<"$guest_identity")
guest_pid1=$(sed -n '2p' <<<"$guest_identity")
guest_systemd=$(sed -n '3p' <<<"$guest_identity")
guest_manager=$(sed -n '4p' <<<"$guest_identity")
guest_virt=$(sed -n '5p' <<<"$guest_identity")
guest_cgroup=$(sed -n '6p' <<<"$guest_identity")
guest_root_bytes=$(sed -n '7p' <<<"$guest_identity")
[[ "$guest_release" == debian:11 ]] || fail "guest release is not Debian 11"
[[ "$guest_pid1" == systemd ]] || fail "guest PID 1 is not systemd"
[[ "$guest_systemd" == systemd\ 247* && "$guest_manager" == 247* ]] || fail "guest systemd is not version 247"
[[ "$guest_virt" == qemu ]] || fail "guest virtualization is not QEMU"
[[ "$guest_cgroup" == cgroup2fs ]] || fail "guest is not using unified cgroup v2"
[[ "$guest_root_bytes" =~ ^[0-9]+$ && "$guest_root_bytes" -ge 6442450944 ]] ||
  fail "guest root filesystem did not grow to the reviewed minimum"
printf 'verified isolated Debian 11 VM: %s; %s; manager %s; %s; root=%s bytes\n' \
  "$guest_release" "$guest_systemd" "$guest_manager" "$guest_cgroup" "$guest_root_bytes"

ssh "${ssh_common[@]}" -p "$ssh_port" debian@127.0.0.1 "install -d -m 0700 '$guest_payload'"
scp "${ssh_common[@]}" -P "$ssh_port" \
  "$candidate" "$repo_archive" "$source_identity" "$payload_manifest" \
  "debian@127.0.0.1:${guest_payload}/"
ssh "${ssh_common[@]}" -p "$ssh_port" debian@127.0.0.1 /bin/bash -s -- "$guest_payload" <<'REMOTE_SETUP'
set -euo pipefail
payload=$1
[[ "$payload" =~ ^/tmp/recasaos-userservice-vm-payload-[0-9]+-[0-9]+$ ]] || {
  printf 'unsafe guest payload path\n' >&2
  exit 1
}
cd -- "$payload"
sha256sum --check payload.sha256
sudo test ! -e /opt/recasaos-userservice-src
sudo install -d -o root -g root -m 0755 /opt/recasaos-userservice-src
sudo tar -C /opt -xf recasaos-userservice.tar
sudo install -o root -g root -m 0444 source.sha /opt/recasaos-userservice-src/.git-archive-sha
sudo install -o root -g root -m 0400 /dev/null /root/RECASAOS_DISPOSABLE_E2E_VM
REMOTE_SETUP

timeout --signal=TERM --kill-after=30s 12m \
  ssh "${ssh_common[@]}" -p "$ssh_port" debian@127.0.0.1 \
    sudo env -i \
      HOME=/root \
      USER=root \
      LOGNAME=root \
      SHELL=/bin/bash \
      PATH=/usr/sbin:/usr/bin:/sbin:/bin \
      GITHUB_RUN_ID="$GITHUB_RUN_ID" \
      GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT" \
      RECASAOS_USERSERVICE_SYSTEMD_CI=1 \
      RECASAOS_USERSERVICE_EXPECTED_SHA="$actual_sha" \
      RECASAOS_USERSERVICE_BINARY_SHA256="$candidate_hash" \
      /bin/bash --noprofile --norc \
        /opt/recasaos-userservice-src/scripts/tests/test-systemd-lifecycle.sh \
        "$guest_payload/casaos-user-service"

ssh "${ssh_common[@]}" -p "$ssh_port" debian@127.0.0.1 'sudo systemctl poweroff' >/dev/null 2>&1 || true
shutdown_deadline=$((SECONDS + 90))
while qemu_process_is_live && ((SECONDS < shutdown_deadline)); do sleep 1; done
qemu_process_is_live && fail "QEMU did not exit after guest poweroff"
if wait "$qemu_pid"; then qemu_status=0; else qemu_status=$?; fi
qemu_pid=
qemu_start_time=
[[ "$qemu_status" == 0 ]] || fail "QEMU exited with a nonzero status after guest poweroff"

printf 'UserService Debian 11 systemd 247 PID1 VM passed for %s\n' "$actual_sha"
