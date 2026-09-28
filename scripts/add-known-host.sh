#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-}"
PORT="${2:-22}"
if [ -z "$HOST" ]; then
  echo "Usage: sudo bash scripts/add-known-host.sh SERVER_IP [PORT]" >&2
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo" >&2
  exit 1
fi

APP_DIR=/opt/amnezia-vpn-monitor
APP_USER=vpnmonitor
install -d -m 700 -o "$APP_USER" -g "$APP_USER" "$APP_DIR/.ssh"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
ssh-keyscan -p "$PORT" -H "$HOST" > "$TMP" 2>/dev/null
if [ ! -s "$TMP" ]; then
  echo "Could not fetch SSH host key from $HOST:$PORT" >&2
  exit 2
fi
cat "$TMP"
echo
echo "Verify this fingerprint against your VPS provider/server console BEFORE accepting it."
ssh-keygen -lf "$TMP"
echo
echo "If it is correct, rerun with ACCEPT=yes:"
echo "  sudo ACCEPT=yes bash scripts/add-known-host.sh '$HOST' '$PORT'"

if [ "${ACCEPT:-no}" = "yes" ]; then
  touch "$APP_DIR/.ssh/known_hosts"
  chown "$APP_USER:$APP_USER" "$APP_DIR/.ssh/known_hosts"
  chmod 600 "$APP_DIR/.ssh/known_hosts"
  grep -Fvx -f "$TMP" "$APP_DIR/.ssh/known_hosts" > "$APP_DIR/.ssh/known_hosts.tmp" || true
  cat "$TMP" >> "$APP_DIR/.ssh/known_hosts.tmp"
  mv "$APP_DIR/.ssh/known_hosts.tmp" "$APP_DIR/.ssh/known_hosts"
  chown "$APP_USER:$APP_USER" "$APP_DIR/.ssh/known_hosts"
  chmod 600 "$APP_DIR/.ssh/known_hosts"
  echo "Host key saved."
fi
