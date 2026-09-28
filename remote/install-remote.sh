#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo bash install-remote.sh '<SSH_PUBLIC_KEY>'"
  exit 1
fi

PUBKEY="${1:-}"
if [ -z "$PUBKEY" ] && [ -f /home/vpnmon/.ssh/authorized_keys ]; then
  # Update mode: reuse the key that is already installed.
  PUBKEY="$(awk '{for(i=1;i<=NF;i++) if($i ~ /^ssh-/){s=$i; for(j=i+1;j<=NF;j++) s=s" "$j; print s; exit}}' /home/vpnmon/.ssh/authorized_keys)"
  [ -n "$PUBKEY" ] && echo "Update mode: keeping the existing monitoring key."
fi
if [ -z "$PUBKEY" ]; then
  echo "Usage: sudo bash install-remote.sh 'ssh-ed25519 AAAA...'"
  exit 1
fi

if [[ "$PUBKEY" != ssh-* ]]; then
  echo "The argument does not look like an OpenSSH public key" >&2
  exit 1
fi

if ! id vpnmon >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash vpnmon
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install -m 755 "$SCRIPT_DIR/vpn-monitor-snapshot" /usr/local/sbin/vpn-monitor-snapshot
install -m 755 "$SCRIPT_DIR/vpn-monitor-speedtest" /usr/local/sbin/vpn-monitor-speedtest
install -m 755 "$SCRIPT_DIR/vpn-monitor-dispatch" /usr/local/sbin/vpn-monitor-dispatch
install -m 755 "$SCRIPT_DIR/vpn-monitor-restart-vpn" /usr/local/sbin/vpn-monitor-restart-vpn
install -m 700 "$SCRIPT_DIR/vpn-monitor-backup" /usr/local/sbin/vpn-monitor-backup

cat >/etc/sudoers.d/vpnmon-monitor <<'EOF'
vpnmon ALL=(root) NOPASSWD: /usr/local/sbin/vpn-monitor-snapshot, /usr/local/sbin/vpn-monitor-speedtest, /usr/local/sbin/vpn-monitor-restart-vpn, /usr/local/sbin/vpn-monitor-backup
EOF
chmod 440 /etc/sudoers.d/vpnmon-monitor

if command -v visudo >/dev/null 2>&1; then
  visudo -cf /etc/sudoers.d/vpnmon-monitor >/dev/null
fi

# Keep the vpnmon systemd user manager running instead of starting/stopping
# it on every monitoring login (once a minute).
loginctl enable-linger vpnmon 2>/dev/null || true

install -d -m 700 -o vpnmon -g vpnmon /home/vpnmon/.ssh
# This key cannot open a shell or forward ports. It can only invoke the dispatcher.
printf 'restrict,command="/usr/local/sbin/vpn-monitor-dispatch" %s\n' "$PUBKEY" \
  > /home/vpnmon/.ssh/authorized_keys
chown vpnmon:vpnmon /home/vpnmon/.ssh/authorized_keys
chmod 600 /home/vpnmon/.ssh/authorized_keys

echo "Monitoring user installed securely."
echo "Allowed remote commands through this key: snapshot, speedtest, restart-vpn, backup"
echo
command -v curl >/dev/null 2>&1 || echo "WARNING: curl not found - /speed will not work (apt install -y curl)"
