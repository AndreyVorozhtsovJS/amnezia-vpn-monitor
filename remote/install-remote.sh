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
install -m 755 "$SCRIPT_DIR/vpn-monitor-security" /usr/local/sbin/vpn-monitor-security
install -m 755 "$SCRIPT_DIR/vpn-monitor-reboot-if-idle" /usr/local/sbin/vpn-monitor-reboot-if-idle
install -m 755 "$SCRIPT_DIR/vpn-monitor-reboot-now" /usr/local/sbin/vpn-monitor-reboot-now

SUDO_TMP="$(mktemp)"
printf '%s\n' 'vpnmon ALL=(root) NOPASSWD: /usr/local/sbin/vpn-monitor-snapshot, /usr/local/sbin/vpn-monitor-speedtest, /usr/local/sbin/vpn-monitor-restart-vpn, /usr/local/sbin/vpn-monitor-backup, /usr/local/sbin/vpn-monitor-security, /usr/local/sbin/vpn-monitor-reboot-if-idle, /usr/local/sbin/vpn-monitor-reboot-now' > "$SUDO_TMP"
chmod 440 "$SUDO_TMP"
# Validate BEFORE installing: a broken file in sudoers.d can disable sudo.
if command -v visudo >/dev/null 2>&1 && ! visudo -cf "$SUDO_TMP" >/dev/null; then
  rm -f "$SUDO_TMP"; echo "ERROR: generated sudoers rule is invalid, nothing changed" >&2; exit 1
fi
mv -f "$SUDO_TMP" /etc/sudoers.d/vpnmon-monitor

# ---------------------------------------------------------------- hardening
# 1) Limit the systemd journal (SSH brute-force noise can grow it to 500+ MB).
mkdir -p /etc/systemd/journald.conf.d
if [ ! -f /etc/systemd/journald.conf.d/size.conf ]; then
  printf "[Journal]\nSystemMaxUse=100M\nRuntimeMaxUse=30M\nMaxRetentionSec=1month\n" \
    > /etc/systemd/journald.conf.d/size.conf
  systemctl restart systemd-journald 2>/dev/null || true
  journalctl --vacuum-size=100M >/dev/null 2>&1 || true
fi
# 2) fail2ban against SSH password guessing (existing config is kept).
if ! command -v fail2ban-client >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o DPkg::Lock::Timeout=180 fail2ban >/dev/null 2>&1 \
    || echo "WARNING: could not install fail2ban (apt busy?) - rerun later"
fi
if command -v fail2ban-client >/dev/null 2>&1; then
  if [ ! -f /etc/fail2ban/jail.d/sshd.local ]; then
    printf "[sshd]\nenabled = true\nbackend = systemd\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\nbantime.increment = true\nignoreip = 127.0.0.1/8 ::1 %s\n" \
      "${MONITOR_IP:-}" > /etc/fail2ban/jail.d/sshd.local
  fi
  systemctl enable --now fail2ban >/dev/null 2>&1 || true
fi
# Remove a leftover from an earlier manual step (invalid under sudo-rs).
rm -f /etc/sudoers.d/vpnmon-quiet

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
echo "Allowed remote commands through this key: snapshot, speedtest, restart-vpn, backup, security, reboot-if-idle, reboot-now"
echo
command -v curl >/dev/null 2>&1 || echo "WARNING: curl not found - /speed will not work (apt install -y curl)"
