#!/usr/bin/env bash
# Run on YOUR COMPUTER (not on a server). Pushes remote/ scripts to each VPN
# server and re-runs install-remote.sh in update mode (keeps the existing key).
#   bash scripts/update-vpn-servers.sh 1.2.3.4 5.6.7.8 ...
# Optional: MONITOR_IP=1.2.3.4 bash scripts/update-vpn-servers.sh ...
#           (whitelists the monitor in fail2ban on first install)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ "$#" -gt 0 ] || { echo "Usage: bash scripts/update-vpn-servers.sh IP [IP ...]"; exit 1; }

REMOTE_CMD="MONITOR_IP='${MONITOR_IP:-}' bash /root/vpnmon-remote/install-remote.sh >/dev/null \
  && /usr/local/sbin/vpn-monitor-snapshot | grep -E '^(vpn_name|vpn_status|peers_online|peers_total)=' \
  && sudo -u vpnmon sudo -n /usr/local/sbin/vpn-monitor-security | grep -E '^(f2b_banned_now|failed_24h)='"

ok=(); failed=()
for ip in "$@"; do
  echo "=== $ip"
  if rsync -a "$ROOT/remote/" "root@$ip:/root/vpnmon-remote/" && ssh "root@$ip" "$REMOTE_CMD"; then
    ok+=("$ip")
  else
    failed+=("$ip")
  fi
done
echo
echo "Updated: ${ok[*]:-none}"
[ "${#failed[@]}" -eq 0 ] || { echo "FAILED: ${failed[*]}"; exit 1; }
