#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo: sudo bash scripts/deploy-monitor-host.sh" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR=/opt/amnezia-vpn-monitor
APP_USER=vpnmonitor

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv openssh-client iputils-ping ca-certificates sudo

if ! id "$APP_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
fi

install -d -m 750 -o "$APP_USER" -g "$APP_USER" "$APP_DIR" "$APP_DIR/keys" "$APP_DIR/.ssh"

# Code is root-owned: the service account can read it but cannot modify it.
install -m 644 -o root -g root "$ROOT/app.py" "$APP_DIR/app.py"
install -m 644 -o root -g root "$ROOT/requirements.txt" "$APP_DIR/requirements.txt"

if [ ! -f "$APP_DIR/config.yaml" ]; then
  install -m 600 -o "$APP_USER" -g "$APP_USER" "$ROOT/config.example.yaml" "$APP_DIR/config.yaml"
fi
if [ ! -f "$APP_DIR/.env" ]; then
  install -m 600 -o "$APP_USER" -g "$APP_USER" "$ROOT/.env.example" "$APP_DIR/.env"
fi

if [ ! -f "$APP_DIR/keys/vpnmon_ed25519" ]; then
  sudo -u "$APP_USER" ssh-keygen -t ed25519 -f "$APP_DIR/keys/vpnmon_ed25519" -N "" -C "amnezia-vpn-monitor"
fi
chmod 600 "$APP_DIR/keys/vpnmon_ed25519" "$APP_DIR/config.yaml" "$APP_DIR/.env"
chmod 644 "$APP_DIR/keys/vpnmon_ed25519.pub"

if [ ! -d "$APP_DIR/.venv" ]; then
  sudo -u "$APP_USER" python3 -m venv "$APP_DIR/.venv"
fi
sudo -u "$APP_USER" "$APP_DIR/.venv/bin/pip" install --upgrade pip
sudo -u "$APP_USER" "$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"

install -m 644 "$ROOT/systemd/amnezia-vpn-monitor.service" /etc/systemd/system/amnezia-vpn-monitor.service
systemctl daemon-reload

echo
echo "Deployment files are ready."
echo "1) Public key:"
cat "$APP_DIR/keys/vpnmon_ed25519.pub"
echo
echo "2) Edit: $APP_DIR/config.yaml"
echo "3) Edit: $APP_DIR/.env"
echo "4) Add the first VPS host key: sudo bash scripts/add-known-host.sh VPS_IP 22"
echo "5) Run preflight: sudo -u $APP_USER $APP_DIR/.venv/bin/python $APP_DIR/app.py --check-server vpn-01"
echo "6) Start: systemctl enable --now amnezia-vpn-monitor"
