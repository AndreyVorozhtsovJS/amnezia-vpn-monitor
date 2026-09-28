# Connect the first real Amnezia VPS

The steps below assume:

- monitoring host: Debian/Ubuntu
- app installed at `/opt/amnezia-vpn-monitor`
- first VPN server will be named `vpn-01`
- you already have administrator/root access to the VPN VPS

Replace `FIRST_VPS_IP` with the real address. If SSH uses a custom port, replace `22` as well.

## 1. Get the monitoring public key

On the monitoring VPS:

```bash
sudo cat /opt/amnezia-vpn-monitor/keys/vpnmon_ed25519.pub
```

Copy the complete single line beginning with `ssh-ed25519`.

Never copy or send the private file `vpnmon_ed25519` to the VPN VPS.

## 2. Copy the four remote files to the VPN VPS

From the repository checkout on your computer or monitoring VPS:

```bash
scp -P 22 remote/vpn-monitor-snapshot \
  remote/vpn-monitor-speedtest \
  remote/vpn-monitor-dispatch \
  remote/install-remote.sh \
  root@FIRST_VPS_IP:/root/
```

If root SSH login is disabled, copy them with your administrative user instead and use `sudo` in the next step.

## 3. Install the restricted `vpnmon` account

On the first VPN VPS:

```bash
ssh root@FIRST_VPS_IP
cd /root
sudo bash install-remote.sh 'ssh-ed25519 AAAA...YOUR_MONITOR_PUBLIC_KEY...'
```

The installer creates `/home/vpnmon/.ssh/authorized_keys` with a forced command. The monitoring key cannot be used as a normal SSH shell key.

Optional speedtest support on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y speedtest-cli
```

## 4. Verify the remote collector locally on the VPN VPS

Still on the VPN VPS:

```bash
sudo /usr/local/sbin/vpn-monitor-snapshot
```

Expected output contains lines like:

```text
cpu_pct=...
mem_pct=...
disk_pct=...
network_interface=...
rx_bytes=...
tx_bytes=...
vpn_name=...
vpn_status=...
peers_online=...
peers_total=...
```

`peers_online` counts peers whose last AWG/WireGuard handshake happened within the last 3 minutes. An idle client without keepalive may therefore be connected but not counted.

If `vpn_name` is empty or `peers_online=-1`, the VPS itself can still be monitored. It only means the current Amnezia protocol/container was not automatically recognized or does not expose AWG/WireGuard peer data.

## 5. Configure `vpn-01` on the monitoring VPS

Edit:

```bash
sudo nano /opt/amnezia-vpn-monitor/config.yaml
```

Use:

```yaml
poll_interval_seconds: 60
ssh_timeout_seconds: 8
alert_after_failures: 3
history_retention_days: 30

thresholds:
  cpu_pct: 90
  memory_pct: 90
  disk_pct: 90
  packet_loss_pct: 10
  ping_ms: 200

servers:
  - name: vpn-01
    employee: Employee 1
    host: FIRST_VPS_IP
    port: 22
    user: vpnmon
    key_path: /opt/amnezia-vpn-monitor/keys/vpnmon_ed25519
```

Then secure the file:

```bash
sudo chown vpnmonitor:vpnmonitor /opt/amnezia-vpn-monitor/config.yaml
sudo chmod 600 /opt/amnezia-vpn-monitor/config.yaml
```

## 6. Add and verify the VPS SSH host key

Do **not** blindly disable SSH host-key checking.

Run:

```bash
sudo bash scripts/add-known-host.sh FIRST_VPS_IP 22
```

The script prints the SSH host-key fingerprint but does not save it yet. Compare the fingerprint with the VPS provider console or with a trusted server-side check such as:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

If it matches, save it:

```bash
sudo ACCEPT=yes bash scripts/add-known-host.sh FIRST_VPS_IP 22
```

## 7. Validate configuration

```bash
sudo -u vpnmonitor /opt/amnezia-vpn-monitor/.venv/bin/python \
  /opt/amnezia-vpn-monitor/app.py \
  --config /opt/amnezia-vpn-monitor/config.yaml \
  --check-config
```

Expected:

```text
OK: config is valid; 1 server(s) configured
```

`--check-config` also verifies that the host key of every server is present in `/opt/amnezia-vpn-monitor/.ssh/known_hosts` (step 6).

## 8. Perform a real end-to-end snapshot test

```bash
sudo -u vpnmonitor /opt/amnezia-vpn-monitor/.venv/bin/python \
  /opt/amnezia-vpn-monitor/app.py \
  --config /opt/amnezia-vpn-monitor/config.yaml \
  --check-server vpn-01
```

Expected result resembles:

```text
🟢 vpn-01
Employee: Employee 1
Host: ...

CPU: ...
RAM: ...
Disk: ...
...
VPN container: ...
VPN status: ...
Active peers: ...
```

Only after this command works should you start the Telegram service.

## 9. Configure Telegram and start the service

Edit:

```bash
sudo nano /opt/amnezia-vpn-monitor/.env
```

At minimum:

```text
TELEGRAM_BOT_TOKEN=YOUR_BOTFATHER_TOKEN
TELEGRAM_CHAT_ID=
TELEGRAM_ALLOWED_CHAT_IDS=
CONFIG_PATH=/opt/amnezia-vpn-monitor/config.yaml
DB_PATH=/var/lib/amnezia-vpn-monitor/metrics.db
LOG_LEVEL=INFO
```

Start:

```bash
sudo systemctl enable --now amnezia-vpn-monitor
sudo journalctl -u amnezia-vpn-monitor -n 100 --no-pager
```

Until chat IDs are set the bot answers only `/start` and `/chatid`. Send `/chatid` to the bot, put that value into `TELEGRAM_CHAT_ID` (alerts; this chat is automatically allowed) and optionally into `TELEGRAM_ALLOWED_CHAT_IDS` for extra chats, then restart:

```bash
sudo systemctl restart amnezia-vpn-monitor
```

## 10. Final checks

In Telegram:

```text
/status
/server vpn-01
/health
```

After enough samples have accumulated:

```text
/history vpn-01 24
```

Run a VPS Internet speed test only when needed:

```text
/speed vpn-01
```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `not found in known_hosts` | Run step 6 for this IP **and port**. |
| `Authentication failed` | Check `/home/vpnmon/.ssh/authorized_keys` on the VPS; if `sshd_config` has `AllowUsers`/`AllowGroups`, add `vpnmon`. |
| `Command not allowed` | Expected for anything except `snapshot`/`speedtest`. |
| `sudo: a password is required` | `/etc/sudoers.d/vpnmon-monitor` missing — rerun `install-remote.sh`. |
| `Ping: n/a` under systemd | The host does not allow unprivileged ICMP; check `sysctl net.ipv4.ping_group_range`. |
| `peers_online=-1` | No `awg`/`wg` on the host and no `*awg*`/`*wireguard*` container; XRay/OpenVPN peers are not counted. |
