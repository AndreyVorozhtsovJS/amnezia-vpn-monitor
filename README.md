# Amnezia VPN Monitor

Production-oriented Telegram monitoring for multiple Amnezia VPN VPS servers.

## Features

**Monitoring (every 60 s)**
- VPS reachability over SSH, with an automatic retry for transient stalls
- CPU (hypervisor *steal* reported separately), RAM, disk, load, uptime, pending reboot
- Amnezia container status (AWG / AWG2 / WireGuard / OpenVPN / XRay)
- VPN clients by device name (from Amnezia `clientsTable`), last handshake, traffic
- current RX/TX rate and daily/monthly traffic accounting per server and per device

**Alerts** (to a Telegram chat or group)
- 🔴 server offline · 🟠 VPN container down · 🟡 CPU/RAM/disk above threshold
- 🟢 recovery messages; hysteresis so short spikes do not wake anyone
- optional provider traffic limit (80 % / 95 %)
- VPS payment reminders (5 days and 1 day before)
- ☀️ daily report: uptime, peaks, steal, traffic, payment and backup status

**Operations**
- restart the VPN container from Telegram (with confirmation)
- VPS Internet speed test (Cloudflare, no extra install)
- nightly **encrypted** backup of the Amnezia configuration ([docs/RESTORE.md](docs/RESTORE.md))
- external dead-man's-switch heartbeat (Better Stack / healthchecks.io / Cronitor)
- **smart nightly reboot** for pending OS updates: staggered per server, only when no VPN user is active, otherwise postponed to the next night; no false OFFLINE alert during the planned reboot
- **security**: fail2ban + journald size limit installed automatically, alert on a root login from a never-seen IP, `/security` summary
- inline buttons, built-in admin guide in Russian (`/help`)

Telegram commands:

```text
/status              all servers (with buttons)
/server vpn-01       details
/peers vpn-01        VPN clients and last connection
/traffic [vpn-01]    traffic this month (per day / per device)
/restart_vpn vpn-01  restart the VPN container
/speed [vpn-01]      VPS Internet speed
/history vpn-01 24   history for N hours
/report              daily summary now
/paid [all|vpn-01 YYYY-MM-DD]   VPS payment dates
/backup [vpn-01]     backup Amnezia config now
/security            SSH attacks, fail2ban, root logins
/rucheck [vpn-01]    Is the server reachable from Russia (on demand)
/reboot vpn-01       reboot a server (with confirmation)
/health              bot, watchdog and backup status
/servers  /chatid  /help
```

## Architecture

```text
VPN VPS 1 ─┐
VPN VPS 2 ─┤
VPN VPS 3 ─┼── SSH (restricted key) ──► Monitor VPS ──► Telegram
VPN VPS 4 ─┤                              │
VPN VPS 5 ─┘                              └── SQLite history
```

For production, run the monitor on a separate small Linux VPS. If the monitor is hosted on one of the five VPN VPS servers, an outage of that VPS also disables monitoring and alerts.

## Security model

The monitor does **not** SSH as root.

Each VPN VPS gets a dedicated `vpnmon` user. The monitor's public key is installed with a forced command and OpenSSH `restrict`; the key cannot open an interactive shell or forward ports. It can request only these exact commands:

- `snapshot` — read-only metrics
- `speedtest` — VPS Internet speed
- `restart-vpn` — restart Amnezia protocol containers only
- `backup` — stream the Amnezia configuration (encrypted by the monitor before storing)
- `security` — fail2ban / SSH login summary (read-only)
- `reboot-if-idle` — reboot only if updates are pending AND no VPN user is active (checked on the server itself)
- `reboot-now` — manual reboot after confirmation in Telegram

A root-owned dispatcher maps those exact strings to root-owned scripts, and `sudoers` allows `vpnmon` to run only those scripts. Anything else returns `Command not allowed`.

Do not commit these files:

- `.env`
- `config.yaml`
- `keys/`

They are covered by `.gitignore`.

## Supported monitoring host

Debian/Ubuntu Linux with Python 3.10+ is the intended production host.

## Production deployment

Clone/copy the repository to the monitoring VPS, then from the repository root run:

```bash
sudo bash scripts/deploy-monitor-host.sh
```

This creates:

```text
/opt/amnezia-vpn-monitor/
├── app.py
├── requirements.txt
├── config.yaml
├── .env
├── .venv/
├── keys/vpnmon_ed25519
└── .ssh/
```

The private monitoring key remains on the monitoring VPS.

The script prints the public key. You can print it again with:

```bash
sudo cat /opt/amnezia-vpn-monitor/keys/vpnmon_ed25519.pub
```

## Connect the first real VPN VPS

Follow [docs/FIRST_SERVER.md](docs/FIRST_SERVER.md).

After the first server passes preflight, start the bot:

```bash
sudo systemctl enable --now amnezia-vpn-monitor
sudo systemctl status amnezia-vpn-monitor --no-pager
```

Logs:

```bash
sudo journalctl -u amnezia-vpn-monitor -f
```

## Telegram authorization

Access is deny-by-default. Chats listed in `TELEGRAM_ALLOWED_CHAT_IDS` plus `TELEGRAM_CHAT_ID` may use the bot. While both are empty, only `/start` and `/chatid` respond, so you can safely discover your chat ID.

1. Put the BotFather token into `/opt/amnezia-vpn-monitor/.env`.
2. Start the service.
3. Send `/chatid` to your bot.
4. Put that numeric ID into both:

```text
TELEGRAM_CHAT_ID=123456789
TELEGRAM_ALLOWED_CHAT_IDS=123456789
```

5. Restart:

```bash
sudo systemctl restart amnezia-vpn-monitor
```

For multiple authorized chats:

```text
TELEGRAM_ALLOWED_CHAT_IDS=123456789,-1001234567890
```

## Configuration validation

Before starting systemd:

```bash
sudo -u vpnmonitor /opt/amnezia-vpn-monitor/.venv/bin/python \
  /opt/amnezia-vpn-monitor/app.py \
  --config /opt/amnezia-vpn-monitor/config.yaml \
  --check-config
```

First-server SSH/collector test:

```bash
sudo -u vpnmonitor /opt/amnezia-vpn-monitor/.venv/bin/python \
  /opt/amnezia-vpn-monitor/app.py \
  --config /opt/amnezia-vpn-monitor/config.yaml \
  --check-server vpn-01
```

## Adding servers 2–5

Once `vpn-01` works, repeat the remote installation and known-host steps for each VPS, then add another block to `config.yaml`:

```yaml
  - name: vpn-02
    employee: Employee 2
    host: REAL_IP_OR_HOSTNAME
    port: 22
    user: vpnmon
    key_path: /opt/amnezia-vpn-monitor/keys/vpnmon_ed25519
```

Validate and restart:

```bash
sudo -u vpnmonitor /opt/amnezia-vpn-monitor/.venv/bin/python \
  /opt/amnezia-vpn-monitor/app.py \
  --config /opt/amnezia-vpn-monitor/config.yaml \
  --check-config

sudo systemctl restart amnezia-vpn-monitor
```

## Updating

From your computer (SSH access to all servers):

```bash
# VPN servers: push remote/ scripts, keeps the existing monitoring key
bash scripts/update-vpn-servers.sh IP1 IP2 IP3 ...

# monitor
rsync -av app.py root@MONITOR_IP:/root/amnezia-vpn-monitor/
ssh root@MONITOR_IP 'install -m 644 /root/amnezia-vpn-monitor/app.py /opt/amnezia-vpn-monitor/app.py && systemctl restart amnezia-vpn-monitor'
```

Optional `.env` settings: `HEALTHCHECK_URL` (external watchdog), `BACKUP_PASSPHRASE` (nightly encrypted backups — keep a copy in a password manager).

## Host steal alert

Steal is CPU time the hypervisor gives to other tenants of the same physical host. The bot averages it over `thresholds.steal_minutes` (default 30) and sends 🟡 when the average reaches `thresholds.steal_pct` (default 20%); it clears only when the average drops below half of the threshold. Short spikes in the daily report do not trigger it. If it keeps firing, ask the hoster to move the VPS to another node.

## About `/rucheck`

On-demand only, never scheduled. The bot first checks the server itself from the monitor; only if it is healthy does it ask [check-host.net](https://check-host.net) nodes located in Russia to open TCP port 22 of the server. The VPN port is never probed. All nodes OK means the IP is not blocked; all failing while the monitor sees the server means a likely IP block. Protocol-level (DPI) blocking by a specific ISP is not detected.

## About `/speed`

`/speed vpn-01` measures **VPS → Internet** bandwidth. It does not measure the employee's full route through the tunnel. Employee-side VPN quality requires an agent or test from the employee device and can be added separately.
