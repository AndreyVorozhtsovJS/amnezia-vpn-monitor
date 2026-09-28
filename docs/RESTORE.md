# Restoring Amnezia from a backup

Backups are made every night by the monitor (`backup_time`, default 04:00) and
kept for `backup_keep_days` days in:

```
/var/lib/amnezia-vpn-monitor/backups/<server>/<server>_YYYY-MM-DD_HHMM.tar.gz.enc
```

They are encrypted with `BACKUP_PASSPHRASE` from `.env`. **Keep a copy of that
passphrase outside the monitor VPS** (password manager) — without it the
backups cannot be opened.

Each backup contains, per Amnezia container:

- `opt-amnezia.tar.gz` — `/opt/amnezia` inside the container: server keys,
  the client list (`clientsTable`) and protocol configs
- `inspect.json` — the container definition (image, ports, env)

## 1. Decrypt (on the monitor VPS)

```bash
cd /tmp
F=$(ls -t /var/lib/amnezia-vpn-monitor/backups/vpn-timur/*.enc | head -1)
sudo -u vpnmonitor env $(grep ^BACKUP_PASSPHRASE /opt/amnezia-vpn-monitor/.env) \
  /opt/amnezia-vpn-monitor/.venv/bin/python /opt/amnezia-vpn-monitor/app.py \
  --decrypt-backup "$F" /tmp/restore.tar.gz
mkdir -p /tmp/restore && tar xzf /tmp/restore.tar.gz -C /tmp/restore && ls -R /tmp/restore | head
```

## 2a. Same server, broken container config

```bash
# copy the unpacked folder to the VPN server, then on the VPN server:
C=amnezia-awg2
mkdir -p /tmp/opt && tar xzf /root/restore/$C/opt-amnezia.tar.gz -C /tmp/opt
docker cp /tmp/opt/opt/amnezia/. $C:/opt/amnezia/
docker restart $C
```

## 2b. New VPS (old one lost)

1. Install the same protocol on the new VPS with the Amnezia app.
2. Stop the new container, copy `/opt/amnezia` from the backup into it
   exactly as in 2a, start it.
3. The server keys and the client list are back. **The IP address changed**, so
   clients must get an updated connection: share it again from the Amnezia app
   (existing client entries are kept) or edit the endpoint in their config.
4. Add the new IP to the monitor (`add-known-host.sh`, `config.yaml`).

> Always delete `/tmp/restore*` after use — the files contain private keys.
