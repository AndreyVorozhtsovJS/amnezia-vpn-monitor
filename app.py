from __future__ import annotations

import argparse
import asyncio
import base64
import datetime as dt
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import paramiko
import yaml
from dotenv import load_dotenv
from telegram import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
)

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("vpn-monitor")
# httpx logs every request URL at INFO, and Telegram URLs contain the bot token.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Server:
    name: str
    employee: str
    host: str
    port: int
    user: str
    key_path: str
    traffic_limit_gb: float | None = None
    paid_until: dt.date | None = None


@dataclass(frozen=True)
class Thresholds:
    cpu_pct: float = 90.0
    memory_pct: float = 90.0
    disk_pct: float = 90.0
    packet_loss_pct: float = 10.0
    ping_ms: float = 200.0


@dataclass(frozen=True)
class Settings:
    poll_interval_seconds: int
    ssh_timeout_seconds: int
    alert_after_failures: int
    resource_alert_after: int
    daily_report_time: dt.time | None
    tz: Any
    traffic_month_start_day: int
    traffic_limit_counts: str
    backup_time: dt.time | None
    backup_keep_days: int
    history_retention_days: int
    known_hosts_path: str
    thresholds: Thresholds
    servers: tuple[Server, ...]


SETTINGS: Settings | None = None
SERVERS: tuple[Server, ...] = ()
SERVER_MAP: dict[str, Server] = {}
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
ALERT_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
DB_PATH = Path(os.getenv("DB_PATH", "data/metrics.db")).expanduser()
HEALTHCHECK_URL = os.getenv("HEALTHCHECK_URL", "").strip()
BACKUP_PASSPHRASE = os.getenv("BACKUP_PASSPHRASE", "")
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", str(DB_PATH.parent / "backups"))).expanduser()
LAST_HEARTBEAT: dict[str, Any] = {"at": None, "ok": None}
LAST_BACKUP: dict[str, dict[str, Any]] = {}

# Explicit path so the result does not depend on $HOME (sudo -u may keep root's HOME).
DEFAULT_KNOWN_HOSTS = str(Path(__file__).resolve().parent / ".ssh" / "known_hosts")

CACHE: dict[str, dict[str, Any]] = {}
PREVIOUS_COUNTERS: dict[str, tuple[float, int, int]] = {}
ALERT_TRACKER: dict[str, dict[str, Any]] = {}
SERVER_LOCKS: dict[str, asyncio.Lock] = {}
SPEEDTEST_LOCKS: dict[str, asyncio.Lock] = {}
RESTART_LOCKS: dict[str, asyncio.Lock] = {}
DB_LOCK: asyncio.Lock | None = None
LAST_POLL_AT: float | None = None


def parse_chat_ids(value: str) -> set[int]:
    if not value.strip():
        return set()
    result: set[int] = set()
    for raw in value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            result.add(int(raw))
        except ValueError as exc:
            raise ConfigError(
                f"TELEGRAM_ALLOWED_CHAT_IDS contains a non-numeric value: {raw!r}"
            ) from exc
    return result


ALLOWED_CHAT_IDS: set[int] = set()


def _as_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _as_float(value: Any, name: str, minimum: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be a number") from exc
    if not minimum <= parsed <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def load_settings(config_path: str | Path) -> Settings:
    path = Path(config_path).expanduser()
    if not path.is_file():
        raise ConfigError(f"Config file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError("Top-level YAML value must be a mapping")

    poll_interval = _as_int(raw.get("poll_interval_seconds", 60), "poll_interval_seconds", 15, 3600)
    ssh_timeout = _as_int(raw.get("ssh_timeout_seconds", 8), "ssh_timeout_seconds", 2, 60)
    alert_after = _as_int(raw.get("alert_after_failures", 3), "alert_after_failures", 1, 20)
    resource_after = _as_int(raw.get("resource_alert_after", 5), "resource_alert_after", 1, 120)

    tz_name = str(raw.get("timezone") or "Europe/Moscow").strip()
    try:
        tz = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ConfigError(f"Unknown timezone: {tz_name}") from exc
    report_raw = raw.get("daily_report_time", "09:00")
    report_time: dt.time | None = None
    if report_raw not in (None, "", False, "off"):
        m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", str(report_raw).strip())
        if not m:
            raise ConfigError("daily_report_time must look like 09:00 (or 'off')")
        report_time = dt.time(int(m.group(1)), int(m.group(2)), tzinfo=tz)
    retention = _as_int(raw.get("history_retention_days", 30), "history_retention_days", 1, 3650)
    backup_raw = raw.get("backup_time", "04:00")
    backup_time: dt.time | None = None
    if backup_raw not in (None, "", False, "off"):
        m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", str(backup_raw).strip())
        if not m:
            raise ConfigError("backup_time must look like 04:00 (or 'off')")
        backup_time = dt.time(int(m.group(1)), int(m.group(2)), tzinfo=tz)
    backup_keep = _as_int(raw.get("backup_keep_days", 14), "backup_keep_days", 1, 365)
    month_start = _as_int(raw.get("traffic_month_start_day", 1), "traffic_month_start_day", 1, 28)
    limit_counts = str(raw.get("traffic_limit_counts", "total")).strip().lower()
    if limit_counts not in ("total", "out", "in"):
        raise ConfigError("traffic_limit_counts must be total, out or in")
    known_hosts = os.path.expanduser(
        str(raw.get("known_hosts_path") or DEFAULT_KNOWN_HOSTS).strip()
    )

    traw = raw.get("thresholds") or {}
    if not isinstance(traw, dict):
        raise ConfigError("thresholds must be a mapping")
    thresholds = Thresholds(
        cpu_pct=_as_float(traw.get("cpu_pct", 90), "thresholds.cpu_pct", 1, 100),
        memory_pct=_as_float(traw.get("memory_pct", 90), "thresholds.memory_pct", 1, 100),
        disk_pct=_as_float(traw.get("disk_pct", 90), "thresholds.disk_pct", 1, 100),
        packet_loss_pct=_as_float(
            traw.get("packet_loss_pct", 10), "thresholds.packet_loss_pct", 0, 100
        ),
        ping_ms=_as_float(traw.get("ping_ms", 200), "thresholds.ping_ms", 1, 10000),
    )

    sraw = raw.get("servers")
    if not isinstance(sraw, list) or not sraw:
        raise ConfigError("servers must be a non-empty list")

    servers: list[Server] = []
    seen: set[str] = set()
    for idx, item in enumerate(sraw, start=1):
        prefix = f"servers[{idx}]"
        if not isinstance(item, dict):
            raise ConfigError(f"{prefix} must be a mapping")

        name = str(item.get("name", "")).strip()
        host = str(item.get("host", "")).strip()
        user = str(item.get("user", "vpnmon")).strip()
        employee = str(item.get("employee", "")).strip()
        key_path = os.path.expanduser(str(item.get("key_path", "")).strip())
        port = _as_int(item.get("port", 22), f"{prefix}.port", 1, 65535)
        paid_raw = item.get("paid_until")
        paid_until = None
        if paid_raw not in (None, ""):
            try:
                paid_until = (paid_raw if isinstance(paid_raw, dt.date)
                              else dt.date.fromisoformat(str(paid_raw).strip()))
            except ValueError as exc:
                raise ConfigError(f"{prefix}.paid_until must look like 2026-10-15") from exc
        limit_raw = item.get("traffic_limit_gb")
        limit_gb = (
            None if limit_raw in (None, "", 0)
            else _as_float(limit_raw, f"{prefix}.traffic_limit_gb", 1, 10_000_000)
        )

        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,39}", name):
            raise ConfigError(f"{prefix}.name is missing or contains unsupported characters")
        if name.lower() in seen:
            raise ConfigError(f"Duplicate server name: {name}")
        seen.add(name.lower())
        if not host:
            raise ConfigError(f"{prefix}.host is required")
        if host.startswith("203.0.113."):
            raise ConfigError(f"{prefix}.host still contains the documentation example IP: {host}")
        if not user:
            raise ConfigError(f"{prefix}.user is required")
        if not key_path:
            raise ConfigError(f"{prefix}.key_path is required")

        servers.append(
            Server(
                name=name,
                employee=employee,
                host=host,
                port=port,
                user=user,
                key_path=key_path,
                traffic_limit_gb=limit_gb,
                paid_until=paid_until,
            )
        )

    return Settings(
        poll_interval_seconds=poll_interval,
        ssh_timeout_seconds=ssh_timeout,
        alert_after_failures=alert_after,
        resource_alert_after=resource_after,
        daily_report_time=report_time,
        tz=tz,
        traffic_month_start_day=month_start,
        traffic_limit_counts=limit_counts,
        backup_time=backup_time,
        backup_keep_days=backup_keep,
        history_retention_days=retention,
        known_hosts_path=known_hosts,
        thresholds=thresholds,
        servers=tuple(servers),
    )


def validate_key_files(settings: Settings) -> list[str]:
    errors: list[str] = []
    checked: set[str] = set()
    for server in settings.servers:
        if server.key_path in checked:
            continue
        checked.add(server.key_path)
        path = Path(server.key_path)
        if not path.is_file():
            errors.append(f"SSH key not found: {path}")
            continue
        try:
            mode = path.stat().st_mode & 0o777
            if mode & 0o077:
                errors.append(f"SSH key permissions are too open ({mode:o}); use chmod 600 {path}")
        except OSError as exc:
            errors.append(f"Cannot stat SSH key {path}: {exc}")
        else:
            try:
                paramiko.PKey.from_path(str(path))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"Cannot load SSH private key {path}: {exc}")
    return errors


def host_key_lookup_name(server: Server) -> str:
    return server.host if server.port == 22 else f"[{server.host}]:{server.port}"


def load_known_hosts(settings: Settings) -> paramiko.HostKeys:
    keys = paramiko.HostKeys()
    path = Path(settings.known_hosts_path)
    if path.is_file():
        keys.load(str(path))
    return keys


def validate_known_hosts(settings: Settings) -> list[str]:
    path = Path(settings.known_hosts_path)
    if not path.is_file():
        return [
            f"known_hosts not found: {path}. "
            "Run: sudo bash scripts/add-known-host.sh SERVER_IP PORT"
        ]
    try:
        keys = load_known_hosts(settings)
    except OSError as exc:
        return [f"Cannot read {path}: {exc}"]
    errors: list[str] = []
    for server in settings.servers:
        if keys.lookup(host_key_lookup_name(server)) is None:
            errors.append(
                f"{server.name}: host key for {server.host}:{server.port} is not in {path}. "
                f"Run: sudo bash scripts/add-known-host.sh {server.host} {server.port}"
            )
    return errors


def configure_runtime(settings: Settings) -> None:
    global SETTINGS, SERVERS, SERVER_MAP, SERVER_LOCKS, SPEEDTEST_LOCKS, DB_LOCK
    SETTINGS = settings
    SERVERS = settings.servers
    SERVER_MAP = {s.name.lower(): s for s in SERVERS}
    SERVER_LOCKS = {s.name: asyncio.Lock() for s in SERVERS}
    SPEEDTEST_LOCKS = {s.name: asyncio.Lock() for s in SERVERS}
    DB_LOCK = asyncio.Lock()


def parse_kv(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def parse_peers(output: str) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    """Parse hs=/tr=/clients=/container= lines emitted by vpn-monitor-snapshot."""
    names: dict[str, str] = {}
    peers: dict[tuple[str, str], dict[str, Any]] = {}
    containers: list[tuple[str, str]] = []
    for line in output.splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        if key == "container":
            cname, _, status = value.partition("|")
            containers.append((cname.strip(), status.strip()))
            continue
        parts = value.split("\t")
        if key == "clients" and len(parts) >= 2:
            try:
                table = json.loads(base64.b64decode(parts[1]).decode("utf-8", "replace"))
                for item in table if isinstance(table, list) else []:
                    cid = str(item.get("clientId", "")).strip()
                    cname = str((item.get("userData") or {}).get("clientName", "")).strip()
                    if cid and cname:
                        names[cid] = cname
            except (ValueError, TypeError, AttributeError):
                pass
        elif key in ("hs", "tr") and len(parts) >= 3:
            src, pub = parts[0], parts[1]
            peer = peers.setdefault((src, pub), {"key": pub, "handshake": 0, "rx": 0, "tx": 0})
            try:
                if key == "hs":
                    peer["handshake"] = int(parts[2])
                elif len(parts) >= 4:
                    peer["rx"], peer["tx"] = int(parts[2]), int(parts[3])
            except ValueError:
                pass
    result = []
    for peer in peers.values():
        peer["name"] = names.get(peer["key"]) or f"{peer['key'][:8]}…"
        result.append(peer)
    return result, containers


def ssh_run(server: Server, command: str, timeout: int | None = None) -> tuple[str, str, int]:
    assert SETTINGS is not None
    timeout = timeout or SETTINGS.ssh_timeout_seconds
    client = paramiko.SSHClient()
    # Only the app's own known_hosts file is trusted; unknown hosts are rejected.
    if Path(SETTINGS.known_hosts_path).is_file():
        client.load_host_keys(SETTINGS.known_hosts_path)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            hostname=server.host,
            port=server.port,
            username=server.user,
            key_filename=server.key_path,
            look_for_keys=False,
            allow_agent=False,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        code = stdout.channel.recv_exit_status()
        return out, err, code
    finally:
        client.close()


def ssh_run_bytes(server: Server, command: str, timeout: int) -> tuple[bytes, str, int]:
    """Like ssh_run but returns raw stdout bytes (for binary payloads)."""
    assert SETTINGS is not None
    client = paramiko.SSHClient()
    if Path(SETTINGS.known_hosts_path).is_file():
        client.load_host_keys(SETTINGS.known_hosts_path)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            hostname=server.host, port=server.port, username=server.user,
            key_filename=server.key_path, look_for_keys=False, allow_agent=False,
            timeout=SETTINGS.ssh_timeout_seconds, banner_timeout=20, auth_timeout=20,
        )
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read()
        err = stderr.read().decode("utf-8", errors="replace")
        return out, err, stdout.channel.recv_exit_status()
    finally:
        client.close()


def ping_host(host: str) -> tuple[float | None, float | None]:
    try:
        p = subprocess.run(
            ["ping", "-c", "3", "-W", "2", host],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        text = (p.stdout or "") + "\n" + (p.stderr or "")
        loss = None
        avg = None

        match = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", text)
        if match:
            loss = float(match.group(1))

        match = re.search(r"=\s*[\d.]+/([\d.]+)/", text)
        if match:
            avg = float(match.group(1))

        return avg, loss
    except Exception:
        return None, None


def fnum(data: dict[str, str], key: str, default: float = 0.0) -> float:
    try:
        return float(data.get(key, default))
    except (TypeError, ValueError):
        return default


def inum(data: dict[str, str], key: str, default: int = 0) -> int:
    try:
        return int(float(data.get(key, default)))
    except (TypeError, ValueError):
        return default


TRANSIENT_SSH_MARKERS = (
    "timeout opening channel", "error reading ssh protocol banner", "timed out",
    "connection reset", "eof", "socket is closed",
)


def is_transient_ssh_error(exc: BaseException) -> bool:
    text = f"{type(exc).__name__} {exc}".lower()
    return any(m in text for m in TRANSIENT_SSH_MARKERS) or isinstance(exc, (TimeoutError, OSError))


def collect_one_blocking(server: Server) -> dict[str, Any]:
    assert SETTINGS is not None
    started = time.time()
    try:
        try:
            out, err, code = ssh_run(server, "snapshot", timeout=max(SETTINGS.ssh_timeout_seconds, 15))
        except Exception as first:  # noqa: BLE001
            # A busy / CPU-starved VPS sometimes stalls for a few seconds while
            # starting the SSH session. Retry once before calling it a failure.
            if not is_transient_ssh_error(first):
                raise
            log.info("Transient SSH error on %s (%s), retrying once", server.name, first)
            time.sleep(2)
            out, err, code = ssh_run(server, "snapshot", timeout=max(SETTINGS.ssh_timeout_seconds, 20))
        if code != 0:
            raise RuntimeError(err.strip() or f"remote exit code {code}")

        raw = parse_kv(out)
        peers, containers = parse_peers(out)
        now = time.time()
        rx = inum(raw, "rx_bytes")
        tx = inum(raw, "tx_bytes")

        rx_mbps: float | None = None
        tx_mbps: float | None = None
        prev = PREVIOUS_COUNTERS.get(server.name)
        if prev:
            prev_ts, prev_rx, prev_tx = prev
            dt = now - prev_ts
            if dt > 0 and rx >= prev_rx and tx >= prev_tx:
                rx_mbps = (rx - prev_rx) * 8 / dt / 1_000_000
                tx_mbps = (tx - prev_tx) * 8 / dt / 1_000_000
        PREVIOUS_COUNTERS[server.name] = (now, rx, tx)

        ping_ms, packet_loss = ping_host(server.host)
        if ping_ms is None and packet_loss is not None and packet_loss >= 100:
            # SSH just succeeded, so the host is up: ICMP is filtered, not lost.
            packet_loss = None

        return {
            "online": True,
            "name": server.name,
            "employee": server.employee,
            "host": server.host,
            "checked_at": now,
            "check_ms": round((time.time() - started) * 1000),
            "cpu_pct": fnum(raw, "cpu_pct"),
            "steal_pct": fnum(raw, "steal_pct") if "steal_pct" in raw else None,
            "mem_pct": fnum(raw, "mem_pct"),
            "disk_pct": fnum(raw, "disk_pct"),
            "load1": fnum(raw, "load1"),
            "uptime_seconds": inum(raw, "uptime_seconds"),
            "disk_free_bytes": inum(raw, "disk_free_bytes"),
            "rx_mbps": rx_mbps,
            "tx_mbps": tx_mbps,
            "ping_ms": ping_ms,
            "packet_loss_pct": packet_loss,
            "network_interface": raw.get("network_interface") or "—",
            "vpn_name": raw.get("vpn_name") or "—",
            "vpn_status": raw.get("vpn_status") or "—",
            "peers_online": inum(raw, "peers_online", -1),
            "peers_total": inum(raw, "peers_total", -1),
            "peers": peers,
            "containers": containers,
            "reboot_required": raw.get("reboot_required") == "1",
            "remote_now": inum(raw, "now", int(now)),
            "rx_bytes": rx,
            "tx_bytes": tx,
        }
    except Exception as exc:
        log.warning("Collection failed for %s: %s", server.name, exc)
        return {
            "online": False,
            "name": server.name,
            "employee": server.employee,
            "host": server.host,
            "checked_at": time.time(),
            "error": str(exc),
        }


async def collect_one(server: Server) -> dict[str, Any]:
    lock = SERVER_LOCKS[server.name]
    async with lock:
        return await asyncio.to_thread(collect_one_blocking, server)


async def collect_all() -> list[dict[str, Any]]:
    results = await asyncio.gather(*(collect_one(server) for server in SERVERS))
    for result in results:
        CACHE[result["name"]] = result
    return results


def _db_connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db_blocking() -> None:
    with _db_connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                server TEXT NOT NULL,
                online INTEGER NOT NULL,
                cpu_pct REAL,
                mem_pct REAL,
                disk_pct REAL,
                load1 REAL,
                rx_mbps REAL,
                tx_mbps REAL,
                ping_ms REAL,
                packet_loss_pct REAL,
                peers_online INTEGER,
                peers_total INTEGER
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_metrics_server_ts ON metrics(server, ts)"
        )
        cols = {row[1] for row in conn.execute("PRAGMA table_info(metrics)")}
        if "steal_pct" not in cols:
            conn.execute("ALTER TABLE metrics ADD COLUMN steal_pct REAL")
        # Last seen raw counters (interface + each VPN peer) to compute deltas.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic_counters (
                server TEXT NOT NULL, key TEXT NOT NULL,
                rx INTEGER NOT NULL, tx INTEGER NOT NULL,
                PRIMARY KEY (server, key)
            )
            """
        )
        # Daily totals. key = IFACE_KEY for the whole server, else peer public key.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic_daily (
                day TEXT NOT NULL, server TEXT NOT NULL, key TEXT NOT NULL,
                name TEXT, rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (day, server, key)
            )
            """
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS payments (server TEXT PRIMARY KEY, paid_until TEXT NOT NULL)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic_limit_alerts (
                server TEXT NOT NULL, period TEXT NOT NULL, level INTEGER NOT NULL,
                PRIMARY KEY (server, period, level)
            )
            """
        )


def save_results_blocking(results: list[dict[str, Any]]) -> None:
    assert SETTINGS is not None
    cutoff = time.time() - SETTINGS.history_retention_days * 86400
    with _db_connect() as conn:
        conn.executemany(
            """
            INSERT INTO metrics (
                ts, server, online, cpu_pct, mem_pct, disk_pct, load1,
                rx_mbps, tx_mbps, ping_ms, packet_loss_pct,
                peers_online, peers_total, steal_pct
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    r["checked_at"],
                    r["name"],
                    1 if r.get("online") else 0,
                    r.get("cpu_pct"),
                    r.get("mem_pct"),
                    r.get("disk_pct"),
                    r.get("load1"),
                    r.get("rx_mbps"),
                    r.get("tx_mbps"),
                    r.get("ping_ms"),
                    r.get("packet_loss_pct"),
                    r.get("peers_online"),
                    r.get("peers_total"),
                    r.get("steal_pct"),
                )
                for r in results
            ],
        )
        conn.execute("DELETE FROM metrics WHERE ts < ?", (cutoff,))
        for r in results:
            if r.get("online"):
                account_traffic(conn, r)
        conn.execute(
            "DELETE FROM traffic_daily WHERE day < ?",
            ((local_now() - dt.timedelta(days=400)).date().isoformat(),),
        )


IFACE_KEY = "__server__"


def local_now() -> dt.datetime:
    assert SETTINGS is not None
    return dt.datetime.now(SETTINGS.tz)


def period_start(day: dt.date) -> dt.date:
    """Start of the billing month that contains `day`."""
    assert SETTINGS is not None
    sd = SETTINGS.traffic_month_start_day
    if day.day >= sd:
        return day.replace(day=sd)
    prev = (day.replace(day=1) - dt.timedelta(days=1)).replace(day=sd)
    return prev


def counter_delta(prev: int | None, new: int) -> int:
    if prev is None:
        return 0
    return new - prev if new >= prev else new  # counter reset (reboot / container restart)


def account_traffic(conn: sqlite3.Connection, r: dict[str, Any]) -> None:
    """Turn raw since-boot counters into per-day totals. Idempotent per snapshot."""
    server = r["name"]
    today = local_now().date()
    boot_day = (local_now() - dt.timedelta(seconds=max(0, r.get("uptime_seconds") or 0))).date()
    # First sighting: counters since boot are attributed to the boot day, but only
    # if the VPS booted inside the current billing period (otherwise they can't be split).
    seed_day = boot_day if boot_day >= period_start(today) else None

    items = [(IFACE_KEY, "server", r.get("rx_bytes") or 0, r.get("tx_bytes") or 0)]
    items += [(p["key"], p.get("name"), p.get("rx") or 0, p.get("tx") or 0) for p in r.get("peers") or []]
    for key, name, rx, tx in items:
        row = conn.execute(
            "SELECT rx, tx FROM traffic_counters WHERE server = ? AND key = ?", (server, key)
        ).fetchone()
        conn.execute(
            "INSERT INTO traffic_counters(server, key, rx, tx) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(server, key) DO UPDATE SET rx = excluded.rx, tx = excluded.tx",
            (server, key, rx, tx),
        )
        if row is None:
            if seed_day is None or not (rx or tx):
                continue
            day, drx, dtx = seed_day, rx, tx
        else:
            day, drx, dtx = today, counter_delta(row[0], rx), counter_delta(row[1], tx)
        if drx or dtx:
            conn.execute(
                "INSERT INTO traffic_daily(day, server, key, name, rx, tx) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(day, server, key) DO UPDATE SET rx = rx + excluded.rx, "
                "tx = tx + excluded.tx, name = excluded.name",
                (day.isoformat(), server, key, name, drx, dtx),
            )


def traffic_summary_blocking() -> dict[str, dict[str, Any]]:
    """Per server: today / yesterday / period totals (rx, tx) for the whole server."""
    today = local_now().date()
    yesterday = today - dt.timedelta(days=1)
    start = period_start(today)
    out: dict[str, dict[str, Any]] = {}
    with _db_connect() as conn:
        for server, day, rx, tx in conn.execute(
            "SELECT server, day, rx, tx FROM traffic_daily WHERE key = ? AND day >= ?",
            (IFACE_KEY, min(start, yesterday).isoformat()),
        ):
            d = out.setdefault(server, {"today": [0, 0], "yesterday": [0, 0], "period": [0, 0],
                                        "since": None})
            dday = dt.date.fromisoformat(day)
            if dday >= start:
                d["period"][0] += rx; d["period"][1] += tx
                d["since"] = min(d["since"] or dday, dday)
            if dday == today:
                d["today"] = [rx, tx]
            elif dday == yesterday:
                d["yesterday"] = [rx, tx]
    for d in out.values():
        d["period_start"] = start
    return out


def traffic_detail_blocking(server: str, days: int = 7) -> dict[str, Any]:
    today = local_now().date()
    start = period_start(today)
    with _db_connect() as conn:
        daily = conn.execute(
            "SELECT day, rx, tx FROM traffic_daily WHERE server = ? AND key = ? AND day >= ? "
            "ORDER BY day DESC",
            (server, IFACE_KEY, (today - dt.timedelta(days=days - 1)).isoformat()),
        ).fetchall()
        peers = conn.execute(
            "SELECT key, MAX(name), SUM(rx), SUM(tx) FROM traffic_daily "
            "WHERE server = ? AND key != ? AND day >= ? GROUP BY key ORDER BY SUM(rx) + SUM(tx) DESC",
            (server, IFACE_KEY, start.isoformat()),
        ).fetchall()
    return {"daily": daily, "peers": peers, "period_start": start}


def limit_used_bytes(server: Server, totals: dict[str, Any] | None) -> int:
    assert SETTINGS is not None
    if not totals:
        return 0
    rx, tx = totals["period"]
    return {"in": rx, "out": tx}.get(SETTINGS.traffic_limit_counts, rx + tx)


async def save_results(results: list[dict[str, Any]]) -> None:
    assert DB_LOCK is not None
    async with DB_LOCK:
        await asyncio.to_thread(save_results_blocking, results)


def history_stats_blocking(server_name: str, hours: int) -> dict[str, Any] | None:
    since = time.time() - hours * 3600
    with _db_connect() as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*),
                AVG(online) * 100.0,
                AVG(cpu_pct), MAX(cpu_pct),
                AVG(mem_pct), MAX(mem_pct),
                AVG(disk_pct), MAX(disk_pct),
                AVG(ping_ms), MAX(ping_ms),
                AVG(packet_loss_pct), MAX(packet_loss_pct),
                AVG(rx_mbps), MAX(rx_mbps),
                AVG(tx_mbps), MAX(tx_mbps)
            FROM metrics
            WHERE server = ? AND ts >= ?
            """,
            (server_name, since),
        ).fetchone()
    if not row or row[0] == 0:
        return None
    return {
        "samples": row[0],
        "availability": row[1],
        "cpu_avg": row[2],
        "cpu_max": row[3],
        "mem_avg": row[4],
        "mem_max": row[5],
        "disk_avg": row[6],
        "disk_max": row[7],
        "ping_avg": row[8],
        "ping_max": row[9],
        "loss_avg": row[10],
        "loss_max": row[11],
        "rx_avg": row[12],
        "rx_max": row[13],
        "tx_avg": row[14],
        "tx_max": row[15],
    }


def human_uptime(seconds: int) -> str:
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def human_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    current = float(value)
    for unit in units:
        if current < 1024 or unit == units[-1]:
            return f"{current:.1f} {unit}"
        current /= 1024
    return f"{current:.1f} TB"


def short_line(result: dict[str, Any]) -> str:
    assert SETTINGS is not None
    if not result.get("online"):
        return f"🔴 {result['name']} — OFFLINE"

    cpu = result["cpu_pct"]
    ram = result["mem_pct"]
    disk = result["disk_pct"]
    ping_ms = result["ping_ms"]
    loss = result["packet_loss_pct"]
    ping = "—" if ping_ms is None else f"{ping_ms:.0f}ms"
    peers = "—" if result["peers_online"] < 0 else str(result["peers_online"])
    t = SETTINGS.thresholds
    warn = (
        cpu >= t.cpu_pct
        or ram >= t.memory_pct
        or disk >= t.disk_pct
        or (loss is not None and loss >= t.packet_loss_pct)
        or (ping_ms is not None and ping_ms >= t.ping_ms)
    )
    icon = "🟠" if vpn_problem(result) else ("🟡" if warn else "🟢")
    return (
        f"{icon} {result['name']} | CPU {cpu:.0f}% | RAM {ram:.0f}% | "
        f"Disk {disk:.0f}% | Ping {ping} | VPN users {peers}"
    )


def detail_text(result: dict[str, Any]) -> str:
    if not result.get("online"):
        return (
            f"🔴 {result['name']} — OFFLINE\n"
            f"Employee: {result.get('employee') or '—'}\n"
            f"Host: {result.get('host')}\n"
            f"Error: {result.get('error', 'unknown error')}"
        )

    rx = "collecting…" if result["rx_mbps"] is None else f"{result['rx_mbps']:.2f} Mbps"
    tx = "collecting…" if result["tx_mbps"] is None else f"{result['tx_mbps']:.2f} Mbps"
    ping = "n/a" if result["ping_ms"] is None else f"{result['ping_ms']:.1f} ms"
    loss = "n/a" if result["packet_loss_pct"] is None else f"{result['packet_loss_pct']:.1f}%"
    peers = (
        "n/a"
        if result["peers_online"] < 0
        else f"{result['peers_online']} / {result['peers_total']}"
    )

    return (
        f"🟢 {result['name']}\n"
        f"Employee: {result.get('employee') or '—'}\n"
        f"Host: {result['host']}\n\n"
        f"CPU: {result['cpu_pct']:.1f}%\n"
        + steal_line(result)
        + f"RAM: {result['mem_pct']:.1f}%\n"
        f"Disk: {result['disk_pct']:.1f}% (free {human_bytes(result['disk_free_bytes'])})\n"
        f"Load 1m: {result['load1']:.2f}\n"
        f"Uptime: {human_uptime(result['uptime_seconds'])}\n\n"
        f"Interface: {result['network_interface']}\n"
        f"Current traffic:\n"
        f"↓ {rx}\n"
        f"↑ {tx}\n"
        f"Ping: {ping}\n"
        f"Loss: {loss}\n\n"
        f"VPN container: {result['vpn_name']}\n"
        f"VPN status: {vpn_status_icon(result)} {result['vpn_status']}\n"
        f"Active peers: {peers}"
        + ("\n\n⚠️ Reboot required (pending updates)" if result.get("reboot_required") else "")
    )


def steal_line(result: dict[str, Any]) -> str:
    steal = result.get("steal_pct")
    if steal is None:
        return ""
    warn = " ⚠️ хостер перегружен" if steal >= 20 else ""
    return f"Steal (забирает хостер): {steal:.1f}%{warn}\n"


def vpn_status_icon(result: dict[str, Any]) -> str:
    return "❌" if vpn_problem(result) else "✅"


def vpn_problem(result: dict[str, Any]) -> str | None:
    """Return a description if a VPN container exists but is not running."""
    bad = [f"{n}: {st}" for n, st in result.get("containers", []) if not st.startswith("Up")]
    return "; ".join(bad) if bad else None


def human_ago(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def peers_text(result: dict[str, Any]) -> str:
    if not result.get("online"):
        return detail_text(result)
    peers = result.get("peers") or []
    if not peers:
        return f"👥 {result['name']}: no AWG/WireGuard peer data available"
    now = result.get("remote_now") or int(time.time())
    peers = sorted(peers, key=lambda p: p["handshake"], reverse=True)
    lines = [f"👥 {result['name']} — {result.get('employee') or ''}".rstrip(" —"), ""]
    for peer in peers:
        hs = peer["handshake"]
        if hs <= 0:
            icon, seen = "⚪", "never connected"
        else:
            age = max(0, now - hs)
            icon = "🟢" if age <= 180 else ("🟡" if age <= 86400 else "⚪")
            seen = human_ago(age)
        lines.append(f"{icon} {peer['name']} — {seen}")
        if peer["rx"] or peer["tx"]:
            lines.append(f"     ↓ {human_bytes(peer['tx'])}  ↑ {human_bytes(peer['rx'])}")
    lines += ["", "🟢 active <3 min · 🟡 today · ⚪ older", "Traffic = since the VPN container started"]
    return "\n".join(lines)


def gb(value: int | float) -> str:
    v = value / 1024**3
    return f"{v:.2f} GB" if v < 10 else f"{v:.1f} GB"


RU_MONTHS = ["янв", "фев", "мар", "апр", "мая", "июн", "июл", "авг", "сен", "окт", "ноя", "дек"]


def ru_date(d: dt.date) -> str:
    return f"{d.day} {RU_MONTHS[d.month - 1]}"


def traffic_overview_text(summary: dict[str, dict[str, Any]]) -> str:
    assert SETTINGS is not None
    start = period_start(local_now().date())
    lines = [f"📊 Трафик с {ru_date(start)} (↓ вход / ↑ выход VPS)", ""]
    grand = 0
    for srv in SERVERS:
        d = summary.get(srv.name)
        if not d:
            lines.append(f"{srv.name}: данных пока нет")
            continue
        rx, tx = d["period"]
        grand += rx + tx
        line = f"{srv.name}: {gb(rx + tx)}  (↓{gb(rx)} ↑{gb(tx)}) · сегодня {gb(sum(d['today']))}"
        if srv.traffic_limit_gb:
            used = limit_used_bytes(srv, d) / 1024**3
            pct = used / srv.traffic_limit_gb * 100
            icon = "🔴" if pct >= 95 else ("🟡" if pct >= 80 else "🟢")
            line += f"\n   {icon} лимит {pct:.0f}% ({used:.0f} из {srv.traffic_limit_gb:.0f} GB)"
        lines.append(line)
        if d.get("since") and d["since"] > start:
            lines.append(f"   учёт с {ru_date(d['since'])}")
    lines += ["", f"Всего: {gb(grand)}", "Подробно: /traffic <сервер>"]
    return "\n".join(lines)


def traffic_detail_text(server: Server, detail: dict[str, Any]) -> str:
    lines = [f"📊 {server.name} — {server.employee or server.host}", "", "По дням (↓ вход / ↑ выход VPS):"]
    if not detail["daily"]:
        lines.append("  данных пока нет")
    for day, rx, tx in detail["daily"]:
        lines.append(f"  {ru_date(dt.date.fromisoformat(day))}: {gb(rx + tx)}  (↓{gb(rx)} ↑{gb(tx)})")
    lines += ["", f"Устройства с {ru_date(detail['period_start'])} (скачал / отправил):"]
    if not detail["peers"]:
        lines.append("  данных пока нет")
    for i, (key, name, rx, tx) in enumerate(detail["peers"]):
        if i >= 20:
            lines.append(f"  … и ещё {len(detail['peers']) - 20}")
            break
        # For the VPN server, tx = sent to the client (client download).
        lines.append(f"  {name or key[:8] + '…'}: ↓{gb(tx)} ↑{gb(rx)}")
    return "\n".join(lines)


async def cmd_traffic(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_authorized(update):
        return
    if context.args:
        server = SERVER_MAP.get(context.args[0].lower())
        if not server:
            await update.effective_message.reply_text("Unknown server. Use /servers.")
            return
        detail = await asyncio.to_thread(traffic_detail_blocking, server.name)
        await update.effective_message.reply_text(
            traffic_detail_text(server, detail), reply_markup=server_keyboard(server.name)
        )
        return
    summary = await asyncio.to_thread(traffic_summary_blocking)
    await update.effective_message.reply_text(traffic_overview_text(summary))


async def check_traffic_limits(context: ContextTypes.DEFAULT_TYPE) -> None:
    if not ALERT_CHAT_ID or not any(s.traffic_limit_gb for s in SERVERS):
        return
    summary = await asyncio.to_thread(traffic_summary_blocking)
    period = period_start(local_now().date()).isoformat()
    for srv in SERVERS:
        if not srv.traffic_limit_gb:
            continue
        used = limit_used_bytes(srv, summary.get(srv.name)) / 1024**3
        pct = used / srv.traffic_limit_gb * 100
        for level in (95, 80):
            if pct < level:
                continue
            def mark() -> bool:
                with _db_connect() as conn:
                    cur = conn.execute(
                        "INSERT OR IGNORE INTO traffic_limit_alerts(server, period, level) VALUES (?, ?, ?)",
                        (srv.name, period, level),
                    )
                    return cur.rowcount == 1
            if await asyncio.to_thread(mark):
                icon = "🔴" if level == 95 else "🟡"
                try:
                    await context.bot.send_message(
                        chat_id=int(ALERT_CHAT_ID),
                        text=(f"{icon} {srv.name} ({srv.employee}): трафик {pct:.0f}% от лимита\n"
                              f"{used:.0f} из {srv.traffic_limit_gb:.0f} GB с {ru_date(dt.date.fromisoformat(period))}\n"
                              f"Подробно: /traffic {srv.name}"),
                    )
                except Exception:  # noqa: BLE001
                    log.exception("Failed to send traffic limit alert")
            break


def server_keyboard(name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("👥 Clients", callback_data=f"peers:{name}"),
                InlineKeyboardButton("📊 Traffic", callback_data=f"traf:{name}"),
                InlineKeyboardButton("↻ Refresh", callback_data=f"srv:{name}"),
            ],
            [
                InlineKeyboardButton("🚀 Speed", callback_data=f"spd:{name}"),
                InlineKeyboardButton("🔄 Restart VPN…", callback_data=f"rstask:{name}"),
            ],
        ]
    )


def status_keyboard() -> InlineKeyboardMarkup:
    buttons = [InlineKeyboardButton(s.name, callback_data=f"srv:{s.name}") for s in SERVERS]
    rows = [buttons[i : i + 2] for i in range(0, len(buttons), 2)]
    rows.append([InlineKeyboardButton("↻ Refresh all", callback_data="status")])
    return InlineKeyboardMarkup(rows)


def effective_allowed_chats() -> set[int]:
    allowed = set(ALLOWED_CHAT_IDS)
    try:
        if ALERT_CHAT_ID:
            allowed.add(int(ALERT_CHAT_ID))
    except ValueError:
        pass
    return allowed


async def ensure_authorized(update: Update) -> bool:
    """Deny by default. With no chat IDs configured only /start and /chatid work."""
    chat = update.effective_chat
    if chat is None:
        return False
    if chat.id in effective_allowed_chats():
        return True
    log.warning("Unauthorized Telegram chat attempted access: %s", chat.id)
    if update.effective_message:
        if not effective_allowed_chats():
            await update.effective_message.reply_text(
                "Bot is not configured yet. Use /chatid and put the ID into "
                "TELEGRAM_ALLOWED_CHAT_IDS / TELEGRAM_CHAT_ID."
            )
        else:
            await update.effective_message.reply_text("Access denied.")
    return False


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "Amnezia VPN Monitor\n\n"
        "/status — все серверы (с кнопками)\n"
        "/server vpn-01 — подробно по серверу\n"
        "/peers vpn-01 — клиенты и когда подключались\n"
        "/restart_vpn vpn-01 — перезапустить VPN\n"
        "/history vpn-01 24 — история за N часов\n"
        "/report — сводка за сутки\n"
        "/traffic — трафик за месяц (/traffic vpn-01 — по дням и устройствам)\n"
        "/speed vpn-01 — скорость интернета VPS\n"
        "/paid — даты оплаты VPS (/paid all 2027-09-14 — всем сразу)\n"
        "/backup — бэкап конфигурации Amnezia сейчас\n"
        "/health — состояние бота\n"
        "/servers — список серверов\n"
        "/chatid — ID этого чата\n\n"
        "📖 /help — как всё работает и что делать при проблемах"
    )
    await update.effective_message.reply_text(text)


def help_texts() -> list[str]:
    assert SETTINGS is not None
    st = SETTINGS
    t = st.thresholds
    poll = st.poll_interval_seconds
    offline_after = st.alert_after_failures * poll
    res_after = st.resource_alert_after * poll
    report = (
        f"каждый день в {st.daily_report_time.strftime('%H:%M')} ({st.daily_report_time.tzinfo})"
        if st.daily_report_time else "выключена"
    )
    example = SERVERS[0].name if SERVERS else "vpn-01"

    guide = f"""📖 КАК РАБОТАЕТ МОНИТОРИНГ

Раз в {poll} с бот заходит на каждый VPN-сервер по SSH ограниченным ключом (он умеет только читать метрики и перезапускать VPN — shell закрыт) и сохраняет результат в историю на {st.history_retention_days} дн.

ЗНАЧКИ В /status
🟢 всё в порядке
🟡 высокая нагрузка (CPU ≥{t.cpu_pct:.0f}%, RAM ≥{t.memory_pct:.0f}% или диск ≥{t.disk_pct:.0f}%)
🟠 сервер жив, но VPN-контейнер остановлен — VPN у сотрудника НЕ работает
🔴 сервер недоступен по SSH (выключен, завис, проблемы у хостера)

ЧТО ОЗНАЧАЮТ ПОЛЯ
• CPU — собственная загрузка сервера за последнюю минуту
• Steal — сколько процессора забрал хостер для соседних VPS. Это не твоя нагрузка, но сервер в это время «притормаживает». Стабильно >10% — перегружен узел хостера; если при этом жалобы на скорость — проси хостера перенести VPS
• RAM / Disk — занято памяти / места на диске
• Ping — «—» норма: серверы не отвечают на ping, доступность проверяется через SSH
• VPN users — клиенты, которые обменивались данными за последние 3 мин
• Current traffic — скорость на сетевой карте VPS прямо сейчас (всех клиентов вместе)
• Reboot required — установлены обновления, нужна перезагрузка

АЛЕРТЫ (приходят сами)
🔴 OFFLINE — нет связи {st.alert_after_failures} проверки подряд (~{offline_after // 60} мин)
🟠 VPN container DOWN — контейнер не работает {st.alert_after_failures} проверки подряд
🟡 CPU / RAM / диск выше порога {st.resource_alert_after} проверок подряд (~{res_after // 60} мин)
🟢 отбой — когда проблема ушла
Короткие всплески не будят — алерт только при устойчивой проблеме.

☀️ Утренняя сводка — {report}: аптайм за сутки, пики нагрузки, максимум пользователей. Нет сводки утром — проверь сам сервер мониторинга.

👥 /peers {example}
🟢 подключался за последние 3 мин — туннель работает
🟡 был сегодня · ⚪ давно или никогда
↓ / ↑ — сколько клиент скачал / отправил с момента запуска VPN-контейнера
Имена устройств — как они названы в приложении Amnezia.

📊 /traffic — трафик каждого сервера с начала месяца, за сегодня и вчера. /traffic {example} — по дням и по каждому устройству. ↓ вход / ↑ выход считаются на сетевой карте VPS: трафик клиента проходит через сервер дважды (внутрь и наружу), поэтому вход и выход примерно равны. Учёт идёт с момента установки этой функции.

🔄 /restart_vpn {example} — перезапускает только VPN-контейнер (сам сервер не перезагружается). Клиенты отключатся на 10–20 с и переподключатся сами. Всегда спрашивает подтверждение.

🚀 /speed {example} или кнопка «Speed» — замер интернет-канала самого VPS через Cloudflare (~30 с, ~70 МБ трафика). Показывает, не упёрся ли сервер в канал хостера.

💳 /paid — до какого числа оплачен каждый VPS. После оплаты: /paid {example} 2026-11-15. За 5 дней и за 1 день до конца бот напомнит в утренней сводке.

💾 Бэкап — каждую ночь бот забирает конфигурацию Amnezia (ключи сервера и список клиентов) со всех серверов, шифрует паролем и хранит {st.backup_keep_days} дн. на сервере мониторинга. /backup — сделать сейчас. Восстановление — docs/RESTORE.md.

🐕 Внешний сторож — если сам бот или сервер мониторинга упадёт, healthchecks.io пришлёт уведомление (статус: /health).

ОГРАНИЧЕНИЯ
• Считаются только клиенты AmneziaWG/WireGuard (не XRay/OpenVPN)
• Бот не видит блокировку VPN у провайдера сотрудника — для этого смотри /peers (ниже)
• Бот отвечает только разрешённым чатам"""

    playbook = f"""🛠 ЧТО ДЕЛАТЬ, ЕСЛИ…

«У МЕНЯ НЕ РАБОТАЕТ VPN»
1. /status — какой значок у сервера сотрудника?
   🔴 → сервер недоступен: панель хостера (включён ли, оплачен ли)
   🟠 → /restart_vpn <сервер>, через минуту проверь /status
   🟢 → сервер в порядке, смотри шаг 2
2. /peers <сервер> — найди устройство сотрудника и попроси его нажать «Подключиться» в Amnezia, затем обнови (↻)
   🟢 обновилось «Ns ago» → туннель работает. Проблема на стороне клиента: конкретный сайт, DNS, приложение. Пусть переподключится или перезапустит Amnezia
   ⚪/🟡 не меняется → трафик не доходит до сервера. Попроси сменить сеть (Wi-Fi ↔ мобильный интернет). Если в одной сети работает, а в другой нет — VPN блокирует провайдер/сеть сотрудника
3. Не работает у нескольких сотрудников на одном сервере → /restart_vpn
4. Ничего не помогло → перевыпусти сотруднику ключ в приложении Amnezia

🟡 ДИСК ПОЧТИ ЗАПОЛНЕН
Зайди на сервер и выполни (безопасно для Amnezia):
journalctl --vacuum-size=100M && apt-get clean && docker image prune -f
Посмотреть, что занимает место: du -xh / --max-depth=2 | sort -h | tail
⚠️ НЕ используй docker system prune — он удалит остановленный контейнер Amnezia вместе с ключами

🟡 ВЫСОКИЙ CPU / RAM ДОЛГО
Открой /peers — кто качает больше всех. Если нагрузка не спадает, перезагрузи сервер ночью (reboot).

⚠️ REBOOT REQUIRED
Перезагрузи сервер в нерабочее время: reboot. Бот пришлёт 🔴, а через 1–2 мин — 🟢. Перезагружай серверы по одному.

🔴 СЕРВЕР OFFLINE ДОЛГО
Проверь в панели хостера: включён ли сервер, оплачен ли, нет ли сообщений об аварии. Перезапусти через панель.

НЕТ УТРЕННЕЙ СВОДКИ
Упал сам сервер мониторинга (или бот). Зайди на него: systemctl status amnezia-vpn-monitor"""
    return [guide, playbook]


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_authorized(update):
        return
    for part in help_texts():
        await update.effective_message.reply_text(part)


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_authorized(update):
        return
    msg = await update.effective_message.reply_text(
        f"Checking {len(SERVERS)} VPN server{'s' if len(SERVERS) != 1 else ''}…"
    )
    results = await collect_all()
    await save_results(results)
    await msg.edit_text(status_text(results), reply_markup=status_keyboard())


def status_text(results: list[dict[str, Any]]) -> str:
    lines = ["VPN SERVERS", ""] + [short_line(result) for result in results]
    lines += ["", "🟢 ok · 🟡 high load · 🟠 VPN container down · 🔴 offline"]
    return "\n".join(lines)


async def cmd_servers(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_authorized(update):
        return
    lines = ["Servers:"] + [f"• {s.name} — {s.employee or s.host}" for s in SERVERS]
    await update.effective_message.reply_text("\n".join(lines))


async def cmd_server(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_authorized(update):
        return
    if not context.args:
        await update.effective_message.reply_text("Usage: /server vpn-01")
        return
    server = SERVER_MAP.get(context.args[0].lower())
    if not server:
        await update.effective_message.reply_text("Unknown server. Use /servers.")
        return

    msg = await update.effective_message.reply_text(f"Checking {server.name}…")
    result = await collect_one(server)
    CACHE[server.name] = result
    await save_results([result])
    await msg.edit_text(detail_text(result), reply_markup=server_keyboard(server.name))


async def cmd_peers(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_authorized(update):
        return
    server = await server_from_args(update, context, "/peers vpn-01")
    if not server:
        return
    msg = await update.effective_message.reply_text(f"Checking clients on {server.name}…")
    result = await collect_one(server)
    CACHE[server.name] = result
    await msg.edit_text(peers_text(result), reply_markup=server_keyboard(server.name))


async def cmd_restart_vpn(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_authorized(update):
        return
    server = await server_from_args(update, context, "/restart_vpn vpn-01")
    if not server:
        return
    await update.effective_message.reply_text(
        restart_question(server), reply_markup=restart_keyboard(server.name)
    )


def restart_question(server: Server) -> str:
    return (
        f"Restart the VPN container on {server.name} ({server.employee or server.host})?\n\n"
        "Connected clients will drop for ~10-20 seconds and reconnect automatically."
    )


def restart_keyboard(name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[
            InlineKeyboardButton("✅ Yes, restart", callback_data=f"rstok:{name}"),
            InlineKeyboardButton("✖ Cancel", callback_data=f"srv:{name}"),
        ]]
    )


def restart_blocking(server: Server) -> str:
    try:
        out, err, code = ssh_run(server, "restart-vpn", timeout=120)
    except Exception as exc:  # noqa: BLE001
        return f"❌ {server.name}: restart failed\n{exc}"
    restarted = [line.split("=", 1)[1] for line in out.splitlines() if line.startswith("restarted=")]
    failed = [line.split("=", 1)[1] for line in out.splitlines() if line.startswith("failed=")]
    _, containers = parse_peers(out)
    lines = [f"{'✅' if code == 0 else '⚠️'} {server.name}: VPN restart"]
    if restarted:
        lines.append("Restarted: " + ", ".join(restarted))
    if failed:
        lines.append("Failed: " + ", ".join(failed))
    for cname, status in containers:
        lines.append(f"{'✅' if status.startswith('Up') else '❌'} {cname}: {status}")
    if code != 0 and not (restarted or failed):
        lines.append(err.strip() or out.strip() or f"exit code {code}")
    return "\n".join(lines)


async def server_from_args(
    update: Update, context: ContextTypes.DEFAULT_TYPE, usage: str
) -> Server | None:
    if not context.args:
        await update.effective_message.reply_text(f"Usage: {usage}\nServers: /servers")
        return None
    server = SERVER_MAP.get(context.args[0].lower())
    if not server:
        await update.effective_message.reply_text("Unknown server. Use /servers.")
    return server


async def on_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None:
        return
    if not await ensure_authorized(update):
        await query.answer("Access denied", show_alert=True)
        return
    action, _, name = (query.data or "").partition(":")
    if action == "status":
        await query.answer("Checking…")
        results = await collect_all()
        await save_results(results)
        await safe_edit(query, status_text(results), status_keyboard())
        return
    server = SERVER_MAP.get(name.lower())
    if not server:
        await query.answer("Unknown server", show_alert=True)
        return
    if action == "srv":
        await query.answer("Checking…")
        result = await collect_one(server)
        CACHE[server.name] = result
        await safe_edit(query, detail_text(result), server_keyboard(server.name))
    elif action == "peers":
        await query.answer("Checking clients…")
        result = await collect_one(server)
        CACHE[server.name] = result
        await safe_edit(query, peers_text(result), server_keyboard(server.name))
    elif action == "spd":
        lock = SPEEDTEST_LOCKS[server.name]
        if lock.locked():
            await query.answer("Speed test already running", show_alert=True)
            return
        await query.answer("Running speed test (~30 s)…")
        await safe_edit(query, f"🚀 Speed test on {server.name}… (~30 s)", None)
        async with lock:
            result = await asyncio.to_thread(speedtest_blocking, server)
        await safe_edit(query, speed_text(server, result), server_keyboard(server.name))
    elif action == "traf":
        await query.answer()
        detail = await asyncio.to_thread(traffic_detail_blocking, server.name)
        await safe_edit(query, traffic_detail_text(server, detail), server_keyboard(server.name))
    elif action == "rstask":
        await query.answer()
        await safe_edit(query, restart_question(server), restart_keyboard(server.name))
    elif action == "rstok":
        lock = RESTART_LOCKS.setdefault(server.name, asyncio.Lock())
        if lock.locked():
            await query.answer("Restart already in progress", show_alert=True)
            return
        await query.answer("Restarting…")
        await safe_edit(query, f"🔄 Restarting VPN on {server.name}…", None)
        user = update.effective_user
        log.warning("VPN restart on %s requested by %s", server.name, user.id if user else "?")
        async with lock:
            text = await asyncio.to_thread(restart_blocking, server)
        await safe_edit(query, text, server_keyboard(server.name))
    else:
        await query.answer()


async def safe_edit(query: Any, text: str, markup: InlineKeyboardMarkup | None) -> None:
    try:
        await query.edit_message_text(text, reply_markup=markup)
    except Exception as exc:  # noqa: BLE001 - e.g. "message is not modified"
        if "not modified" not in str(exc).lower():
            log.warning("Could not edit message: %s", exc)


async def cmd_history(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_authorized(update):
        return
    if not context.args:
        await update.effective_message.reply_text("Usage: /history vpn-01 24")
        return
    server = SERVER_MAP.get(context.args[0].lower())
    if not server:
        await update.effective_message.reply_text("Unknown server. Use /servers.")
        return
    try:
        hours = int(context.args[1]) if len(context.args) > 1 else 24
    except ValueError:
        await update.effective_message.reply_text("Hours must be a number, e.g. /history vpn-01 24")
        return
    hours = max(1, min(hours, 24 * 365))
    stats = await asyncio.to_thread(history_stats_blocking, server.name, hours)
    if not stats:
        await update.effective_message.reply_text(
            f"No history for {server.name} in the last {hours}h yet."
        )
        return

    def fmt(value: float | None, suffix: str = "") -> str:
        return "n/a" if value is None else f"{value:.1f}{suffix}"

    await update.effective_message.reply_text(
        f"📊 {server.name} — last {hours}h\n"
        f"Samples: {stats['samples']}\n"
        f"Availability: {fmt(stats['availability'], '%')}\n\n"
        f"CPU avg/max: {fmt(stats['cpu_avg'], '%')} / {fmt(stats['cpu_max'], '%')}\n"
        f"RAM avg/max: {fmt(stats['mem_avg'], '%')} / {fmt(stats['mem_max'], '%')}\n"
        f"Disk avg/max: {fmt(stats['disk_avg'], '%')} / {fmt(stats['disk_max'], '%')}\n"
        f"Ping avg/max: {fmt(stats['ping_avg'], ' ms')} / {fmt(stats['ping_max'], ' ms')}\n"
        f"Loss avg/max: {fmt(stats['loss_avg'], '%')} / {fmt(stats['loss_max'], '%')}\n"
        f"RX avg/max: {fmt(stats['rx_avg'], ' Mbps')} / {fmt(stats['rx_max'], ' Mbps')}\n"
        f"TX avg/max: {fmt(stats['tx_avg'], ' Mbps')} / {fmt(stats['tx_max'], ' Mbps')}"
    )


def parse_speed_json(text: str) -> dict[str, Any]:
    data = json.loads(text)
    if data.get("error"):
        return {"error": data["error"]}

    if (
        "download" in data
        and "upload" in data
        and isinstance(data["download"], (int, float))
        and isinstance(data["upload"], (int, float))
    ):
        return {
            "download_mbps": float(data["download"]) / 1_000_000,
            "upload_mbps": float(data["upload"]) / 1_000_000,
            "ping_ms": float(data.get("ping", 0)),
            "server": (data.get("server") or {}).get("sponsor", "—"),
        }

    if "download" in data and isinstance(data["download"], dict):
        return {
            "download_mbps": float(data["download"]["bandwidth"]) * 8 / 1_000_000,
            "upload_mbps": float(data["upload"]["bandwidth"]) * 8 / 1_000_000,
            "ping_ms": float((data.get("ping") or {}).get("latency", 0)),
            "server": (data.get("server") or {}).get("name", "—"),
        }

    return {"error": "unknown_speedtest_format"}


def speedtest_blocking(server: Server) -> dict[str, Any]:
    try:
        out, err, code = ssh_run(server, "speedtest", timeout=120)
        if code != 0 and not out.strip():
            return {"error": err.strip() or f"remote exit code {code}"}
        return parse_speed_json(out)
    except Exception as exc:
        log.warning("Speed test failed for %s: %s", server.name, exc)
        return {"error": str(exc)}


async def cmd_speed(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_authorized(update):
        return
    if not context.args:
        buttons = [InlineKeyboardButton(f"🚀 {x.name}", callback_data=f"spd:{x.name}") for x in SERVERS]
        await update.effective_message.reply_text(
            "Где замерить скорость канала VPS? (~30 с)",
            reply_markup=InlineKeyboardMarkup([buttons[i : i + 2] for i in range(0, len(buttons), 2)]),
        )
        return
    server = SERVER_MAP.get(context.args[0].lower())
    if not server:
        await update.effective_message.reply_text("Unknown server. Use /servers.")
        return

    lock = SPEEDTEST_LOCKS[server.name]
    if lock.locked():
        await update.effective_message.reply_text(f"A speed test is already running on {server.name}.")
        return

    msg = await update.effective_message.reply_text(
        f"Running Internet speed test on {server.name}…"
    )
    async with lock:
        result = await asyncio.to_thread(speedtest_blocking, server)

    await msg.edit_text(speed_text(server, result))


def speed_text(server: Server, result: dict[str, Any]) -> str:
    if "error" in result:
        return f"❌ {server.name}: speed test failed\n{result['error']}"
    return (
        f"🚀 {server.name} VPS speed\n"
        f"↓ {result['download_mbps']:.1f} Mbps\n"
        f"↑ {result['upload_mbps']:.1f} Mbps\n"
        f"Ping: {result['ping_ms']:.1f} ms\n"
        f"Test server: {result['server']}\n\n"
        "Это канал самого VPS, не скорость у сотрудника."
    )


async def cmd_health(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_authorized(update):
        return
    if LAST_POLL_AT is None:
        last_poll = "not yet"
    else:
        age = max(0, int(time.time() - LAST_POLL_AT))
        last_poll = f"{age}s ago"
    online = sum(1 for item in CACHE.values() if item.get("online"))
    await update.effective_message.reply_text(
        f"✅ Bot is running\nServers: {len(SERVERS)}\n"
        f"Last known online: {online}/{len(SERVERS)}\nLast poll: {last_poll}\n"
        f"External watchdog: {heartbeat_state()}\n"
        f"Backups: {'on, ' + str(SETTINGS.backup_time)[:5] if BACKUP_PASSPHRASE and SETTINGS and SETTINGS.backup_time else 'OFF'}"
    )


def heartbeat_state() -> str:
    if not HEALTHCHECK_URL:
        return "not configured"
    if LAST_HEARTBEAT["at"] is None:
        return "pending"
    age = int(time.time() - LAST_HEARTBEAT["at"])
    return f"{'ok' if LAST_HEARTBEAT['ok'] else 'FAILING'} ({age}s ago)"


async def cmd_chatid(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.effective_message.reply_text(f"Chat ID: {update.effective_chat.id}")


def alert_conditions(result: dict[str, Any]) -> dict[str, tuple[bool, str]]:
    """Per-kind (is_bad, description) for an ONLINE result."""
    assert SETTINGS is not None
    t = SETTINGS.thresholds
    vpn = vpn_problem(result)
    return {
        "vpn": (vpn is not None, f"VPN container is DOWN\n{vpn}" if vpn else ""),
        "cpu": (result["cpu_pct"] >= t.cpu_pct, f"high CPU {result['cpu_pct']:.0f}% (≥{t.cpu_pct:.0f}%)"),
        "mem": (result["mem_pct"] >= t.memory_pct, f"high RAM {result['mem_pct']:.0f}% (≥{t.memory_pct:.0f}%)"),
        "disk": (result["disk_pct"] >= t.disk_pct, f"disk almost full {result['disk_pct']:.0f}% (≥{t.disk_pct:.0f}%)"),
    }


RECOVERY_TEXT = {
    "offline": "is ONLINE again",
    "vpn": "VPN container is running again",
    "cpu": "CPU back to normal",
    "mem": "RAM back to normal",
    "disk": "disk usage back to normal",
}


async def process_alerts(context: ContextTypes.DEFAULT_TYPE, results: list[dict[str, Any]]) -> None:
    if not ALERT_CHAT_ID:
        return
    assert SETTINGS is not None
    try:
        chat_id = int(ALERT_CHAT_ID)
    except ValueError:
        log.error("TELEGRAM_CHAT_ID must be numeric")
        return

    async def send(text: str) -> bool:
        try:
            await context.bot.send_message(chat_id=chat_id, text=text)
            return True
        except Exception:  # noqa: BLE001 - retry on the next poll
            log.exception("Failed to send Telegram alert")
            return False

    for result in results:
        name = result["name"]
        who = f" ({result.get('employee')})" if result.get("employee") else ""
        if result.get("online"):
            checks = {"offline": (False, "")} | alert_conditions(result)
        else:
            # While offline, only the offline state changes; others keep their state.
            checks = {"offline": (True, result.get("error", ""))}

        for kind, (bad, description) in checks.items():
            state = ALERT_TRACKER.setdefault(f"{name}:{kind}", {"count": 0, "alerted": False})
            if not bad:
                if state["alerted"]:
                    sep = " " if kind == "offline" else ": "
                    if not await send(f"🟢 {name}{who}{sep}{RECOVERY_TEXT[kind]}"):
                        continue
                state["count"] = 0
                state["alerted"] = False
                continue
            state["count"] += 1
            needed = (
                SETTINGS.resource_alert_after
                if kind in ("cpu", "mem", "disk")
                else SETTINGS.alert_after_failures
            )
            if state["count"] >= needed and not state["alerted"]:
                if kind == "offline":
                    text = f"🔴 {name}{who} is OFFLINE\nFailed checks: {state['count']}\n{description}"
                elif kind == "vpn":
                    text = f"🟠 {name}{who}: {description}\n\nFix: /restart_vpn {name}"
                else:
                    text = f"🟡 {name}{who}: {description} for {state['count']} checks in a row"
                state["alerted"] = await send(text)


def report_stats_blocking(hours: int = 24) -> dict[str, dict[str, Any]]:
    since = time.time() - hours * 3600
    with _db_connect() as conn:
        rows = conn.execute(
            """
            SELECT server, COUNT(*), AVG(online) * 100.0,
                   MAX(cpu_pct), MAX(mem_pct), MAX(disk_pct), MAX(peers_online),
                   AVG(steal_pct), MAX(steal_pct)
            FROM metrics WHERE ts >= ? GROUP BY server
            """,
            (since,),
        ).fetchall()
    return {
        r[0]: {"samples": r[1], "availability": r[2], "cpu_max": r[3], "mem_max": r[4],
               "disk_max": r[5], "peers_max": r[6], "steal_avg": r[7], "steal_max": r[8]}
        for r in rows
    }


async def build_report() -> str:
    results = await collect_all()
    await save_results(results)
    stats = await asyncio.to_thread(report_stats_blocking, 24)
    traffic = await asyncio.to_thread(traffic_summary_blocking)

    def f(v: float | None, suffix: str = "%") -> str:
        return "n/a" if v is None else f"{v:.0f}{suffix}"

    lines = ["☀️ VPN daily report (last 24h)", ""]
    for r in results:
        st = stats.get(r["name"], {})
        lines.append(short_line(r))
        extra = (
            f"   uptime {f(st.get('availability'))} · peak CPU {f(st.get('cpu_max'))}"
            f" · RAM {f(st.get('mem_max'))} · disk {f(st.get('disk_max'))}"
        )
        if st.get("peers_max") is not None and st["peers_max"] >= 0:
            extra += f" · max users {st['peers_max']}"
        lines.append(extra)
        if st.get("steal_avg") is not None:
            warn = " ⚠️" if st["steal_avg"] >= 10 else ""
            lines.append(f"   host steal avg {f(st['steal_avg'])} · max {f(st.get('steal_max'))}{warn}")
        t = traffic.get(r["name"])
        if t:
            lines.append(
                f"   traffic: yesterday {gb(sum(t['yesterday']))} · since "
                f"{ru_date(t['period_start'])} {gb(sum(t['period']))}"
            )
        srv_obj = SERVER_MAP.get(r["name"].lower())
        extras = []
        if srv_obj is not None:
            pl = payment_line(srv_obj, await asyncio.to_thread(paid_until_for, srv_obj))
            if pl:
                extras.append(pl)
        bl = backup_status_line(r["name"])
        if bl:
            extras.append(("💾 " if "ok" in bl else "❌ ") + bl)
        if extras:
            lines.append("   " + " · ".join(extras))
        if r.get("reboot_required"):
            lines.append("   ⚠️ reboot required (pending updates)")
    total = sum(s.get("samples", 0) for s in stats.values())
    lines += ["", f"Monitor: {total} checks in 24h. No report tomorrow = check the monitor VPS."]
    return "\n".join(lines)


async def daily_report_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    if not ALERT_CHAT_ID:
        return
    try:
        await context.bot.send_message(chat_id=int(ALERT_CHAT_ID), text=await build_report())
    except Exception:  # noqa: BLE001
        log.exception("Daily report failed")
    await payment_reminders(context)


async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_authorized(update):
        return
    msg = await update.effective_message.reply_text("Building report…")
    await msg.edit_text(await build_report())


# ---------------------------------------------------------------- heartbeat
async def send_heartbeat() -> None:
    """Dead man's switch: an external service alerts if these pings stop."""
    if not HEALTHCHECK_URL:
        return
    import httpx

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(HEALTHCHECK_URL)
        LAST_HEARTBEAT.update(at=time.time(), ok=resp.status_code < 400)
        if resp.status_code >= 400:
            log.warning("Heartbeat rejected: HTTP %s (check HEALTHCHECK_URL)", resp.status_code)
    except Exception as exc:  # noqa: BLE001
        LAST_HEARTBEAT.update(at=time.time(), ok=False)
        log.warning("Heartbeat failed: %s", exc)


# ---------------------------------------------------------------- backups
BACKUP_MAGIC = b"AVMB1"


def _fernet(passphrase: str, salt: bytes) -> Any:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_backup(data: bytes, passphrase: str) -> bytes:
    salt = os.urandom(16)
    return BACKUP_MAGIC + salt + _fernet(passphrase, salt).encrypt(data)


def decrypt_backup(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(BACKUP_MAGIC):
        raise ValueError("not an amnezia-vpn-monitor backup file")
    salt = blob[len(BACKUP_MAGIC):len(BACKUP_MAGIC) + 16]
    return _fernet(passphrase, salt).decrypt(blob[len(BACKUP_MAGIC) + 16:])


def backup_one_blocking(server: Server) -> dict[str, Any]:
    assert SETTINGS is not None
    try:
        data, err, code = ssh_run_bytes(server, "backup", timeout=180)
        if code != 0 or not data.startswith(b"\x1f\x8b"):
            raise RuntimeError(err.strip() or f"remote exit code {code}")
        folder = BACKUP_DIR / server.name
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        stamp = local_now().strftime("%Y-%m-%d_%H%M")
        path = folder / f"{server.name}_{stamp}.tar.gz.enc"
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(encrypt_backup(data, BACKUP_PASSPHRASE))
        os.chmod(tmp, 0o600)
        tmp.replace(path)
        cutoff = time.time() - SETTINGS.backup_keep_days * 86400
        for old in folder.glob("*.tar.gz.enc"):
            if old.stat().st_mtime < cutoff:
                old.unlink()
        return {"ok": True, "at": time.time(), "size": len(data), "file": path.name}
    except Exception as exc:  # noqa: BLE001
        log.warning("Backup failed for %s: %s", server.name, exc)
        return {"ok": False, "at": time.time(), "error": str(exc)}


async def run_backups(servers: tuple[Server, ...] | list[Server]) -> list[str]:
    lines = []
    for srv in servers:  # sequential: gentle on small VPSes
        result = await asyncio.to_thread(backup_one_blocking, srv)
        LAST_BACKUP[srv.name] = result
        if result["ok"]:
            lines.append(f"✅ {srv.name}: {human_bytes(result['size'])} → {result['file']}")
        else:
            lines.append(f"❌ {srv.name}: {result['error']}")
    return lines


async def backup_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    if not BACKUP_PASSPHRASE:
        return
    lines = await run_backups(SERVERS)
    failed = [line for line in lines if line.startswith("❌")]
    if failed and ALERT_CHAT_ID:
        try:
            await context.bot.send_message(
                chat_id=int(ALERT_CHAT_ID), text="💾 Backup failed\n" + "\n".join(failed)
            )
        except Exception:  # noqa: BLE001
            log.exception("Failed to send backup alert")


async def cmd_backup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_authorized(update):
        return
    if not BACKUP_PASSPHRASE:
        await update.effective_message.reply_text(
            "Backups are disabled: set BACKUP_PASSPHRASE in .env and restart the bot."
        )
        return
    targets = list(SERVERS)
    if context.args:
        srv = SERVER_MAP.get(context.args[0].lower())
        if not srv:
            await update.effective_message.reply_text("Unknown server. Use /servers.")
            return
        targets = [srv]
    msg = await update.effective_message.reply_text(f"💾 Backing up {len(targets)} server(s)…")
    lines = await run_backups(targets)
    await msg.edit_text("💾 Backup (encrypted, kept "
                        f"{SETTINGS.backup_keep_days if SETTINGS else '?'} days)\n" + "\n".join(lines))


def backup_status_line(name: str) -> str | None:
    b = LAST_BACKUP.get(name)
    if b is None:
        folder = BACKUP_DIR / name
        files = sorted(folder.glob("*.tar.gz.enc")) if folder.is_dir() else []
        if not files:
            return None
        b = {"ok": True, "at": files[-1].stat().st_mtime}
    when = dt.datetime.fromtimestamp(b["at"], local_now().tzinfo).strftime("%d.%m %H:%M")
    return f"backup {'ok' if b['ok'] else 'FAILED'} {when}"


# ---------------------------------------------------------------- payments
def paid_until_for(server: Server) -> dt.date | None:
    with _db_connect() as conn:
        row = conn.execute("SELECT paid_until FROM payments WHERE server = ?", (server.name,)).fetchone()
    if row:
        return dt.date.fromisoformat(row[0])
    return server.paid_until


def payment_line(server: Server, paid: dt.date | None) -> str | None:
    if paid is None:
        return None
    days = (paid - local_now().date()).days
    if days < 0:
        return f"💳 ❗ оплата просрочена на {-days} дн. (до {ru_date(paid)})"
    icon = "🔴" if days <= 1 else ("🟡" if days <= 5 else "💳")
    return f"{icon} оплачен до {ru_date(paid)} {paid.year} ({days} дн.)"


async def cmd_paid(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/paid                       -> list
    /paid vpn-01 2026-11-15      -> set one
    /paid all 2026-11-15         -> set all
    several "/paid <srv> <date>" lines in one message are all applied."""
    if not await ensure_authorized(update):
        return
    tokens = [t for t in (context.args or []) if not t.lower().startswith("/paid")]
    if tokens:
        if len(tokens) % 2:
            await update.effective_message.reply_text("Формат: /paid vpn-01 2026-11-15 (или /paid all 2026-11-15)")
            return
        updates: list[tuple[Server, dt.date]] = []
        for name, raw_date in zip(tokens[::2], tokens[1::2]):
            try:
                day = dt.date.fromisoformat(raw_date)
            except ValueError:
                await update.effective_message.reply_text(f"Неверная дата «{raw_date}». Формат: 2026-11-15")
                return
            if name.lower() == "all":
                updates += [(srv, day) for srv in SERVERS]
                continue
            srv = SERVER_MAP.get(name.lower())
            if not srv:
                await update.effective_message.reply_text(f"Неизвестный сервер «{name}». Список: /servers")
                return
            updates.append((srv, day))

        def save() -> None:
            with _db_connect() as conn:
                conn.executemany(
                    "INSERT INTO payments(server, paid_until) VALUES (?, ?) "
                    "ON CONFLICT(server) DO UPDATE SET paid_until = excluded.paid_until",
                    [(srv.name, day.isoformat()) for srv, day in updates],
                )
        await asyncio.to_thread(save)
        await update.effective_message.reply_text(
            "\n".join(f"✅ {srv.name}: {payment_line(srv, day)}" for srv, day in updates)
        )
        return
    lines = ["💳 Оплата VPS", ""]
    for srv in SERVERS:
        paid = await asyncio.to_thread(paid_until_for, srv)
        lines.append(f"{srv.name}: {payment_line(srv, paid) or 'дата не указана'}")
    lines += ["", "Указать: /paid vpn-01 2026-11-15 · всем сразу: /paid all 2026-11-15"]
    await update.effective_message.reply_text("\n".join(lines))


async def payment_reminders(context: ContextTypes.DEFAULT_TYPE) -> None:
    if not ALERT_CHAT_ID:
        return
    due = []
    for srv in SERVERS:
        paid = await asyncio.to_thread(paid_until_for, srv)
        if paid is not None and (paid - local_now().date()).days <= 5:
            due.append(f"{srv.name} ({srv.employee}): {payment_line(srv, paid)}")
    if due:
        try:
            await context.bot.send_message(
                chat_id=int(ALERT_CHAT_ID),
                text="💳 Пора оплатить VPS\n\n" + "\n".join(due)
                     + "\n\nПосле оплаты: /paid <сервер> <новая дата>",
            )
        except Exception:  # noqa: BLE001
            log.exception("Failed to send payment reminder")


async def poll_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    global LAST_POLL_AT
    try:
        results = await collect_all()
        await save_results(results)
        LAST_POLL_AT = time.time()
        await process_alerts(context, results)
        await check_traffic_limits(context)
        await send_heartbeat()
    except Exception:
        log.exception("Scheduled poll failed")


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.error("Unhandled Telegram bot error", exc_info=context.error)


async def post_init(application: Application) -> None:
    global LAST_POLL_AT
    assert SETTINGS is not None
    await application.bot.set_my_commands(
        [
            BotCommand("status", "Status of all VPN servers"),
            BotCommand("help", "Как работает бот и что делать при проблемах"),
            BotCommand("server", "Detailed server status"),
            BotCommand("history", "Server history"),
            BotCommand("peers", "VPN clients of a server"),
            BotCommand("restart_vpn", "Restart VPN container"),
            BotCommand("report", "Daily summary now"),
            BotCommand("traffic", "Traffic this month"),
            BotCommand("paid", "VPS payment dates"),
            BotCommand("backup", "Backup Amnezia config now"),
            BotCommand("speed", "Run VPS Internet speed test"),
            BotCommand("health", "Bot health"),
            BotCommand("servers", "List server names"),
            BotCommand("chatid", "Show current chat ID"),
        ]
    )
    await asyncio.to_thread(init_db_blocking)
    results = await collect_all()
    await save_results(results)
    LAST_POLL_AT = time.time()
    for result in results:
        ALERT_TRACKER[f"{result['name']}:offline"] = {
            "count": 0 if result.get("online") else 1,
            "alerted": False,
        }
    if SETTINGS.daily_report_time is not None:
        application.job_queue.run_daily(
            daily_report_job, time=SETTINGS.daily_report_time, name="daily-report"
        )
    if SETTINGS.backup_time is not None and BACKUP_PASSPHRASE:
        application.job_queue.run_daily(backup_job, time=SETTINGS.backup_time, name="backup")
    elif not BACKUP_PASSPHRASE:
        log.warning("BACKUP_PASSPHRASE is not set: nightly Amnezia backups are disabled")
    await send_heartbeat()

    application.job_queue.run_repeating(
        poll_job,
        interval=SETTINGS.poll_interval_seconds,
        first=SETTINGS.poll_interval_seconds,
        name="vpn-poll",
    )
    if not effective_allowed_chats():
        log.warning(
            "No TELEGRAM_ALLOWED_CHAT_IDS / TELEGRAM_CHAT_ID set: only /start and /chatid respond"
        )
    log.info("Bot initialized for %d server(s)", len(SERVERS))


def build_app() -> Application:
    if not BOT_TOKEN or BOT_TOKEN == "PASTE_TOKEN_FROM_BOTFATHER":
        raise ConfigError("TELEGRAM_BOT_TOKEN is missing or still contains the example value")
    app = ApplicationBuilder().token(BOT_TOKEN).post_init(post_init).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("server", cmd_server))
    app.add_handler(CommandHandler("history", cmd_history))
    app.add_handler(CommandHandler("speed", cmd_speed))
    app.add_handler(CommandHandler("peers", cmd_peers))
    app.add_handler(CommandHandler("restart_vpn", cmd_restart_vpn))
    app.add_handler(CommandHandler("report", cmd_report))
    app.add_handler(CommandHandler("traffic", cmd_traffic))
    app.add_handler(CommandHandler("backup", cmd_backup))
    app.add_handler(CommandHandler("paid", cmd_paid))
    app.add_handler(CallbackQueryHandler(on_button))
    app.add_handler(CommandHandler("health", cmd_health))
    app.add_handler(CommandHandler("servers", cmd_servers))
    app.add_handler(CommandHandler("chatid", cmd_chatid))
    app.add_error_handler(error_handler)
    return app


def print_preflight_result(result: dict[str, Any]) -> None:
    if result.get("online"):
        print(detail_text(result))
        return
    print(detail_text(result), file=sys.stderr)
    raise SystemExit(2)


def main() -> None:
    global ALLOWED_CHAT_IDS
    parser = argparse.ArgumentParser(description="Amnezia VPN Monitor")
    parser.add_argument(
        "--config",
        default=os.getenv("CONFIG_PATH", "config.yaml"),
        help="Path to YAML config (default: CONFIG_PATH or config.yaml)",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate configuration and SSH key files, then exit",
    )
    parser.add_argument(
        "--check-server",
        metavar="NAME",
        help="Connect to one configured server, collect a snapshot, then exit",
    )
    parser.add_argument(
        "--decrypt-backup",
        nargs=2,
        metavar=("ENCRYPTED_FILE", "OUTPUT_TAR_GZ"),
        help="Decrypt a backup file (passphrase from BACKUP_PASSPHRASE or prompt)",
    )
    args = parser.parse_args()

    if args.decrypt_backup:
        import getpass

        src, dst = args.decrypt_backup
        phrase = BACKUP_PASSPHRASE or getpass.getpass("Backup passphrase: ")
        try:
            data = decrypt_backup(Path(src).read_bytes(), phrase)
        except Exception as exc:  # noqa: BLE001
            print(f"Cannot decrypt: {str(exc) or 'wrong passphrase or damaged file'}", file=sys.stderr)
            raise SystemExit(2) from exc
        Path(dst).write_bytes(data)
        os.chmod(dst, 0o600)
        print(f"OK: {dst} ({human_bytes(len(data))})")
        return

    try:
        ALLOWED_CHAT_IDS = parse_chat_ids(os.getenv("TELEGRAM_ALLOWED_CHAT_IDS", ""))
        settings = load_settings(args.config)
        configure_runtime(settings)
        key_errors = validate_key_files(settings)
        if key_errors:
            raise ConfigError("; ".join(key_errors))

        if args.check_config:
            host_errors = validate_known_hosts(settings)
            if host_errors:
                raise ConfigError("; ".join(host_errors))
            print(f"OK: config is valid; {len(settings.servers)} server(s) configured")
            return

        if args.check_server:
            server = SERVER_MAP.get(args.check_server.lower())
            if not server:
                raise ConfigError(f"Unknown server: {args.check_server}")
            result = collect_one_blocking(server)
            print_preflight_result(result)
            return

        app = build_app()
        app.run_polling(drop_pending_updates=True)
    except ConfigError as exc:
        log.error("Configuration error: %s", exc)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
