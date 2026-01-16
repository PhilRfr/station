import argparse
import json
import os
import secrets
import sqlite3
import sys
import tarfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = "1"
DEFAULTS = {
    "http_backend_start": 17001,
    "http_backend_end": 17100,
    "tcp_start": 7001,
    "tcp_end": 7010,
    "udp_start": 6001,
    "udp_end": 6010,
    "http_backend_strategy": "auto",
}

STATUS_OK = 0
STATUS_USAGE = 2
STATUS_NOT_INITIALIZED = 3
STATUS_CONFLICT = 4
STATUS_DEPLOY_FAILED = 5
STATUS_RUNTIME = 6


@dataclass
class Paths:
    project: Path
    db: Path
    station_dir: Path
    generated_dir: Path
    logs_dir: Path


class StationError(Exception):
    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        self.code = code


def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def resolve_paths(args: argparse.Namespace) -> Paths:
    project = Path(args.project).resolve()
    db = Path(args.db) if args.db else project / ".station" / "station.sqlite3"
    if not db.is_absolute():
        db = (project / db).resolve()
    station_dir = project / ".station"
    generated_dir = station_dir / "generated"
    logs_dir = station_dir / "logs"
    return Paths(project=project, db=db, station_dir=station_dir, generated_dir=generated_dir, logs_dir=logs_dir)


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def ensure_initialized(paths: Paths) -> None:
    if not paths.db.exists():
        raise StationError(
            f"Projet non initialisé: {paths.db} introuvable. Lancez 'station init'.",
            STATUS_NOT_INITIALIZED,
        )


def parse_range(value: str) -> Tuple[int, int]:
    if "-" not in value:
        raise StationError("Range invalide (format min-max)", STATUS_USAGE)
    start_str, end_str = value.split("-", 1)
    try:
        start = int(start_str)
        end = int(end_str)
    except ValueError as exc:
        raise StationError("Range invalide (entiers requis)", STATUS_USAGE) from exc
    if start >= end:
        raise StationError("Range invalide (min doit être < max)", STATUS_USAGE)
    return start, end


def parse_target(value: str) -> Dict[str, Any]:
    if value.startswith("docker:"):
        parts = value.split(":", 2)
        if len(parts) != 3:
            raise StationError("Target docker invalide", STATUS_USAGE)
        name, port_str = parts[1], parts[2]
        try:
            port = int(port_str)
        except ValueError as exc:
            raise StationError("Port docker invalide", STATUS_USAGE) from exc
        return {
            "kind": "docker",
            "docker_name": name,
            "docker_port": port,
            "docker_network": None,
            "host_addr": None,
            "host_port": None,
        }
    if value.startswith("host:"):
        parts = value.split(":", 2)
        if len(parts) != 3:
            raise StationError("Target host invalide", STATUS_USAGE)
        addr, port_str = parts[1], parts[2]
        try:
            port = int(port_str)
        except ValueError as exc:
            raise StationError("Port host invalide", STATUS_USAGE) from exc
        return {
            "kind": "host",
            "docker_name": None,
            "docker_port": None,
            "docker_network": None,
            "host_addr": addr,
            "host_port": port,
        }
    raise StationError("Target invalide (utilisez docker:... ou host:...)", STATUS_USAGE)


def emit(data: Any, args: argparse.Namespace) -> None:
    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        if isinstance(data, str):
            print(data)
        else:
            print(json.dumps(data, indent=2, ensure_ascii=False))


def init_command(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    if paths.db.exists() and not args.force:
        raise StationError("DB déjà existante (utilisez --force pour écraser)", STATUS_CONFLICT)
    paths.station_dir.mkdir(parents=True, exist_ok=True)
    paths.generated_dir.mkdir(parents=True, exist_ok=True)
    paths.logs_dir.mkdir(parents=True, exist_ok=True)
    if paths.db.exists():
        paths.db.unlink()
    conn = connect(paths.db)
    try:
        conn.executescript(
            """
            CREATE TABLE meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE config (
                id INTEGER PRIMARY KEY CHECK(id=1),
                http_backend_start INTEGER NOT NULL,
                http_backend_end INTEGER NOT NULL,
                tcp_start INTEGER NOT NULL,
                tcp_end INTEGER NOT NULL,
                udp_start INTEGER NOT NULL,
                udp_end INTEGER NOT NULL,
                http_backend_strategy TEXT NOT NULL CHECK(http_backend_strategy IN ('auto','manual'))
            );
            CREATE TABLE vps (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                method TEXT NOT NULL CHECK(method IN ('ssh','upload')),
                deploy_path TEXT NOT NULL,
                caddy_domain TEXT,
                rathole_bind TEXT NOT NULL,
                ssh_host TEXT,
                ssh_port INTEGER,
                ssh_user TEXT,
                ssh_key_path TEXT,
                ssh_known_hosts TEXT CHECK(ssh_known_hosts IN ('strict','accept-new','off')),
                upload_url TEXT,
                upload_user TEXT,
                upload_pass TEXT
            );
            CREATE TABLE keys (
                id INTEGER PRIMARY KEY,
                name TEXT,
                private_key TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                active INTEGER NOT NULL CHECK(active IN (0,1))
            );
            CREATE TABLE services (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                type TEXT NOT NULL CHECK(type IN ('http','tcp','udp')),
                enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
                token TEXT NOT NULL,
                hostname TEXT,
                public_port INTEGER,
                backend_port INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE targets (
                service_id INTEGER PRIMARY KEY REFERENCES services(id) ON DELETE CASCADE,
                kind TEXT NOT NULL CHECK(kind IN ('docker','host')),
                docker_name TEXT,
                docker_network TEXT,
                docker_port INTEGER,
                host_addr TEXT,
                host_port INTEGER
            );
            CREATE TABLE deployments (
                id INTEGER PRIMARY KEY,
                vps_id INTEGER NOT NULL REFERENCES vps(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('ok','failed','dry-run')),
                hash TEXT NOT NULL,
                log_path TEXT
            );
            """
        )
        conn.execute("INSERT INTO meta(key, value) VALUES (?, ?)", ("schema_version", SCHEMA_VERSION))
        conn.execute(
            """
            INSERT INTO config(
                id, http_backend_start, http_backend_end, tcp_start, tcp_end, udp_start, udp_end, http_backend_strategy
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                DEFAULTS["http_backend_start"],
                DEFAULTS["http_backend_end"],
                DEFAULTS["tcp_start"],
                DEFAULTS["tcp_end"],
                DEFAULTS["udp_start"],
                DEFAULTS["udp_end"],
                DEFAULTS["http_backend_strategy"],
            ),
        )
        conn.commit()
    finally:
        conn.close()
    emit("Projet initialisé.", args)


def config_show(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        row = conn.execute("SELECT * FROM config WHERE id=1").fetchone()
        meta = conn.execute("SELECT value FROM meta WHERE key='default_vps'").fetchone()
        data = dict(row)
        data["default_vps"] = meta[0] if meta else None
    finally:
        conn.close()
    emit(data, args)


def config_set(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    updates = {}
    if args.http_backend_range:
        updates["http_backend_start"], updates["http_backend_end"] = parse_range(args.http_backend_range)
    if args.tcp_range:
        updates["tcp_start"], updates["tcp_end"] = parse_range(args.tcp_range)
    if args.udp_range:
        updates["udp_start"], updates["udp_end"] = parse_range(args.udp_range)
    if args.http_backend_strategy:
        if args.http_backend_strategy not in ("auto", "manual"):
            raise StationError("Stratégie invalide", STATUS_USAGE)
        updates["http_backend_strategy"] = args.http_backend_strategy
    conn = connect(paths.db)
    try:
        if updates:
            columns = ", ".join(f"{key}=?" for key in updates)
            values = list(updates.values())
            values.append(1)
            conn.execute(f"UPDATE config SET {columns} WHERE id=?", values)
        if args.default_vps:
            conn.execute(
                "INSERT INTO meta(key, value) VALUES ('default_vps', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (args.default_vps,),
            )
        conn.commit()
    finally:
        conn.close()
    emit("Configuration mise à jour.", args)


def vps_add(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    if args.method not in ("ssh", "upload"):
        raise StationError("Méthode invalide", STATUS_USAGE)
    conn = connect(paths.db)
    try:
        conn.execute(
            """
            INSERT INTO vps(
                name, method, deploy_path, caddy_domain, rathole_bind,
                ssh_host, ssh_port, ssh_user, ssh_key_path, ssh_known_hosts,
                upload_url, upload_user, upload_pass
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                args.name,
                args.method,
                args.deploy_path,
                args.caddy_domain,
                args.rathole_bind,
                args.ssh_host,
                args.ssh_port,
                args.ssh_user,
                args.ssh_key,
                args.ssh_known_hosts,
                args.upload_url,
                args.upload_user,
                args.upload_pass,
            ),
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        raise StationError("VPS déjà existant", STATUS_CONFLICT) from exc
    finally:
        conn.close()
    emit("VPS ajouté.", args)


def vps_list(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        rows = conn.execute("SELECT * FROM vps ORDER BY name").fetchall()
        data = [dict(row) for row in rows]
    finally:
        conn.close()
    emit(data, args)


def vps_show(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        row = conn.execute("SELECT * FROM vps WHERE name=?", (args.name,)).fetchone()
        if not row:
            raise StationError("VPS introuvable", STATUS_USAGE)
        data = dict(row)
    finally:
        conn.close()
    emit(data, args)


def vps_set(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    updates = {}
    for field in [
        "method",
        "deploy_path",
        "caddy_domain",
        "rathole_bind",
        "ssh_host",
        "ssh_port",
        "ssh_user",
        "ssh_key",
        "ssh_known_hosts",
        "upload_url",
        "upload_user",
        "upload_pass",
    ]:
        value = getattr(args, field)
        if value is not None:
            column = field if field != "ssh_key" else "ssh_key_path"
            updates[column] = value
    if not updates:
        raise StationError("Aucune option à mettre à jour", STATUS_USAGE)
    conn = connect(paths.db)
    try:
        row = conn.execute("SELECT id FROM vps WHERE name=?", (args.name,)).fetchone()
        if not row:
            raise StationError("VPS introuvable", STATUS_USAGE)
        columns = ", ".join(f"{key}=?" for key in updates)
        values = list(updates.values())
        values.append(args.name)
        conn.execute(f"UPDATE vps SET {columns} WHERE name=?", values)
        conn.commit()
    finally:
        conn.close()
    emit("VPS mis à jour.", args)


def vps_rm(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        row = conn.execute("SELECT id FROM vps WHERE name=?", (args.name,)).fetchone()
        if not row:
            raise StationError("VPS introuvable", STATUS_USAGE)
        conn.execute("DELETE FROM vps WHERE name=?", (args.name,))
        conn.commit()
    finally:
        conn.close()
    emit("VPS supprimé.", args)


def vps_test(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        if args.name:
            row = conn.execute("SELECT * FROM vps WHERE name=?", (args.name,)).fetchone()
        else:
            row = conn.execute(
                "SELECT vps.* FROM vps JOIN meta ON meta.key='default_vps' AND meta.value=vps.name"
            ).fetchone()
        if not row:
            raise StationError("VPS introuvable", STATUS_USAGE)
        vps = dict(row)
    finally:
        conn.close()
    result = {"name": vps["name"], "method": vps["method"], "status": "skipped"}
    emit(result, args)


def keys_list(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        rows = conn.execute("SELECT id, name, public_key, created_at, active FROM keys ORDER BY id").fetchall()
        data = [dict(row) for row in rows]
    finally:
        conn.close()
    emit(data, args)


def keys_show(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        row = conn.execute("SELECT * FROM keys WHERE active=1 ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            raise StationError("Aucune clé active", STATUS_USAGE)
        data = dict(row)
    finally:
        conn.close()
    if not args.reveal:
        data["private_key"] = "***"
    emit(data, args)


def keys_regen(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    private_key = secrets.token_hex(32)
    public_key = secrets.token_hex(16)
    name = args.comment or f"key-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    conn = connect(paths.db)
    try:
        if not args.keep_old:
            conn.execute("UPDATE keys SET active=0")
        conn.execute(
            "INSERT INTO keys(name, private_key, public_key, created_at, active) VALUES (?, ?, ?, ?, 1)",
            (name, private_key, public_key, now_iso()),
        )
        conn.commit()
    finally:
        conn.close()
    emit("Clé régénérée.", args)


def keys_activate(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        row = conn.execute("SELECT id FROM keys WHERE id=?", (args.key_id,)).fetchone()
        if not row:
            raise StationError("Clé introuvable", STATUS_USAGE)
        conn.execute("UPDATE keys SET active=0")
        conn.execute("UPDATE keys SET active=1 WHERE id=?", (args.key_id,))
        conn.commit()
    finally:
        conn.close()
    emit("Clé activée.", args)


def _get_config(conn: sqlite3.Connection) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM config WHERE id=1").fetchone()
    if not row:
        raise StationError("Configuration introuvable", STATUS_RUNTIME)
    return row


def _allocate_backend_port(conn: sqlite3.Connection) -> int:
    config = _get_config(conn)
    used_rows = conn.execute(
        "SELECT backend_port FROM services WHERE type='http' AND backend_port IS NOT NULL"
    ).fetchall()
    used = {row[0] for row in used_rows}
    for port in range(config["http_backend_start"], config["http_backend_end"] + 1):
        if port not in used:
            return port
    raise StationError("Plus de ports backend disponibles", STATUS_CONFLICT)


def _ensure_port_available(conn: sqlite3.Connection, field: str, port: int, service_type: str) -> None:
    row = conn.execute(
        f"SELECT name FROM services WHERE type=? AND {field}=?",
        (service_type, port),
    ).fetchone()
    if row:
        raise StationError("Port déjà utilisé", STATUS_CONFLICT)


def service_add(args: argparse.Namespace, service_type: str) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    target = parse_target(args.target)
    enabled = 1 if args.enabled else 0
    conn = connect(paths.db)
    try:
        config = _get_config(conn)
        backend_port = args.backend_port
        if service_type == "http":
            if config["http_backend_strategy"] == "manual" and backend_port is None:
                raise StationError("backend-port requis", STATUS_USAGE)
            if backend_port is None:
                backend_port = _allocate_backend_port(conn)
            _ensure_port_available(conn, "backend_port", backend_port, "http")
        if service_type in ("tcp", "udp"):
            if args.public_port is None:
                raise StationError("public-port requis", STATUS_USAGE)
            _ensure_port_available(conn, "public_port", args.public_port, service_type)
        conn.execute(
            """
            INSERT INTO services(name, type, enabled, token, hostname, public_port, backend_port, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                args.name,
                service_type,
                enabled,
                args.token or secrets.token_hex(16),
                args.host if service_type == "http" else None,
                args.public_port if service_type in ("tcp", "udp") else None,
                backend_port if service_type == "http" else None,
                now_iso(),
                now_iso(),
            ),
        )
        service_id = conn.execute("SELECT id FROM services WHERE name=?", (args.name,)).fetchone()[0]
        conn.execute(
            """
            INSERT INTO targets(service_id, kind, docker_name, docker_network, docker_port, host_addr, host_port)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                service_id,
                target["kind"],
                target["docker_name"],
                args.network or target["docker_network"],
                target["docker_port"],
                target["host_addr"],
                target["host_port"],
            ),
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        raise StationError("Service déjà existant", STATUS_CONFLICT) from exc
    finally:
        conn.close()
    emit("Service ajouté.", args)


def service_list(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        query = "SELECT * FROM services"
        clauses = []
        values: List[Any] = []
        if args.type:
            clauses.append("type=?")
            values.append(args.type)
        if args.enabled is not None:
            clauses.append("enabled=?")
            values.append(1 if args.enabled else 0)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY name"
        rows = conn.execute(query, values).fetchall()
        data = [dict(row) for row in rows]
    finally:
        conn.close()
    emit(data, args)


def service_show(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        row = conn.execute("SELECT * FROM services WHERE name=?", (args.name,)).fetchone()
        if not row:
            raise StationError("Service introuvable", STATUS_USAGE)
        target = conn.execute("SELECT * FROM targets WHERE service_id=?", (row["id"],)).fetchone()
        data = dict(row)
        data["target"] = dict(target) if target else None
    finally:
        conn.close()
    emit(data, args)


def service_set(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        row = conn.execute("SELECT * FROM services WHERE name=?", (args.name,)).fetchone()
        if not row:
            raise StationError("Service introuvable", STATUS_USAGE)
        updates = {}
        if args.host is not None:
            updates["hostname"] = args.host
        if args.public_port is not None:
            _ensure_port_available(conn, "public_port", args.public_port, row["type"])
            updates["public_port"] = args.public_port
        if args.backend_port is not None:
            _ensure_port_available(conn, "backend_port", args.backend_port, "http")
            updates["backend_port"] = args.backend_port
        if args.token is not None:
            updates["token"] = args.token
        if args.enabled is not None:
            updates["enabled"] = 1 if args.enabled else 0
        updates["updated_at"] = now_iso()
        if updates:
            columns = ", ".join(f"{key}=?" for key in updates)
            values = list(updates.values())
            values.append(args.name)
            conn.execute(f"UPDATE services SET {columns} WHERE name=?", values)
        if args.target:
            target = parse_target(args.target)
            conn.execute(
                """
                UPDATE targets
                SET kind=?, docker_name=?, docker_network=?, docker_port=?, host_addr=?, host_port=?
                WHERE service_id=?
                """,
                (
                    target["kind"],
                    target["docker_name"],
                    args.network or target["docker_network"],
                    target["docker_port"],
                    target["host_addr"],
                    target["host_port"],
                    row["id"],
                ),
            )
        conn.commit()
    finally:
        conn.close()
    emit("Service mis à jour.", args)


def service_rm(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        row = conn.execute("SELECT id FROM services WHERE name=?", (args.name,)).fetchone()
        if not row:
            raise StationError("Service introuvable", STATUS_USAGE)
        conn.execute("DELETE FROM services WHERE name=?", (args.name,))
        conn.commit()
    finally:
        conn.close()
    emit("Service supprimé.", args)


def service_enable(args: argparse.Namespace, enabled: bool) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        row = conn.execute("SELECT id FROM services WHERE name=?", (args.name,)).fetchone()
        if not row:
            raise StationError("Service introuvable", STATUS_USAGE)
        conn.execute("UPDATE services SET enabled=?, updated_at=? WHERE name=?", (1 if enabled else 0, now_iso(), args.name))
        conn.commit()
    finally:
        conn.close()
    emit("Service mis à jour.", args)


def _ensure_dir(path: Path, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise StationError("Chemin de sortie déjà existant", STATUS_CONFLICT)
    path.mkdir(parents=True, exist_ok=True)


def generate_vps(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        if args.name:
            vps = conn.execute("SELECT * FROM vps WHERE name=?", (args.name,)).fetchone()
        else:
            vps = conn.execute(
                "SELECT vps.* FROM vps JOIN meta ON meta.key='default_vps' AND meta.value=vps.name"
            ).fetchone()
        if not vps:
            raise StationError("VPS introuvable", STATUS_USAGE)
        services = conn.execute("SELECT * FROM services WHERE enabled=1").fetchall()
        targets = {
            row["service_id"]: dict(row)
            for row in conn.execute("SELECT * FROM targets").fetchall()
        }
    finally:
        conn.close()
    out_dir = Path(args.out) if args.out else paths.generated_dir / "vps" / vps["name"]
    if not out_dir.is_absolute():
        out_dir = (paths.project / out_dir).resolve()
    _ensure_dir(out_dir, args.overwrite)
    caddy_lines = []
    for svc in services:
        if svc["type"] == "http" and svc["hostname"]:
            caddy_lines.append(f"{svc['hostname']} {{")
            caddy_lines.append(f"    reverse_proxy 127.0.0.1:{svc['backend_port']}")
            caddy_lines.append("}")
    caddyfile = "\n".join(caddy_lines) + "\n" if caddy_lines else ""
    rathole_lines = ["[server]", f"bind = \"{vps['rathole_bind']}\""]
    for svc in services:
        if svc["type"] in ("tcp", "udp"):
            rathole_lines.append("[server.services.%s]" % svc["name"])
            rathole_lines.append(f"type = \"{svc['type']}\"")
            rathole_lines.append(f"bind_addr = \"0.0.0.0:{svc['public_port']}\"")
            rathole_lines.append(f"token = \"{svc['token']}\"")
    rathole_content = "\n".join(rathole_lines) + "\n"
    docker_compose = """
version: "3.8"
services:
  rathole:
    image: ghcr.io/rapiz1/rathole
    volumes:
      - ./rathole-server.toml:/config.toml:ro
    command: ["server", "/config.toml"]
    ports:
      - "{rathole_bind}"
  caddy:
    image: caddy:2
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
    ports:
      - "80:80"
      - "443:443"
""".format(
        rathole_bind=vps["rathole_bind"],
    )
    (out_dir / "Caddyfile").write_text(caddyfile, encoding="utf-8")
    (out_dir / "rathole-server.toml").write_text(rathole_content, encoding="utf-8")
    (out_dir / "docker-compose.yml").write_text(docker_compose.lstrip(), encoding="utf-8")
    emit({"out": str(out_dir)}, args)


def generate_client(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        svc = conn.execute("SELECT * FROM services WHERE name=?", (args.name,)).fetchone()
        if not svc:
            raise StationError("Service introuvable", STATUS_USAGE)
        target = conn.execute("SELECT * FROM targets WHERE service_id=?", (svc["id"],)).fetchone()
        vps = conn.execute(
            "SELECT vps.* FROM vps JOIN meta ON meta.key='default_vps' AND meta.value=vps.name"
        ).fetchone()
        if not vps:
            raise StationError("VPS par défaut introuvable", STATUS_USAGE)
    finally:
        conn.close()
    out_dir = Path(args.out) if args.out else paths.generated_dir / "clients" / svc["name"]
    if not out_dir.is_absolute():
        out_dir = (paths.project / out_dir).resolve()
    _ensure_dir(out_dir, args.overwrite)
    network = args.network or target["docker_network"]
    client_lines = ["[client]", f"remote_addr = \"{vps['rathole_bind']}\""]
    client_lines.append("[client.services.%s]" % svc["name"])
    client_lines.append(f"token = \"{svc['token']}\"")
    if svc["type"] == "http":
        client_lines.append(f"local_addr = \"127.0.0.1:{svc['backend_port']}\"")
        client_lines.append("type = \"tcp\"")
    else:
        target_addr = "127.0.0.1"
        port = target["docker_port"] or target["host_port"]
        client_lines.append(f"local_addr = \"{target_addr}:{port}\"")
        client_lines.append(f"type = \"{svc['type']}\"")
    client_content = "\n".join(client_lines) + "\n"
    run_script = f"""#!/usr/bin/env bash
set -euo pipefail
CONFIG=\"{out_dir / 'client.toml'}\"
IMAGE=\"ghcr.io/rapiz1/rathole\"
NAME=\"rathole_{svc['name']}\"
NET_ARG=()
if [ -n \"{network or ''}\" ]; then
  NET_ARG=(--network \"{network}\")
fi
docker run -d --name \"${{NAME}}\" --restart unless-stopped "${{NET_ARG[@]}}" \
  -v \"${{CONFIG}}:/config.toml:ro\" "${{IMAGE}}" client /config.toml
"""
    (out_dir / "client.toml").write_text(client_content, encoding="utf-8")
    run_path = out_dir / "run.sh"
    run_path.write_text(run_script, encoding="utf-8")
    run_path.chmod(0o755)
    emit({"out": str(out_dir)}, args)


def _bundle_dir(src: Path, bundle_path: Path) -> None:
    if bundle_path.exists():
        bundle_path.unlink()
    with tarfile.open(bundle_path, "w:gz") as tar:
        tar.add(src, arcname=".")


def deploy_command(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        if args.name:
            vps = conn.execute("SELECT * FROM vps WHERE name=?", (args.name,)).fetchone()
        else:
            vps = conn.execute(
                "SELECT vps.* FROM vps JOIN meta ON meta.key='default_vps' AND meta.value=vps.name"
            ).fetchone()
        if not vps:
            raise StationError("VPS introuvable", STATUS_USAGE)
    finally:
        conn.close()
    generate_args = argparse.Namespace(
        project=str(paths.project),
        db=str(paths.db),
        json=True,
        name=vps["name"],
        out=None,
        overwrite=True,
    )
    generate_vps(generate_args)
    out_dir = paths.generated_dir / "vps" / vps["name"]
    bundle_path = out_dir / "bundle.tar.gz"
    _bundle_dir(out_dir, bundle_path)
    log_path = Path(args.log) if args.log else paths.logs_dir / f"deploy-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.log"
    status = "dry-run" if args.dry_run else "ok"
    log_path.write_text(f"deploy {status}\n", encoding="utf-8")
    conn = connect(paths.db)
    try:
        conn.execute(
            "INSERT INTO deployments(vps_id, created_at, status, hash, log_path) VALUES (?, ?, ?, ?, ?)",
            (vps["id"], now_iso(), status, secrets.token_hex(8), str(log_path)),
        )
        conn.commit()
    finally:
        conn.close()
    emit({"status": status, "bundle": str(bundle_path)}, args)


def tunnel_cmd(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    out_dir = paths.generated_dir / "clients" / args.name
    client_path = out_dir / "client.toml"
    if not client_path.exists():
        generate_client(
            argparse.Namespace(
                project=str(paths.project),
                db=str(paths.db),
                json=False,
                name=args.name,
                out=str(out_dir),
                network=args.network,
                overwrite=True,
            )
        )
    name = args.name_override or f"rathole_{args.name}"
    network_arg = f"--network {args.network} " if args.network else ""
    cmd = (
        f"docker run -d --name {name} --restart {args.restart} {network_arg}"
        f"-v {client_path}:/config.toml:ro ghcr.io/rapiz1/rathole client /config.toml"
    )
    if args.format == "script":
        script = f"""#!/usr/bin/env bash
set -euo pipefail
{cmd}
"""
        emit(script, args)
    else:
        emit(cmd, args)


def tunnel_up(args: argparse.Namespace) -> None:
    tunnel_cmd_args = argparse.Namespace(
        project=args.project,
        db=args.db,
        json=args.json,
        name=args.name,
        network=args.network,
        name_override=args.name_override,
        restart=args.restart,
        format="one-liner",
    )
    tunnel_cmd(tunnel_cmd_args)
    emit("Tunnel démarré (commande générée).", args)


def tunnel_down(args: argparse.Namespace) -> None:
    name = args.name_override or f"rathole_{args.name}"
    cmd = f"docker rm -f {name}"
    emit(cmd, args)


def tunnel_ps(args: argparse.Namespace) -> None:
    cmd = "docker ps --format '{{.Names}}' | grep '^rathole_'"
    emit(cmd, args)


def status_command(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        config = conn.execute("SELECT * FROM config WHERE id=1").fetchone()
        services = conn.execute("SELECT * FROM services ORDER BY name").fetchall()
        last_deploy = conn.execute("SELECT * FROM deployments ORDER BY id DESC LIMIT 1").fetchone()
    finally:
        conn.close()
    data = {
        "config": dict(config) if config else None,
        "services": [dict(row) for row in services],
        "last_deploy": dict(last_deploy) if last_deploy else None,
    }
    emit(data, args)


def logs_list(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        rows = conn.execute("SELECT id, created_at, status, log_path FROM deployments ORDER BY id DESC").fetchall()
        data = [dict(row) for row in rows]
    finally:
        conn.close()
    emit(data, args)


def logs_show(args: argparse.Namespace) -> None:
    paths = resolve_paths(args)
    ensure_initialized(paths)
    conn = connect(paths.db)
    try:
        row = conn.execute("SELECT log_path FROM deployments WHERE id=?", (args.deployment_id,)).fetchone()
        if not row:
            raise StationError("Déploiement introuvable", STATUS_USAGE)
        log_path = Path(row["log_path"])
    finally:
        conn.close()
    if not log_path.exists():
        raise StationError("Log introuvable", STATUS_USAGE)
    emit(log_path.read_text(encoding="utf-8"), args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="station")
    parser.add_argument("--project", default=".")
    parser.add_argument("--db")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--force", action="store_true")
    init_parser.set_defaults(func=init_command)

    config_parser = subparsers.add_parser("config")
    config_sub = config_parser.add_subparsers(dest="config_command")
    config_show_parser = config_sub.add_parser("show")
    config_show_parser.set_defaults(func=config_show)
    config_set_parser = config_sub.add_parser("set")
    config_set_parser.add_argument("--http-backend-range")
    config_set_parser.add_argument("--tcp-range")
    config_set_parser.add_argument("--udp-range")
    config_set_parser.add_argument("--http-backend-strategy")
    config_set_parser.add_argument("--default-vps")
    config_set_parser.set_defaults(func=config_set)

    vps_parser = subparsers.add_parser("vps")
    vps_sub = vps_parser.add_subparsers(dest="vps_command")
    vps_add_parser = vps_sub.add_parser("add")
    vps_add_parser.add_argument("name")
    vps_add_parser.add_argument("--deploy-path", required=True)
    vps_add_parser.add_argument("--caddy-domain")
    vps_add_parser.add_argument("--rathole-bind", required=True)
    vps_add_parser.add_argument("--rathole-control-port")
    vps_add_parser.add_argument("--method", required=True)
    vps_add_parser.add_argument("--ssh-host")
    vps_add_parser.add_argument("--ssh-user")
    vps_add_parser.add_argument("--ssh-port", type=int)
    vps_add_parser.add_argument("--ssh-key")
    vps_add_parser.add_argument("--ssh-known-hosts")
    vps_add_parser.add_argument("--upload-url")
    vps_add_parser.add_argument("--upload-user")
    vps_add_parser.add_argument("--upload-pass")
    vps_add_parser.set_defaults(func=vps_add)

    vps_list_parser = vps_sub.add_parser("list")
    vps_list_parser.set_defaults(func=vps_list)

    vps_show_parser = vps_sub.add_parser("show")
    vps_show_parser.add_argument("name")
    vps_show_parser.set_defaults(func=vps_show)

    vps_set_parser = vps_sub.add_parser("set")
    vps_set_parser.add_argument("name")
    vps_set_parser.add_argument("--method")
    vps_set_parser.add_argument("--deploy-path")
    vps_set_parser.add_argument("--caddy-domain")
    vps_set_parser.add_argument("--rathole-bind")
    vps_set_parser.add_argument("--ssh-host")
    vps_set_parser.add_argument("--ssh-user")
    vps_set_parser.add_argument("--ssh-port", type=int)
    vps_set_parser.add_argument("--ssh-key")
    vps_set_parser.add_argument("--ssh-known-hosts")
    vps_set_parser.add_argument("--upload-url")
    vps_set_parser.add_argument("--upload-user")
    vps_set_parser.add_argument("--upload-pass")
    vps_set_parser.set_defaults(func=vps_set)

    vps_rm_parser = vps_sub.add_parser("rm")
    vps_rm_parser.add_argument("name")
    vps_rm_parser.add_argument("--force", action="store_true")
    vps_rm_parser.set_defaults(func=vps_rm)

    vps_test_parser = vps_sub.add_parser("test")
    vps_test_parser.add_argument("name", nargs="?")
    vps_test_parser.set_defaults(func=vps_test)

    keys_parser = subparsers.add_parser("keys")
    keys_sub = keys_parser.add_subparsers(dest="keys_command")
    keys_show_parser = keys_sub.add_parser("show")
    keys_show_parser.add_argument("--reveal", action="store_true")
    keys_show_parser.set_defaults(func=keys_show)
    keys_regen_parser = keys_sub.add_parser("regen")
    keys_regen_parser.add_argument("--keep-old", action="store_true")
    keys_regen_parser.add_argument("--comment")
    keys_regen_parser.set_defaults(func=keys_regen)
    keys_list_parser = keys_sub.add_parser("list")
    keys_list_parser.set_defaults(func=keys_list)
    keys_activate_parser = keys_sub.add_parser("activate")
    keys_activate_parser.add_argument("key_id", type=int)
    keys_activate_parser.set_defaults(func=keys_activate)

    service_parser = subparsers.add_parser("service")
    service_sub = service_parser.add_subparsers(dest="service_command")
    service_add_http = service_sub.add_parser("add-http")
    service_add_http.add_argument("name")
    service_add_http.add_argument("--host", required=True)
    service_add_http.add_argument("--target", required=True)
    service_add_http.add_argument("--network")
    service_add_http.add_argument("--backend-port", type=int)
    service_add_http.add_argument("--token")
    service_add_http.add_argument("--enabled", type=lambda x: x.lower() == "true", default=True)
    service_add_http.set_defaults(func=lambda args: service_add(args, "http"))

    service_add_tcp = service_sub.add_parser("add-tcp")
    service_add_tcp.add_argument("name")
    service_add_tcp.add_argument("--public-port", type=int, required=True)
    service_add_tcp.add_argument("--target", required=True)
    service_add_tcp.add_argument("--network")
    service_add_tcp.add_argument("--token")
    service_add_tcp.add_argument("--enabled", type=lambda x: x.lower() == "true", default=True)
    service_add_tcp.set_defaults(func=lambda args: service_add(args, "tcp"))

    service_add_udp = service_sub.add_parser("add-udp")
    service_add_udp.add_argument("name")
    service_add_udp.add_argument("--public-port", type=int, required=True)
    service_add_udp.add_argument("--target", required=True)
    service_add_udp.add_argument("--network")
    service_add_udp.add_argument("--token")
    service_add_udp.add_argument("--enabled", type=lambda x: x.lower() == "true", default=True)
    service_add_udp.set_defaults(func=lambda args: service_add(args, "udp"))

    service_list_parser = service_sub.add_parser("list")
    service_list_parser.add_argument("--type")
    service_list_parser.add_argument("--enabled", type=lambda x: x.lower() == "true")
    service_list_parser.set_defaults(func=service_list)

    service_show_parser = service_sub.add_parser("show")
    service_show_parser.add_argument("name")
    service_show_parser.set_defaults(func=service_show)

    service_set_parser = service_sub.add_parser("set")
    service_set_parser.add_argument("name")
    service_set_parser.add_argument("--host")
    service_set_parser.add_argument("--public-port", type=int)
    service_set_parser.add_argument("--target")
    service_set_parser.add_argument("--network")
    service_set_parser.add_argument("--backend-port", type=int)
    service_set_parser.add_argument("--token")
    service_set_parser.add_argument("--enabled", type=lambda x: x.lower() == "true")
    service_set_parser.set_defaults(func=service_set)

    service_rm_parser = service_sub.add_parser("rm")
    service_rm_parser.add_argument("name")
    service_rm_parser.add_argument("--force", action="store_true")
    service_rm_parser.set_defaults(func=service_rm)

    service_enable_parser = service_sub.add_parser("enable")
    service_enable_parser.add_argument("name")
    service_enable_parser.set_defaults(func=lambda args: service_enable(args, True))

    service_disable_parser = service_sub.add_parser("disable")
    service_disable_parser.add_argument("name")
    service_disable_parser.set_defaults(func=lambda args: service_enable(args, False))

    generate_parser = subparsers.add_parser("generate")
    generate_sub = generate_parser.add_subparsers(dest="generate_command")
    generate_vps_parser = generate_sub.add_parser("vps")
    generate_vps_parser.add_argument("name", nargs="?")
    generate_vps_parser.add_argument("--out")
    generate_vps_parser.add_argument("--overwrite", action="store_true")
    generate_vps_parser.set_defaults(func=generate_vps)

    generate_client_parser = generate_sub.add_parser("client")
    generate_client_parser.add_argument("name")
    generate_client_parser.add_argument("--out")
    generate_client_parser.add_argument("--network")
    generate_client_parser.add_argument("--overwrite", action="store_true")
    generate_client_parser.set_defaults(func=generate_client)

    deploy_parser = subparsers.add_parser("deploy")
    deploy_parser.add_argument("name", nargs="?")
    deploy_parser.add_argument("--method")
    deploy_parser.add_argument("--dry-run", action="store_true")
    deploy_parser.add_argument("--no-restart", action="store_true")
    deploy_parser.add_argument("--log")
    deploy_parser.set_defaults(func=deploy_command)

    tunnel_parser = subparsers.add_parser("tunnel")
    tunnel_sub = tunnel_parser.add_subparsers(dest="tunnel_command")
    tunnel_cmd_parser = tunnel_sub.add_parser("cmd")
    tunnel_cmd_parser.add_argument("name")
    tunnel_cmd_parser.add_argument("--network")
    tunnel_cmd_parser.add_argument("--name", dest="name_override")
    tunnel_cmd_parser.add_argument("--format", choices=["one-liner", "script"], default="one-liner")
    tunnel_cmd_parser.add_argument("--restart", default="unless-stopped")
    tunnel_cmd_parser.set_defaults(func=tunnel_cmd)

    tunnel_up_parser = tunnel_sub.add_parser("up")
    tunnel_up_parser.add_argument("name")
    tunnel_up_parser.add_argument("--network")
    tunnel_up_parser.add_argument("--local", action="store_true")
    tunnel_up_parser.add_argument("--on-host")
    tunnel_up_parser.add_argument("--ssh-user")
    tunnel_up_parser.add_argument("--ssh-host")
    tunnel_up_parser.add_argument("--ssh-key")
    tunnel_up_parser.add_argument("--ssh-port", type=int)
    tunnel_up_parser.add_argument("--name", dest="name_override")
    tunnel_up_parser.add_argument("--restart", default="unless-stopped")
    tunnel_up_parser.set_defaults(func=tunnel_up)

    tunnel_down_parser = tunnel_sub.add_parser("down")
    tunnel_down_parser.add_argument("name")
    tunnel_down_parser.add_argument("--local", action="store_true")
    tunnel_down_parser.add_argument("--on-host")
    tunnel_down_parser.add_argument("--name", dest="name_override")
    tunnel_down_parser.set_defaults(func=tunnel_down)

    tunnel_ps_parser = tunnel_sub.add_parser("ps")
    tunnel_ps_parser.add_argument("--local", action="store_true")
    tunnel_ps_parser.add_argument("--on-host")
    tunnel_ps_parser.set_defaults(func=tunnel_ps)

    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("name", nargs="?")
    status_parser.add_argument("--vps")
    status_parser.set_defaults(func=status_command)

    logs_parser = subparsers.add_parser("logs")
    logs_sub = logs_parser.add_subparsers(dest="logs_command")
    logs_list_parser = logs_sub.add_parser("list")
    logs_list_parser.set_defaults(func=logs_list)
    logs_show_parser = logs_sub.add_parser("show")
    logs_show_parser.add_argument("deployment_id", type=int)
    logs_show_parser.set_defaults(func=logs_show)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return STATUS_USAGE
    try:
        args.func(args)
    except StationError as exc:
        if not args.quiet:
            print(str(exc), file=sys.stderr)
        return exc.code
    return STATUS_OK


if __name__ == "__main__":
    raise SystemExit(main())
