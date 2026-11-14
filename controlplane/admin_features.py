"""Operator-facing configuration metadata; all changes stay in the lab DB.

Neither these functions nor their web routes change Nginx, Docker, DNS or SSL.
Raw proxy configs and credential material are NEVER written to public logs.
"""
from __future__ import annotations

import ipaddress
import re
import sqlite3
import hashlib
import difflib

from werkzeug.security import generate_password_hash, check_password_hash

from .core import audit, hostname, matches, upstream

DEFAULT_ALLOWED = ("127.0.0.1/32", "::1/128", "192.168.1.192/32")
USERNAME = re.compile(r"[a-zA-Z][a-zA-Z0-9_.-]{2,31}\Z")
INCLUDE_NAME = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{0,63}\.conf\Z")
STREAM_NAME = re.compile(r"[a-z][a-z0-9_-]{1,39}\Z")
ROLE_ORDER = {"viewer": 0, "editor": 1, "admin": 2}


def ensure_features(conn: sqlite3.Connection, bootstrap_hash: str | None = None):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS panel_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('viewer','editor','admin')),
            active INTEGER NOT NULL DEFAULT 1,
            auth_epoch INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS panel_allowed_nets (
            network TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS domain_includes (
            domain TEXT NOT NULL REFERENCES domains(name) ON DELETE CASCADE,
            filename TEXT NOT NULL,
            PRIMARY KEY(domain, filename)
        );
        CREATE TABLE IF NOT EXISTS security_options (
            domain TEXT PRIMARY KEY REFERENCES domains(name) ON DELETE CASCADE,
            hsts INTEGER NOT NULL DEFAULT 0,
            xframe INTEGER NOT NULL DEFAULT 0,
            nosniff INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS include_catalog (
            filename TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'reference'
               CHECK(status IN ('reference','staged')),
            description TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS include_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL REFERENCES include_catalog(filename),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            body TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS ix_include_versions_file
            ON include_versions(filename,id);
        CREATE TABLE IF NOT EXISTS stream_services (
            name TEXT PRIMARY KEY,
            protocol TEXT NOT NULL CHECK(protocol IN ('tcp','udp')),
            listen_host TEXT NOT NULL,
            listen_port INTEGER NOT NULL CHECK(listen_port BETWEEN 1 AND 65535),
            target TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            description TEXT NOT NULL DEFAULT '',
            UNIQUE(protocol,listen_host,listen_port)
        );
        CREATE TABLE IF NOT EXISTS stream_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            body TEXT NOT NULL
        );
    """)
    for network in DEFAULT_ALLOWED:
        # Only initialize the defaults if the set is empty; changes made via
        # admin settings must persist and must not be overwritten on startup.
        pass
    if not conn.execute("SELECT 1 FROM panel_allowed_nets LIMIT 1").fetchone():
        conn.executemany("INSERT INTO panel_allowed_nets(network) VALUES (?)",
                         [(n,) for n in DEFAULT_ALLOWED])
    for filename, description in (
        ("security.conf", "Existing security.conf legacy include"),
        ("buffer.conf", "Existing buffer.conf legacy include"),
    ):
        conn.execute("INSERT OR IGNORE INTO include_catalog(filename, description) VALUES(?,?)",
                     (filename, description))
    if bootstrap_hash and not conn.execute("SELECT 1 FROM panel_users LIMIT 1").fetchone():
        conn.execute(
            "INSERT INTO panel_users(username,password_hash,role) VALUES('admin',?,'admin')",
            (bootstrap_hash,)
        )
        audit(conn, "bootstrap-user", "admin")
    conn.commit()


def authenticate(conn: sqlite3.Connection, username: str, password: str):
    username = (username or "").strip()
    row = conn.execute(
        "SELECT * FROM panel_users WHERE username=? AND active=1", (username,)
    ).fetchone()
    # Always verify a hash to avoid obvious inactive-user timing discrepancies.
    if row and check_password_hash(row["password_hash"], password):
        return row
    return None


def get_session_user(conn: sqlite3.Connection, session):
    uid, epoch = session.get("uid"), session.get("epoch")
    if not isinstance(uid, int) or not isinstance(epoch, int):
        return None
    row = conn.execute("SELECT * FROM panel_users WHERE id=? AND active=1", (uid,)).fetchone()
    if row and row["auth_epoch"] == epoch:
        return row
    return None


def user_upsert(conn: sqlite3.Connection, actor_id: int, username: str,
                password: str, role: str):
    username = (username or "").strip()
    if not USERNAME.fullmatch(username):
        raise ValueError("Username must be 3-32 letters/digits/_.-")
    if role not in ROLE_ORDER:
        raise ValueError("Unknown role")
    if len(password) < 12 or len(password) > 256:
        raise ValueError("Password must have 12-256 characters")
    if conn.execute("SELECT 1 FROM panel_users WHERE username=?", (username,)).fetchone():
        raise ValueError("User already exists")
    with conn:
        conn.execute(
            "INSERT INTO panel_users(username,password_hash,role) VALUES(?,?,?)",
            (username, generate_password_hash(password), role)
        )
        audit(conn, "user-create", f"by:{actor_id} {username} role:{role}")


def user_update(conn: sqlite3.Connection, actor_id: int, uid: int, role: str,
                active: bool, new_password: str = ""):
    if role not in ROLE_ORDER:
        raise ValueError("Unknown role")
    old = conn.execute("SELECT * FROM panel_users WHERE id=?", (uid,)).fetchone()
    if not old:
        raise ValueError("User not found")
    if old["id"] == actor_id and (not active or role != "admin"):
        raise ValueError("You cannot remove your own admin access")
    if old["role"] == "admin" and old["active"] and (not active or role != "admin"):
        admins = conn.execute(
            "SELECT count(*) FROM panel_users WHERE active=1 AND role='admin'"
        ).fetchone()[0]
        if admins <= 1:
            raise ValueError("Cannot disable or demote the last administrator")
    if new_password and not 12 <= len(new_password) <= 256:
        raise ValueError("Password must have 12-256 characters")
    with conn:
        if new_password:
            conn.execute(
                """UPDATE panel_users SET role=?,active=?,password_hash=?,
                   auth_epoch=auth_epoch+1 WHERE id=?""",
                (role, int(active), generate_password_hash(new_password), uid)
            )
        else:
            conn.execute(
                """UPDATE panel_users SET role=?,active=?,auth_epoch=auth_epoch+1
                   WHERE id=?""", (role, int(active), uid)
            )
        audit(conn, "user-update", f"by:{actor_id} {old['username']} role:{role} active:{active}")


def valid_local_net(value: str) -> str:
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise ValueError("Invalid CIDR or IP address")
    if not (network.is_private or network.is_loopback) or network.is_unspecified:
        raise ValueError("Only local/private IP ranges are permitted")
    if network.version == 4 and network.prefixlen < 16:
        raise ValueError("IPv4 allowlist ranges broader than /16 are not permitted")
    if network.version == 6 and network.prefixlen < 48:
        raise ValueError("IPv6 allowlist ranges broader than /48 are not permitted")
    return str(network)


def allowed_networks(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute("SELECT network FROM panel_allowed_nets ORDER BY network")]


def is_allowed_peer(conn: sqlite3.Connection, address: str) -> bool:
    """Direct socket address only; NEVER trust X-Forwarded-For from a client."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(net) for net in allowed_networks(conn))


def add_allowed_net(conn: sqlite3.Connection, cidr: str, actor: str):
    value = valid_local_net(cidr)
    with conn:
        conn.execute("INSERT OR IGNORE INTO panel_allowed_nets VALUES(?)", (value,))
        audit(conn, "acl-add", f"{actor}: {value}")


def remove_allowed_net(conn: sqlite3.Connection, cidr: str, actor: str):
    value = valid_local_net(cidr)
    if value in ("127.0.0.1/32", "::1/128"):
        raise ValueError("Loopback access cannot be removed")
    with conn:
        conn.execute("DELETE FROM panel_allowed_nets WHERE network=?", (value,))
        audit(conn, "acl-delete", f"{actor}: {value}")


def known_inventory_hosts(conn: sqlite3.Connection) -> set[str]:
    """Collect validated names from inventory and archived live server_name.

    Nginx aliases are discovery evidence, not automatically deployable routes.
    Wildcard/regex/catch-all server names are intentionally not treated as
    literal hostnames.
    """
    hosts = {row["name"] for row in conn.execute("SELECT name FROM domains")}
    hosts.update(
        "www." + row["name"] for row in
        conn.execute("SELECT name FROM domains WHERE redirect_www=1")
    )
    has_history = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='config_versions'"
    ).fetchone() is not None
    if has_history:
        for row in conn.execute(
            "SELECT body FROM config_versions WHERE origin='live_snapshot'"
        ):
            for match in re.finditer(r"(?m)^\s*server_name\s+([^;\r\n]+);",
                                     row["body"]):
                for value in match.group(1).split():
                    try:
                        hosts.add(hostname(value))
                    except ValueError:
                        continue
    return hosts


def archived_certificate_paths(conn: sqlite3.Connection) -> dict[str, list[str]]:
    """Expose public cert *file references* from snapshots, never key paths."""
    found: dict[str, set[str]] = {}
    if not conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='config_versions'"
    ).fetchone():
        return {}
    for row in conn.execute(
        "SELECT domain,body FROM config_versions WHERE origin='live_snapshot'"
    ):
        refs = set(re.findall(
            r"(?m)^\s*ssl_certificate\s+(/etc/nginx/ssl/[a-zA-Z0-9_.-]+\.crt)\s*;",
            row["body"]
        ))
        found.setdefault(row["domain"], set()).update(refs)
    return {domain: sorted(paths) for domain, paths in found.items()}


def recommended_zones(conn: sqlite3.Connection) -> list[dict]:
    """Conservative suggestions for known .ir and .com suffixes only.

    Registered-domain boundaries must be verified by the operator/DNS provider.
    No attempts to issue or infer NSIN authority are made here.
    """
    # Include manually edited live server_name aliases in the coverage plan.
    names = known_inventory_hosts(conn)
    groups: dict[str, set[str]] = {}
    for domain in names:
        labels = domain.split(".")
        if len(labels) < 2 or labels[-1] not in {"ir", "com"}:
            continue
        zone = ".".join(labels[-2:])
        groups.setdefault(zone, set()).add(domain)
    cert_refs = archived_certificate_paths(conn)
    results = []
    for zone, members in sorted(groups.items()):
        covered = sorted(d for d in members if d == zone or matches("*." + zone, d))
        uncovered = sorted(set(members) - set(covered))
        results.append({
            "zone": zone,
            "wildcard": "*." + zone,
            "covered": covered,
            "not_covered": uncovered,
            "count": len(covered),
            "requires_dns_confirmation": True,
            "archived_cert_paths": sorted({
                path for host, paths in cert_refs.items()
                if host == zone or matches("*." + zone, host)
                for path in paths
            }),
        })
    # Deep hostnames require a separate wildcard at a deeper DNS zone.
    # Suggest them separately instead of falsely claiming *.apex covers them.
    nested_zones = set()
    for group in results:
        for name in group["not_covered"]:
            labels = name.split(".")
            if len(labels) >= 4:
                nested_zones.add(".".join(labels[-3:]))
    for zone in sorted(nested_zones):
        if zone in groups:
            continue
        relevant = sorted(name for name in names if name == zone or
                          matches("*." + zone, name))
        if relevant:
            results.append({
                "zone": zone,
                "wildcard": "*." + zone,
                "covered": relevant,
                "not_covered": [],
                "count": len(relevant),
                "requires_dns_confirmation": True,
                "nested_zone": True,
                "archived_cert_paths": sorted({
                    path for host, paths in cert_refs.items()
                    if host == zone or matches("*." + zone, host)
                    for path in paths
                }),
            })
    for result in results:
        result.setdefault("nested_zone", False)
    return sorted(results, key=lambda g: (-g["count"], g["zone"]))


def register_include(conn: sqlite3.Connection, filename: str, description: str):
    if not INCLUDE_NAME.fullmatch(filename):
        raise ValueError("Only simple *.conf include filenames are supported")
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO include_catalog(filename,description,status) VALUES(?,?,'reference')",
            (filename, description[:250])
        )
        audit(conn, "include-register", filename)


def set_domain_include(conn: sqlite3.Connection, domain: str, filename: str,
                       enabled: bool):
    domain = hostname(domain)
    if not INCLUDE_NAME.fullmatch(filename):
        raise ValueError("Invalid include filename")
    if not conn.execute("SELECT 1 FROM domains WHERE name=?", (domain,)).fetchone():
        raise ValueError("Unknown domain")
    if not conn.execute("SELECT 1 FROM include_catalog WHERE filename=?", (filename,)).fetchone():
        raise ValueError("Include must be added to the approved catalog first")
    with conn:
        if enabled:
            conn.execute("INSERT OR IGNORE INTO domain_includes VALUES(?,?)", (domain, filename))
        else:
            conn.execute("DELETE FROM domain_includes WHERE domain=? AND filename=?",
                         (domain, filename))
        audit(conn, "domain-include", f"{domain} {filename} enabled:{enabled}")


def set_security_options(conn: sqlite3.Connection, domain: str,
                         hsts: bool, nosniff: bool, xframe: bool):
    domain = hostname(domain)
    if not conn.execute("SELECT 1 FROM domains WHERE name=?", (domain,)).fetchone():
        raise ValueError("Unknown domain")
    with conn:
        conn.execute(
            """INSERT INTO security_options(domain,hsts,nosniff,xframe) VALUES(?,?,?,?)
               ON CONFLICT(domain) DO UPDATE SET hsts=excluded.hsts,
               nosniff=excluded.nosniff,xframe=excluded.xframe""",
            (domain, int(hsts), int(nosniff), int(xframe))
        )
        audit(conn, "security-settings", f"{domain} hsts:{hsts} nosniff:{nosniff} xframe:{xframe}")


def add_stream(conn: sqlite3.Connection, name: str, protocol: str,
               listen_host: str, listen_port: int, target: str, description: str = ""):
    if not STREAM_NAME.fullmatch(name):
        raise ValueError("Invalid stream name")
    if protocol not in {"tcp", "udp"}:
        raise ValueError("Stream protocol must be tcp or udp")
    listen_host = listen_host.strip()
    try:
        ip = ipaddress.ip_address(listen_host)
    except ValueError:
        raise ValueError("Stream listener must be an IP address")
    if ip.is_unspecified:
        raise ValueError("Wildcard stream listen is not allowed in staging defaults")
    port = int(listen_port)
    if not 1 <= port <= 65535 or port in (80, 443, 8787):
        raise ValueError("Stream port must be 1..65535 and not 80, 443 or 8787")
    target = upstream(target)
    with conn:
        conn.execute(
            """INSERT INTO stream_services(name,protocol,listen_host,listen_port,target,description)
               VALUES(?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET
               protocol=excluded.protocol,listen_host=excluded.listen_host,
               listen_port=excluded.listen_port,target=excluded.target,
               description=excluded.description""",
            (name, protocol, listen_host, port, target, description[:250])
        )
        audit(conn, "stream-stage", f"{name} {protocol} {listen_host}:{port} -> {target}")


def stream_preview(conn: sqlite3.Connection, name: str) -> str:
    row = conn.execute("SELECT * FROM stream_services WHERE name=?", (name,)).fetchone()
    if not row:
        raise ValueError("Unknown stream")
    # A stream/server fragment belongs inside top-level stream {}, NEVER http {}.
    flag = " udp" if row["protocol"] == "udp" else ""
    body = (f"# V2 STAGING ONLY: stream {row['name']}\n"
            f"server {{\n    listen {row['listen_host']}:{row['listen_port']}{flag};\n"
            f"    proxy_pass {row['target']};\n}}\n")
    with conn:
        conn.execute("INSERT INTO stream_versions(name,body) VALUES(?,?)", (name, body))
        audit(conn, "stream-preview", name)
    return body



def save_include_revision(conn: sqlite3.Connection, filename: str, body: str, note: str = "") -> int:
    """Keep custom Nginx snippets in SQLite for review; NEVER deploy directly."""
    if not INCLUDE_NAME.fullmatch(filename):
        raise ValueError("Only simple *.conf filenames are permitted")
    if not conn.execute("SELECT 1 FROM include_catalog WHERE filename=?", (filename,)).fetchone():
        raise ValueError("Register the include filename first")
    if not isinstance(body, str) or not body.strip() or "\x00" in body:
        raise ValueError("Snippet must not be empty or contain NUL")
    body = body.replace("\r\n", "\n")
    if len(body.encode("utf-8")) > 64 * 1024:
        raise ValueError("Snippet exceeds 64 KiB")
    with conn:
        cur = conn.execute(
            """INSERT INTO include_versions(filename,body,sha256,note)
               VALUES(?,?,?,?)""",
            (filename, body, hashlib.sha256(body.encode("utf-8")).hexdigest(), note[:500])
        )
        conn.execute("UPDATE include_catalog SET status='staged' WHERE filename=?",
                     (filename,))
        audit(conn, "include-version", f"{filename} #{cur.lastrowid}")
    return cur.lastrowid


def include_history(conn: sqlite3.Connection, filename: str) -> list[sqlite3.Row]:
    if not INCLUDE_NAME.fullmatch(filename):
        raise ValueError("Invalid include filename")
    return conn.execute(
        """SELECT id,created_at,sha256,note FROM include_versions
           WHERE filename=? ORDER BY id DESC LIMIT 40""",
        (filename,)
    ).fetchall()


def include_version_diff(conn: sqlite3.Connection, filename: str, version_id: int):
    if not INCLUDE_NAME.fullmatch(filename):
        raise ValueError("Invalid include filename")
    row = conn.execute(
        "SELECT * FROM include_versions WHERE filename=? AND id=?",
        (filename, version_id)
    ).fetchone()
    if not row:
        raise ValueError("Include revision not found")
    prev = conn.execute(
        """SELECT id,body FROM include_versions WHERE filename=? AND id<?
           ORDER BY id DESC LIMIT 1""",
        (filename, version_id)
    ).fetchone()
    before = prev["body"] if prev else ""
    diff = "".join(difflib.unified_diff(
        before.splitlines(keepends=True), row["body"].splitlines(keepends=True),
        fromfile=f"v{prev['id']}" if prev else "empty", tofile=f"v{version_id}"
    ))
    return row, diff


def delete_stream(conn: sqlite3.Connection, name: str):
    """Remove a staged stream definition. Do not remove past previews or live files."""
    if not STREAM_NAME.fullmatch(name):
        raise ValueError("Invalid stream identifier")
    with conn:
        if conn.execute("DELETE FROM stream_services WHERE name=?", (name,)).rowcount == 0:
            raise ValueError("Stream not found")
        audit(conn, "stream-delete-staging", name)
