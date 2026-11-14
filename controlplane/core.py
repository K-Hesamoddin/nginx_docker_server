"""Validated inventory, legacy importer, certificate resolver and Nginx renderer."""
from __future__ import annotations

import datetime as dt
import ipaddress
import re
import shlex
import sqlite3
import subprocess
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

HOST_RE = re.compile(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\Z")
PATH_RE = re.compile(r"/[a-zA-Z0-9_./~-]*\Z")
STUB_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")


def hostname(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not HOST_RE.fullmatch(value):
        raise ValueError(f"Invalid hostname: {value!r}")
    return value


def route_path(value: str) -> str:
    if not PATH_RE.fullmatch(value) or "//" in value or ".." in value:
        raise ValueError(f"Invalid route path: {value!r}")
    return value


def upstream(value: str) -> str:
    # Deliberately disallow user-provided schemes, ports outside 1..65535,
    # arbitrary nginx tokens, Unix sockets and credential-bearing URLs.
    if value.count(":") != 1:
        raise ValueError("Upstream must be host:port")
    host, port_text = value.split(":")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        hostname(host)
    if not port_text.isdecimal() or not 1 <= int(port_text) <= 65535:
        raise ValueError("Invalid upstream port")
    return f"{host.lower()}:{int(port_text)}"


def cert_stub(value: str) -> str:
    if not STUB_RE.fullmatch(value) or value in {".", ".."}:
        raise ValueError("Invalid certificate filename")
    return value


def open_db(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS domains (
            name TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1,
            redirect_www INTEGER NOT NULL DEFAULT 0,
            body_limit_mb INTEGER NOT NULL DEFAULT 50,
            security_profile TEXT NOT NULL DEFAULT 'legacy'
        );
        CREATE TABLE IF NOT EXISTS routes (
            id INTEGER PRIMARY KEY,
            domain TEXT NOT NULL REFERENCES domains(name) ON DELETE CASCADE,
            path TEXT NOT NULL, target TEXT NOT NULL,
            strip_prefix INTEGER NOT NULL DEFAULT 1,
            websocket INTEGER NOT NULL DEFAULT 0,
            UNIQUE(domain, path)
        );
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY,
            zone TEXT NOT NULL, kind TEXT NOT NULL,
            stub TEXT NOT NULL UNIQUE,
            CHECK(kind IN ('dedicated','wildcard'))
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL, detail TEXT NOT NULL
        );
    """)
    conn.commit()
    return conn


def audit(conn: sqlite3.Connection, action: str, detail: str) -> None:
    conn.execute("INSERT INTO audit(action, detail) VALUES(?,?)", (action, detail))


def save_domain(conn: sqlite3.Connection, domain: str, redirect_www=False,
                body_limit_mb=50, security_profile="legacy") -> None:
    domain = hostname(domain)
    if security_profile not in ("legacy", "baseline"):
        raise ValueError("Unsupported security profile")
    if not 1 <= int(body_limit_mb) <= 500:
        raise ValueError("Body limit must be 1..500 MB")
    conn.execute("""INSERT INTO domains(name,redirect_www,body_limit_mb,security_profile)
                    VALUES (?,?,?,?) ON CONFLICT(name) DO UPDATE SET
                    redirect_www=excluded.redirect_www,
                    body_limit_mb=excluded.body_limit_mb,
                    security_profile=excluded.security_profile""",
                 (domain, int(bool(redirect_www)), int(body_limit_mb), security_profile))
    audit(conn, "domain-upsert", domain)
    conn.commit()


def save_route(conn: sqlite3.Connection, domain: str, path: str, target: str,
               strip_prefix=True, websocket=False) -> None:
    domain, path, target = hostname(domain), route_path(path), upstream(target)
    if conn.execute("SELECT 1 FROM domains WHERE name=?", (domain,)).fetchone() is None:
        raise ValueError("Add domain before route")
    conn.execute("""INSERT INTO routes(domain,path,target,strip_prefix,websocket)
                    VALUES(?,?,?,?,?) ON CONFLICT(domain,path) DO UPDATE SET
                    target=excluded.target, strip_prefix=excluded.strip_prefix,
                    websocket=excluded.websocket""",
                 (domain, path, target, int(bool(strip_prefix)), int(bool(websocket))))
    audit(conn, "route-upsert", f"{domain} {path} -> {target}")
    conn.commit()


def save_certificate(conn: sqlite3.Connection, zone: str, kind: str, stub: str) -> None:
    zone, stub = hostname(zone), cert_stub(stub)
    if kind not in {"dedicated", "wildcard"}:
        raise ValueError("kind must be dedicated or wildcard")
    conn.execute("""INSERT INTO certificates(zone,kind,stub) VALUES(?,?,?)
                    ON CONFLICT(stub) DO UPDATE SET zone=excluded.zone,kind=excluded.kind""",
                 (zone, kind, stub))
    audit(conn, "certificate-register", f"{zone} {kind} {stub}")
    conn.commit()


def import_domains_list(conn: sqlite3.Connection, filename: str | Path) -> dict:
    """Idempotent importer. Preserve legacy flag semantics: 0=do not regenerate."""
    result = {"imported": 0, "skipped": 0, "errors": []}
    for lineno, raw in enumerate(Path(filename).read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            tokens = shlex.split(line)
            if len(tokens) < 2 or tokens[0] not in ("0", "1"):
                raise ValueError("expected: flag domain [path upstream]...")
            domain = hostname(tokens[1])
            rest = tokens[2:]
            if len(rest) % 2:
                raise ValueError("route/upstream pairs are incomplete")
            # Import is non-destructive: never overwrite edits already in the DB.
            if conn.execute("SELECT 1 FROM domains WHERE name=?", (domain,)).fetchone():
                result["skipped"] += 1
                continue
            # Validate each route before making any changes for this line.
            for path, target in zip(rest[::2], rest[1::2]):
                route_path(path)
                upstream(target)
            save_domain(conn, domain, redirect_www=(domain.count(".") == 1))
            for path, target in zip(rest[::2], rest[1::2]):
                save_route(conn, domain, path, target)
            result["imported"] += 1
        except (ValueError, sqlite3.Error) as exc:
            result["errors"].append(f"line {lineno}: {exc}")
    return result


def export_domains_list(conn: sqlite3.Connection) -> str:
    """Backwards-compatible snapshot. DB is authoritative after migration."""
    lines = ["# Generated by controlplane; do not edit this export."]
    for d in conn.execute("SELECT * FROM domains ORDER BY name"):
        parts = ["1", d["name"]]
        for r in conn.execute("SELECT * FROM routes WHERE domain=? ORDER BY LENGTH(path) DESC, path",
                              (d["name"],)):
            parts += [r["path"], r["target"]]
        lines.append(" ".join(parts))
    return "\n".join(lines) + "\n"


def matches(pattern: str, name: str) -> bool:
    pattern, name = pattern.lower(), name.lower()
    if pattern == name:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return name.endswith("." + suffix) and name.count(".") == suffix.count(".") + 1
    return False


@dataclass(frozen=True)
class CertInfo:
    stub: str
    names: tuple[str, ...]
    expires: dt.datetime
    cert_path: Path
    key_path: Path


def inspect_certificate(ssl_dir: str | Path, stub: str, min_days=14) -> CertInfo:
    stub = cert_stub(stub)
    root = Path(ssl_dir).resolve()
    crt, key = root / f"{stub}.crt", root / f"{stub}.key"
    cert = x509.load_pem_x509_certificate(crt.read_bytes())
    private = serialization.load_pem_private_key(key.read_bytes(), password=None)
    if (cert.public_key().public_bytes(serialization.Encoding.DER,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)
        != private.public_key().public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)):
        raise ValueError(f"Private key mismatch for {stub}")
    # Verify trust against the OS CA store (or a deliberate custom trust bundle).
    ca_bundle = os.environ.get("CONTROLPLANE_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt")
    verification = subprocess.run(
        ["openssl", "verify", "-CAfile", ca_bundle, "-untrusted", str(crt), str(crt)],
        capture_output=True, text=True, check=False)
    if verification.returncode != 0:
        raise ValueError(f"Untrusted certificate chain for {stub}: {verification.stderr.strip()}")
    names = tuple(n.lower() for n in cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName))
    expiry = cert.not_valid_after_utc
    if expiry <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=min_days):
        raise ValueError(f"Certificate {stub} expired or within {min_days} days of expiry")
    return CertInfo(stub, names, expiry, crt, key)


def resolve_certificate(conn: sqlite3.Connection, ssl_dir: str | Path,
                        name: str, min_days=14) -> CertInfo:
    name = hostname(name)
    candidates = []
    for row in conn.execute("SELECT * FROM certificates ORDER BY id"):
        try:
            info = inspect_certificate(ssl_dir, row["stub"], min_days)
        except (OSError, ValueError, x509.ExtensionNotFound):
            continue
        if any(matches(pattern, name) for pattern in info.names):
            # Exact SAN preferred; shared wildcard is fallback for expired/missing dedicated.
            exact = name in info.names
            candidates.append((0 if exact else 1, info.stub, info))
    if not candidates:
        raise ValueError(f"No valid certificate (including wildcard) for {name}")
    return min(candidates, key=lambda x: (x[0], x[1]))[2]


def render_config(conn: sqlite3.Connection, ssl_dir: str | Path, domain: str) -> str:
    domain = hostname(domain)
    d = conn.execute("SELECT * FROM domains WHERE name=? AND enabled=1", (domain,)).fetchone()
    if d is None:
        raise ValueError(f"Domain not enabled: {domain}")
    names = [domain] + ([f"www.{domain}"] if d["redirect_www"] else [])
    certs = {name: resolve_certificate(conn, ssl_dir, name) for name in names}
    lines = [f"# Managed by nginx-control-plane-v2: {domain}",
             "server {", "    listen 80;", f"    server_name {' '.join(names)};",
             f"    return 301 https://{domain}$request_uri;", "}"]
    for alias in names[1:]:
        cert = certs[alias]
        lines += ["server {", "    listen 443 ssl;",
                  f"    server_name {alias};",
                  f"    ssl_certificate /etc/nginx/ssl/{cert.stub}.crt;",
                  f"    ssl_certificate_key /etc/nginx/ssl/{cert.stub}.key;",
                  f"    return 301 https://{domain}$request_uri;", "}"]
    cert = certs[domain]
    lines += ["server {", "    listen 443 ssl;",
              f"    server_name {domain};",
              f"    ssl_certificate /etc/nginx/ssl/{cert.stub}.crt;",
              f"    ssl_certificate_key /etc/nginx/ssl/{cert.stub}.key;",
              f"    client_max_body_size {d['body_limit_mb']}m;",
              "    server_tokens off;"]
    if d["security_profile"] == "legacy":
        lines.append("    include /etc/nginx/conf.d/includes/security.conf;")
    else:
        lines += ["    ssl_protocols TLSv1.2 TLSv1.3;",
                  "    add_header X-Content-Type-Options nosniff always;",
                  "    add_header Referrer-Policy strict-origin-when-cross-origin always;"]
    routes = conn.execute("SELECT * FROM routes WHERE domain=? ORDER BY LENGTH(path) DESC, path",
                          (domain,)).fetchall()
    if not routes:
        raise ValueError(f"No backend routes configured for {domain}")
    for r in routes:
        target, path = r["target"], r["path"]
        # Validate again at the rendering boundary.
        upstream(target)
        route_path(path)
        destination = f"http://{target}" + ("/" if r["strip_prefix"] else "")
        lines += [f"    location {path} {{",
                  f"        proxy_pass {destination};",
                  "        proxy_http_version 1.1;",
                  "        proxy_set_header Host $host;",
                  "        proxy_set_header X-Real-IP $remote_addr;",
                  "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
                  "        proxy_set_header X-Forwarded-Proto $scheme;"]
        if r["websocket"]:
            lines += ["        proxy_set_header Upgrade $http_upgrade;",
                      "        proxy_set_header Connection \"upgrade\";"]
        lines += ["    }"]
    lines += ["}", ""]
    return "\n".join(lines)
