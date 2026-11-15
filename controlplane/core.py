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
    # Inventory can include private internal routes and later config snapshots.
    # Never leave a newly created or existing DB world-readable.
    os.chmod(path, 0o600)
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
            proxy_uri TEXT,
            UNIQUE(domain, path)
        );
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY,
            zone TEXT NOT NULL, kind TEXT NOT NULL,
            stub TEXT NOT NULL UNIQUE,
            CHECK(kind IN ('dedicated','wildcard'))
        );
        CREATE TABLE IF NOT EXISTS legacy_flags (
            domain TEXT PRIMARY KEY REFERENCES domains(name) ON DELETE CASCADE,
            flag_count INTEGER NOT NULL CHECK(flag_count IN (1,2)),
            first_flag TEXT NOT NULL CHECK(first_flag IN ('0','1')),
            second_flag TEXT CHECK(second_flag IS NULL OR second_flag IN ('0','1'))
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL, detail TEXT NOT NULL
        );
    """)
    # Safe additive migration for the existing lab SQLite database.
    if "proxy_uri" not in {
        row[1] for row in conn.execute("PRAGMA table_info(routes)")
    }:
        conn.execute("ALTER TABLE routes ADD COLUMN proxy_uri TEXT")
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
               strip_prefix=True, websocket=False, proxy_uri=None) -> None:
    domain, path, target = hostname(domain), route_path(path), upstream(target)
    if proxy_uri is not None:
        if not isinstance(proxy_uri, str):
            raise ValueError("Proxy URI must be a string or null")
        proxy_uri = route_path(proxy_uri) if proxy_uri else ""
    if conn.execute("SELECT 1 FROM domains WHERE name=?", (domain,)).fetchone() is None:
        raise ValueError("Add domain before route")
    conn.execute("""INSERT INTO routes(domain,path,target,strip_prefix,websocket,proxy_uri)
                    VALUES(?,?,?,?,?,?) ON CONFLICT(domain,path) DO UPDATE SET
                    target=excluded.target, strip_prefix=excluded.strip_prefix,
                    websocket=excluded.websocket, proxy_uri=excluded.proxy_uri""",
                 (domain, path, target, int(bool(strip_prefix)), int(bool(websocket)), proxy_uri))
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
    """Import both historical formats, without interpreting the regeneration flags.

    Accepted input:
      1 example.com / 192.0.2.10:3000             (one flag)
      1 0 example.com / 192.0.2.10:3000           (two flags)

    A flag of 0 does NOT mean a host is disabled. Its historical meaning is
    generator-specific; V2 preserves flags as opaque values in legacy_flags.
    The full file is validated before *any* DB mutation. Existing records
    are never overwritten. Intended only as initial inventory migration.
    """
    result = {"imported": 0, "skipped": 0, "errors": []}
    pending = []
    seen = set()
    try:
        source_lines = Path(filename).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        result["errors"].append(str(exc))
        return result

    for lineno, raw in enumerate(source_lines, 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            tokens = shlex.split(line)
            if len(tokens) < 4 or tokens[0] not in ("0", "1"):
                raise ValueError("expected flag [flag] domain path host:port")
            two_flags = tokens[1] in ("0", "1")
            domain_index = 2 if two_flags else 1
            if len(tokens) < domain_index + 3:
                raise ValueError("missing domain or backend route")
            domain = hostname(tokens[domain_index])
            rest = tokens[domain_index + 1:]
            if len(rest) % 2:
                raise ValueError("route/target pairs are incomplete")
            if domain in seen:
                raise ValueError(f"duplicate domain {domain!r} in input")
            routes = list(zip(rest[::2], rest[1::2]))
            locations = set()
            for path, target in routes:
                route_path(path)
                upstream(target)
                if path in locations:
                    raise ValueError(f"duplicate location {path!r} for {domain}")
                locations.add(path)
            pending.append((domain, tokens[:domain_index], routes))
            seen.add(domain)
        except ValueError as exc:
            result["errors"].append(f"line {lineno}: {exc}")

    if result["errors"]:
        # Especially important for pasted/truncated inventory: no partial import.
        return result

    with conn:
        existing = {row["name"] for row in conn.execute("SELECT name FROM domains")}
        for domain, flags, routes in pending:
            if domain in existing:
                result["skipped"] += 1
                continue
            # An explicitly managed www host must not be claimed as an implicit
            # redirect alias of its apex domain.
            redirect_www = (
                domain.count(".") == 1
                and f"www.{domain}" not in seen
                and f"www.{domain}" not in existing
            )
            conn.execute(
                "INSERT INTO domains(name,redirect_www) VALUES (?,?)",
                (domain, int(redirect_www))
            )
            for path, target in routes:
                conn.execute(
                    "INSERT INTO routes(domain,path,target) VALUES(?,?,?)",
                    (domain, path, upstream(target))
                )
            conn.execute(
                """INSERT INTO legacy_flags(domain,flag_count,first_flag,second_flag)
                   VALUES(?,?,?,?)""",
                (domain, len(flags), flags[0], flags[1] if len(flags) == 2 else None)
            )
            audit(conn, "legacy-import", f"{domain} ({len(flags)} flags, {len(routes)} routes)")
            result["imported"] += 1
    return result


def export_domains_list(conn: sqlite3.Connection) -> str:
    """Round-trip inventory flags and route order, not a deploy command.

    New DB-only domains use conservative 0 0 compatibility placeholders.
    Never hand this to legacy v1 shell scripts without reviewing their parser:
    repository v1 parses only one flag, while deployed input uses two.
    """
    lines = ["# V2 inventory export. Validate against original before using with legacy scripts."]
    for d in conn.execute("SELECT * FROM domains ORDER BY name"):
        flags = conn.execute("SELECT * FROM legacy_flags WHERE domain=?",
                             (d["name"],)).fetchone()
        if flags is None:
            parts = ["0", "0", d["name"]]
        else:
            parts = [flags["first_flag"]]
            if flags["flag_count"] == 2:
                parts.append(flags["second_flag"])
            parts.append(d["name"])
        for r in conn.execute("SELECT * FROM routes WHERE domain=? ORDER BY id",
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
    # cryptography <42 exposes only the naive-UTC not_valid_after attribute.
    # acme.sh reload hooks may run with the host Python rather than the venv;
    # preserve the same timezone-aware expiry check on both versions.
    expiry = getattr(cert, "not_valid_after_utc", None)
    if expiry is None:
        expiry = cert.not_valid_after
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=dt.timezone.utc)
        else:
            expiry = expiry.astimezone(dt.timezone.utc)
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
            # V2 converges hostnames on the shared wildcard for their zone.
            # Valid legacy dedicated certs remain a fallback until migrated.
            # Among wildcard generations prefer the freshest valid certificate.
            priority = 0 if row["kind"] == "wildcard" else 1
            candidates.append((priority, -info.expires.timestamp(), info.stub, info))
    if not candidates:
        raise ValueError(f"No valid certificate (including wildcard) for {name}")
    return min(candidates, key=lambda x: (x[0], x[1], x[2]))[3]


def render_config(conn: sqlite3.Connection, ssl_dir: str | Path, domain: str, *,
                  allow_missing_cert: bool = False) -> str:
    domain = hostname(domain)
    d = conn.execute("SELECT * FROM domains WHERE name=? AND enabled=1", (domain,)).fetchone()
    if d is None:
        raise ValueError(f"Domain not enabled: {domain}")
    # Explicit www sites own their hostname; prevent duplicate server_name
    # claims and unnecessary redirects when migrating legacy inventory.
    explicit_www = conn.execute(
        "SELECT 1 FROM domains WHERE name=? AND enabled=1",
        (f"www.{domain}",)
    ).fetchone() is not None
    names = [domain] + ([f"www.{domain}"] if d["redirect_www"] and not explicit_www else [])
    certs = {}
    pending = []
    for name in names:
        try:
            certs[name] = resolve_certificate(conn, ssl_dir, name).stub
        except ValueError:
            if not allow_missing_cert:
                raise
            # Draft-only placeholder. This intentionally cannot be deployed:
            # validation rejects PENDING-SSL, and nginx -t would fail.
            certs[name] = f"PENDING-SSL-{name}"
            pending.append(name)
    lines = [f"# Managed by nginx-control-plane-v2: {domain}",
             *[f"# PENDING-SSL for {name}: certificate must be issued and draft regenerated" for name in pending],
             "server {", "    listen 80;", "    listen [::]:80;", f"    server_name {' '.join(names)};",
             f"    return 301 https://{domain}$request_uri;", "}"]
    for alias in names[1:]:
        cert = certs[alias]
        lines += ["server {", "    listen 443 ssl;", "    listen [::]:443 ssl;",
                  "    http2 on;", f"    server_name {alias};",
                  f"    ssl_certificate /etc/nginx/ssl/{cert}.crt;",
                  f"    ssl_certificate_key /etc/nginx/ssl/{cert}.key;",
                  f"    return 301 https://{domain}$request_uri;", "}"]
    cert = certs[domain]
    lines += ["server {", "    listen 443 ssl;", "    listen [::]:443 ssl;",
              "    http2 on;", f"    server_name {domain};",
              f"    ssl_certificate /etc/nginx/ssl/{cert}.crt;",
              f"    ssl_certificate_key /etc/nginx/ssl/{cert}.key;",
              f"    client_max_body_size {d['body_limit_mb']}m;",
              "    server_tokens off;"]
    if d["security_profile"] == "legacy":
        lines += [
            "    include /etc/nginx/conf.d/includes/security.conf;",
            "    include /etc/nginx/conf.d/buffer.conf;",
            "    access_log off;",
            f"    error_log logs/{domain}.error.log warn;",
        ]
    else:
        lines += ["    ssl_protocols TLSv1.2 TLSv1.3;",
                  "    add_header X-Content-Type-Options nosniff always;",
                  "    add_header Referrer-Policy strict-origin-when-cross-origin always;"]
    # Optional staged per-host controls. These are not retroactive changes to
    # the original V1 live config, and require explicit draft generation.
    has_security = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='security_options'"
    ).fetchone() is not None
    if has_security:
        flags = conn.execute("SELECT * FROM security_options WHERE domain=?",
                             (domain,)).fetchone()
        if flags:
            if flags["hsts"]:
                lines.append('    add_header Strict-Transport-Security "max-age=31536000" always;')
            if flags["nosniff"]:
                lines.append('    add_header X-Content-Type-Options "nosniff" always;')
            if flags["xframe"]:
                lines.append('    add_header X-Frame-Options "SAMEORIGIN" always;')
    has_includes = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='domain_includes'"
    ).fetchone() is not None
    if has_includes:
        from .admin_features import INCLUDE_NAME
        for inc in conn.execute("SELECT filename FROM domain_includes WHERE domain=? ORDER BY filename",
                                (domain,)):
            filename = inc["filename"]
            if not INCLUDE_NAME.fullmatch(filename):
                raise ValueError("Unsafe staged include name")
            directive = f"    include /etc/nginx/conf.d/includes/{filename};"
            if directive not in lines:
                lines.append(directive)
    routes = conn.execute("SELECT * FROM routes WHERE domain=? ORDER BY id",
                          (domain,)).fetchall()
    if not routes:
        raise ValueError(f"No backend routes configured for {domain}")
    for r in routes:
        target, path = r["target"], r["path"]
        # Validate again at the rendering boundary.
        upstream(target)
        route_path(path)
        # proxy_uri overrides legacy slash-stripping. It supports special
        # locations like /health -> backend/health without accidental rewriting.
        suffix = r["proxy_uri"] if r["proxy_uri"] is not None else (
            "/" if r["strip_prefix"] else ""
        )
        if suffix:
            route_path(suffix)
        destination = f"http://{target}" + suffix
        lines += [f"    location {path} {{",
                  f"        proxy_pass {destination};",
                  "        proxy_http_version 1.1;"]
        # Legacy config forwards Upgrade and Connection unconditionally for
        # every location. Preserve it in parity mode; new profiles can opt in.
        if d["security_profile"] == "legacy" or r["websocket"]:
            lines += ["        proxy_set_header Upgrade $http_upgrade;",
                      "        proxy_set_header Connection \"upgrade\";"]
        lines += [
            "        proxy_set_header Host $host;",
            "        proxy_set_header X-Real-IP $remote_addr;",
            "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "        proxy_set_header X-Forwarded-Proto $scheme;",
        ]
        if d["security_profile"] == "legacy":
            lines += ["        proxy_set_header X-Forwarded-Host $host;",
                      "        proxy_set_header X-Forwarded-Server $host;"]
        lines += ["    }"]
    lines += ["}", ""]
    return "\n".join(lines)
