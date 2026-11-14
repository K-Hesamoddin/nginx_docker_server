"""Staged, per-domain configuration revisions and operator-job queue.

No live file writes, Docker commands, ACME requests or privileged runner calls
are made by this module. A route edit NEVER implicitly regenerates a draft.
Every generated or manually edited draft is an immutable saved revision.
"""
from __future__ import annotations

import difflib
import hashlib
import sqlite3
from pathlib import Path

from .core import audit, hostname, render_config

MAX_CONFIG_BYTES = 128 * 1024
MAX_NOTE_CHARS = 500


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS config_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL REFERENCES domains(name) ON DELETE CASCADE,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        origin TEXT NOT NULL CHECK(origin IN ('generated','manual','live_snapshot')),
        body TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS ix_config_versions_domain ON config_versions(domain,id);
    CREATE TABLE IF NOT EXISTS config_heads (
        domain TEXT PRIMARY KEY REFERENCES domains(name) ON DELETE CASCADE,
        draft_version_id INTEGER REFERENCES config_versions(id),
        deployed_version_id INTEGER REFERENCES config_versions(id)
    );
    CREATE TABLE IF NOT EXISTS operator_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL CHECK(kind IN ('deploy','issue-dedicated','issue-wildcard')),
        domain TEXT NOT NULL,
        version_id INTEGER REFERENCES config_versions(id),
        status TEXT NOT NULL DEFAULT 'pending'
            CHECK(status IN ('pending','running','succeeded','failed','cancelled')),
        requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        started_at TEXT,
        finished_at TEXT,
        result TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS ix_operator_jobs_status ON operator_jobs(status,id);
    """)
    conn.commit()


def _existing_domain(conn: sqlite3.Connection, domain: str) -> str:
    name = hostname(domain)
    if conn.execute("SELECT 1 FROM domains WHERE name=?", (name,)).fetchone() is None:
        raise ValueError(f"Domain {name} is not registered")
    return name


def store_version(conn: sqlite3.Connection, domain: str, body: str, origin: str,
                  note: str = "") -> int:
    domain = _existing_domain(conn, domain)
    if origin not in {"generated", "manual", "live_snapshot"}:
        raise ValueError("Unsupported revision source")
    if not isinstance(body, str) or not body.strip() or "\x00" in body:
        raise ValueError("Config revision is empty or contains a NUL byte")
    body = body.replace("\r\n", "\n")
    if len(body.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise ValueError("Config revision exceeds 128 KiB")
    note = (note or "").strip()[:MAX_NOTE_CHARS]
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    with conn:
        cursor = conn.execute(
            """INSERT INTO config_versions(domain,origin,body,sha256,note)
               VALUES(?,?,?,?,?)""",
            (domain, origin, body, digest, note)
        )
        rev_id = cursor.lastrowid
        if origin != "live_snapshot":
            conn.execute(
                """INSERT INTO config_heads(domain,draft_version_id)
                   VALUES(?,?) ON CONFLICT(domain) DO UPDATE SET
                   draft_version_id=excluded.draft_version_id""",
                (domain, rev_id)
            )
        audit(conn, "config-version", f"{domain} #{rev_id} {origin} {digest[:12]}")
    return rev_id


def generate_revision(conn: sqlite3.Connection, ssl_dir: Path,
                      domain: str) -> int:
    """Explicit generation only. Missing SSL is labelled PENDING-SSL in draft."""
    domain = _existing_domain(conn, domain)
    body = render_config(conn, ssl_dir, domain, allow_missing_cert=True)
    return store_version(conn, domain, body, "generated", "Generated from current routes")


def load_version(conn: sqlite3.Connection, domain: str, revision_id: int) -> sqlite3.Row:
    domain = _existing_domain(conn, domain)
    row = conn.execute(
        "SELECT * FROM config_versions WHERE id=? AND domain=?",
        (int(revision_id), domain)
    ).fetchone()
    if row is None:
        raise ValueError("Revision does not belong to domain")
    return row


def config_history(conn: sqlite3.Connection, domain: str, limit: int = 40):
    domain = _existing_domain(conn, domain)
    return conn.execute(
        """SELECT id,created_at,origin,sha256,note FROM config_versions
           WHERE domain=? ORDER BY id DESC LIMIT ?""",
        (domain, max(1, min(100, limit)))
    ).fetchall()


def revision_diff(conn: sqlite3.Connection, domain: str, revision_id: int) -> str:
    row = load_version(conn, domain, revision_id)
    older = conn.execute(
        """SELECT id,body FROM config_versions
           WHERE domain=? AND id<? ORDER BY id DESC LIMIT 1""",
        (domain, int(row["id"]))
    ).fetchone()
    before = older["body"] if older else ""
    comparison = difflib.unified_diff(
        before.splitlines(keepends=True), row["body"].splitlines(keepends=True),
        fromfile=f"version-{older['id']}" if older else "empty",
        tofile=f"version-{row['id']}"
    )
    return "".join(comparison)


def snapshot_live(conn: sqlite3.Connection, nginx_dump: str, domain: str) -> int | None:
    """Archive current legacy conf for review, never mark as V2-deployed."""
    from .audit import extract_live_block
    domain = _existing_domain(conn, domain)
    body = extract_live_block(nginx_dump, domain)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    row = conn.execute(
        """SELECT id FROM config_versions
           WHERE domain=? AND origin='live_snapshot' AND sha256=?
           ORDER BY id DESC LIMIT 1""",
        (domain, digest)
    ).fetchone()
    if row:
        return None
    return store_version(conn, domain, body, "live_snapshot",
                         "Read-only snapshot from nginx -T; not V2-deployed")


def snapshot_all(conn: sqlite3.Connection, nginx_dump: str) -> dict:
    """Import read-only historical baselines; skip missing hosts with reasons."""
    result = {"stored": 0, "unchanged": 0, "missing": []}
    for row in conn.execute("SELECT name FROM domains ORDER BY name").fetchall():
        domain = row["name"]
        try:
            version = snapshot_live(conn, nginx_dump, domain)
        except ValueError as exc:
            result["missing"].append({"domain": domain, "error": str(exc)})
            continue
        if version is None:
            result["unchanged"] += 1
        else:
            result["stored"] += 1
    return result


def queue_deployment(conn: sqlite3.Connection, domain: str,
                     revision_id: int) -> int:
    """Only record request. Do not test/reload, even when admin requests it."""
    row = load_version(conn, domain, revision_id)
    if row["origin"] == "live_snapshot":
        raise ValueError("A legacy snapshot is reference-only; save it as a reviewed manual draft")
    if f"# Managed by nginx-control-plane-v2: {domain}" not in row["body"].splitlines()[:4]:
        raise ValueError("Managed V2 header missing; cannot enqueue")
    with conn:
        job = conn.execute(
            """INSERT INTO operator_jobs(kind,domain,version_id)
               VALUES('deploy',?,?)""", (domain, revision_id)
        )
        audit(conn, "deploy-requested", f"{domain} revision #{revision_id} job #{job.lastrowid}")
    return job.lastrowid


def queue_certificate(conn: sqlite3.Connection, zone: str, kind: str) -> int:
    """Queue explicit DNS-01 request; API tokens never enter SQLite."""
    zone = hostname(zone)
    if kind not in {"dedicated", "wildcard"}:
        raise ValueError("Certificate kind must be dedicated or wildcard")
    existing = {
        row["name"] for row in conn.execute("SELECT name FROM domains")
    }
    if kind == "dedicated":
        alias = zone.startswith("www.") and zone[4:] in existing
        if zone not in existing and not alias:
            raise ValueError("Add the domain or its apex before requesting a dedicated cert")
    elif not (zone in existing or any(d.endswith("." + zone) for d in existing)):
        raise ValueError("Zone is not related to a registered hostname")
    with conn:
        job = conn.execute(
            "INSERT INTO operator_jobs(kind,domain) VALUES(?,?)",
            (f"issue-{kind}", zone)
        )
        audit(conn, "certificate-requested", f"{kind} {zone} job #{job.lastrowid}")
    return job.lastrowid
