"""One-shot single-job Nginx deploy operator.

Dry-run is the default. A live deployment is NEVER triggered by the web UI,
the panel user service, a timer or by importing this module. It requires an
explicit shell invocation and multiple operator-supplied revision/current-file
hash approvals. Do not install a privileged wrapper from the writable lab.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import fcntl
from pathlib import Path

from .core import hostname, inspect_certificate, matches
from .management import load_version
from .preflight import review_revision

SHA = re.compile(r"[a-f0-9]{64}\Z")
SERVER = re.compile(r"(?m)^\s*server\s*\{")
NAMES = re.compile(r"(?m)^\s*server_name\s+([^;]+);")
CERT = re.compile(r"(?m)^\s*ssl_certificate\s+([^;]+);")
KEY = re.compile(r"(?m)^\s*ssl_certificate_key\s+([^;]+);")
CERT_PATH = re.compile(r"/etc/nginx/ssl/([a-zA-Z0-9][a-zA-Z0-9_.-]{0,127})\.crt\Z")
KEY_PATH = re.compile(r"/etc/nginx/ssl/([a-zA-Z0-9][a-zA-Z0-9_.-]{0,127})\.key\Z")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _no_symlink(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"Refusing symlink: {path}")


def _layout(root: Path, domain: str) -> Path:
    root = root.absolute()
    if not root.is_dir():
        raise ValueError("Production root missing")
    for part in (root, root / "conf", root / "conf" / "auto", root / "ssl"):
        _no_symlink(part)
        if not part.is_dir():
            raise ValueError(f"Required production directory missing: {part}")
    target = root / "conf" / "auto" / (hostname(domain) + ".conf")
    _no_symlink(target)
    if not target.is_file() or not stat.S_ISREG(target.stat().st_mode):
        # Initial migration is explicitly existing-file only.
        raise ValueError("No existing regular per-domain live config; new-domain deployment not supported")
    return target


def _ssl_server_blocks(body: str) -> list[tuple[str, str, str]]:
    """Restricted block parser. Fail closed on ambiguous SSL config."""
    result = []
    for match in SERVER.finditer(body):
        pos = match.end()
        depth = 1
        i = pos
        in_quote = False
        while i < len(body) and depth:
            ch = body[i]
            if ch == '"':
                in_quote = not in_quote
            elif not in_quote and ch == '{':
                depth += 1
            elif not in_quote and ch == '}':
                depth -= 1
            i += 1
        if depth:
            raise ValueError("Unbalanced server braces")
        block = body[pos:i - 1]
        # Only count directives at server block scope, not nested locations.
        direct = []
        nest = 0
        for line in block.splitlines():
            stripped = line.strip()
            if nest == 0:
                direct.append(line)
            nest += line.count("{") - line.count("}")
            if nest < 0:
                raise ValueError("Unexpected closing brace")
        scope = "\n".join(direct)
        if not re.search(r"(?m)^\s*listen\s+[^;]*\bssl\b[^;]*;", scope):
            continue
        n = NAMES.findall(scope)
        c = CERT.findall(scope)
        k = KEY.findall(scope)
        if len(n) != 1 or len(c) != 1 or len(k) != 1:
            raise ValueError("Every TLS server requires one server_name and one certificate/key pair")
        result.append((n[0].strip(), c[0].strip(), k[0].strip()))
    if not result:
        raise ValueError("No TLS server blocks in candidate")
    return result


def _check_tls_certificates(body: str, ssl_dir: Path) -> list[str]:
    issues = []
    for names, certificate, key in _ssl_server_blocks(body):
        crt = CERT_PATH.fullmatch(certificate)
        priv = KEY_PATH.fullmatch(key)
        if not crt or not priv or crt[1] != priv[1]:
            issues.append("Invalid or mismatched TLS certificate and key references")
            continue
        stub = crt[1]
        if (ssl_dir / (stub + ".crt")).is_symlink() or (ssl_dir / (stub + ".key")).is_symlink():
            issues.append(f"SSL symlink not supported in deployment: {stub}")
            continue
        try:
            info = inspect_certificate(ssl_dir, stub, min_days=14)
        except Exception:
            issues.append(f"Invalid, untrusted, expired or missing certificate: {stub}")
            continue
        # V2 deployment requires a shared wildcard, not legacy per-host certs.
        if not any(n.startswith("*.") for n in info.names):
            issues.append(f"New V2 deployment must use a wildcard certificate: {stub}")
        for name in names.split():
            try:
                host = hostname(name)
            except ValueError:
                issues.append("Unsupported server_name in SSL block")
                continue
            if not any(matches(pattern, host) for pattern in info.names):
                issues.append(f"Certificate {stub} does not cover SSL server_name {host}")
    return issues


def plan_job(conn: sqlite3.Connection, root: Path, job_id: int) -> dict:
    job = conn.execute("SELECT * FROM operator_jobs WHERE id=?", (int(job_id),)).fetchone()
    if not job or job["kind"] != "deploy" or job["version_id"] is None:
        raise ValueError("A queued per-domain deploy job ID is required")
    domain = hostname(job["domain"])
    target = _layout(root, domain)
    record = load_version(conn, domain, job["version_id"])
    body = record["body"]
    current = target.read_bytes()
    report = review_revision(conn, root / "ssl", domain, record["id"])
    # Route/upstream changes are a legitimate purpose of a deploy. Preflight
    # classifies them as requiring human review; the CLI requires a separate
    # reviewed-diff acknowledgement AND the exact current-file SHA256.
    # Missing/invalid SSL, unknown syntax and missing snapshots are never bypassed.
    review_required = [
        item for item in report["blockers"]
        if item.startswith("تفاوت Route ") or item.startswith("Includeهای جدید")
    ]
    blockers = [item for item in report["blockers"] if item not in review_required]
    if job["status"] != "pending":
        blockers.append("Deployment job must be pending")
    if digest(body.encode("utf-8")) != record["sha256"]:
        blockers.append("Candidate revision SHA256 mismatch")
    if f"# Managed by nginx-control-plane-v2: {domain}" not in body.splitlines()[:4]:
        blockers.append("Candidate is not explicitly V2-managed")
    if "PENDING-SSL-" in body:
        blockers.append("PENDING-SSL is not deployable")
    try:
        blockers.extend(_check_tls_certificates(body, root / "ssl"))
    except ValueError as exc:
        blockers.append(str(exc))
    flags = conn.execute(
        "SELECT first_flag,second_flag FROM legacy_flags WHERE domain=?", (domain,)
    ).fetchone()
    legacy = bool(flags and "0" in (flags["first_flag"], flags["second_flag"]))
    return {
        "job": int(job_id), "domain": domain, "revision": record["id"],
        "current_sha256": digest(current), "revision_sha256": record["sha256"],
        "live_file": str(target), "legacy_manual": legacy,
        "blockers": list(dict.fromkeys(blockers)),
        "review_required": review_required,
        "warnings": report["warnings"],
        "eligible_for_operator_review": not blockers,
        "scope": "No Docker calls or writes in plan. Approval does not bypass TLS/route blockers.",
    }


def _docker(*args: str) -> str:
    done = subprocess.run(["docker", *args], capture_output=True, text=True,
                          timeout=30, check=True)
    return done.stdout


def _verify_mounts(root: Path) -> None:
    mounts = json.loads(_docker("inspect", "--format", "{{json .Mounts}}", "nginx-proxy"))
    got = {m.get("Destination"): Path(m.get("Source", "")).resolve()
           for m in mounts if m.get("Type") == "bind"}
    for destination, subdir in (
        ("/etc/nginx/conf.d", "conf"), ("/etc/nginx/ssl", "ssl"),
    ):
        if got.get(destination) != (root / subdir).resolve():
            raise ValueError(f"nginx-proxy is not bind-mounted to expected {subdir} directory")


def _probe(host: str) -> int:
    """Check local TLS handshake + a short root request after reload."""
    ctx = ssl.create_default_context()
    with socket.create_connection(("127.0.0.1", 443), timeout=6) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as secure:
            secure.settimeout(6)
            secure.sendall(("HEAD / HTTP/1.1\r\nHost: " + host +
                            "\r\nConnection: close\r\n\r\n").encode("ascii"))
            data = secure.recv(512)
    match = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})\b", data)
    if not match or int(match[1]) >= 500:
        raise ValueError("Local origin health check failed")
    return int(match[1])


def _atomic(target: Path, data: bytes) -> None:
    previous = target.stat() if target.exists() else None
    fd, name = tempfile.mkstemp(prefix=".v2-atomic-", dir=target.parent)
    try:
        os.fchmod(fd, stat.S_IMODE(previous.st_mode) if previous else 0o644)
        if previous and os.geteuid() == 0:
            os.fchown(fd, previous.st_uid, previous.st_gid)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, target)
        dir_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        Path(name).unlink(missing_ok=True)


def execute_job(conn: sqlite3.Connection, root: Path, job_id: int, *,
                expected_current_sha256: str, expected_revision_sha256: str,
                confirm_domain: str, reviewed_diff: bool = False,
                reviewed_legacy: bool = False) -> dict:
    """Operator-only action. Must never be invoked by the web request handler."""
    root = root.absolute()
    # Operator state belongs to the V2 database's existing data directory,
    # never to the unrelated V1 production Nginx tree. Requiring production
    # data/ broke existing production layouts and needlessly wrote there.
    db_files = conn.execute("PRAGMA database_list").fetchall()
    main_db = next((entry[2] for entry in db_files if entry[1] == "main"), "")
    if not main_db:
        raise ValueError("A file-backed V2 SQLite database is required for deployment")
    state_dir = Path(main_db).absolute().parent
    _no_symlink(state_dir)
    if not state_dir.is_dir():
        raise ValueError("V2 database data directory is missing")
    if stat.S_IMODE(state_dir.stat().st_mode) & 0o002:
        raise ValueError("V2 state directory must not be world-writable")
    lock_path = state_dir / "v2-oneshot-deploy.lock"
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(lock_fd, "a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        plan = plan_job(conn, root, job_id)
        if plan["blockers"]:
            raise ValueError("Preflight blockers: " + "; ".join(plan["blockers"]))
        if confirm_domain != plan["domain"]:
            raise ValueError("Must explicitly confirm the exact domain")
        if not reviewed_diff or (plan["legacy_manual"] and not reviewed_legacy):
            raise ValueError("Human review of config and manual-legacy ownership required")
        if (not SHA.fullmatch(expected_current_sha256) or
                expected_current_sha256 != plan["current_sha256"] or
                not SHA.fullmatch(expected_revision_sha256) or
                expected_revision_sha256 != plan["revision_sha256"]):
            raise ValueError("Live/candidate SHA256 changed; re-review before deployment")
        _verify_mounts(root)
        target = _layout(root, plan["domain"])
        # Ensure old configuration currently passes nginx -t before touching files.
        _docker("exec", "nginx-proxy", "nginx", "-t")
        # Ensure origin works before change. Unavailable sites cannot auto-migrate.
        _probe(plan["domain"])
        version = load_version(conn, plan["domain"], plan["revision"])
        old = target.read_bytes()
        body = version["body"].encode("utf-8")
        if digest(old) != expected_current_sha256:
            raise ValueError("Live file changed during validation")
        backup_root = state_dir / "v2-deploy-backups"
        _no_symlink(backup_root)
        backup_root.mkdir(mode=0o700, exist_ok=True)
        backup = backup_root / (str(int(time.time())) + "-job" + str(job_id))
        backup.mkdir(mode=0o700)
        old_path = backup / "before.conf"
        new_path = backup / "candidate.conf"
        for dest, data in ((old_path, old), (new_path, body)):
            with dest.open("xb") as out:
                os.chmod(dest, 0o600)
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
        changed = False
        try:
            _atomic(target, body)
            changed = True
            _docker("exec", "nginx-proxy", "nginx", "-t")
            _docker("exec", "nginx-proxy", "nginx", "-s", "reload")
            # Check each HTTPS name, including www. An expired old www cert
            # must not be silently accepted after switching to a wildcard.
            tested_hosts = set()
            for ssl_names, _, _ in _ssl_server_blocks(version["body"]):
                for host in ssl_names.split():
                    if host not in tested_hosts:
                        _probe(host)
                        tested_hosts.add(host)
            with conn:
                from .core import audit
                result = conn.execute(
                    """UPDATE operator_jobs SET status='succeeded',
                       started_at=COALESCE(started_at,CURRENT_TIMESTAMP),
                       finished_at=CURRENT_TIMESTAMP,
                       result=?
                       WHERE id=? AND status='pending' AND kind='deploy'
                       AND domain=? AND version_id=?""",
                    ("Applied single revision; backup " + str(backup),
                     job_id, plan["domain"], plan["revision"])
                )
                if result.rowcount != 1:
                    raise ValueError("Job status changed; deployment cannot be committed")
                conn.execute(
                    """INSERT INTO config_heads(domain,deployed_version_id)
                       VALUES(?,?) ON CONFLICT(domain) DO UPDATE SET
                       deployed_version_id=excluded.deployed_version_id""",
                    (plan["domain"], plan["revision"])
                )
                audit(conn, "deploy-succeeded",
                      f"job {job_id}, {plan['domain']}, revision {plan['revision']}")
            return {"status": "succeeded", "job": job_id,
                    "domain": plan["domain"], "backup": str(backup)}
        except Exception:
            if changed:
                try:
                    _atomic(target, old)
                    _docker("exec", "nginx-proxy", "nginx", "-t")
                    _docker("exec", "nginx-proxy", "nginx", "-s", "reload")
                except Exception as rollback_exc:
                    raise RuntimeError(
                        "CRITICAL: rollback failed. Backup preserved at " + str(backup)
                    ) from rollback_exc
            # A failed attempt must not remain misleadingly pending.
            with conn:
                from .core import audit
                conn.execute(
                    """UPDATE operator_jobs
                       SET status='failed', started_at=COALESCE(started_at,CURRENT_TIMESTAMP),
                           finished_at=CURRENT_TIMESTAMP, result=?
                       WHERE id=? AND kind='deploy' AND status='pending'""",
                    ("Deployment failed; prior config restored; backup " + str(backup),
                     job_id)
                )
                audit(conn, "deploy-failed-rolled-back",
                      f"job {job_id}, {plan['domain']}")
            # Preserve backup for forensic review and explicit future rollback.
            raise


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="V2 one-shot operator deploy; plan-only by default")
    p.add_argument("--db", type=Path, required=True)
    p.add_argument("--production-root", type=Path, required=True)
    p.add_argument("--job-id", type=int, required=True)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--confirm-domain")
    p.add_argument("--expected-current-sha256")
    p.add_argument("--expected-revision-sha256")
    p.add_argument("--reviewed-diff", action="store_true")
    p.add_argument("--reviewed-legacy", action="store_true")
    args = p.parse_args(argv)
    try:
        if not args.db.is_file():
            raise ValueError("Existing V2 SQLite database required")
        if args.execute:
            from .core import open_db
            conn = open_db(args.db)
        else:
            conn = sqlite3.connect("file:" + str(args.db.resolve()) + "?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
        with conn:
            if args.execute:
                output = execute_job(
                    conn, args.production_root, args.job_id,
                    expected_current_sha256=args.expected_current_sha256 or "",
                    expected_revision_sha256=args.expected_revision_sha256 or "",
                    confirm_domain=args.confirm_domain or "",
                    reviewed_diff=args.reviewed_diff,
                    reviewed_legacy=args.reviewed_legacy,
                )
            else:
                output = plan_job(conn, args.production_root, args.job_id)
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return 0 if output.get("eligible_for_operator_review", True) else 2
    except (ValueError, OSError, RuntimeError, sqlite3.Error,
            subprocess.SubprocessError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
