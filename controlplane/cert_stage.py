"""Operator-approved staging of an already issued shared wildcard into Docker's SSL bind mount.

No Nginx configuration changes, certificate issuance, Docker reload/restart,
or overwriting of existing certificate paths. Dry-run is the default.
Run as an unprivileged user with existing write access to the production SSL
directory; NEVER use sudo against a user-writable checkout.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from .core import cert_stub, hostname, inspect_certificate


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"Expected a real directory, not a symlink: {path}")


def _source_bytes(path: Path, max_length: int) -> bytes:
    if path.is_symlink():
        raise ValueError(f"Source symlink is forbidden: {path}")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode) or not 100 <= details.st_size <= max_length:
            raise ValueError(f"Invalid source certificate/key file: {path.name}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(max_length + 1)
        if len(data) != details.st_size:
            raise ValueError("Certificate/key changed during read")
        return data
    finally:
        os.close(fd)


def _existing_state(path: Path, desired: bytes, *, private: bool) -> str:
    # Explicitly do not follow symlinks (including broken symlinks).
    if path.is_symlink():
        raise ValueError(f"Target symlink is forbidden: {path}")
    try:
        details = path.stat()
    except FileNotFoundError:
        return "missing"
    if not stat.S_ISREG(details.st_mode):
        raise ValueError(f"Target is not a regular file: {path}")
    if private and (stat.S_IMODE(details.st_mode) & 0o077):
        raise ValueError(f"Private key has unsafe permissions: {path.name}")
    if path.read_bytes() != desired:
        raise ValueError(f"Existing immutable target differs; refusing overwrite: {path.name}")
    return "identical"


def _load_candidate(db: sqlite3.Connection, lab_ssl: Path, zone: str,
                    stub: str) -> tuple[bytes, bytes, str]:
    zone, stub = hostname(zone), cert_stub(stub)
    if not stub.startswith(f"wildcard.{zone}."):
        raise ValueError("Certificate stub does not belong to the requested wildcard zone")
    exists = db.execute(
        "SELECT 1 FROM certificates WHERE zone=? AND kind='wildcard' AND stub=?",
        (zone, stub),
    ).fetchone()
    if exists is None:
        raise ValueError("Requested wildcard has not been registered in V2 inventory")
    _directory(lab_ssl)
    cert_file = lab_ssl / (stub + ".crt")
    key_file = lab_ssl / (stub + ".key")
    crt = _source_bytes(cert_file, 1024 * 1024)
    key = _source_bytes(key_file, 128 * 1024)
    # Every immutable V2 cert has a content-derived filename. Prevent staging
    # swapped bytes under an old revision's still-referenced filename.
    combined = _sha(crt + key)
    if stub != f"wildcard.{zone}.{combined[:20]}":
        raise ValueError("Certificate/key bytes do not match the immutable V2 stub")
    info = inspect_certificate(lab_ssl, stub, min_days=14)
    if not {zone, f"*.{zone}"}.issubset(set(info.names)):
        raise ValueError("Certificate must cover zone apex and its one-level wildcard")
    # Detect concurrent modification after validation, before copying.
    if _source_bytes(cert_file, 1024 * 1024) != crt or _source_bytes(key_file, 128 * 1024) != key:
        raise ValueError("Source changed after certificate validation")
    return crt, key, info.expires.isoformat()


def _live_ssl(root: Path) -> Path:
    if not root.is_absolute():
        raise ValueError("Production root must be an absolute path")
    root = root.absolute()
    _directory(root)
    _directory(root / "ssl")
    _directory(root / "conf")
    _directory(root / "conf" / "auto")
    return root / "ssl"


def _verify_mounts(root: Path) -> None:
    """Ensure this is the SSL directory used by the existing nginx-proxy container."""
    done = subprocess.run(
        ["docker", "inspect", "--format", "{{json .Mounts}}", "nginx-proxy"],
        capture_output=True, text=True, check=True, timeout=20,
    )
    mounts = json.loads(done.stdout)
    mapped = {m.get("Destination"): Path(m.get("Source", "")).resolve()
              for m in mounts if m.get("Type") == "bind"}
    if mapped.get("/etc/nginx/ssl") != (root / "ssl").resolve():
        raise ValueError("Production SSL directory is not the nginx-proxy SSL bind mount")
    if mapped.get("/etc/nginx/conf.d") != (root / "conf").resolve():
        raise ValueError("Production conf directory is not the nginx-proxy conf bind mount")


def plan(db: sqlite3.Connection, lab_ssl: Path, root: Path, zone: str,
         stub: str) -> dict:
    crt, key, expiry = _load_candidate(db, lab_ssl, zone, stub)
    ssl = _live_ssl(root)
    cert_file, key_file = ssl / (stub + ".crt"), ssl / (stub + ".key")
    cert_status = _existing_state(cert_file, crt, private=False)
    key_status = _existing_state(key_file, key, private=True)
    return {
        "zone": zone, "stub": stub, "expires_utc": expiry,
        "certificate_sha256": _sha(crt),
        "certificate_file": str(cert_file), "certificate_state": cert_status,
        "private_key_file": str(key_file), "private_key_state": key_status,
        "ready_to_stage": True,
        "action": "Plan only. No production writes, Nginx changes or reload.",
    }


def _publish_exclusive(path: Path, data: bytes, mode: int) -> bool:
    """Publish a complete fsynced regular file without ever replacing a name."""
    fd, tmp = tempfile.mkstemp(prefix=".v2-cert-stage-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        # Hard linking the temporary inode guarantees an existing target cannot
        # be overwritten, including if another process creates it concurrently.
        try:
            os.link(tmp, path, follow_symlinks=False)
        except FileExistsError:
            _existing_state(path, data, private=(mode == 0o600))
            return False
        return True
    finally:
        Path(tmp).unlink(missing_ok=True)


def stage(db: sqlite3.Connection, lab_ssl: Path, root: Path,
          zone: str, stub: str, *, confirm_zone: str) -> dict:
    if confirm_zone != hostname(zone):
        raise ValueError("Explicit --confirm-zone must match the exact DNS zone")
    ssl = _live_ssl(root)
    # Do not permit unintentional writes to any unrelated Docker mount.
    _verify_mounts(root)
    lock_path = ssl / ".v2-cert-stage.lock"
    lock_fd = os.open(
        lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        with os.fdopen(lock_fd, "a+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            # Re-read and revalidate under the lock; no trust in an old plan.
            candidate = plan(db, lab_ssl, root, zone, stub)
            crt, key, _ = _load_candidate(db, lab_ssl, zone, stub)
            cert_file, key_file = ssl / (stub + ".crt"), ssl / (stub + ".key")
            created: list[tuple[Path, bytes]] = []
            try:
                if _publish_exclusive(key_file, key, 0o600):
                    created.append((key_file, key))
                if _publish_exclusive(cert_file, crt, 0o644):
                    created.append((cert_file, crt))
                _existing_state(key_file, key, private=True)
                _existing_state(cert_file, crt, private=False)
                info = inspect_certificate(ssl, stub, min_days=14)
                if not {zone, f"*.{zone}"}.issubset(set(info.names)):
                    raise ValueError("Production copy does not cover the zone")
            except Exception:
                # Do not remove pre-existing files, and do not delete a newly
                # published file if another actor has changed its contents.
                for path, expected in reversed(created):
                    if path.is_file() and not path.is_symlink() and path.read_bytes() == expected:
                        path.unlink()
                raise
            directory_fd = os.open(ssl, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            candidate["certificate_state"] = "verified-in-production"
            candidate["private_key_state"] = "verified-in-production"
            candidate["action"] = (
                "Staged and verified only. No config writes, Docker restart or Nginx reload."
            )
            return candidate
    except Exception:
        # os.fdopen() owns the descriptor after a successful call.
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Stage an already registered wildcard into Docker SSL; plan-only by default"
    )
    parser.add_argument("--db", type=Path, default=Path("data/migration-review.sqlite3"))
    parser.add_argument("--lab-ssl", type=Path, default=Path("ssl"))
    parser.add_argument("--production-root", type=Path, required=True)
    parser.add_argument("--zone", required=True)
    parser.add_argument("--stub", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-zone")
    args = parser.parse_args(argv)
    try:
        if not args.db.is_file():
            raise ValueError("Existing V2 inventory database required")
        with sqlite3.connect(f"file:{args.db.resolve()}?mode=ro", uri=True) as db:
            db.row_factory = sqlite3.Row
            result = (stage(db, args.lab_ssl, args.production_root, args.zone,
                            args.stub, confirm_zone=args.confirm_zone or "")
                      if args.execute else
                      plan(db, args.lab_ssl, args.production_root, args.zone, args.stub))
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError,
            json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
