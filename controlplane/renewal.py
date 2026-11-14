"""Certificate renewal bridge: acme.sh DNS-01 -> validated immutable inventory.

No direct Nginx access by default. Automatic deployment is possible only after
a separate operator enablement file AND the all-V2-managed apply guard.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from .core import hostname, inspect_certificate, save_certificate


def has_valid_wildcard(conn: sqlite3.Connection, ssl_dir: Path, zone: str,
                       min_days: int = 30) -> bool:
    """Never issue repeatedly for covered subdomains while a valid wildcard exists."""
    zone = hostname(zone)
    for row in conn.execute("SELECT stub FROM certificates WHERE zone=? AND kind='wildcard'", (zone,)):
        try:
            info = inspect_certificate(ssl_dir, row["stub"], min_days=min_days)
        except (OSError, ValueError, subprocess.SubprocessError, Exception) as exc:
            # Invalid/expired cert does not count. Fail closed on trust failures.
            continue
        if {zone, f"*.{zone}"}.issubset(set(info.names)):
            return True
    return False


def reload_command(root: Path, db_file: Path, ssl_dir: Path, zone: str) -> str:
    """Build persistent, quoted acme.sh reloadcmd with no API token in it."""
    zone = hostname(zone)
    root, db_file, ssl_dir = root.resolve(), db_file.resolve(), ssl_dir.resolve()
    env = (f"CONTROLPLANE_ROOT={shlex.quote(str(root))} "
           f"CONTROLPLANE_DB={shlex.quote(str(db_file))} "
           f"SSL_DIR={shlex.quote(str(ssl_dir))}")
    python = shlex.quote(str(Path(sys.executable).resolve()))
    return (f"cd {shlex.quote(str(root))} && {env} {python} "
            f"-m controlplane.cli sync-renewed {shlex.quote(zone)}")


def configure_renewal_hook(root: Path, db_file: Path, ssl_dir: Path,
                           zone: str, acme_bin: str) -> str:
    """Have acme.sh persist stable install targets and a renewal hook.

    acme.sh invokes the reload command during installation and after future
    successful renewals. A root-owned opt-in marker gates live deployment.
    """
    zone = hostname(zone)
    if not shutil.which(acme_bin):
        raise ValueError(f"acme.sh not installed: {acme_bin}")
    staging = ssl_dir / ".acme" / zone
    staging.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(staging, 0o700)
    cmd = reload_command(root, db_file, ssl_dir, zone)
    subprocess.run([acme_bin, "--install-cert", "-d", zone, "--ecc",
                    "--fullchain-file", str(staging / "fullchain.pem"),
                    "--key-file", str(staging / "privkey.pem"),
                    "--reloadcmd", cmd], check=True)
    return cmd


def _write_exclusive(target: Path, data: bytes, mode: int) -> bool:
    """Never modify an already-existing live certificate name."""
    if target.exists():
        if target.read_bytes() != data:
            raise ValueError(f"Immutable certificate path has different content: {target.name}")
        return False
    fd, tmp = tempfile.mkstemp(prefix=".newcert-", dir=target.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        # Existing names cannot be replaced, including by a concurrent process.
        try:
            os.link(tmp, target)
        except FileExistsError:
            if target.read_bytes() != data:
                raise ValueError(f"Certificate collision: {target.name}")
            return False
        return True
    finally:
        Path(tmp).unlink(missing_ok=True)


def sync_renewed(conn: sqlite3.Connection, root: Path, ssl_dir: Path,
                 zone: str, auto_apply: bool = True) -> str:
    """Validate ACME staging pair, register immutable cert and optionally deploy.

    This is the command invoked by acme.sh's stored --reloadcmd.
    The default marker is absent; therefore Nginx is not changed.
    """
    zone = hostname(zone)
    root = root.resolve()
    ssl_dir = ssl_dir.resolve()
    stage = ssl_dir / ".acme" / zone
    if stage.is_symlink() or not stage.is_dir():
        raise ValueError("ACME staging directory missing or symbolic link")
    cert_file, key_file = stage / "fullchain.pem", stage / "privkey.pem"
    if cert_file.is_symlink() or key_file.is_symlink():
        raise ValueError("ACME staging file must not be a symlink")
    cert_bytes = cert_file.read_bytes()
    key_bytes = key_file.read_bytes()
    if not 100 <= len(cert_bytes) <= 1024 * 1024 or not 100 <= len(key_bytes) <= 128 * 1024:
        raise ValueError("Unexpected certificate or private key size")
    lock_path = ssl_dir / ".certsync.lock"
    with lock_path.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        # Verify in temporary isolated directory before publishing.
        with tempfile.TemporaryDirectory(prefix=".verify-", dir=ssl_dir) as tmp:
            tmp_root = Path(tmp)
            (tmp_root / "candidate.crt").write_bytes(cert_bytes)
            (tmp_root / "candidate.key").write_bytes(key_bytes)
            info = inspect_certificate(tmp_root, "candidate", min_days=14)
            if not {zone, f"*.{zone}"}.issubset(set(info.names)):
                raise ValueError(f"ACME certificate must cover {zone} and *.{zone}")
        digest = hashlib.sha256(cert_bytes + key_bytes).hexdigest()[:20]
        stub = f"wildcard.{zone}.{digest}"
        cert_dest, key_dest = ssl_dir / (stub + ".crt"), ssl_dir / (stub + ".key")
        # Immutable names are never overwritten; both files exist before DB update.
        _write_exclusive(key_dest, key_bytes, 0o600)
        _write_exclusive(cert_dest, cert_bytes, 0o644)
        inspect_certificate(ssl_dir, stub, min_days=14)
        save_certificate(conn, zone, "wildcard", stub)
        marker = root / "data" / "enable-auto-deploy"
        if auto_apply and marker.is_file() and not marker.is_symlink():
            if marker.read_text().strip() != "ALLOW_V2_MANAGED_DEPLOY":
                raise ValueError("Invalid auto-deploy activation marker")
            # Blocks replacing any legacy-managed config; also validates all domains.
            from .cli import apply_config
            apply_config(conn, root, ssl_dir, allow_replace_v1=False)
        return stub
