#!/usr/bin/env python3
"""Initialize or repair the HTTPS-only LAN lab panel, without touching Nginx.

Commands:
  init                  First-time TLS/session secret and initial admin account
  reset-admin-password  Change admin password locally from the server console
  status                Safe non-sensitive local configuration checks

No Docker, Nginx, DNS, UFW, iptables or privileged API calls.
"""
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import ipaddress
import os
import secrets
import stat
import sys
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from werkzeug.security import generate_password_hash

ROOT = Path(__file__).resolve().parent.parent
DB = Path(os.environ.get("CONTROLPLANE_DB", str(ROOT / "data/migration-review.sqlite3")))
STORE = ROOT / "data" / "panel-lan"
IP = os.environ.get("PANEL_LAN_IP", "192.168.1.205")


def require_server_user():
    if os.geteuid() == 0:
        raise RuntimeError("Refusing to initialize the web app as root")
    ip = ipaddress.ip_address(IP)
    if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_unspecified:
        raise ValueError("PANEL_LAN_IP must be a specific private IPv4 host interface")
    if not DB.is_file() or DB.is_symlink():
        raise ValueError(f"Existing lab inventory database is required: {DB}")
    if STORE.is_symlink():
        raise ValueError("Unsafe symlink panel state folder")
    STORE.mkdir(mode=0o700, parents=True, exist_ok=True)
    STORE.chmod(0o700)


def write_secret(name: str, data: bytes):
    target = STORE / name
    if target.exists() or target.is_symlink():
        raise ValueError(f"Will not overwrite existing state: {target}")
    fd, tmp = tempfile.mkstemp(prefix=".staging-", dir=STORE)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fp:
            fp.write(data)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp, target)
        target.chmod(0o600)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def ensure_secret():
    path = STORE / "session-secret"
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise ValueError("Unsafe session key path")
        if len(path.read_text().strip()) < 48:
            raise ValueError("Persistent session secret is invalid")
        path.chmod(0o600)
    else:
        write_secret("session-secret", (secrets.token_urlsafe(64) + "\n").encode())


def ensure_cert():
    cert_path, key_path = STORE / "server.crt", STORE / "server.key"
    if cert_path.is_symlink() or key_path.is_symlink():
        raise ValueError("Unsafe TLS file path")
    if cert_path.exists() != key_path.exists():
        raise ValueError("Certificate/key is incomplete. Inspect manually before changing.")
    if cert_path.exists():
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if ipaddress.ip_address(IP) not in sans.get_values_for_type(x509.IPAddress):
            raise ValueError("Stored TLS certificate has different IP SAN; inspect before replacing")
        if cert.not_valid_after_utc <= dt.datetime.now(dt.timezone.utc):
            raise ValueError("Stored TLS certificate expired. Manual rotation is required.")
        cert_path.chmod(0o600)
        key_path.chmod(0o600)
        return
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Nginx V2 LAN Lab")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([
            x509.IPAddress(ipaddress.ip_address(IP))
        ]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    write_secret("server.key", key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))
    write_secret("server.crt", cert.public_bytes(serialization.Encoding.PEM))


def prompt_password():
    first = getpass.getpass("New administrator password (min 12 chars): ")
    if len(first) < 12 or len(first) > 256:
        raise ValueError("Password must be 12-256 characters")
    second = getpass.getpass("Repeat administrator password: ")
    if not secrets.compare_digest(first, second):
        raise ValueError("Passwords do not match")
    return generate_password_hash(first)


def init_db(reset=False):
    # Import after local dependencies are available and environment is checked.
    sys.path.insert(0, str(ROOT))
    from controlplane.core import open_db, audit
    from controlplane.admin_features import ensure_features
    from controlplane.management import ensure_schema
    with open_db(DB) as conn:
        ensure_schema(conn)
        ensure_features(conn)
        existing = conn.execute(
            "SELECT id FROM panel_users WHERE username='admin'"
        ).fetchone()
        if reset:
            if not existing:
                raise ValueError("No admin account to reset; use init first")
            pwd_hash = prompt_password()
            with conn:
                conn.execute(
                    """UPDATE panel_users SET password_hash=?,active=1,role='admin',
                       auth_epoch=auth_epoch+1 WHERE username='admin'""",
                    (pwd_hash,)
                )
                audit(conn, "admin-password-reset", "local console")
            print("Administrator password reset; old sessions invalidated.")
        elif not existing:
            if conn.execute("SELECT count(*) FROM panel_users").fetchone()[0]:
                raise ValueError("User table has no admin account; manual review required")
            pwd_hash = prompt_password()
            with conn:
                conn.execute(
                    "INSERT INTO panel_users(username,password_hash,role) VALUES('admin',?,'admin')",
                    (pwd_hash,)
                )
                audit(conn, "bootstrap-user", "admin via local LAN installer")
            print("Admin account initialized in lab SQLite.")
        else:
            print("Existing admin account retained; password was NOT reset.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "reset-admin-password", "status"))
    args = parser.parse_args()
    try:
        require_server_user()
        if args.command == "status":
            print(f"LAN bind IP: {IP}, DB exists: {DB.is_file()}")
            print("TLS cert present:", (STORE / "server.crt").is_file())
            print("Secret present:", (STORE / "session-secret").is_file())
            return
        ensure_secret()
        ensure_cert()
        init_db(reset=args.command == "reset-admin-password")
        print(f"Secure LAN endpoint prepared: https://{IP}:8787/admin")
        print("The self-signed certificate is not yet trusted by browsers.")
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
