"""Offline tests: no DNS calls, no Docker changes and no real CA issuance."""
import datetime as dt
import os
from pathlib import Path
from shutil import copyfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from controlplane.core import (
    open_db, resolve_certificate, save_certificate, save_domain, save_route,
)
from controlplane.renewal import (
    has_valid_wildcard, reload_command, sync_renewed,
)


def make_issued_pair(stage: Path, trust_bundle: Path, zone="example.com", days=75):
    stage.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Offline Test Root")])
    root = (x509.CertificateBuilder()
            .subject_name(root_name).issuer_name(root_name)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=100))
            .not_valid_after(now + dt.timedelta(days=200))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(root_key, hashes.SHA256()))
    trust_bundle.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, zone)])
    leaf = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(root_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=2))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName(zone), x509.DNSName(f"*.{zone}")]), critical=False)
            .sign(root_key, hashes.SHA256()))
    (stage / "fullchain.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (stage / "privkey.pem").write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))


@pytest.fixture
def renewal_env(tmp_path, monkeypatch):
    root = tmp_path
    ssl = root / "ssl"
    ssl.mkdir()
    stage = ssl / ".acme" / "example.com"
    ca = root / "root.pem"
    make_issued_pair(stage, ca)
    monkeypatch.setenv("CONTROLPLANE_CA_BUNDLE", str(ca))
    conn = open_db(root / "data" / "controlplane.sqlite3")
    yield conn, root, ssl, stage
    conn.close()


def test_synced_cert_is_immutable_and_reused(renewal_env):
    conn, root, ssl, stage = renewal_env
    first = sync_renewed(conn, root, ssl, "example.com")
    assert first.startswith("wildcard.example.com.")
    assert (ssl / f"{first}.crt").is_file()
    assert (ssl / f"{first}.key").is_file()
    assert os.stat(ssl / f"{first}.key").st_mode & 0o777 == 0o600
    assert has_valid_wildcard(conn, ssl, "example.com")
    assert resolve_certificate(conn, ssl, "www.example.com").stub == first
    assert sync_renewed(conn, root, ssl, "example.com") == first
    assert conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0] == 1


def test_invalid_certificate_rejected_before_inventory_change(renewal_env):
    conn, root, ssl, stage = renewal_env
    make_issued_pair(stage, root / "root.pem", zone="not-example.com")
    with pytest.raises(ValueError, match="must cover"):
        sync_renewed(conn, root, ssl, "example.com")
    assert conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0] == 0


def test_expiring_cert_rejected(renewal_env):
    conn, root, ssl, stage = renewal_env
    make_issued_pair(stage, root / "root.pem", days=4)
    with pytest.raises(ValueError, match="expired or within"):
        sync_renewed(conn, root, ssl, "example.com")
    assert conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0] == 0


def test_auto_deploy_marker_is_ignored_to_protect_manual_v1_config(renewal_env):
    conn, root, ssl, stage = renewal_env
    save_domain(conn, "example.com", redirect_www=True)
    save_route(conn, "example.com", "/", "192.168.1.178:3000")
    legacy = root / "conf" / "auto" / "example.com.conf"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("# old production config\nserver { listen 443 ssl; }\n")
    marker = root / "data" / "enable-auto-deploy"
    marker.write_text("ALLOW_V2_MANAGED_DEPLOY\n")
    # The old auto-deploy marker is deliberately ignored. Renewal records
    # a candidate and NEVER rewrites a manually managed V1 configuration.
    sync_renewed(conn, root, ssl, "example.com")
    assert legacy.read_text().startswith("# old production")
    # The newly validated cert remains in the inventory; deployment was blocked.
    assert has_valid_wildcard(conn, ssl, "example.com")


def test_no_trust_no_publish(renewal_env, monkeypatch):
    conn, root, ssl, stage = renewal_env
    monkeypatch.setenv("CONTROLPLANE_CA_BUNDLE", str(root / "missing-ca.pem"))
    with pytest.raises(ValueError, match="Untrusted certificate"):
        sync_renewed(conn, root, ssl, "example.com")
    assert not list(ssl.glob("wildcard.*.crt"))


def test_reload_command_quotes_inputs(renewal_env):
    conn, root, ssl, stage = renewal_env
    cmd = reload_command(root, root / "data" / "controlplane.sqlite3", ssl, "example.com")
    assert "sync-renewed example.com" in cmd
    assert "NSIN_Api_Key" not in cmd
    assert "CONTROLPLANE_ROOT=" in cmd
