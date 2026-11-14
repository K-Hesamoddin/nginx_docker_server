import datetime as dt
from pathlib import Path
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from controlplane.core import (
    export_domains_list, hostname, import_domains_list, matches, open_db,
    render_config, resolve_certificate, save_certificate, save_domain,
    save_route, upstream,
)

def make_cert(folder: Path, stub: str, names: list[str], expired=False):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test local CA " + stub)])
    ca_cert = (x509.CertificateBuilder()
               .subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(days=100))
               .not_valid_after(now + dt.timedelta(days=200))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(ca_key, hashes.SHA256()))
    ca_bundle = folder / "test-ca-bundle.pem"
    with ca_bundle.open("ab") as output:
        output.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=80))
            .not_valid_after(now - dt.timedelta(days=1) if expired else now + dt.timedelta(days=80))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    (folder / (stub + ".crt")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (folder / (stub + ".key")).write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))


def test_hostname_and_upstream_reject_nginx_injection():
    for value in ["bad;return 200;", "x\nserver", "example.com/../", "*.example.com"]:
        with pytest.raises(ValueError):
            hostname(value)
    for value in ["127.0.0.1:0", "127.0.0.1:99999", "host:80;return", "http://x:80"]:
        with pytest.raises(ValueError):
            upstream(value)

def test_wildcard_one_level():
    assert matches("*.example.com", "api.example.com")
    assert not matches("*.example.com", "example.com")
    assert not matches("*.example.com", "a.b.example.com")

def test_dedicated_precedence_then_expired_falls_back(tmp_path, monkeypatch):
    db = open_db(tmp_path / "v2.sqlite")
    make_cert(tmp_path, "wildcard", ["example.com", "*.example.com"])
    make_cert(tmp_path, "dedicated", ["www.example.com"])
    monkeypatch.setenv("CONTROLPLANE_CA_BUNDLE", str(tmp_path / "test-ca-bundle.pem"))
    save_certificate(db, "example.com", "wildcard", "wildcard")
    save_certificate(db, "www.example.com", "dedicated", "dedicated")
    assert resolve_certificate(db, tmp_path, "www.example.com").stub == "dedicated"
    make_cert(tmp_path, "dedicated", ["www.example.com"], expired=True)
    assert resolve_certificate(db, tmp_path, "www.example.com").stub == "wildcard"
    save_domain(db, "example.com", redirect_www=True)
    save_route(db, "example.com", "/", "192.168.1.178:3000")
    conf = render_config(db, tmp_path, "example.com")
    assert "server_name www.example.com;" in conf
    assert "ssl_certificate /etc/nginx/ssl/wildcard.crt;" in conf

def test_missing_cert_blocks_render(tmp_path):
    db = open_db(tmp_path / "v2.sqlite")
    save_domain(db, "example.com")
    save_route(db, "example.com", "/", "127.0.0.1:3000")
    with pytest.raises(ValueError, match="No valid certificate"):
        render_config(db, tmp_path, "example.com")

def test_legacy_import_export(tmp_path):
    dfile = tmp_path / "domains.list"
    dfile.write_text("1 example.com / 192.168.1.178:3000 /product_backend/ 192.168.1.178:1010\n")
    db = open_db(tmp_path / "v2.sqlite")
    assert import_domains_list(db, dfile)["imported"] == 1
    assert import_domains_list(db, dfile)["skipped"] == 1
    snapshot = export_domains_list(db)
    assert "example.com" in snapshot and "/product_backend/" in snapshot

def test_admin_uses_explicit_auth(tmp_path, monkeypatch):
    from werkzeug.security import generate_password_hash
    from controlplane.web import create_app
    monkeypatch.setenv("PANEL_SECRET_KEY", "x" * 48)
    monkeypatch.setenv("PANEL_PASSWORD_HASH", generate_password_hash("test-password"))
    monkeypatch.setenv("CONTROLPLANE_DB", str(tmp_path / "v2.sqlite"))
    monkeypatch.setenv("SSL_DIR", str(tmp_path))
    app = create_app()
    client = app.test_client()
    assert client.post("/domains", data={"name": "example.com"}).status_code == 401
    assert client.post("/login", data={"password": "test-password"}).status_code == 302
    assert client.post("/domains", data={"name": "example.com"}).status_code == 403
    with client.session_transaction() as s:
        csrf = s["csrf"]
    assert client.post("/domains", data={"csrf": csrf, "name": "example.com"}).status_code == 302
    assert b"example.com" in client.get("/").data
