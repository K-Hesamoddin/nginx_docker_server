"""LAN-only HTTPS launcher, app ACL and browser session behavior."""
from __future__ import annotations

import ipaddress
import subprocess
from pathlib import Path

from cryptography import x509
from werkzeug.security import generate_password_hash

from controlplane.admin_features import ensure_features
from controlplane.core import open_db
from controlplane.web import create_app


def test_stale_session_redirects_to_login_and_https_cookie(tmp_path, monkeypatch):
    path = tmp_path / "lab.sqlite3"
    db = open_db(path)
    ensure_features(db, bootstrap_hash=generate_password_hash("very-strong-password"))
    db.close()
    monkeypatch.setenv("CONTROLPLANE_DB", str(path))
    monkeypatch.setenv("PANEL_PASSWORD_HASH", generate_password_hash("ignored-once-initialized"))
    monkeypatch.setenv("PANEL_SECRET_KEY", "x" * 60)
    monkeypatch.setenv("PANEL_HTTPS_ONLY", "1")
    app = create_app()
    app.testing = True
    client = app.test_client()

    assert client.get("/admin", base_url="http://127.0.0.1").status_code == 403
    anon = client.get("/admin", base_url="https://192.168.1.205:8787")
    assert anon.status_code == 302
    assert anon.location.endswith("/")
    assert client.get("/login", base_url="https://192.168.1.205:8787").status_code == 302
    assert client.get("/", base_url="https://192.168.1.205:8787").status_code == 200
    logged = client.post("/login", base_url="https://192.168.1.205:8787", data={
        "username": "admin", "password": "very-strong-password"
    })
    assert logged.status_code == 302
    assert "Secure" in logged.headers["Set-Cookie"]
    assert client.get("/admin", base_url="https://192.168.1.205:8787").status_code == 200
    denied = client.get("/admin", base_url="https://192.168.1.205:8787",
                        environ_overrides={"REMOTE_ADDR": "192.168.1.193"})
    assert denied.status_code == 403


def test_lan_cert_has_ip_san_and_private_files_without_network_or_docker(tmp_path, monkeypatch):
    from scripts import controlplane_lan as lan

    monkeypatch.setattr(lan, "STORE", tmp_path / "data" / "panel-lan")
    monkeypatch.setattr(lan, "DB", tmp_path / "data" / "lab.sqlite3")
    monkeypatch.setattr(lan, "IP", "192.168.1.205")
    monkeypatch.setattr(lan.os, "geteuid", lambda: 1000)
    lan.DB.parent.mkdir()
    lan.DB.touch()
    lan.require_server_user()
    lan.ensure_secret()
    lan.ensure_cert()
    original = (lan.STORE / "session-secret").read_bytes()
    lan.ensure_secret()
    lan.ensure_cert()
    assert (lan.STORE / "session-secret").read_bytes() == original
    cert = x509.load_pem_x509_certificate((lan.STORE / "server.crt").read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert ipaddress.ip_address("192.168.1.205") in san.get_values_for_type(x509.IPAddress)
    for p in lan.STORE.iterdir():
        assert (p.stat().st_mode & 0o777) == 0o600
    assert (lan.STORE.stat().st_mode & 0o777) == 0o700


def test_lan_scripts_are_valid_bash_and_not_docker_commands():
    root = Path(__file__).resolve().parents[1]
    for name in ("start-controlplane-lan.sh", "install-controlplane-lan.sh"):
        path = root / "scripts" / name
        assert subprocess.run(["bash", "-n", str(path)],
                              check=False, capture_output=True).returncode == 0
        content = path.read_text()
        assert "docker exec" not in content
        assert "docker compose" not in content
        assert "systemctl restart nginx" not in content

    # User-owned systemd lacks CAP_SETPCAP on this host; these sandbox
    # options caused 218/CAPABILITIES and repeated restart loops.
    installer = (root / "scripts" / "install-controlplane-lan.sh").read_text()
    unit = installer.split('cat > "$UNIT" <<EOF', 1)[1].split("\nEOF", 1)[0]
    assert "CapabilityBoundingSet=" not in unit
    assert "PrivateTmp=" not in unit
    assert "RestrictSUIDSGID=" not in unit
    assert "NoNewPrivileges=yes" in unit
    assert "systemctl --user restart nginx-controlplane-v2.service" in installer
    assert "systemctl --user is-active --quiet" in installer
    assert "ss -ltn" in installer

    runner = (root / "scripts" / "start-controlplane-lan.sh").read_text()
    assert '--certfile "$ROOT/data/panel-lan/server.crt"' in runner
    assert '--bind "${PANEL_LAN_IP}:8787"' in runner
    assert "export PANEL_HTTPS_ONLY=1" in runner
