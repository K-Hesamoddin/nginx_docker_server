"""Migration preflight is read-only and blocks unsafe assumptions."""
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

from controlplane.admin_features import ensure_features
from controlplane.core import open_db, save_domain, save_route
from controlplane.management import ensure_schema, generate_revision, store_version
from controlplane.preflight import review_revision
from controlplane.web import create_app


@pytest.fixture
def inventory(tmp_path, monkeypatch):
    path = tmp_path / "inventory.sqlite"
    monkeypatch.setenv("CONTROLPLANE_DB", str(path))
    monkeypatch.setenv("SSL_DIR", str(tmp_path / "ssl"))
    monkeypatch.setenv("PANEL_SECRET_KEY", "k" * 48)
    monkeypatch.setenv("PANEL_PASSWORD_HASH", generate_password_hash("a-long-test-password"))
    db = open_db(path)
    ensure_schema(db)
    ensure_features(db, bootstrap_hash=generate_password_hash("a-long-test-password"))
    save_domain(db, "staging.example.com")
    save_route(db, "staging.example.com", "/", "192.0.2.18:3000")
    yield db, tmp_path
    db.close()


def test_missing_draft_and_archive_are_blocked(inventory):
    db, root = inventory
    out = review_revision(db, root / "ssl", "staging.example.com")
    assert out["revision_id"] is None
    assert any("Draft" in x for x in out["blockers"])
    assert db.execute("SELECT count(*) FROM operator_jobs").fetchone()[0] == 0


def test_preflight_does_not_skip_live_drift_or_pending_ssl(inventory):
    db, root = inventory
    archived = """server {
    server_name staging.example.com;
    include /etc/nginx/conf.d/includes/security.conf;
    include /etc/nginx/conf.d/buffer.conf;
    location / { proxy_pass http://192.0.2.18:3000/; }
    location /health { proxy_pass http://192.0.2.18:3000/health; }
}"""
    store_version(db, "staging.example.com", archived, "live_snapshot")
    ver = generate_revision(db, root / "ssl", "staging.example.com")
    before = db.execute("SELECT count(*) FROM config_versions").fetchone()[0]
    res = review_revision(db, root / "ssl", "staging.example.com", ver)
    assert res["revision_id"] == ver
    assert any("PENDING-SSL" in x for x in res["blockers"])
    assert any("Route /health" in x for x in res["blockers"])
    assert any("snapshot" in x.lower() for x in res["checks"])
    assert any("nginx -t" in x for x in res["warnings"])
    assert db.execute("SELECT count(*) FROM config_versions").fetchone()[0] == before
    assert db.execute("SELECT count(*) FROM operator_jobs").fetchone()[0] == 0


def test_fake_ssl_reference_never_makes_preflight_pass(inventory):
    db, root = inventory
    domain = "staging.example.com"
    stored = store_version(db, domain, """# Managed by nginx-control-plane-v2: staging.example.com
server {
    listen 443 ssl;
    server_name staging.example.com;
    ssl_certificate /etc/nginx/ssl/fake.crt;
    ssl_certificate_key /etc/nginx/ssl/fake.key;
    location / { proxy_pass http://192.0.2.18:3000/; }
}""", "manual")
    out = review_revision(db, root / "ssl", domain, stored)
    assert any("fake" in x for x in out["blockers"])
    assert any("snapshot" in x for x in out["blockers"])


def test_http_preflight_is_authorized_read_only(inventory):
    db, root = inventory
    app = create_app()
    app.testing = True
    unauth = app.test_client()
    assert unauth.get("/manage/staging.example.com/preflight").status_code == 302
    client = app.test_client()
    assert client.post("/login", data={
        "username": "admin", "password": "a-long-test-password"
    }).status_code == 302
    before = db.execute("SELECT count(*) FROM audit").fetchone()[0]
    r = client.get("/manage/staging.example.com/preflight")
    assert r.status_code == 200
    assert "بررسی آمادگی مهاجرت".encode() in r.data
    assert b"nginx -t" in r.data
    assert client.get("/manage/staging.example.com").status_code == 200
    assert b"/manage/staging.example.com/preflight" in client.get("/manage/staging.example.com").data
    assert db.execute("SELECT count(*) FROM audit").fetchone()[0] == before
    assert db.execute("SELECT count(*) FROM operator_jobs").fetchone()[0] == 0
    with client.session_transaction() as sess:
        csrf = sess["csrf"]
    assert client.post("/manage/staging.example.com/preflight",
                       data={"csrf": csrf}).status_code == 405
