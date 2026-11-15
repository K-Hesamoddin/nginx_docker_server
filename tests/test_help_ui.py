"""The Persian handbook and every tour are linked, read-only and access-controlled."""
import pytest
from markupsafe import escape
from werkzeug.security import generate_password_hash

from controlplane.core import open_db, save_domain, save_route
from controlplane.management import ensure_schema
from controlplane.admin_features import ensure_features, user_upsert
from controlplane.help_ui import GUIDE_ORDER, GUIDES
from controlplane.web import create_app


@pytest.fixture
def site(tmp_path, monkeypatch):
    db_path = tmp_path / "operator-docs.sqlite3"
    monkeypatch.setenv("CONTROLPLANE_DB", str(db_path))
    monkeypatch.setenv("SSL_DIR", str(tmp_path / "ssl"))
    monkeypatch.setenv("PANEL_SECRET_KEY", "s" * 48)
    monkeypatch.setenv("PANEL_PASSWORD_HASH", generate_password_hash("test-admin-strong-password"))
    db = open_db(db_path)
    ensure_schema(db)
    ensure_features(db, bootstrap_hash=generate_password_hash("test-admin-strong-password"))
    save_domain(db, "cloud.micromodern.ir")
    save_route(db, "cloud.micromodern.ir", "/", "192.168.1.52:8082")
    app = create_app()
    app.testing = True
    client = app.test_client()
    assert client.post("/login", data={
        "username": "admin", "password": "test-admin-strong-password"
    }).status_code == 302
    yield client, db
    db.close()


def test_all_help_pages_render_guide_and_step_tours(site):
    client, db = site
    index = client.get("/help")
    assert index.status_code == 200
    assert "راهنمای عملیاتی پنل".encode() in index.data
    assert len(GUIDE_ORDER) == 11
    assert len(set(GUIDE_ORDER)) == len(GUIDE_ORDER)
    for key in GUIDE_ORDER:
        entry = GUIDES[key]
        assert entry["title"] and entry["summary"] and entry["scenario"]
        assert entry["warnings"] and len(entry["steps"]) >= 5
        guide = client.get(f"/help/{key}")
        assert guide.status_code == 200, key
        assert entry["title"].encode() in guide.data
        assert f"/help/{key}/tour?step=1".encode() in guide.data
        for step_idx, step in enumerate(entry["steps"], start=1):
            assert len(step) == 4
            assert all(step)
            heading, description, verify, path = step
            assert path.startswith("/") and not path.startswith("//")
            assert "http://" not in path
            tour = client.get(f"/help/{key}/tour?step={step_idx}")
            assert tour.status_code == 200, (key, step_idx)
            assert heading.encode() in tour.data
            assert str(escape(description)).encode() in tour.data
            assert str(escape(verify)).encode() in tour.data
            assert f"گام {step_idx} از {len(entry['steps'])}".encode() in tour.data
        assert client.get(f"/help/{key}/tour?step=0").status_code == 404
        assert client.get(f"/help/{key}/tour?step=999").status_code == 404

    # Reading the entire handbook doesn't create revisions, jobs or audit logs.
    assert db.execute("SELECT count(*) FROM operator_jobs").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM config_versions").fetchone()[0] == 0


def test_help_requires_login_and_rejects_invalid_slug(site):
    client, db = site
    stranger = client.application.test_client()
    unauth = stranger.get("/help")
    assert unauth.status_code == 302
    assert unauth.location.endswith("/")
    assert stranger.get("/help/routes/tour?step=1").status_code == 302
    assert client.get("/help/not-a-real-section").status_code == 404
    assert client.get("/help/not-a-real-section/tour").status_code == 404

    user_upsert(db, 1, "viewer2", "my-strong-viewer-password", "viewer")
    viewer = client.application.test_client()
    assert viewer.post("/login", data={
        "username": "viewer2", "password": "my-strong-viewer-password"
    }).status_code == 302
    assert viewer.get("/help").status_code == 200
    assert viewer.get("/help/security/tour?step=1").status_code == 200
    assert viewer.post("/help/security").status_code == 403


def test_each_admin_section_has_contextual_help_and_tour(site):
    client, _ = site
    pages = {
        "/admin": "overview",
        "/admin/ssl": "ssl",
        "/admin/includes": "security",
        "/admin/streams": "streams",
        "/admin/users": "users",
        "/admin/access": "access",
    }
    for page, key in pages.items():
        response = client.get(page)
        assert response.status_code == 200, page
        assert f"/help/{key}".encode() in response.data
        assert f"/help/{key}/tour?step=1".encode() in response.data

    index = client.get("/manage")
    assert index.status_code == 200
    assert b"/help/domains" in index.data
    assert b"/help/jobs" in index.data
    detail = client.get("/manage/cloud.micromodern.ir")
    assert detail.status_code == 200
    assert b"/help/routes/tour?step=1" in detail.data
    assert b"/help/versions/tour?step=1" in detail.data
    assert b"/help/ssl" in detail.data
    home = client.get("/")
    assert home.status_code == 200
    assert b"/help" in home.data
