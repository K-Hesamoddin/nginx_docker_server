"""Admin workflow regressions: explicit generation, immutable versions and safe queue."""
import os

import pytest
from werkzeug.security import generate_password_hash

from controlplane.core import open_db, save_domain, save_route
from controlplane.management import (
    config_history, ensure_schema, generate_revision, load_version,
    queue_certificate, queue_deployment, revision_diff, snapshot_live,
    store_version,
)
from controlplane.web import create_app
from tests.test_audit import DUMP


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("CONTROLPLANE_DB", str(tmp_path / "data" / "test.db"))
    monkeypatch.setenv("SSL_DIR", str(tmp_path / "ssl"))
    conn = open_db(tmp_path / "data" / "test.db")
    ensure_schema(conn)
    save_domain(conn, "micmodshop.ir", redirect_www=True)
    save_route(conn, "micmodshop.ir", "/", "192.168.1.178:3000")
    return conn


@pytest.fixture
def app_client(db, tmp_path, monkeypatch):
    monkeypatch.setenv("PANEL_SECRET_KEY", "t" * 48)
    monkeypatch.setenv("PANEL_PASSWORD_HASH", generate_password_hash("local-test-secret"))
    app = create_app()
    app.testing = True
    client = app.test_client()
    assert client.post("/login", data={"password": "local-test-secret"}).status_code == 302
    with client.session_transaction() as session:
        csrf = session["csrf"]
    return client, csrf


def test_generate_only_on_button_and_never_rewrite_version_on_route_change(db, tmp_path):
    assert config_history(db, "micmodshop.ir") == []
    save_route(db, "micmodshop.ir", "/product_backend/", "192.168.1.178:1010")
    assert config_history(db, "micmodshop.ir") == []
    version = generate_revision(db, tmp_path / "ssl", "micmodshop.ir")
    body = load_version(db, "micmodshop.ir", version)["body"]
    assert "# Managed by nginx-control-plane-v2: micmodshop.ir" in body
    assert "PENDING-SSL-micmodshop.ir" in body
    assert "location /product_backend/" in body
    save_route(db, "micmodshop.ir", "/product_backend/", "192.168.1.178:2000")
    assert load_version(db, "micmodshop.ir", version)["body"] == body
    assert len(config_history(db, "micmodshop.ir")) == 1
    with pytest.raises(ValueError, match="Domain"):
        generate_revision(db, tmp_path / "ssl", "not-registered.example")


def test_manual_revision_and_diff_are_immutable(db, tmp_path):
    first = generate_revision(db, tmp_path / "ssl", "micmodshop.ir")
    old = load_version(db, "micmodshop.ir", first)["body"]
    second = store_version(db, "micmodshop.ir", old + "\n# reviewed patch\n", "manual", "I changed it")
    assert second != first
    assert load_version(db, "micmodshop.ir", first)["body"] == old
    assert "reviewed patch" in revision_diff(db, "micmodshop.ir", second)
    head = db.execute("SELECT * FROM config_heads WHERE domain='micmodshop.ir'").fetchone()
    assert head["draft_version_id"] == second
    assert head["deployed_version_id"] is None
    assert os.stat(tmp_path / "data" / "test.db").st_mode & 0o777 == 0o600


def test_snapshot_existing_live_config_never_becomes_deployed(db):
    first = snapshot_live(db, DUMP, "micmodshop.ir")
    assert first > 0
    assert snapshot_live(db, DUMP, "micmodshop.ir") is None
    row = load_version(db, "micmodshop.ir", first)
    assert row["origin"] == "live_snapshot"
    assert "ssl_certificate" in row["body"]
    assert db.execute("SELECT COUNT(*) FROM config_heads").fetchone()[0] == 0
    with pytest.raises(ValueError, match="reference-only"):
        queue_deployment(db, "micmodshop.ir", first)


def test_jobs_are_durable_requests_not_executions(db, tmp_path):
    rev = generate_revision(db, tmp_path / "ssl", "micmodshop.ir")
    job = queue_deployment(db, "micmodshop.ir", rev)
    record = db.execute("SELECT * FROM operator_jobs WHERE id=?", (job,)).fetchone()
    assert record["status"] == "pending"
    assert record["kind"] == "deploy"
    assert record["version_id"] == rev
    # No background worker is bundled; the job cannot have applied anything.
    assert db.execute(
        "SELECT deployed_version_id FROM config_heads WHERE domain='micmodshop.ir'"
    ).fetchone()[0] is None
    wildcard_job = queue_certificate(db, "micmodshop.ir", "wildcard")
    dedicated_job = queue_certificate(db, "www.micmodshop.ir", "dedicated")
    assert wildcard_job != dedicated_job
    with pytest.raises(ValueError, match="Zone"):
        queue_certificate(db, "other.example.com", "wildcard")


def test_auth_and_csrf_cover_sensitive_admin_endpoints(app_client, db):
    client, csrf = app_client
    anonymous = create_app().test_client()
    assert anonymous.get("/manage").status_code == 401
    assert anonymous.post("/manage/micmodshop.ir/generate", data={}).status_code == 401
    assert client.get("/manage").status_code == 200
    assert client.get("/manage/micmodshop.ir").status_code == 200
    assert client.post("/manage/micmodshop.ir/generate", data={}).status_code == 403
    assert client.post(
        "/manage/micmodshop.ir/generate", data={"csrf": csrf}
    ).status_code == 302
    versions = config_history(db, "micmodshop.ir")
    assert len(versions) == 1
    assert client.get("/manage/micmodshop.ir").status_code == 200
    # Saving new manual config does not touch deployed version.
    body = load_version(db, "micmodshop.ir", versions[0]["id"])["body"]
    response = client.post(
        "/manage/micmodshop.ir/save",
        data={"csrf": csrf, "if_match": versions[0]["id"],
              "body": body + "\n# staged manual change\n", "note": "review"},
    )
    assert response.status_code == 302
    assert len(config_history(db, "micmodshop.ir")) == 2
    # Lost-update protection: a concurrent editor cannot replace newer draft.
    client.post(
        "/manage/micmodshop.ir/save",
        data={"csrf": csrf, "if_match": versions[0]["id"],
              "body": body + "\n# stale change\n", "note": "stale"},
    )
    assert len(config_history(db, "micmodshop.ir")) == 2
    assert db.execute(
        "SELECT deployed_version_id FROM config_heads WHERE domain='micmodshop.ir'"
    ).fetchone()[0] is None


def test_admin_explicit_requests_never_call_docker(app_client, db):
    client, csrf = app_client
    draft = generate_revision(db, __import__("pathlib").Path("/nonexistent/ssl"),
                              "micmodshop.ir")
    response = client.post(
        "/manage/micmodshop.ir/request-deploy",
        data={"csrf": csrf, "version": draft, "confirm": "yes"},
    )
    assert response.status_code == 302
    response = client.post(
        "/manage/micmodshop.ir/request-ssl",
        data={"csrf": csrf, "kind": "wildcard", "zone": "micmodshop.ir"},
    )
    assert response.status_code == 302
    assert [
        r["kind"] for r in db.execute("SELECT kind FROM operator_jobs ORDER BY id")
    ] == ["deploy", "issue-wildcard"]
    assert db.execute(
        "SELECT deployed_version_id FROM config_heads WHERE domain='micmodshop.ir'"
    ).fetchone()[0] is None
