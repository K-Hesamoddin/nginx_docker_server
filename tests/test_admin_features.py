"""UI/admin features stay staged, protect users, and do not open production ports."""
import pytest
from werkzeug.security import generate_password_hash

from controlplane.admin_features import (
    add_allowed_net, add_stream, allowed_networks, authenticate, ensure_features,
    get_session_user, is_allowed_peer, recommended_zones, register_include,
    remove_allowed_net, set_domain_include, set_security_options, stream_preview,
    user_update, user_upsert
)
from controlplane.core import open_db, import_domains_list, render_config, save_domain, save_route
from controlplane.management import ensure_schema, generate_revision
from controlplane.web import create_app


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "lab.sqlite"
    monkeypatch.setenv("CONTROLPLANE_DB", str(path))
    monkeypatch.setenv("SSL_DIR", str(tmp_path / "none"))
    monkeypatch.setenv("PANEL_SECRET_KEY", "s" * 48)
    monkeypatch.setenv("PANEL_PASSWORD_HASH", generate_password_hash("strong-start-password"))
    conn = open_db(path)
    ensure_features(conn, bootstrap_hash=generate_password_hash("strong-start-password"))
    ensure_schema(conn)
    for host, target in (
        ("micromodern.ir", "192.168.1.37:1000"),
        ("cloud.micromodern.ir", "192.168.1.52:8082"),
        ("test.erp.micromodern.ir", "192.168.200.2:80"),
        ("micmodshop.ir", "192.168.1.178:3000"),
        ("www.hibarco.com", "192.168.1.112:80"),
    ):
        save_domain(conn, host)
        save_route(conn, host, "/", target)
    yield conn
    conn.close()


@pytest.fixture
def login(db):
    app = create_app()
    app.testing = True
    client = app.test_client()
    response = client.post(
        "/login", data={"username": "admin", "password": "strong-start-password"}
    )
    assert response.status_code == 302
    with client.session_transaction() as sess:
        token = sess["csrf"]
    return client, token


def test_default_local_allowlist_and_spoofed_forwarded_header(db, login):
    client, _ = login
    assert set(allowed_networks(db)) == {
        "127.0.0.1/32", "::1/128", "192.168.1.192/32"
    }
    assert is_allowed_peer(db, "192.168.1.192")
    assert not is_allowed_peer(db, "192.168.1.193")
    assert not is_allowed_peer(db, "8.8.8.8")
    assert client.get("/admin", environ_overrides={"REMOTE_ADDR": "192.168.1.193"},
                      headers={"X-Forwarded-For": "127.0.0.1"}).status_code == 403
    assert client.get("/admin", environ_overrides={"REMOTE_ADDR": "192.168.1.192"}).status_code == 200
    with pytest.raises(ValueError, match="Only local"):
        add_allowed_net(db, "8.8.8.8/32", "admin")
    with pytest.raises(ValueError, match="Loopback"):
        remove_allowed_net(db, "127.0.0.1", "admin")


def test_users_admin_editor_viewer_and_deactivate_revokes_session(db, login):
    client, csrf = login
    assert client.get("/admin/users").status_code == 200
    assert client.post("/admin/users/create", data={
        "csrf": csrf, "username": "editor2", "password": "another-strong-password", "role": "editor"
    }).status_code == 302
    editor = authenticate(db, "editor2", "another-strong-password")
    assert editor and editor["role"] == "editor"
    editor_client = create_app().test_client()
    assert editor_client.post("/login", data={
        "username": "editor2", "password": "another-strong-password"
    }).status_code == 302
    assert editor_client.get("/admin/users").status_code == 403
    assert editor_client.get("/admin/ssl").status_code == 200
    with editor_client.session_transaction() as sess:
        ed_token = sess["csrf"]
    assert editor_client.post("/admin/ssl/request", data={
        "csrf": ed_token, "zone": "micmodshop.ir", "kind": "wildcard"
    }).status_code == 403
    assert client.post("/admin/users/update", data={
        "csrf": csrf, "id": editor["id"], "role": "editor", "active": "0"
    }).status_code == 302
    assert editor_client.get("/admin").status_code == 401

    with pytest.raises(ValueError, match="own admin"):
        user_update(db, 1, 1, "viewer", True)

    user_upsert(db, 1, "reader3", "viewer-password-123", "viewer")
    viewer_client = create_app().test_client()
    viewer_client.post("/login", data={"username": "reader3", "password": "viewer-password-123"})
    with viewer_client.session_transaction() as sess:
        viewer_token = sess["csrf"]
    assert viewer_client.get("/admin").status_code == 200
    assert viewer_client.post("/admin/streams/save", data={
        "csrf": viewer_token, "name": "redis-test", "protocol": "tcp",
        "listen_host": "127.0.0.1", "listen_port": "16379",
        "target": "192.168.1.22:6379"
    }).status_code == 403


def test_ssl_wildcard_groups_and_deep_domain_warning(db, login):
    zones = recommended_zones(db)
    mm = next(z for z in zones if z["zone"] == "micromodern.ir")
    assert "cloud.micromodern.ir" in mm["covered"]
    assert "test.erp.micromodern.ir" in mm["not_covered"]
    assert "*.micromodern.ir" == mm["wildcard"]
    nested = next(z for z in zones if z["zone"] == "erp.micromodern.ir")
    assert nested["wildcard"] == "*.erp.micromodern.ir"
    assert nested["nested_zone"]
    assert "test.erp.micromodern.ir" in nested["covered"]
    client, csrf = login
    resp = client.get("/admin/ssl")
    assert resp.status_code == 200
    assert b"test.erp.micromodern.ir" in resp.data
    assert b"*.micromodern.ir" in resp.data
    assert client.post("/admin/ssl/request", data={
        "csrf": csrf, "zone": "micromodern.ir", "kind": "wildcard"
    }).status_code == 302
    job = db.execute("SELECT * FROM operator_jobs WHERE kind='issue-wildcard'").fetchone()
    assert job and job["status"] == "pending"


def test_per_domain_include_security_and_invalid_filename(db, tmp_path, login):
    client, csrf = login
    register_include(db, "custom-safe.conf", "An operator must provision it")
    set_domain_include(db, "cloud.micromodern.ir", "custom-safe.conf", True)
    set_security_options(db, "cloud.micromodern.ir", True, True, True)
    body = render_config(db, tmp_path, "cloud.micromodern.ir", allow_missing_cert=True)
    assert "include /etc/nginx/conf.d/includes/custom-safe.conf;" in body
    assert "Strict-Transport-Security" in body
    assert "X-Frame-Options" in body
    assert "X-Content-Type-Options" in body
    with pytest.raises(ValueError, match="simple"):
        register_include(db, "../nginx.conf", "unsafe")
    assert client.get("/admin/includes?domain=cloud.micromodern.ir").status_code == 200
    assert client.post("/admin/security/save", data={
        "csrf": csrf, "domain": "cloud.micromodern.ir", "hsts": "on"
    }).status_code == 302
    assert db.execute("SELECT hsts FROM security_options WHERE domain='cloud.micromodern.ir'").fetchone()[0] == 1
    # Config revision is never regenerated by security mutation.
    assert db.execute("SELECT count(*) FROM config_versions").fetchone()[0] == 0


def test_stream_staged_and_does_not_publish_listener(db, login):
    client, csrf = login
    with pytest.raises(ValueError, match="not 80"):
        add_stream(db, "public", "tcp", "127.0.0.1", 443, "127.0.0.1:4000")
    with pytest.raises(ValueError, match="Wildcard"):
        add_stream(db, "wild", "tcp", "0.0.0.0", 16379, "127.0.0.1:4000")
    assert client.post("/admin/streams/save", data={
        "csrf": csrf, "name": "redis-test", "protocol": "tcp",
        "listen_host": "127.0.0.1", "listen_port": "16379",
        "target": "192.168.1.22:6379"
    }).status_code == 302
    assert client.get("/admin/streams").status_code == 200
    response = client.post("/admin/streams/preview", data={
        "csrf": csrf, "name": "redis-test"
    })
    assert response.status_code == 200
    assert b"proxy_pass 192.168.1.22:6379;" in response.data
    assert "STAGING ONLY" in stream_preview(db, "redis-test")
    row = db.execute("SELECT * FROM stream_services WHERE name='redis-test'").fetchone()
    assert row["enabled"] == 0


def test_custom_include_revisions_are_immutable_and_never_live(db, login):
    from controlplane.admin_features import (
        save_include_revision, include_history, include_version_diff, delete_stream
    )
    client, csrf = login
    register_include(db, "extra-policy.conf", "staged safety policy")
    first = save_include_revision(db, "extra-policy.conf",
                                  "add_header X-Policy one always;\n", "first")
    second = save_include_revision(db, "extra-policy.conf",
                                   "add_header X-Policy two always;\n", "second")
    versions = include_history(db, "extra-policy.conf")
    assert [v["id"] for v in versions] == [second, first]
    row, diff = include_version_diff(db, "extra-policy.conf", second)
    assert "X-Policy two" in row["body"]
    assert "+add_header X-Policy two" in diff
    assert "-add_header X-Policy one" in diff
    assert client.get("/admin/includes?include=extra-policy.conf").status_code == 200
    assert client.post("/admin/includes/save", data={
        "csrf": csrf, "filename": "extra-policy.conf",
        "body": "add_header X-Policy three always;", "note": "third"
    }).status_code == 302
    assert len(include_history(db, "extra-policy.conf")) == 3
    assert db.execute("SELECT count(*) FROM operator_jobs").fetchone()[0] == 0
    with pytest.raises(ValueError, match="simple"):
        register_include(db, "../../../../nginx.conf", "bad")


def test_stream_edit_and_removal_are_only_inventory(db, login):
    client, csrf = login
    add_stream(db, "service-tcp", "tcp", "127.0.0.1", 12345, "192.168.1.5:3000")
    response = client.get("/admin/streams?edit=service-tcp")
    assert response.status_code == 200
    assert b"service-tcp" in response.data
    assert client.post("/admin/streams/save", data={
        "csrf": csrf, "name": "service-tcp", "protocol": "tcp",
        "listen_host": "127.0.0.1", "listen_port": "12345",
        "target": "192.168.1.5:3001"
    }).status_code == 302
    assert db.execute(
        "SELECT target FROM stream_services WHERE name='service-tcp'"
    ).fetchone()[0] == "192.168.1.5:3001"
    assert client.post("/admin/streams/delete", data={
        "csrf": csrf, "name": "service-tcp", "confirm": "yes"
    }).status_code == 302
    assert db.execute("SELECT count(*) FROM stream_services").fetchone()[0] == 0


def test_management_search_filters_domain_cards(db, login):
    client, _ = login
    full = client.get("/manage")
    assert full.status_code == 200
    assert b"cloud.micromodern.ir" in full.data
    result = client.get("/manage?q=cloud")
    assert result.status_code == 200
    assert b"cloud.micromodern.ir" in result.data
    assert b"micmodshop.ir" not in result.data
    assert b"ssl" in result.data.lower()
