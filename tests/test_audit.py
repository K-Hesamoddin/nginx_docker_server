"""Read-only audit and migration parity tests with a synthetic nginx -T dump."""
from pathlib import Path

from controlplane.audit import audit_live
from controlplane.core import import_domains_list, open_db, render_config
from tests.test_controlplane import make_cert
import pytest


def fixture_db(tmp_path):
    listing = tmp_path / "domains.list"
    listing.write_text(
        "0 0 micmodshop.ir / 192.168.1.178:3000 "
        "/product_backend/ 192.168.1.178:1010 "
        "/shop_backend/ 192.168.1.178:2000\n"
    )
    conn = open_db(tmp_path / "db.sqlite")
    assert import_domains_list(conn, listing)["imported"] == 1
    return conn


DUMP = """# configuration file /etc/nginx/nginx.conf:
worker_processes auto;

# configuration file /etc/nginx/conf.d/auto/micmodshop.ir.conf:
server {
  listen 80;
  listen [::]:80;
  server_name micmodshop.ir www.micmodshop.ir;
  return 301 https://micmodshop.ir$request_uri;
}
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  http2 on;
  server_name www.micmodshop.ir;
  ssl_certificate /etc/nginx/ssl/www.micmodshop.ir.crt;
  ssl_certificate_key /etc/nginx/ssl/www.micmodshop.ir.key;
  return 301 https://micmodshop.ir$request_uri;
}
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  http2 on;
  server_name micmodshop.ir;
  ssl_certificate /etc/nginx/ssl/micmodshop.ir.crt;
  ssl_certificate_key /etc/nginx/ssl/micmodshop.ir.key;
  client_max_body_size 50M;
  include /etc/nginx/conf.d/includes/security.conf;
  include /etc/nginx/conf.d/buffer.conf;
  access_log off;
  error_log logs/micmodshop.ir.error.log warn;
  location / {
    proxy_pass http://192.168.1.178:3000/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Server $host;
  }
  location /product_backend/ {
    proxy_pass http://192.168.1.178:1010/;
  }
  location /shop_backend/ {
    proxy_pass http://192.168.1.178:2000/;
  }
}
# configuration file /etc/nginx/conf.d/auto/other.conf:
server { listen 80; }
"""


def test_audit_matches_live_three_routes(tmp_path):
    conn = fixture_db(tmp_path)
    result = audit_live(conn, DUMP, "micmodshop.ir")
    assert result["routes_match"]
    assert result["expected_route_count"] == 3
    assert result["live_route_count"] == 3
    assert result["live_features"]["http2"]
    assert result["live_features"]["buffer_include"]
    assert result["live_features"]["forwarded_host"]
    assert len(result["live_cert_paths"]) == 2


def test_audit_flags_drift_and_extra_location(tmp_path):
    conn = fixture_db(tmp_path)
    changed = DUMP.replace("192.168.1.178:1010/", "192.168.1.178:9999/")
    changed = changed.replace("  location /shop_backend/ {", "  location /extra/ {\n    proxy_pass http://192.168.1.10:8000/;\n  }\n  location /shop_backend/ {")
    result = audit_live(conn, changed, "micmodshop.ir")
    assert not result["routes_match"]
    assert any("product_backend" in x for x in result["mismatches"])
    assert any("Extra live location" in x for x in result["mismatches"])


def test_legacy_renderer_parity(tmp_path, monkeypatch):
    conn = fixture_db(tmp_path)
    # Test PKI fixture from existing suite.
    make_cert(tmp_path, "both", ["micmodshop.ir", "www.micmodshop.ir"])
    monkeypatch.setenv("CONTROLPLANE_CA_BUNDLE", str(tmp_path / "test-ca-bundle.pem"))
    from controlplane.core import save_certificate
    save_certificate(conn, "micmodshop.ir", "dedicated", "both")
    rendered = render_config(conn, tmp_path, "micmodshop.ir")
    for required in (
        "listen [::]:80;", "listen [::]:443 ssl;", "http2 on;",
        "include /etc/nginx/conf.d/buffer.conf;", "access_log off;",
        "error_log logs/micmodshop.ir.error.log warn;",
        "proxy_set_header Upgrade $http_upgrade;",
        'proxy_set_header Connection "upgrade";',
        "proxy_set_header X-Forwarded-Host $host;",
        "proxy_set_header X-Forwarded-Server $host;",
        "proxy_pass http://192.168.1.178:3000/;",
        "proxy_pass http://192.168.1.178:1010/;",
        "proxy_pass http://192.168.1.178:2000/;",
    ):
        assert required in rendered
    assert rendered.index("location / {") < rendered.index("location /product_backend/ {")


def test_audit_requires_expected_host(tmp_path):
    conn = fixture_db(tmp_path)
    with pytest.raises(ValueError, match="No domain in inventory"):
        audit_live(conn, DUMP, "www.micmodshop.ir")
    with pytest.raises(ValueError, match="No configuration heading"):
        audit_live(conn, DUMP.replace("/etc/nginx/conf.d/auto/micmodshop.ir.conf:", "/etc/nginx/conf.d/auto/example.com.conf:"), "micmodshop.ir")
