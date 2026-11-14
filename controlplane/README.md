# Nginx Control Plane V2 (feature preview)

> NOT DEPLOYED. Do not merge to main or run against production before audit.

Current capabilities:
- Local-only password-protected and CSRF-protected Flask admin UI for domains, routes, registered certificates and policy profile.
- SQLite inventory with idempotent legacy domains.list import and export for compatibility.
- Certificate resolver chooses valid exact dedicated SAN first, then valid matching wildcard SAN; blocks config generation if no cert.
- DNS-01 wildcard issue via acme.sh dns_nsin plugin (NSIN API credentials in environment only). No self-signed production fallback.
- Explicit preview and guarded apply with backup, nginx -t, reload and rollback attempt.
- Tests and GitHub Actions checks.

## Important restrictions

Admin edits stage only in SQLite; no live Nginx changes. CLI apply is intentionally a separate reviewed step.
Certificate renewal uses an acme.sh reload hook to verify, archive and register new immutable certificates. Automatic live deployment stays OFF by default; a separate administrator marker is required, and the V2-only apply guard blocks overwriting legacy configs.
Certificate verification checks SAN, key match, dates and CA-chain trust against a system CA bundle (or CONTROLPLANE_CA_BUNDLE). Production still requires external TLS and deployment integration testing.
Generated config supports common HTTP reverse proxies and basic policy profiles. Migrate custom per-site snippets only after reviewing diffs.
First activation is a migration, not a blind replacement. Never run legacy setup.sh to deploy the new manager.

## Install (development/staging only)

1. python3 -m venv .venv
2. . .venv/bin/activate
3. pip install -r requirements-controlplane.txt
4. export CONTROLPLANE_ROOT=$PWD
5. python -m controlplane.cli init
6. python -m controlplane.cli import-legacy --file domains.list
7. python -m controlplane.cli export-legacy (check output against original file)
8. python -m controlplane.cli preview --domain micmodshop.ir (requires registered valid SSL)
9. python -m pytest -q tests/test_controlplane.py

## Legacy `domains.list` migration (verified from production excerpt)

Your actual file has two opaque flags before the domain, e.g.:

```text
1 0 micromodernonline.ir / 192.168.1.26:80 /product_backend/ 192.168.1.26:8001 /shop_backend/ 192.168.1.26:8000
0 0 micmodshop.ir / 192.168.1.178:3000 /product_backend/ 192.168.1.178:1010 /shop_backend/ 192.168.1.178:2000
0 0 hibarco.com / 192.168.1.112:80 /media/ 192.168.1.112:8000 /api/ 192.168.1.112:8000
0 0 www.hibarco.com / 192.168.1.112:80 /media/ 192.168.1.112:8000 /api/ 192.168.1.112:8000
```

The V2 importer accepts both one-flag and two-flag lines, **does not treat
`0 0` as a disabled hostname**, and preserves those fields verbatim for
inventory/export. Their intended operational semantics are not assumed.
Route order within each domain is preserved. For imported apex domains without
a separately managed `www` row, a redirect alias can be generated. An
explicit `www` row takes precedence over the redirect.

Import is **all-or-nothing for malformed input**. An incomplete/truncated line
must be repaired from the actual source file before importing; no domain name
should be guessed from pasted output. Existing DB rows are left untouched.

**Do not run `setup.sh` or the original
`scripts/generate-{configs,certificates}.sh` on your live input**: those
committed V1 scripts currently read a *single* flag and treat column 2 as
the domain name. With your dual-flag file, they would instead parse `0`
as the hostname. Treat the raw file and running `nginx -T` as distinct
sources until the version drift has been investigated.

For a read-only preview of imported inventory in a **fresh lab database**:

```bash
python -m controlplane.cli init
python -m controlplane.cli import-legacy --file domains.list
python -m controlplane.cli export-legacy > /tmp/v2-domains-export.list
```

Compare the exported routes and flags to the original. Do not run
`apply` on a live host until the migration is reviewed.

## Auditing the live Nginx config without certificate keys

After a successful lab import, compare its registered routes with the
currently running (unmodified) Nginx configuration:

```bash
cd /home/cms/nginx-control-plane-v2-lab
source .venv/bin/activate
export CONTROLPLANE_ROOT="$PWD"
export CONTROLPLANE_DB="$PWD/data/migration-review.sqlite3"

sudo docker exec nginx-proxy nginx -T 2>/dev/null | \
  python -m controlplane.cli audit-live --domain micmodshop.ir --stdin
```

The command prints a small JSON report and never writes a certificate or
Nginx file. It tests all imported locations (host/port, URI prefix stripping)
against the matching `/etc/nginx/conf.d/auto/{domain}.conf` section of
`nginx -T`. It also reports detected header, HTTP/2, IPv6, buffering
features and the referenced certificate *paths*, not private keys.
Exit code 0 means route comparison passed, 2 means drift, 1 means malformed
input or a missing config. This is a limited semantic comparison, **not**
a proof of Nginx config equivalence or TLS validity. Never upload the full
`nginx -T` dump because it may contain secrets.

The legacy renderer now retains observed HTTP/2, IPv6 listen, forwarding
headers, unconditional legacy websocket headers, buffer include, access/error
logging and original route ordering. Nonlegacy policy profiles remain
opt-in. Review `proxy_pass` URI semantics for each route before any rollout.

## Batch audit of every imported host (read-only)

After the individual micmodshop.ir audit passes, run one nginx -T capture through the batch auditor:

```bash
cd /home/cms/nginx-control-plane-v2-lab
git pull --ff-only
source .venv/bin/activate
export CONTROLPLANE_ROOT="$PWD"
export CONTROLPLANE_DB="$PWD/data/migration-review.sqlite3"
python -m pytest -q tests/
set -o pipefail
sudo docker exec nginx-proxy nginx -T 2>/dev/null | \
  python -m controlplane.cli audit-all --stdin
```

This command does not modify Nginx or run certbot. Only a compact JSON
report (totals and discrepancies) is printed. The --include-matches option
also lists passing hosts. Exit code 2 signals drift/unverified hosts.

matched means common location/proxy_pass route mappings matched. drift means
routes differ or parser warnings were raised. unverified means a matching
conf/auto config header was not found. Unverified hosts may be deliberately
managed elsewhere, but require manual review. This is not complete Nginx
semantic equivalence or a TLS validity check.

## Local-only dashboard

Generate a password hash using:
  python -c 'from werkzeug.security import generate_password_hash; import getpass; print(generate_password_hash(getpass.getpass()))'
Generate a secret using:
  python -c 'import secrets; print(secrets.token_urlsafe(48))'

Export PANEL_PASSWORD_HASH and PANEL_SECRET_KEY securely outside Git.
Run gunicorn with only a loopback listener:
  gunicorn --workers 1 --bind 127.0.0.1:8787 'controlplane.web:create_app()'
Connect with SSH forwarding, e.g. ssh -L 8787:127.0.0.1:8787 user@server
Open http://127.0.0.1:8787 in your local browser.
Do not publish admin UI under a public subdomain or NSIN proxy.

## NSIN wildcard issuance (explicit operator step)

NSIN must be authoritative for the zone; install acme.sh and its documented dns_nsin plugin.
Set a scoped, non-read-only NSIN_Api_Key via a secure env mechanism; never commit or paste the API key.
Then run **on staging only**, after installing acme.sh and its verified DNS plugin:
  python -m controlplane.cli issue-wildcard micmodshop.ir

The command skips unnecessary issuance if a registered wildcard remains valid for
30+ days. It installs a persistent acme.sh --reloadcmd through
`--install-cert`. The hook executes `sync-renewed` whenever acme.sh
successfully renews and installs a certificate; it verifies chain/key/SAN/expiry,
writes a new immutable certificate pair, and records it in SQLite. Certificate
issuance and renewal do not stop Nginx.

To configure the hook for an existing acme.sh lineage without requesting a new
certificate, run:
  python -m controlplane.cli configure-renewal-hook micmodshop.ir

You can manually test the hook after a *staging* ACME install with:
  python -m controlplane.cli sync-renewed micmodshop.ir

**Safe-by-default:** certificate synchronization does not change Nginx.
After ALL configured domains have been migrated to V2, reviewed against current
configs and tested on staging, a privileged administrator may opt in to automatic
V2-only deployment by placing the exact string
`ALLOW_V2_MANAGED_DEPLOY` in `data/enable-auto-deploy`.
This marker must be root-owned and never editable by the web panel.
Do not create this file in production yet. A renewal then invokes guarded
config apply, Nginx validation and rollback attempts. A rejected legacy config
stops deployment rather than overwriting it.
The old certificate artifacts remain for rollback.

Cert for micmodshop.ir + *.micmodshop.ir covers www and api at one level, NOT test.api.micmodshop.ir.
After a certificate is registered, review generated configuration:
  python -m controlplane.cli preview > /tmp/v2-preview.txt

Promotion is deliberate, and first adoption requires --allow-replace-v1 after a config diff and backup:
  python -m controlplane.cli apply --yes --allow-replace-v1

## Phase 2 work required before production

- Complete operational renewal-to-deploy integration tests, CA-chain edge cases and expiry alerts.
- Per-site safe diffs, preview of migrated advanced config, complete rollback, disabled-host removal handling.
- Role-based users, approvals and privileged runner separation; a queue for issue/deploy actions from the panel.
- Harden security policy engine for CSP/HSTS/CORS, real IP trust ranges and per-route cache bypass.
- Nginx dry-run integration tests, staged deployment to external test host, monitoring and audited recovery.
- Reconcile current Certbot lineages; many renewal jobs fail because standalone cannot bind port 80.

IMPORTANT: this branch does not change current Nginx, the running container, Certbot, MikroTik or NSIN. A green unit test is NOT production deployment approval.
