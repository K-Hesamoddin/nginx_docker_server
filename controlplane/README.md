# Nginx Control Plane V2 (feature preview)

> NOT DEPLOYED. Do not merge to main or run against production before audit.

Current capabilities:
- Local-only password-protected and CSRF-protected Flask admin UI for domains, routes, registered certificates and policy profile.
- SQLite inventory with idempotent legacy domains.list import and export for compatibility.
- Certificate resolver chooses valid exact dedicated SAN first, then valid matching wildcard SAN; blocks config generation if no cert.
- DNS-01 wildcard issue via acme.sh dns_nsin plugin (NSIN API credentials in environment only). No self-signed production fallback.
- Explicit per-domain draft generation, manual editor, immutable revision history, diffs and queued deploy/SSL requests (web UI; queue is not executed yet).
- Tests and GitHub Actions checks.

## Important restrictions

Admin edits and request buttons stage changes only in SQLite; no live Nginx changes. The old bulk `apply` command is disabled to protect hand-edited configurations.
Certificate renewal uses an acme.sh hook to verify and register immutable certificate candidates. Automatic config regeneration and reload are forbidden; all publication needs a reviewed per-domain revision.
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

## Handling the seven migration drifts

Run `audit-all --stdin` against the unmodified running Nginx and inspect the
`review_items` fields. Each entry has `requires_approval: true`; no database
or live configuration update is made from the audit.

- proxy_pass_uri_semantics: the trailing `/` of proxy_pass changes Nginx URI
  forwarding behavior. Keep the observed configuration until tested.
- unmanaged_live_location: a live route was not present in domains.list;
  do not drop `/health`, `/packs`, `/widget` or `/cable` while migrating.
- upstream_or_uri_changed: IP, port or URI differs (e.g. hibarco media,
  vakil129). Have the service owner verify which backend is correct.

The user-provided initial audit showed 22 matches and 7 drifted domains.
Do not automatically reconcile those differences and do not use the
`apply` or `--allow-replace-v1` commands on production. Review site-specific
locations and security settings beyond the current simplistic parser.

## Per-domain drafts, edits, history, rollback requests and SSL status

Phase-1 UI uses Flask exclusively for unprivileged SQLite staging. After
configuring the login described below, browse `/manage`, choose a domain,
and explicitly click **Generate from routes**. Merely changing `routes`,
the upstream, a security profile or a domain does NOT overwrite a saved
draft or regenerate any live Nginx file.

Every generation and manual textarea save creates an immutable revision,
timestamp, SHA256 fingerprint and optional note. The UI offers version
history, a unified diff against the previous version, and selection of an
older version as a rollback request. `/manage` shows job states.

Imported legacy update flags including `0` remain read-only metadata.
The true original V1 conf must be snapshotted explicitly before migration:

```bash
cd /home/cms/nginx-control-plane-v2-lab
source .venv/bin/activate
export CONTROLPLANE_ROOT="$PWD"
export CONTROLPLANE_DB="$PWD/data/migration-review.sqlite3"
set -o pipefail
sudo docker exec nginx-proxy nginx -T 2>/dev/null | \
  python -m controlplane.cli snapshot-live --stdin
```

This archives each existing `conf/auto/*.conf` in protected lab SQLite as
`live_snapshot` for reference. It never marks a snapshot as V2-deployed,
never copies private key files and never modifies Nginx. Config files can
contain sensitive values, so keep this lab database private and never upload
it publicly.

Some legacy proxy_pass directives contain a custom URI e.g. `/health`,
`/packs`, or no URI at all. Each route now has an optional `proxy_uri`
override, independent of host:port. The old `strip_prefix` boolean remains
for default behavior. The `domains.list` export cannot encode all V2-only
metadata, so treat it as a legacy compatibility snapshot, not a full backup.

Without a registered valid certificate, Generate makes a DRAFT with
`PENDING-SSL` placeholders. Such drafts cannot be queued for deployment.
Each domain also offers an on-demand origin TLS check using SNI against
`127.0.0.1:443`; it reports issuer and expiry but does NOT test NSIN's edge.

**Not connected to production yet:** the Deploy/Restore and SSL Request
buttons only record durable `pending` jobs. They do not run Docker, acme.sh,
certbot, DNS API calls, reload or Compose. A locked-down privileged runner,
approval policy, CA/DNS provider integration, staging tests and rollback
must be completed before enabling execution. Do NOT expose this UI publicly.

## Verified migration checkpoint

On 2026-11-14 the operator reported `32 passed`, then `snapshot-live`
recorded `{ "stored": 29, "unchanged": 0, "missing": [] }` from the running
Nginx. These are **reference-only archives in the lab SQLite DB**. They do
not imply that 29 sites are V2-managed or that rollback is ready.

Per-domain Route Add/Edit/Delete is available directly on `/manage/<domain>`.
Every route mutation affects only the DB; the existing draft and running
configuration remain unchanged until an explicit Generate + reviewed
deployment. The last route of a domain cannot be deleted in the UI.

To run the staging panel on the existing host without exposing a public port,
use the dedicated launcher rather than starting Flask's development server:

```bash
cd /home/cms/nginx-control-plane-v2-lab
git pull --ff-only
source .venv/bin/activate
export CONTROLPLANE_DB="$PWD/data/migration-review.sqlite3"
bash scripts/start-controlplane-lab.sh
```

The launcher prompts for a password (12+ characters) without saving the
plaintext password or inserting it in shell history. It refuses root and
binds Gunicorn to 127.0.0.1:8787 only. From a workstation with SSH access,
forward localhost:8787 to the same existing server SSH destination and
open `http://127.0.0.1:8787/` to log in; `/manage` lists saved snapshots.

The lab database contains original configuration text that may have secrets:
protect it as sensitive data and keep a permissions-restricted SQLite backup.
Stop the test panel with Ctrl+C. Never expose port 8787 to the public Internet.

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

**Safe-by-default:** certificate synchronization records a validated candidate only.
Even if an old auto-deploy marker exists, it is ignored; certificate renewal
never rewrites a manually managed site or reloads the running container.
Saved prior certificate versions remain available for future rollback.

Cert for micmodshop.ir + *.micmodshop.ir covers www and api at one level, NOT test.api.micmodshop.ir.
After a certificate is registered, review generated configuration:
  python -m controlplane.cli preview > /tmp/v2-preview.txt

The old bulk `apply` command is intentionally disabled. A separate privileged executor with strict validation, audit, backup and rollback remains to be built and vetted for production.

## Phase 2 work required before production

- Complete operational renewal-to-deploy integration tests, CA-chain edge cases and expiry alerts.
- Privileged execution worker and strict per-domain validation, backups, nginx -t/reload, active revision tracking and atomic rollback.
- Role-based users, per-domain approvals and privilege separation; the queue exists but its executor is not yet installed.
- Harden security policy engine for CSP/HSTS/CORS, real IP trust ranges and per-route cache bypass.
- Nginx dry-run integration tests, staged deployment to external test host, monitoring and audited recovery.
- Reconcile current Certbot lineages; many renewal jobs fail because standalone cannot bind port 80.

IMPORTANT: this branch does not change current Nginx, the running container, Certbot, MikroTik or NSIN. A green unit test is NOT production deployment approval.
