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
Certificate issuance and acme.sh renewal are NOT yet a complete automatic promotion pipeline. Immutable certs must be re-registered and deployed after renewal until a secure hook is implemented.
All Phase 1 checks inspect SAN, key match, and validity dates; they do not yet check CA chain trust. Browser verification is required.
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
Then run:
  python -m controlplane.cli issue-wildcard micmodshop.ir

Cert for micmodshop.ir + *.micmodshop.ir covers www and api at one level, NOT test.api.micmodshop.ir.
After a certificate is registered, review generated configuration:
  python -m controlplane.cli preview > /tmp/v2-preview.txt

Promotion is deliberate, and first adoption requires --allow-replace-v1 after a config diff and backup:
  python -m controlplane.cli apply --yes --allow-replace-v1

## Phase 2 work required before production

- ACME renewal-to-deploy hooks, strict CA-chain verification and expiry alerts.
- Per-site safe diffs, preview of migrated advanced config, complete rollback, disabled-host removal handling.
- Role-based users, approvals and privileged runner separation; a queue for issue/deploy actions from the panel.
- Harden security policy engine for CSP/HSTS/CORS, real IP trust ranges and per-route cache bypass.
- Nginx dry-run integration tests, staged deployment to external test host, monitoring and audited recovery.
- Reconcile current Certbot lineages; many renewal jobs fail because standalone cannot bind port 80.

IMPORTANT: this branch does not change current Nginx, the running container, Certbot, MikroTik or NSIN.
