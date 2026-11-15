# Nginx Control Plane V2 (feature preview)

## Safe wildcard SSL staging (operator-approved, no reload)

An issued wildcard is saved in V2 lab inventory, not automatically
copied into the production Nginx bind mount. Use the generic
`controlplane.cert_stage` operator command for one DNS zone and one immutable
certificate generation. No ACME API key is required for this step.

For the already issued micmodshop.ir wildcard, inspect the read-only plan:

```bash
cd /home/cms/nginx-control-plane-v2-lab
source .venv/bin/activate
python -m controlplane.cert_stage \
  --db "$PWD/data/migration-review.sqlite3" \
  --lab-ssl "$PWD/ssl" \
  --production-root /home/cms/nginx_docker_server \
  --zone micmodshop.ir \
  --stub wildcard.micmodshop.ir.7be99665e00bdf3c6117
```

After independent approval to copy the SSL pair only, use the same command
with `--execute --confirm-zone micmodshop.ir`. It validates the certificate
chain, SAN coverage, key match, expiry, immutable content-derived filename,
V2 inventory registration and destination paths; verifies Docker's actual bind
mount; then publishes `.key` (0600) and `.crt` (0644) as new regular files,
never replacing an existing path. Recoverable failures remove only new files
created by this command. Re-running an identical pair is idempotent.

This operation does not update Nginx config, reload/restart Nginx, activate
the new certificate, run Certbot, or authorize a V2 revision deploy.
A separately approved deployment must still pass Nginx checks, runtime
probes and rollback requirements. All older certificates stay untouched.
Production copying is deliberately not automatic on renewal: stage each
new immutable generation explicitly. Requires unprivileged write permission
to the destination. If permission is denied, use a separately audited,
root-owned limited helper. Never run `sudo python` from the writable lab.



## One-shot deploy runner prototype (operator-gated, NOT installed in production)

The feature branch now contains `controlplane/deployer.py`. It is a local,
explicit executor for an existing `operator_jobs(kind='deploy')` queue entry.
It is never called by Flask, systemd, a timer, or a background worker.
The old bulk `controlplane.cli apply` is still disabled.

### Read-only plan (safe, no docker calls or writes)

```bash
cd /home/cms/nginx-control-plane-v2-lab
source .venv/bin/activate
python -m controlplane.deployer \
  --db /home/cms/nginx-control-plane-v2-lab/data/migration-review.sqlite3 \
  --production-root /home/cms/nginx_docker_server \
  --job-id JOB_ID
```

The plan prints the domain, immutable revision SHA256, current live file
SHA256, preflight blockers and warnings. It refuses absent/symlinked
files and non-deploy jobs. `JOB_ID` must already be present in the panel
queue; `micmodshop.ir` revision #30 cannot enter that queue while it
contains `PENDING-SSL` placeholders, which is intentional.

### Explicit operator execution (NOT approved for the real host yet)

The executable path is test-driven with fake Docker; it must be
separately audited on a staging clone with the actual Nginx image/mounts,
not run as root from a user-writable lab checkout. A production-capable
deployment identity and root-owned reviewed installation must be agreed
and tested separately. **Do not use sudo on this lab checkout.**

Execution requires the exact queued job, matching current-file SHA256,
matching immutable revision SHA256, typed domain confirmation and
acknowledged diff; a legacy flag 0 adds explicit ownership approval.
No acknowledgement can bypass preflight blockers or incomplete SSL.
The runner checks Nginx container bind mounts, validates running config,
checks current origin TLS, makes a persistent 0600 backup under the
**existing V2 database directory** (`/home/cms/nginx-control-plane-v2-lab/data/v2-deploy-backups/`),
and holds its operator lock there. It neither requires nor creates a
`data/` directory inside the V1 production Nginx checkout. It atomically
changes only `conf/auto/<domain>.conf`, runs `nginx -t`, reloads only
the existing Nginx process, and probes all candidate HTTPS server_names.
If validation or health fails, it restores and reloads the previous
file and marks the job failed. Success updates the queued job status
and V2 deployed revision. An unsuccessful rollback is a critical
manual-intervention event, and the original backup is preserved.

**Limitations:** no production integration test, no privileged wrapper
hardening, no automatic web job consumer, no live ACME wildcard issuance
or renewal. This is an operator tool prototype, not a one-click panel
deploy or authorization to change the 29 active legacy configs.
New-domain deployment and Stream/Docker port changes are not supported.
Availability checks are a local TLS handshake plus HEAD /; application
endpoint-specific tests are still required before production approval.

## Per-domain preflight in the panel (read-only)

Open `/manage/<domain>/preflight` from the domain's detail page to
review an immutable V2 revision **before planning migration**. It checks:

- The selected revision and its SHA256 integrity; legacy snapshots are never deployable.
- Missing or placeholder `PENDING-SSL` certificates and incomplete
  `ssl_certificate` / `ssl_certificate_key` file-name pairs.
- Certificate trust, SAN and expiry **when the referenced file pair is
  available in the V2 lab SSL directory** (not a test of the live Docker cert).
- Historic `live_snapshot` presence, simple location/proxy_pass drift,
  include-set differences and explicit manual-legacy-flag warnings.
- Never claims to prove nginx syntax, current production configuration,
  origin reachability, DNS authority, or actual deployment safety.

The report has blockers, warnings and passed checks. It does not write to
SQLite, generate new revisions, call Docker or issue SSL. Even zero blockers
is NOT an authorization to touch the active proxy. No executor is connected.
The next implementation milestone is a small, narrowly privileged one-shot
helper, initially disabled, that can validate a single selected domain
against the real container, back up only its managed path, perform
`nginx -t`, reload and roll back upon failure after operator approval.
Never run the legacy bulk `apply` or overwrite unmanaged V1 config files.

## SSL issuance policy: one shared wildcard per DNS zone

**The new V2 panel must never issue certificates subdomain-by-subdomain.**
For each DNS Zone, request one certificate containing BOTH SANs:
`example.com` and `*.example.com`. All directly nested HTTP hosts,
including `www.example.com`, may share this validated cert after review.
Deep hosts (`test.erp.example.com`) require an additional wildcard group:
`erp.example.com` + `*.erp.example.com`; one-level wildcard does NOT
cover multiple labels. Separate registered domains need separate groups.

- `/admin/ssl` is the central UI that queues one `issue-wildcard` job per
  Zone, deduplicated while it remains pending or running.
- V2 now refuses new `issue-dedicated` requests and wildcard requests
  for accidental per-host zones such as `www.example.com`.
- Existing dedicated certificates and old Certbot renewal entries
  remain untouched until each domain is migrated and verified.
- Wildcards require DNS-01 at the actual authoritative DNS provider
  for the Zone, whether Cloudflare, NSIN, or another DNS service.
  An API-enabled provider is needed for unattended renewal.
- Issuance and deployment are still NOT wired to the production worker.
  Queuing a wildcard is not a fix for an expired certificate.
- Only after issuing and validating a shared cert, reviewing each
  domain config, running real `nginx -t`, backup and controlled apply,
  can obsolete per-subdomain issuance/renewal be safely retired.

## DNS-provider-neutral SSL and simplified deployment plan

**DNS routing is not the ACME issuer selection.** A record/CNAME targets and
Cloudflare proxying are independent of who hosts the authoritative DNS zone.
Never assume every hostname uses NSIN. The operator chooses one provider for
each zone at `/admin/ssl`:

- `Cloudflare`: planned API-based DNS-01 integration for zones managed there.
- `NSIN`: optional legacy API-based DNS-01 integration for its authoritative zones.
- `Other DNS / custom API`: integration will require a compatible plugin.
- `Manual TXT`: possible DNS-01 choice when no API exists, but unattended
  renewal is **not** available.
- `Unconfigured`: do not start certificate issuance until DNS authority
  is verified by the operator.

Provider selection is saved in lab SQLite **without any DNS credentials**.
It does not call an ACME client, update DNS, create certificates, or change
Nginx. The existing CLI `issue-wildcard` is an **NSIN-only experimental
prototype** and is **not** invoked by the web UI. It is not a generic
issuer or a reason to standardize all zones on NSIN. Certificate selection
at runtime must use a provider-specific ACME DNS-01 adapter; ordinary
existing dedicated certificates remain historical inventory; new per-subdomain issuance is disabled in V2.

**Keep deployment simple:** one Nginx Docker container and one local, narrowly
privileged execution helper (not a fleet of workers). For each explicitly
approved domain revision, the helper should (1) back up the existing
per-domain configuration, (2) stage and validate the new file with `nginx -t`
in the real container context, (3) reload only Nginx on success and log
the result, and (4) restore/reload the previous config if validation or
health checking fails. No `docker compose down/up` or global re-generation.
A separate certificate action asks the configured provider's ACME adapter
for a cert, verifies it and records it before a reviewed per-domain config
update. Special TCP/UDP stream port publication remains outside the
simple HTTP-only deploy path and needs a separate explicit operation.

**Not connected to production:** the one-shot executor is test-only and disabled
by default; Cloudflare/custom DNS adapters, DNS credential integration,
actual panel-triggered issuance/deployment, hardened privileged installation
and full production health checks/rollback testing are still outstanding. Legacy Nginx and renewal continue to own
production until each domain is individually verified and migrated.
Never execute the old NSIN CLI against a Cloudflare or other-provider zone.

## Persian in-panel operations guide and step-by-step tours

The V2 lab panel has a self-contained, authenticated **فارسی راهنمای پنل**:

- \`https://192.168.1.205:8787/help\` — full guide index.
- \`/help/overview\` — login and safe workflow.
- \`/help/domains\` and \`/help/routes\` — domain creation, upstream/URI behavior, legacy migration exceptions.
- \`/help/versions\` — immutable revisions, snapshots, Generate, manual editing, diffs and queued rollback.
- \`/help/ssl\` — shared wildcard per-zone coverage, SAN, pending DNS-01 requests and certificate status limitations.
- \`/help/security\` — per-domain security headers, Include catalog and versioned snippet drafts.
- \`/help/streams\` — staged TCP/UDP listener, protocol, backend and stream context constraints.
- \`/help/users\` — Viewer/Editor/Admin roles, second accounts and revocation.
- \`/help/access\` — direct LAN IP/CIDR allowlist, HTTP 403 versus network timeout.
- \`/help/jobs\` — statuses and the fact that there is no deploy/ACME worker yet.
- \`/help/troubleshooting\` — safe health checks and HTTPS/operator password recovery.

Every guide has a **شروع تور** link to a GET-only server-rendered wizard with Next/Previous,
step counter, current task, expected check and link to its real panel page. The
pages in \`/admin\`, \`/admin/ssl\`, \`/admin/includes\`, \`/admin/streams\`,
\`/admin/users\`, \`/admin/access\` and \`/manage\` each display a contextual
guide and tour link. This avoids weakening the current strict CSP with scripts.
These routes require existing authentication and the same source-IP ACL.

**Operational scope:** The help explicitly distinguishes lab-only state changes
from real Nginx/Docker/NSIN actions. Reading the guide or taking a tour never
changes config, creates a job, manipulates ACLs or writes a certificate.

After merging the feature branch into the lab checkout, restart **only**
the unprivileged user panel service (not Docker and not nginx-proxy):

\`\`\`bash
cd /home/cms/nginx-control-plane-v2-lab
git pull --ff-only
source .venv/bin/activate
python -m pytest -q tests/
systemctl --user restart nginx-controlplane-v2
\`\`\`


## Direct private-LAN HTTPS access (no workstation tunnel)

The LAN pilot is separate from Docker and the production nginx-proxy. It does
not change ports 80/443, reload Nginx, apply configurations or issue certificates.
**Only the operator with server shell access can run the following setup.**

Stop the old 127.0.0.1:8787 Gunicorn process (Ctrl+C in the terminal that
launched it). Then, as the ordinary `cms` user on the server:

```bash
cd /home/cms/nginx-control-plane-v2-lab
git pull --ff-only
source .venv/bin/activate
export CONTROLPLANE_DB="$PWD/data/migration-review.sqlite3"
python -m pytest -q tests/
sudo loginctl enable-linger cms
bash scripts/install-controlplane-lan.sh
```

The installer first checks the existing lab DB and, only if no admin is
configured, prompts for a NEW admin password (12+ characters, entered twice).
It generates a locally self-signed IP-SAN certificate and a persistent secret
under `data/panel-lan/` with mode 0600 (parent 0700). It installs a **user-scoped**
systemd unit, and starts a single unprivileged HTTPS Gunicorn process on
`192.168.1.205:8787`, NOT `0.0.0.0`. It needs no Docker restart.
The service stays running after logout thanks to linger.

From the allowed LAN workstation `192.168.1.192`, open:

`https://192.168.1.205:8787/admin`

Username: `admin`. The browser will warn that the self-signed certificate
is not trusted; verify its fingerprint with the operator before accepting the
one-time exception. This encrypts traffic but self-signed TLS is not a
substitute for a certificate issued by a trusted local CA. Never use the
plain HTTP URL or expose port 8787 via router/NAT. For broader production
access, prefer a private trusted certificate and VPN/firewall ACL.

Allowlist defaults to `127.0.0.1/32`, `::1/128` and
**`192.168.1.192/32`**. Every request checks the direct socket source IP,
ignoring X-Forwarded-For. Unauthorized IPs receive HTTP 403.
The app ACL is not itself a packet-filtering firewall; for hard enforcement
at the host ingress, add a *narrow* per-source firewall rule after reviewing
the host's current firewall policies. Do not change blanket INPUT or Docker
rules. On a host with active UFW and blocked port, an operator can permit
only the desired source with:

```bash
sudo ufw status verbose
# If UFW is active and port 8787 is blocked:
sudo ufw allow from 192.168.1.192 to 192.168.1.205 port 8787 proto tcp
```

Server-side checks (do not affect Nginx):

```bash
systemctl --user --no-pager status nginx-controlplane-v2
ss -ltn '( sport = :8787 )'
openssl x509 -in data/panel-lan/server.crt -noout -fingerprint -sha256
```

If the administrator password is unknown after an upgrade, reset it **only
from the server console** (not through a browser and not by deleting SQLite):

```bash
cd /home/cms/nginx-control-plane-v2-lab
source .venv/bin/activate
python scripts/controlplane_lan.py reset-admin-password
```

To restart only the panel after a later code update:

`systemctl --user restart nginx-controlplane-v2`

To inspect errors: `journalctl --user -u nginx-controlplane-v2 -n 60 --no-pager`.
The UI remains a **staging panel only**. Deploy, SSL and stream publication
buttons write pending jobs to SQLite and never touch production.


> NOT DEPLOYED. Do not merge to main or run against production before audit.

Current capabilities:
- Local-only password-protected and CSRF-protected Flask admin UI for domains, routes, registered certificates and policy profile.
- SQLite inventory with idempotent legacy domains.list import and export for compatibility.
- Certificate resolver in V2 drafts prefers a verified shared wildcard SAN first, with a valid existing dedicated SAN only as a legacy fallback. Drafts can show PENDING-SSL, but live render and queued deploy of those drafts are blocked.
- Existing experimental NSIN-only CLI wildcard issuer (not connected to the web UI); per-zone Cloudflare/NSIN/other/manual selection is staging metadata only. No self-signed production fallback.
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

## Modern admin hub (feature preview only)

After updating the lab branch, stop the **old** Gunicorn process with Ctrl+C
and restart with `bash scripts/start-controlplane-lab.sh`. Existing config
snapshots and route inventory remain in `data/migration-review.sqlite3`.
The first start of the new multi-user build prompts for the initial admin
password and stores its salted hash in SQLite; later starts detect the existing
users and do not reset their password. The login username is `admin`.

Pages available after login:

- `/admin`: compact starting dashboard with domain, revision, SSL and job counts.
- `/manage`: searchable domain cards; choose one to inspect routes, original
  `live_snapshot`, manual config editor, immutable history and diffs.
- `/admin/ssl`: unified wildcard proposals derived from the known `.ir` / `.com`
  hostnames. A proposal for `zone` includes `zone` and `*.zone`. A separate
  `*.erp.micromodern.ir` is needed to cover `test.erp.micromodern.ir`;
  `*.micromodern.ir` alone does not cover nested hosts. DNS authority and ACME
  ownership are NOT verified by these proposals. SSL requests stay pending.
- `/admin/users`: create a second user, choose `viewer`, `editor` or `admin`,
  change passwords/roles and deactivate a user. Sessions are revoked when
  an account is changed. The last admin cannot be disabled.
- `/admin/access`: edit the CIDR allowlist. Defaults are `127.0.0.1/32`,
  `::1/128`, **`192.168.1.192/32`**. Access is determined from the direct
  socket peer, never from untrusted X-Forwarded-For headers. Public networks
  are rejected. Loopback access cannot be removed.
- `/admin/includes`: opt-in HSTS (without includeSubDomains), nosniff and
  X-Frame-Options per domain; a catalog of whitelisted .conf basenames;
  per-domain include selection; and immutable editor/diff history for staged
  custom security snippets. REGISTERING OR EDITING an include does not
  create or change any file in the real Nginx container.
- `/admin/streams`: add/update/remove staged TCP/UDP mappings, choose a
  local listen IP, and create previews. Stream requires Nginx stream module,
  top-level stream {} configuration and explicit Docker port mapping in any
  future deployment. No port is opened from this page.

Security restrictions: only `admin` can manage users/CIDRs and queue SSL or
deployment requests; `editor` can stage domain, include and stream edits;
`viewer` can read but not write. Every edit uses the same CSRF-protected login
session. **Not ready for public or shared-LAN exposure**: the launcher stays
bound to 127.0.0.1:8787 and you reach it through an SSH tunnel. Adding
`192.168.1.192` to the application's allowlist does not make the listener
reachable from that computer. If LAN-direct access is introduced in future,
it must sit behind trusted HTTPS, firewall/VPN restrictions and source-IP
enforcement at the real ingress, particularly when proxied.

The database may contain sensitive archived nginx -T text, credentials
embedded in manual configuration, and password hashes. Protect it as
confidential infrastructure data and back it up with file permissions 0600.

Still outstanding for a production panel: secured privileged worker to
execute approved immutable per-domain deployments with `nginx -t`, staged
atomic release, reload, persistent rollback and tested job logs; NSIN DNS-01
certificate issuance/renewal; live stream-module/port discovery and stream
deployment; hardened multi-user auth (lockout/MFA), external TLS checks,
and full end-to-end testing. No Docker Compose restart is required for
reading this preview, and no production Nginx change has been made.

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

## Legacy NSIN-only wildcard CLI prototype (not the default provider)

Only use this legacy prototype if NSIN is truly authoritative for the selected zone; otherwise do not run it. For Cloudflare or other providers, the corresponding ACME provider adapter must first be implemented and tested. Install acme.sh and dns_nsin only when testing an NSIN-managed zone.
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
