#!/usr/bin/env bash
# Unprivileged HTTPS Gunicorn bound ONLY to the selected LAN interface.
# Application CIDR ACL is additionally enforced on every request. No Docker.
set -euo pipefail

ROOT="$(cd "$(dirname "\${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"

if [[ "$(id -u)" -eq 0 ]]; then
    echo "ERROR: Refusing to run the web process as root." >&2
    exit 1
fi
if [[ ! -x "$ROOT/.venv/bin/gunicorn" || ! -x "$ROOT/.venv/bin/python" ]]; then
    echo "ERROR: Run the project venv setup first." >&2
    exit 1
fi

export PANEL_LAN_IP="\${PANEL_LAN_IP:-192.168.1.205}"
export CONTROLPLANE_ROOT="$ROOT"
export CONTROLPLANE_DB="\${CONTROLPLANE_DB:-$ROOT/data/migration-review.sqlite3}"
export SSL_DIR="\${SSL_DIR:-$ROOT/ssl}"
export PANEL_HTTPS_ONLY=1

"$ROOT/.venv/bin/python" scripts/controlplane_lan.py status
if [[ ! -f "$ROOT/data/panel-lan/server.crt" ||
      ! -f "$ROOT/data/panel-lan/server.key" ||
      ! -f "$ROOT/data/panel-lan/session-secret" ]]; then
    echo "ERROR: Run python scripts/controlplane_lan.py init from a terminal first." >&2
    exit 1
fi
PANEL_SECRET_KEY="$(<"$ROOT/data/panel-lan/session-secret")"
if [[ "\${#PANEL_SECRET_KEY}" -lt 48 ]]; then
    echo "ERROR: Persistent panel session key is invalid." >&2
    exit 1
fi
# The bootstrap hash is intentionally unusable. Real account hashes live in
# SQLite and remain stable on restart; this never resets any user password.
PANEL_PASSWORD_HASH="$("$ROOT/.venv/bin/python" -c 'import secrets; from werkzeug.security import generate_password_hash; print(generate_password_hash(secrets.token_urlsafe(48)))')"
export PANEL_SECRET_KEY PANEL_PASSWORD_HASH

umask 077
echo "Staging HTTPS panel: https://\${PANEL_LAN_IP}:8787/admin"
echo "Only CIDRs on the DB allowlist may authenticate. No Nginx/Docker changes."
exec "$ROOT/.venv/bin/gunicorn" --workers 1 \
    --bind "\${PANEL_LAN_IP}:8787" \
    --certfile "$ROOT/data/panel-lan/server.crt" \
    --keyfile "$ROOT/data/panel-lan/server.key" \
    --timeout 30 --graceful-timeout 20 \
    --limit-request-line 4094 --limit-request-field_size 4096 \
    'controlplane.web:create_app()'
