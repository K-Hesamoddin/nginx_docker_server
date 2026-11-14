#!/usr/bin/env bash
# Start the staged admin interface on loopback only. Never call Docker/ACME.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"

if [[ "$(id -u)" -eq 0 ]]; then
    echo "Refusing to run the admin web process as root." >&2
    exit 1
fi
if [[ ! -x "$ROOT/.venv/bin/python" || ! -x "$ROOT/.venv/bin/gunicorn" ]]; then
    echo "Install requirements in $ROOT/.venv first." >&2
    exit 1
fi

export CONTROLPLANE_ROOT="$ROOT"
export CONTROLPLANE_DB="${CONTROLPLANE_DB:-$ROOT/data/migration-review.sqlite3}"
export SSL_DIR="${SSL_DIR:-$ROOT/ssl}"

if [[ ! -f "$CONTROLPLANE_DB" ]]; then
    echo "Lab database is missing: $CONTROLPLANE_DB" >&2
    exit 1
fi

# The password is read by getpass, not passed as a shell literal, argument,
# environment variable or saved file. Its salted hash stays in this process.
PANEL_PASSWORD_HASH="$("$ROOT/.venv/bin/python" -c 'import getpass; from werkzeug.security import generate_password_hash; p=getpass.getpass("Lab admin password: "); print(generate_password_hash(p)) if len(p)>=12 else exit("Use a password of 12+ characters")')"
PANEL_SECRET_KEY="$("$ROOT/.venv/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))')"
export PANEL_PASSWORD_HASH PANEL_SECRET_KEY

echo "Staging panel listening on 127.0.0.1:8787 ONLY."
echo "Use an SSH port-forward to access /manage. Stop with Ctrl+C."
exec "$ROOT/.venv/bin/gunicorn" --workers 1 --bind 127.0.0.1:8787 \
    --timeout 30 --limit-request-line 4094 --limit-request-field_size 4096 \
    'controlplane.web:create_app()'
