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

# First launch: get a bootstrap admin password without exposing plaintext.
# Subsequent launches MUST NOT silently reset the existing admin password:
# authentication now uses persistent salted hashes from the SQLite user table.
USER_ACCOUNTS_EXIST="$("$ROOT/.venv/bin/python" -c '
import sqlite3, os
conn = sqlite3.connect(os.environ["CONTROLPLANE_DB"])
exists = conn.execute("SELECT count(*) FROM sqlite_master WHERE type=\x27table\x27 AND name=\x27panel_users\x27").fetchone()[0]
print("yes" if exists and conn.execute("SELECT 1 FROM panel_users LIMIT 1").fetchone() else "no")
conn.close()
')"
if [[ "$USER_ACCOUNTS_EXIST" == "yes" ]]; then
    PANEL_PASSWORD_HASH="$("$ROOT/.venv/bin/python" -c 'import secrets; from werkzeug.security import generate_password_hash; print(generate_password_hash(secrets.token_urlsafe(48)))')"
    echo "Existing admin users detected. Log in with an already configured username/password."
else
    PANEL_PASSWORD_HASH="$("$ROOT/.venv/bin/python" -c 'import getpass; from werkzeug.security import generate_password_hash; p=getpass.getpass("New lab admin password (12+ characters): "); print(generate_password_hash(p)) if len(p)>=12 else exit("Use a password of 12+ characters")')"
fi
PANEL_SECRET_KEY="$("$ROOT/.venv/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))')"
export PANEL_PASSWORD_HASH PANEL_SECRET_KEY

echo "Staging panel listening on 127.0.0.1:8787 ONLY."
echo "Use an SSH port-forward to access /manage. Stop with Ctrl+C."
exec "$ROOT/.venv/bin/gunicorn" --workers 1 --bind 127.0.0.1:8787 \
    --timeout 30 --limit-request-line 4094 --limit-request-field_size 4096 \
    'controlplane.web:create_app()'
