#!/usr/bin/env bash
# One-time user-scoped service installation. Does NOT modify Nginx/Docker/firewall.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"
if [[ "$(id -u)" -eq 0 ]]; then
  echo "ERROR: Run as ordinary cms user, not root." >&2
  exit 1
fi

export CONTROLPLANE_ROOT="$ROOT"
export CONTROLPLANE_DB="${CONTROLPLANE_DB:-$ROOT/data/migration-review.sqlite3}"
export PANEL_LAN_IP="${PANEL_LAN_IP:-192.168.1.205}"
"$ROOT/.venv/bin/python" scripts/controlplane_lan.py init

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd unavailable. Run: bash scripts/start-controlplane-lan.sh" >&2
  exit 1
fi
if ! systemctl --user show-environment >/dev/null 2>&1; then
  echo "User systemd bus unavailable. Start in foreground with bash scripts/start-controlplane-lan.sh" >&2
  exit 1
fi
UNIT_DIR="$HOME/.config/systemd/user"
UNIT="$UNIT_DIR/nginx-controlplane-v2.service"
mkdir -p "$UNIT_DIR"
chmod 700 "$UNIT_DIR"
if [[ "$ROOT" == *$'\n'* || "$ROOT" == *" "* ]]; then
  echo "Repo path cannot contain whitespace/newline in this installer" >&2
  exit 1
fi
# Keep this user-owned; no root/system-wide deployment.
cat > "$UNIT" <<EOF
[Unit]
Description=Nginx V2 staging admin over HTTPS on private LAN only
Documentation=https://github.com/K-Hesamoddin/nginx_docker_server
StartLimitIntervalSec=120
StartLimitBurst=12

[Service]
Type=simple
WorkingDirectory=$ROOT
Environment=CONTROLPLANE_DB=$CONTROLPLANE_DB
Environment=PANEL_LAN_IP=$PANEL_LAN_IP
ExecStart=/bin/bash $ROOT/scripts/start-controlplane-lan.sh
Restart=on-failure
RestartSec=10
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=
LimitNOFILE=1024

[Install]
WantedBy=default.target
EOF
chmod 600 "$UNIT"
systemctl --user daemon-reload
systemctl --user enable --now nginx-controlplane-v2.service
echo "Installed user service nginx-controlplane-v2.service"
echo "Direct private-LAN URL: https://$PANEL_LAN_IP:8787/admin"
echo "This service cannot deploy Nginx or issue certificates."
echo "For boot persistence after SSH logout, administrator must separately allow linger:"
echo "  sudo loginctl enable-linger $(id -un)"
echo "User-service status:"
systemctl --user --no-pager status nginx-controlplane-v2.service || true
