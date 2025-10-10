#!/bin/bash

DOMAINS_FILE=${DOMAINS_FILE:-"domains.list"}
CONF_DIR=${CONF_DIR:-"conf"}
AUTO_DIR="$CONF_DIR/auto"
LOG_DIR=${LOG_DIR:-"logs/nginx"}

echo "Using domains file: $DOMAINS_FILE"
echo "Using auto config directory: $AUTO_DIR"
echo "Using log directory: $LOG_DIR"

if [ ! -f "$DOMAINS_FILE" ]; then
    echo "ERROR: domains.list not found at: $DOMAINS_FILE"
    exit 1
fi

mkdir -p "$AUTO_DIR"
mkdir -p "$LOG_DIR"

echo "Generating Nginx configurations..."

grep -v "^#" "$DOMAINS_FILE" | while IFS= read -r line; do
    [ -z "$line" ] && continue

    # خواندن پرچم، دامنه و بقیه
    update_flag=$(echo "$line" | awk '{print $1}')
    domain=$(echo "$line" | awk '{print $2}')
    rest=$(echo "$line" | cut -d' ' -f3-)

    config_file="$AUTO_DIR/${domain}.conf"

    if [ "$update_flag" -eq 0 ] && [ -f "$config_file" ]; then
        echo "Skipping $domain (update_flag=0 and file exists)"
        continue
    fi

    echo "Creating/updating config for: $domain"

    cat > "$config_file" << EOF
# Auto-generated config for $domain

# Redirect HTTP -> HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name $domain;

    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name $domain www.$domain;

    ssl_certificate     /etc/nginx/ssl/$domain.crt;
    ssl_certificate_key /etc/nginx/ssl/$domain.key;

    include /etc/nginx/conf.d/includes/security.conf;

    access_log $LOG_DIR/${domain}.access.log;
    error_log $LOG_DIR/${domain}.error.log;
EOF

    # پردازش location ها (proxy_pass)
    set -- $rest
    while [ $# -gt 0 ]; do
        location=$1
        target=$2
        shift 2

        ip=$(echo "$target" | cut -d: -f1)
        port=$(echo "$target" | cut -d: -f2)

        cat >> "$config_file" << EOF

    location $location {
        proxy_pass http://$ip:$port/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Server \$host;
    }
EOF
    done

    echo "}" >> "$config_file"
    echo "✓ Config for $domain created/updated: $config_file"
done

echo "Nginx configuration generation completed."
