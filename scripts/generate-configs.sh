#!/bin/bash

DOMAINS_FILE=${DOMAINS_FILE:-"domains.list"}
CONF_DIR=${CONF_DIR:-"conf"}
LOG_DIR=${LOG_DIR:-"logs/nginx"}

echo "Using domains file: $DOMAINS_FILE"
echo "Using config directory: $CONF_DIR"
echo "Using log directory: $LOG_DIR"

if [ ! -f "$DOMAINS_FILE" ]; then
    echo "ERROR: domains.list not found at: $DOMAINS_FILE"
    exit 1
fi

mkdir -p "$CONF_DIR"
mkdir -p "$LOG_DIR"

echo "Generating Nginx configurations..."

grep -v "^#" "$DOMAINS_FILE" | while IFS= read -r line; do
    if [ -z "$line" ]; then
        continue
    fi
    
    domain=$(echo $line | awk '{print $1}')
    ip=$(echo $line | awk '{print $2}')
    port=$(echo $line | awk '{print $3}')
    
    if [ -z "$domain" ]; then
        continue
    fi
    
    config_file="$CONF_DIR/auto_${domain}.conf"
    
    echo "Creating config for: $domain"
    
    cat > "$config_file" << EOF
# Auto-generated config for $domain
server {
    listen 80;
    listen [::]:80;
    server_name $domain;

    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $domain;

    ssl_certificate     /etc/nginx/ssl/$domain.crt;
    ssl_certificate_key /etc/nginx/ssl/$domain.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    access_log $LOG_DIR/${domain}.access.log;
    error_log $LOG_DIR/${domain}.error.log;

    location / {
        proxy_pass http://$ip:$port;
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
}
EOF
    
    echo "✓ Config for $domain created: $config_file"
done

echo "Nginx configuration generation completed."
