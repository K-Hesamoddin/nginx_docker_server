#!/bin/bash

DOMAINS_FILE=${DOMAINS_FILE:-"domains.list"}
SSL_DIR=${SSL_DIR:-"ssl"}

COMPANY_EMAIL=${COMPANY_EMAIL:-"admin@mycompany.com"}
COUNTRY_CODE=${COUNTRY_CODE:-"IR"}
STATE_NAME=${STATE_NAME:-"Tehran"}
CITY_NAME=${CITY_NAME:-"Tehran"}
ORGANIZATION_NAME=${ORGANIZATION_NAME:-"My Organization"}

FORCE_SSL=${FORCE_SSL:-0}

echo "Using domains file: $DOMAINS_FILE"
echo "Using SSL directory: $SSL_DIR"
echo "Force SSL: $FORCE_SSL"

if [ ! -f "$DOMAINS_FILE" ]; then
    echo "ERROR: domains.list not found at: $DOMAINS_FILE"
    exit 1
fi

mkdir -p "$SSL_DIR"

echo "Generating SSL certificates..."

grep -v "^#" "$DOMAINS_FILE" | while IFS= read -r line; do
    line=${line%%#*}
    line=$(echo "$line" | xargs)
    [ -z "$line" ] && continue

    # اگر خط شبیه این باشد:
    # 1 domain.com
    # یا فقط domain.com
    domain=$(echo "$line" | awk '{print $2}')
    [ -z "$domain" ] && domain=$(echo "$line" | awk '{print $1}')

    [ -z "$domain" ] && continue

    crt_file="$SSL_DIR/$domain.crt"
    key_file="$SSL_DIR/$domain.key"

    # --- فقط ملاک اصلی ----
    if [ $FORCE_SSL -eq 0 ] && [ -f "$crt_file" ] && [ -f "$key_file" ]; then
        echo "Skipping $domain (certificate already exists)"
        continue
    fi
    # ----------------------

    echo "Processing domain: $domain"
    echo "Trying Let's Encrypt..."

    if sudo certbot certonly --standalone --non-interactive --agree-tos \
        --email "$COMPANY_EMAIL" -d "$domain" 2>/dev/null; then

        sudo cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$crt_file"
        sudo cp "/etc/letsencrypt/live/$domain/privkey.pem" "$key_file"
        sudo chown $USER:$USER "$crt_file" "$key_file"

        echo "✅ Let's Encrypt certificate created for $domain"

    else
        echo "⚠ Let's Encrypt failed, creating self-signed certificate"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$key_file" \
            -out "$crt_file" \
            -subj "/C=$COUNTRY_CODE/ST=$STATE_NAME/L=$CITY_NAME/O=$ORGANIZATION_NAME/CN=$domain/emailAddress=$COMPANY_EMAIL" \
            -addext "subjectAltName = DNS:$domain" >/dev/null 2>&1

        echo "⚠ Self-signed certificate created for $domain"
    fi

done

echo "SSL certificate generation completed."
