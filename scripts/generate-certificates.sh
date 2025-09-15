#!/bin/bash

# استفاده از متغیرهای محیطی یا مقادیر پیش‌فرض
DOMAINS_FILE=${DOMAINS_FILE:-"domains.list"}
SSL_DIR=${SSL_DIR:-"ssl"}

# اطلاعات شرکت برای fallback
COMPANY_NAME=${COMPANY_NAME:-"My Company"}
COMPANY_EMAIL=${COMPANY_EMAIL:-"admin@mycompany.com"}
COUNTRY_CODE=${COUNTRY_CODE:-"IR"}
STATE_NAME=${STATE_NAME:-"Tehran"}
CITY_NAME=${CITY_NAME:-"Tehran"}
ORGANIZATION_NAME=${ORGANIZATION_NAME:-"My Organization"}

echo "Using domains file: $DOMAINS_FILE"
echo "Using SSL directory: $SSL_DIR"

if [ ! -f "$DOMAINS_FILE" ]; then
    echo "ERROR: domains.list not found at: $DOMAINS_FILE"
    exit 1
fi

mkdir -p "$SSL_DIR"

echo "Generating SSL certificates..."

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
    
    echo "Processing domain: $domain"
    
    # همیشه سعی کن سرتیفیکیت بسازی، حتی اگر از قبل وجود دارد
    echo "Generating SSL certificate for: $domain"
    
    # اولویت: استفاده از Let's Encrypt
    echo "Trying Let's Encrypt first..."
    if sudo certbot certonly --standalone --non-interactive --agree-tos \
        --email "$COMPANY_EMAIL" -d "$domain" 2>/dev/null; then
        
        # کپی سرتیفیکیت‌های Let's Encrypt
        sudo cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$SSL_DIR/$domain.crt"
        sudo cp "/etc/letsencrypt/live/$domain/privkey.pem" "$SSL_DIR/$domain.key"
        sudo chown $USER:$USER "$SSL_DIR/$domain.crt" "$SSL_DIR/$domain.key"
        
        echo "✅ Let's Encrypt certificate for $domain generated successfully!"
        
    else
        echo "⚠ Let's Encrypt failed, creating self-signed certificate"
        
        # Fallback: سرتیفیکیت خودامضا
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$SSL_DIR/$domain.key" \
            -out "$SSL_DIR/$domain.crt" \
            -subj "/C=$COUNTRY_CODE/ST=$STATE_NAME/L=$CITY_NAME/O=$ORGANIZATION_NAME/CN=$domain/emailAddress=$COMPANY_EMAIL" \
            -addext "subjectAltName = DNS:$domain" 2>/dev/null
        
        echo "⚠ Self-signed certificate created as fallback"
    fi
    
done

echo "SSL certificate generation completed."
