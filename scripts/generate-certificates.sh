#!/bin/bash

# استفاده از متغیرهای محیطی یا مقادیر پیش‌فرض
DOMAINS_FILE=${DOMAINS_FILE:-"domains.list"}
SSL_DIR=${SSL_DIR:-"ssl"}

# اطلاعات شرکت
COMPANY_NAME=${COMPANY_NAME:-"My Company"}
COMPANY_EMAIL=${COMPANY_EMAIL:-"admin@mycompany.com"}
COUNTRY_CODE=${COUNTRY_CODE:-"IR"}
STATE_NAME=${STATE_NAME:-"Tehran"}
CITY_NAME=${CITY_NAME:-"Tehran"}
ORGANIZATION_NAME=${ORGANIZATION_NAME:-"My Organization"}
ORGANIZATIONAL_UNIT=${ORGANIZATIONAL_UNIT:-"IT Department"}

echo "Using domains file: $DOMAINS_FILE"
echo "Using SSL directory: $SSL_DIR"
echo "Company: $COMPANY_NAME"
echo "Email: $COMPANY_EMAIL"

if [ ! -f "$DOMAINS_FILE" ]; then
    echo "ERROR: domains.list not found at: $DOMAINS_FILE"
    exit 1
fi

mkdir -p "$SSL_DIR"

echo "Generating SSL certificates with company information..."

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
    
    if [ -f "$SSL_DIR/$domain.crt" ] && [ -f "$SSL_DIR/$domain.key" ] && [ -s "$SSL_DIR/$domain.crt" ]; then
        echo "✓ Certificate for $domain already exists and is valid"
        continue
    fi
    
    echo "Generating SSL certificate for: $domain"
    
    # ایجاد فایل config با اطلاعات کامل
    cat > "$SSL_DIR/$domain.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
default_bits = 2048
default_keyfile = $domain.key
encrypt_key = no
default_md = sha256

[req_distinguished_name]
C = $COUNTRY_CODE
ST = $STATE_NAME
L = $CITY_NAME
O = $ORGANIZATION_NAME
OU = $ORGANIZATIONAL_UNIT
CN = $domain
emailAddress = $COMPANY_EMAIL

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[alt_names]
DNS.1 = $domain
DNS.2 = www.$domain
IP.1 = $ip
EOF
    
    # تولید کلید خصوصی
    echo "Generating private key..."
    openssl genrsa -out "$SSL_DIR/$domain.key" 2048
    
    # ایجاد Certificate Signing Request
    echo "Creating CSR..."
    openssl req -new -key "$SSL_DIR/$domain.key" -out "$SSL_DIR/$domain.csr" \
        -config "$SSL_DIR/$domain.cnf"
    
    # تولید سرتیفیکیت
    echo "Generating certificate..."
    openssl x509 -req -days 365 -in "$SSL_DIR/$domain.csr" \
        -signkey "$SSL_DIR/$domain.key" -out "$SSL_DIR/$domain.crt" \
        -extensions v3_req -extfile "$SSL_DIR/$domain.cnf"
    
    # تمیز کردن فایل‌های موقت
    rm -f "$SSL_DIR/$domain.csr" "$SSL_DIR/$domain.cnf"
    
    if [ -s "$SSL_DIR/$domain.crt" ]; then
        echo "✓ Certificate for $domain generated successfully!"
        echo "✓ Subject: $(openssl x509 -in "$SSL_DIR/$domain.crt" -noout -subject 2>/dev/null)"
    else
        echo "✗ Failed to generate certificate for $domain"
        # ایجاد فایل‌های dummy برای تست
        echo "Creating self-signed certificate for testing..."
        openssl req -x509 -newkey rsa:2048 -keyout "$SSL_DIR/$domain.key" \
            -out "$SSL_DIR/$domain.crt" -days 365 -nodes \
            -subj "/C=$COUNTRY_CODE/ST=$STATE_NAME/L=$CITY_NAME/O=$ORGANIZATION_NAME/OU=$ORGANIZATIONAL_UNIT/CN=$domain/emailAddress=$COMPANY_EMAIL"
    fi
done

echo "SSL certificate generation completed."
