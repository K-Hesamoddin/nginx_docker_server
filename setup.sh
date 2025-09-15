#!/bin/bash

# تنظیمات پیش‌فرض برای اطلاعات شرکت (برای fallback)
COMPANY_NAME=${COMPANY_NAME:-"MICROMODERN"}
COMPANY_EMAIL=${COMPANY_EMAIL:-"micromodern.ah@gmail.com"}
COUNTRY_CODE=${COUNTRY_CODE:-"IR"}
STATE_NAME=${STATE_NAME:-"Tehran"}
CITY_NAME=${CITY_NAME:-"Tehran"}
ORGANIZATION_NAME=${COMPANY_NAME:-"MICROMODERN"}

# ایجاد فولدرهای مورد نیاز
mkdir -p scripts conf ssl logs html

# ایجاد فایل domains.list اگر وجود ندارد
if [ ! -f domains.list ]; then
    echo "sipad.micromodern.ir 192.168.1.75 8000" > domains.list
    echo "Created domains.list file with example domain"
fi

echo "=== Company Information (for fallback) ==="
echo "Company: $COMPANY_NAME"
echo "Email: $COMPANY_EMAIL"
echo "Country: $COUNTRY_CODE"
echo "State: $STATE_NAME"
echo "City: $CITY_NAME"
echo "Organization: $ORGANIZATION_NAME"
echo "=========================================="

echo "=== Checking domains.list ==="
cat domains.list
echo "============================="

# تولید سرتیفیکیت‌ها با Let's Encrypt (اولویت) + fallback با اطلاعات شرکت
echo "=== Generating SSL certificates ==="
COMPANY_NAME="$COMPANY_NAME" \
COMPANY_EMAIL="$COMPANY_EMAIL" \
COUNTRY_CODE="$COUNTRY_CODE" \
STATE_NAME="$STATE_NAME" \
CITY_NAME="$CITY_NAME" \
ORGANIZATION_NAME="$ORGANIZATION_NAME" \
DOMAINS_FILE="domains.list" \
SSL_DIR="ssl" \
bash scripts/generate-certificates.sh

# تولید کانفیگ‌ها (بدون تغییر)
echo "=== Generating Nginx configurations ==="
DOMAINS_FILE="domains.list" CONF_DIR="conf" LOG_DIR="logs" bash scripts/generate-configs.sh

# حذف کانفیگ‌های قدیمی
echo "=== Cleaning up old config files ==="
DOMAINS_FILE="domains.list" CONF_DIR="conf" bash scripts/cleanup-configs.sh

# نمایش نتایج
echo "=== Generated files ==="
echo "Config files:"
ls -la conf/auto_*.conf 2>/dev/null || echo "No config files found!"

echo "SSL files:"
ls -la ssl/*.crt 2>/dev/null || echo "No SSL certificates found!"

echo "=== Certificate details ==="
for cert_file in ssl/*.crt; do
    if [ -f "$cert_file" ]; then
        echo "Certificate: $(basename $cert_file)"
        issuer=$(openssl x509 -in "$cert_file" -noout -issuer 2>/dev/null | cut -d= -f2-)
        if echo "$issuer" | grep -q "Let's Encrypt"; then
            echo "  Issuer: ✅ $issuer (VALID)"
        else
            echo "  Issuer: ⚠ $issuer (Self-Signed)"
        fi
        openssl x509 -in "$cert_file" -noout -subject -dates 2>/dev/null || echo "  Could not read certificate details"
        echo "---"
    fi
done

echo "=== Setup completed! ==="
