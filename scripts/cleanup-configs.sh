#!/bin/bash

# استفاده از متغیرهای محیطی یا مقادیر پیش‌فرض
DOMAINS_FILE=${DOMAINS_FILE:-"domains.list"}
CONF_DIR=${CONF_DIR:-"conf"}
AUTO_DIR="$CONF_DIR/auto"

echo "Cleaning up old config files..."

# ایجاد لیست دامنه‌های فعال
active_domains=()
if [ -f "$DOMAINS_FILE" ]; then
    echo "Reading domains from: $DOMAINS_FILE"
    while IFS= read -r domain; do
        if [ -n "$domain" ]; then
            active_domains+=("$domain")
            echo "Active domain found: $domain"
        fi
    done < <(grep -v "^#" "$DOMAINS_FILE" | awk '{print $1}')
else
    echo "Warning: $DOMAINS_FILE not found!"
fi

echo "Found ${#active_domains[@]} active domains: ${active_domains[*]}"

# اگر پوشه auto وجود ندارد، ایجادش کن
mkdir -p "$AUTO_DIR"

# حذف فایل‌های کانفیگ غیرفعال در auto/
if [ -d "$AUTO_DIR" ]; then
    for config_file in "$AUTO_DIR"/*.conf; do
        [ -f "$config_file" ] || continue
        filename=$(basename "$config_file")
        domain=${filename%.conf}

        echo "Checking config file: $filename (domain: $domain)"

        found=0
        for active_domain in "${active_domains[@]}"; do
            if [ "$domain" = "$active_domain" ]; then
                found=1
                break
            fi
        done

        if [ $found -eq 0 ]; then
            echo "Removing config for deleted domain: $domain"
            rm -f "$config_file"
        else
            echo "Keeping config for active domain: $domain"
        fi
    done
fi

echo "Cleanup completed."
