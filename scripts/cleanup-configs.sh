#!/bin/bash

# استفاده از متغیرهای محیطی یا مقادیر پیش‌فرض
DOMAINS_FILE=${DOMAINS_FILE:-"domains.list"}
CONF_DIR=${CONF_DIR:-"conf"}

echo "Cleaning up old config files..."

# ایجاد لیست دامنه‌های فعال
active_domains=()
if [ -f "$DOMAINS_FILE" ]; then
    echo "Reading domains from: $DOMAINS_FILE"
    # استفاده از grep برای فیلتر کردن کامنت‌ها و خطوط خالی
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

# اگر پوشه conf وجود ندارد، ایجادش کن
mkdir -p "$CONF_DIR"

# حذف فایل‌های کانفیگ غیرفعال
if [ -d "$CONF_DIR" ]; then
    for config_file in "$CONF_DIR"/auto_*.conf; do
        if [ -f "$config_file" ]; then
            filename=$(basename "$config_file")
            domain=${filename#auto_}
            domain=${domain%.conf}
            
            echo "Checking config file: $filename (domain: $domain)"
            
            # بررسی آیا دامنه در لیست فعال وجود دارد
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
        fi
    done
fi

echo "Cleanup completed."
