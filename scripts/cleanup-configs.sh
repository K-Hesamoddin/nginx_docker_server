#!/bin/bash

# استفاده از متغیرهای محیطی یا مقادیر پیش‌فرض
DOMAINS_FILE=${DOMAINS_FILE:-"domains.list"}
CONF_DIR=${CONF_DIR:-"conf"}
AUTO_DIR="$CONF_DIR/auto"

echo "Cleaning up old config files..."

# ایجاد لیست دامنه‌های فعال با پرچم
declare -A active_domains
if [ -f "$DOMAINS_FILE" ]; then
    echo "Reading domains from: $DOMAINS_FILE"
    while IFS= read -r line; do
        line=${line%%#*}          # حذف کامنت داخلی خط
        line=$(echo "$line" | xargs) # حذف فاصله اضافی
        [ -z "$line" ] && continue
        flag=$(echo "$line" | awk '{print $1}')
        domain=$(echo "$line" | awk '{print $2}')
        active_domains["$domain"]=$flag
        echo "Active domain found: $domain (flag=$flag)"
    done < "$DOMAINS_FILE"
else
    echo "Warning: $DOMAINS_FILE not found!"
fi

echo "Found ${#active_domains[@]} active domains: ${!active_domains[@]}"

# اگر پوشه auto وجود ندارد، ایجادش کن
mkdir -p "$AUTO_DIR"

# حذف فایل‌های کانفیگ غیرفعال در auto/
if [ -d "$AUTO_DIR" ]; then
    for config_file in "$AUTO_DIR"/*.conf; do
        [ -f "$config_file" ] || continue
        filename=$(basename "$config_file")
        domain=${filename%.conf}

        echo "Checking config file: $filename (domain: $domain)"

        flag=${active_domains[$domain]:-0} # اگر دامنه نبود، پرچم 0

        if [[ -z "${active_domains[$domain]}" ]]; then
            echo "Removing config for deleted domain: $domain"
            rm -f "$config_file"
        elif [ "$flag" -eq 0 ]; then
            echo "Keeping config for active domain (flag=0): $domain"
        else
            echo "Keeping config for active domain (flag=1): $domain"
        fi
    done
fi

echo "Cleanup completed."
