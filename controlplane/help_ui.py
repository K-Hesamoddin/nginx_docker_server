"""Persian on-panel operator manual and step-by-step tours.

Read-only GET routes. No background worker, Docker, DNS, SSL, firewall, or
configuration writes. Guides describe the *actual staged capabilities* of V2.
The global authentication and LAN allowlist are enforced by web.create_app().
"""
from __future__ import annotations

from flask import Blueprint, abort, render_template_string, request, session, url_for

bp = Blueprint("help", __name__)

GUIDES = {
    "overview": {
        "title": "شروع کار و نقشه پنل",
        "summary": "از ورود تا ثبت امن یک تغییر: تشخیص امکانات واقعی، نقش کاربران و تفاوت پیش‌نویس با کانفیگ فعال.",
        "location": "/admin",
        "roles": "Viewer / Editor / Admin",
        "status": "راهنمای وضعیت آزمایشی V2",
        "scenario": "می‌خواهی بدون تغییر سایت‌های فعال، اطلاعات یک سرویس را بررسی یا برای تغییر آماده کنی.",
        "steps": [
            ("ورود امن", "از HTTPS روی IP داخلی 192.168.1.205 و پورت 8787 وارد شو. نام کاربری و رمز خودت را بنویس. گواهی اولیه self-signed است؛ قبل از اعتماد به آن، اثرانگشتش را با مسئول سرور تطبیق بده.", "صفحه اصلی /admin باز می‌شود و نام کاربری به نشست معتبر متصل است.", "/admin"),
            ("شناخت کارت‌های خلاصه", "در نمای کلی تعداد دامنه‌ها، snapshotها، گروه‌های SSL پیشنهادی و کارهای pending دیده می‌شوند. این تعدادها گزارش دیتابیس آزمایشی‌اند، نه تعداد سرویس‌های سالم و منتشرشده.", "ممکن است درخواست‌های pending وجود داشته باشد بدون اینکه عملیاتی اجرا شده باشد.", "/admin"),
            ("باز کردن یک دامنه", "از «دامنه‌ها و تاریخچه» یک دامنه را جست‌وجو و باز کن؛ نسخه live_snapshot از nginx -T قبلی را می‌توانی به عنوان مرجع ببینی.", "live_snapshot مرجع تاریخی است، نه نسخه‌ای که V2 منتشر کرده باشد.", "/manage"),
            ("بررسی Routeها و پیش‌نویس", "اول مقصد هر Route و URI پراکسی را بخوان. پس از بررسی، با دکمه «ساخت نسخه جدید» یک پیش‌نویس غیرعملیاتی بساز. تغییر Route به‌تنهایی هیچ نسخه‌ای نمی‌سازد.", "اگر گواهی در V2 ثبت نشده باشد، پیش‌نویس نشان PENDING-SSL دارد.", "/manage"),
            ("مقایسه و ثبت تاریخچه", "نسخه تولیدشده را با snapshot و نسخه‌های قبل مقایسه کن. ویرایش متن کانفیگ با «ذخیره» نسخه جدیدی می‌سازد؛ نسخه قدیمی باقی می‌ماند.", "متن قدیمی را با عجله جایگزین نکن؛ تنظیمات اختصاصی سایت‌ها در snapshotها هستند.", "/manage"),
            ("شناخت مرز اجرای واقعی", "درخواست SSL و انتشار فعلاً فقط رکورد pending در صف می‌سازد. هیچ Worker اجرایی متصل نیست و Nginx، Docker و گواهی عملیاتی با این دکمه‌ها تغییر نمی‌کنند.", "تا تکمیل Worker، nginx -t، backup، rollback و DNS-01، هیچ تغییری روی سایت‌های زنده انتظار نداشته باش.", "/manage"),
        ],
        "warnings": [
            "پنل V2 روی هاست در حال اجراست، اما گردش‌کار انتشار، تمدید SSL و تغییر Stream عملیاتی هنوز اجرا نمی‌شود.",
            "فلگ‌های قدیمی 0/1 در domains.list اطلاعات تاریخی‌اند و نباید بدون بررسی به فرمان جایگزینی کانفیگ تعبیر شوند.",
        ],
    },
    "domains": {
        "title": "دامنه‌ها و ساب‌دامنه‌ها",
        "summary": "ثبت، جست‌وجو و شناسایی سرویس‌ها؛ حفظ کانفیگ‌های دستی و aliasهای قدیمی.",
        "location": "/manage",
        "roles": "مشاهده: همه | ثبت دامنه: Editor / Admin",
        "status": "ثبت در دیتابیس؛ بدون اعمال خودکار",
        "scenario": "می‌خواهی ساب‌دامنه‌ای مثل api.example.com را برای یک Backend داخلی اضافه کنی.",
        "steps": [
            ("جست‌وجوی سرویس", "در /manage از کادر جست‌وجو نام دامنه را وارد کن و کارت مربوط را باز کن. کارت تعداد Routeها، وضعیت Draft، سابقه V2 و خلاصه SSL ثبت‌شده را نشان می‌دهد.", "کارت با V2 deployed: خیر، الزاماً به معنی آفلاین بودن سایت نیست؛ ممکن است توسط V1 فعال باشد.", "/manage"),
            ("ساخت دامنه تازه", "در «پنل اولیه» (/)، فرم «دامنه‌ها» را باز کن. نام دقیق FQDN مانند api.example.com، حداکثر اندازه آپلود MB، Security profile و در صورت نیاز WWW Redirect را تنظیم و ثبت کن.", "دامنه فقط در SQLite اضافه می‌شود؛ DNS، Virtual Host و SSL ساخته نمی‌شوند.", "/"),
            ("شناخت تنظیمات دامنه", "WWW Redirect در صورت نداشتن تعریف مستقل www رفتار ریدایرکت ایجاد می‌کند؛ به alias مستقل مثل www.hibarco.com توجه کن. Body limit و Security profile به پیش‌نویس‌های بعدی مربوط‌اند.", "ترجیح بده پیش از فعال‌سازی www، SAN گواهی و کانفیگ موجود را بررسی کنی.", "/"),
            ("تعریف Route", "بعد از ثبت، دامنه را از /manage باز کن و در بخش Routeهای همان دامنه حداقل یک مسیر، مثل /، به میزبان:پورت مقصد مرتبط کن.", "بدون Route معتبر نمی‌توان کانفیگ قابل‌استفاده ایجاد کرد.", "/manage"),
            ("حفظ نمونه عملیاتی", "در تاریخچه هر دامنه نسخه live_snapshot را بخوان. اگر نام یا مسیرهای اضافی در فایل قدیمی وجود دارد که هنوز در دیتابیس نیست، آن‌ها را پیش از ساخت نسخه نهایی بررسی کن.", "۲۹ snapshot به عنوان مرجع قبلاً ثبت شده‌اند؛ ۷ دامنه در ممیزی Route اختلاف داشتند.", "/manage"),
            ("تولید فقط با درخواست صریح", "ثبت یا تغییر دامنه و Route هیچ فایل فعال Nginx را تغییر نمی‌دهد. دکمه ساخت کانفیگ را صرفاً پس از کنترل Routeها بزن و سپس Diff را بررسی کن.", "وجود دامنه در فهرست معادل وجود رکورد DNS یا گواهی معتبر نیست.", "/manage"),
        ],
        "warnings": [
            "در بعضی کانفیگ‌های دستی، server_name اضافه یا location اختصاصی وجود دارد؛ حذف آن‌ها در مهاجرت می‌تواند سرویس را مختل کند.",
            "ساخت دامنه جدید به تنهایی DNS record یا SSL واقعی ایجاد نمی‌کند.",
        ],
    },
    "routes": {
        "title": "Route و Reverse Proxy",
        "summary": "تنظیم Path، آدرس Backend، Prefix stripping، URI پراکسی و WebSocket؛ با مثال‌های قابل تست.",
        "location": "/manage",
        "roles": "مشاهده: همه | ویرایش: Editor / Admin",
        "status": "فقط دیتابیس؛ نیازمند Generate برای پیش‌نویس",
        "scenario": "می‌خواهی /api/ را به 192.168.1.178:1010 بفرستی، بدون اینکه / یا سایر مسیرها تغییر کنند.",
        "steps": [
            ("انتخاب دامنه", "در /manage نام دامنه را جست‌وجو و صفحه اختصاصی آن را باز کن. هر فرم یک Location موجود را با path قفل‌شده برای ویرایش Backend نمایش می‌دهد.", "برای تغییر نام Location، معمولاً Route جدید بساز و پس از بررسی، قبلی را جداگانه حذف کن.", "/manage"),
            ("تعیین مسیر و مقصد", "در Route جدید، Location مثل /api/ و Backend را به شکل IP:PORT مثل 192.168.1.178:1010 وارد کن. این مسیر و مقصد در دیتابیس ذخیره می‌شوند.", "مقصد باید توسط شبکه Docker/Nginx در دسترس باشد؛ پنل فعلاً اتصال واقعی آن را تست نمی‌کند.", "/manage"),
            ("فهم دقیق proxy_pass", "Proxy URI خالی یعنی رفتار قدیمی از Strip prefix تعیین می‌شود: در حالت روشن، پسوند / به proxy_pass اضافه می‌شود؛ در حالت خاموش URI افزوده نمی‌شود. برای رفتاری مانند location /health با proxy_pass .../health، مقدار /health را صریحاً وارد کن.", "وجود یا نبود / انتهایی proxy_pass ممکن است URI دریافتی Backend را تغییر دهد؛ بدون تست آن را عادی‌سازی نکن.", "/manage"),
            ("فعال‌سازی WebSocket در صورت نیاز", "برای Backendهایی که Upgrade دارند، WebSocket را انتخاب کن. این تنظیم روی پیش‌نویس بعدی اثر می‌گذارد؛ پیش‌نویس و Config قبلی بازنویسی نمی‌شوند.", "وجود checkbox جای بررسی headerهای خاص و timeoutهای سرویس را نمی‌گیرد.", "/manage"),
            ("ذخیره یا حذف محتاطانه", "«ذخیره Route» فقط SQLite را تغییر می‌دهد؛ حذف نیازمند تأیید است و حذف آخرین Route دامنه در صفحه اختصاصی مسدود می‌شود.", "برای مسیرهایی مانند /health، /packs، /widget و /cable که در Nginx زنده وجود داشته‌اند، حذف یا عدم ثبت خطر از دست دادن رفتار دارد.", "/manage"),
            ("ساخت و مقایسه نسخه", "پس از تکمیل Routeها به قسمت «ساخت نسخه جدید از Routeها» برو، سپس متن و Diff کانفیگ تولیدشده را با نسخه live_snapshot مقایسه کن.", "یکسان بودن تعداد Routeها به معنای برابری کامل تنظیمات Nginx نیست.", "/manage"),
        ],
        "warnings": [
            "cloud.micromodern.ir، erp.micromodern.ir و git.micromodern.ir تفاوت حساس slash در proxy_pass داشته‌اند.",
            "hibarco.com در /media/ اختلاف IP و vakil129.com اختلاف پورت/URI داشته است؛ تغییر مقصد بدون تأیید صاحب سرویس مجاز نیست.",
        ],
    },
    "versions": {
        "title": "پیش‌نویس، تاریخچه، Diff و بازگردانی",
        "summary": "کار با Generate، ذخیره ویرایش دستی، نسخه‌های immutable، بازبینی تغییرات و درخواست Rollback.",
        "location": "/manage",
        "roles": "مشاهده: همه | ویرایش: Editor / Admin | درخواست انتشار: Admin",
        "status": "تاریخچه قابل استفاده؛ انتشار/بازگردانی فقط صف",
        "scenario": "می‌خواهی متن کانفیگ جدید را بسازی ولی نسخه موجود روی سایت بدون تغییر بماند.",
        "steps": [
            ("ابتدا نسخه مرجع را ببین", "از کارت دامنه وارد جزئیات شو. در تاریخچه، سطر live_snapshot را باز کن تا متن ذخیره‌شده از Nginx قدیمی را ببینی.", "live_snapshot قابل انتشار مستقیم از V2 نیست؛ فقط برای بررسی و نگهداری تاریخچه است.", "/manage"),
            ("ساخت نسخه از Routeها", "پس از تنظیم صحیح Route و SSL، «ساخت نسخه جدید از Routeها» را بزن. یک revision از نوع generated ساخته و به عنوان Draft انتخاب می‌شود.", "با هر بار Generate نسخه جدیدی ساخته می‌شود، حتی اگر Routeها دست نخورده باشند.", "/manage"),
            ("تشخیص SSL ناقص", "اگر resolver برای نام‌های موردنیاز گواهی ثبت‌شده معتبر نداشته باشد، پیش‌نویس شامل PENDING-SSL است. این نسخه قابل صف کردن برای انتشار نیست.", "متن placeholder را به‌جای گواهی واقعی قرار نده؛ Worker آینده باید گواهی را جداگانه تأیید کند.", "/manage"),
            ("ویرایش دستی متن", "در ویرایشگر متن می‌توانی کانفیگ را ببینی و با توضیح دلیل تغییر ذخیره کنی. ذخیره یک نسخه manual جدید با زمان و SHA256 تولید می‌کند؛ نسخه قبلی پاک نمی‌شود.", "ادیتور متن آزاد است، پس درستی تمام directiveها هنوز به عهده بازبینی است. این مرحله nginx -t واقعی نمی‌زند.", "/manage"),
            ("بازبینی Diff", "در جدول تاریخچه نسخه‌ای را انتخاب کن. بخش Diff تفاوت آن نسخه با نسخه قبلی همان دامنه را نشان می‌دهد؛ الزاماً مقایسه مستقیم با نسخه فعلی سرور نیست.", "برای مقایسه با live_snapshot، هر دو متن را آگاهانه بررسی کن.", "/manage"),
            ("بازیابی نسخه قدیمی", "برای بازگرداندن محتوا، نسخه قدیمی را باز و متنش را در یک Draft دستی جدید ذخیره کن. تاریخچه گذشته باقی می‌ماند.", "دکمه درخواست انتشار/بازگردانی فقط job در صف ایجاد می‌کند. Rollback واقعی هنوز پیاده نشده است.", "/manage"),
            ("بررسی صف درخواست‌ها", "به /manage برگرد و جدول «صف عملیات» را ببین. pending یعنی درخواست هنوز اجرا نشده؛ V2 deployed تا زمان وجود Worker و ثبت نتیجه واقعی خالی می‌ماند.", "هیچ‌وقت تغییر وضعیت pending را با reload یا deployment موفق اشتباه نگیر.", "/manage"),
        ],
        "warnings": [
            "تفاوت مسیرها، Includeها، TLS، WebSocket و Headerها باید پیش از مهاجرت کامل بازبینی شود.",
            "سیستم فعلی هنوز مجریِ nginx -t، reload، برگشت اتمیک یا تاریخچه انتشار زنده ندارد.",
        ],
    },
    "ssl": {
        "title": "SSL مشترک Wildcard برای هر DNS Zone",
        "summary": "یک گواهی برای هر Zone شامل apex و *.zone، DNS-01 چندارائه‌دهنده، نگهداری موقت گواهی‌های Legacy و محدودیت صف.",
        "location": "/admin/ssl",
        "roles": "مشاهده: همه | درخواست SSL: Admin",
        "status": "پیشنهاد و صف؛ صدور/تمدید واقعی هنوز غیرفعال",
        "scenario": "چندین subdomain زیر micromodern.ir داری و می‌خواهی درخواست تجمیعی درست ثبت کنی.",
        "steps": [
            ("مطالعه گروه‌ها", "در /admin/ssl گروه‌های پیشنهادی از دامنه‌های ثبت‌شده و server_name کانفیگ‌های بایگانی‌شده تولید می‌شوند. کارت نام Zone و شمار نام‌های در پوشش را نمایش می‌دهد.", "پیشنهاد، سرویس‌دهنده واقعی DNS یا مالکیت Zone را به‌طور خودکار تشخیص نمی‌دهد.", "/admin/ssl"),
            ("انتخاب DNS Provider", "در کارت هر Zone از منوی DNS Provider یکی از Cloudflare، NSIN، DNS دیگر یا روش دستی TXT را مشخص و ذخیره کن. این انتخاب بر اساس محل مدیریت رکوردهای authoritative انجام می‌شود، نه IP مقصد دامنه.", "این انتخاب فقط تنظیم SQLite است؛ هنوز هیچ کلید API یا DNS TXT توسط پنل ارسال نمی‌شود. در روش دستی تمدید خودکار کامل وجود ندارد.", "/admin/ssl"),
            ("تفاوت wildcard و apex", "گواهی مشترک باید SAN جدا برای micromodern.ir و *.micromodern.ir داشته باشد؛ خود wildcard دامنه اصلی را پوشش نمی‌دهد. طراحی درخواست این دو نام را در نظر دارد.", "Wildcard فقط یک سطح را پوشش می‌دهد؛ test.erp.micromodern.ir زیر *.micromodern.ir قرار نمی‌گیرد.", "/admin/ssl"),
            ("پوشش نام‌های چندسطحی", "برای test.erp.micromodern.ir یک گروه Wildcard عمیق‌تر مانند *.erp.micromodern.ir با SAN برای خود erp.micromodern.ir و کنترل DNS لازم است. صدور جدید تک‌ساب‌دامنه‌ای مجاز نیست.", "نباید تصور کرد یک wildcard همه عمق‌های یک دامنه را پوشش می‌دهد.", "/admin/ssl"),
            ("شناسایی گواهی موجود", "مسیر فایل‌های .crt که در snapshotهای قدیمی آمده، فقط «ارجاع قدیمی» است. جدول گواهی V2 تا ثبت فایل و اعتبارسنجی آن می‌تواند خالی باشد، حتی اگر Nginx زنده گواهی سرو کند.", "نام فایل یا مسیر .crt، اعتبار زمانی، زنجیره CA یا تطابق کلید را ثابت نمی‌کند.", "/admin/ssl"),
            ("ثبت درخواست", "از کارت Zone فقط روی «ثبت درخواست گواهی مشترک Zone» کلیک کن. یک job از نوع issue-wildcard در حالت pending ثبت می‌شود؛ کلیک تکراری کار جدید ایجاد نمی‌کند. صدور جدید Dedicated برای ساب‌دامنه در V2 مسدود است.", "تا وقتی موتور ACME و افزونه مربوط به همان DNS Provider وصل نشده‌اند، هیچ رکورد TXT و هیچ گواهی واقعی صادر نمی‌شود.", "/admin/ssl"),
            ("بررسی TLS دامنه", "از /manage، دامنه را باز کن و لینک بررسی TLS با SNI را بزن. این ابزار به 127.0.0.1:443 روی خود هاست تلاش می‌کند و ممکن است به Nginx Docker واقعی وصل نباشد.", "نتیجه این پروب را با وضعیت TLS عمومی سایت یا گواهی داخل کانتینر یکسان ندان.", "/manage"),
            ("آمادگی برای انتشار", "پس از صدور و ثبت گواهی معتبر در آینده، باید نام‌های SAN و کلید، فایل واقعی و اعتبار زنجیره بررسی شوند و سپس نسخه جدید Config ساخته شود.", "پنل فعلی صدور/تمدید خودکار SSL یا Reload Nginx را اجرا نمی‌کند.", "/admin/ssl"),
        ],
        "warnings": [
            "گواهی www.micmodshop.ir در Certbot و Nginx زنده منقضی است؛ راه‌حل هدف در V2 مهاجرت Apex و www به یک گواهی مشترک Wildcard است، نه صدور مجدد گواهی اختصاصی www. تا صدور و انتشار موفق، تنظیمات عملیاتی را بدون تغییر نگه دار.",
            "کلیدهای API هر ارائه‌دهنده DNS و کلید خصوصی گواهی را در متن کانفیگ، Note یا گفت‌وگو وارد نکن.",
        ],
    },
    "security": {
        "title": "هدرهای امنیتی و Includeهای سفارشی",
        "summary": "انتخاب Security Header برای هر دامنه، کاتالوگ Includeها، ویرایش نسخه‌دار snippet و احتیاط HSTS.",
        "location": "/admin/includes",
        "roles": "مشاهده: همه | ویرایش: Editor / Admin",
        "status": "تغییر در SQLite/پیش‌نویس؛ فایل واقعی Include منتشر نمی‌شود",
        "scenario": "دامنه‌ای به security.conf و یک cors-custom.conf خاص نیاز دارد.",
        "steps": [
            ("انتخاب دامنه", "در /admin/includes از فهرست، دامنه هدف را انتخاب کن. تیک‌های Security Headers و Includeها متعلق به همان دامنه هستند، نه کل Nginx.", "وجود یک Include در کانفیگ زنده را با انتخاب آن در دیتابیس V2 اشتباه نگیر.", "/admin/includes"),
            ("هدرهای پیش‌فرض قابل تنظیم", "با HSTS، nosniff و X-Frame-Options: SAMEORIGIN می‌توانی تنظیمات پیشنهادی را برای Draftهای بعدی تعیین کنی. پس از تغییر، «ذخیره تنظیمات امنیتی» را بزن.", "HSTS ممکن است روی بازدیدهای آینده کاربران اثر پایدار داشته باشد؛ بدون تست HTTPS روشن نکن.", "/admin/includes"),
            ("اضافه کردن نام Include", "نام امن فایل مثل cors-custom.conf را در کاتالوگ ثبت کن. فقط نام ساده .conf قابل ثبت است؛ مسیر دلخواه مثل ../ یا متن include از ورودی آزاد پذیرفته نمی‌شود.", "ثبت کاتالوگ به معنای ایجاد فایل روی /etc/nginx/conf.d/includes/ نیست.", "/admin/includes"),
            ("اختصاص Include به دامنه", "پس از انتخاب دامنه، checkbox فایل موردنظر را فعال/غیرفعال و ذخیره کن. هنگام Generate بعدی یک include برای مسیر مورد انتظار در پیش‌نویس قرار می‌گیرد.", "اگر فایل در Nginx واقعی موجود نباشد، کانفیگ آینده نمی‌تواند بدون provisioning امن اعمال شود.", "/admin/includes"),
            ("نوشتن متن snippet", "در فرم «ویرایش نسخه‌های Include» یک فایل را انتخاب کن، متن را وارد و با Note ذخیره کن. نسخه، زمان، SHA256 و Diff مستقل نگهداری می‌شوند.", "ویرایش snippet فعلاً فقط بایگانی در SQLite است و متن آن در فایل فعال سرور ذخیره نمی‌شود.", "/admin/includes"),
            ("بررسی تداخل تنظیمات", "در پیش‌نویس دامنه، وجود includeهای مشترک مثل security.conf و buffer.conf و همچنین add_headerهای مستقیم را بررسی کن. قوانین inheritance و تداخل add_header در Nginx مهم‌اند.", "وجود دو دستور تکراری یا تعارض HSTS/CORS ممکن است رفتار سرویس را تغییر دهد.", "/manage"),
        ],
        "warnings": [
            "Security profile قدیمی legacy/baseline با checkboxهای اختصاصی فرق دارد؛ پیش از مهاجرت معادل‌سازی کامل انجام بده.",
            "اجرای واقعی فایل Include، صحت syntax و مقایسه تنظیمات امنیتی با سرور هنوز خودکار نیست.",
        ],
    },
    "streams": {
        "title": "Streamهای TCP و UDP",
        "summary": "تفکیک Stream از HTTP، Listener، Backend، پیش‌نمایش و الزامات Docker/ماژول Stream.",
        "location": "/admin/streams",
        "roles": "مشاهده: همه | تعریف/ویرایش: Editor / Admin",
        "status": "Inventory و Preview؛ هیچ پورتی باز نمی‌شود",
        "scenario": "می‌خواهی یک سرویس TCP داخلی را از یک پورت مشخص به Backend دیگری عبور دهی.",
        "steps": [
            ("تشخیص نوع سرویس", "Stream برای TCP/UDP لایه چهار است، نه location /api/ در HTTP. مسیر URL، Header HTTP یا SSL دامنه در آن به‌طور خودکار اعمال نمی‌شود.", "برای HTTP reverse proxy از بخش Route استفاده کن؛ برای اتصال TCP/UDP از Stream.", "/admin/streams"),
            ("تعریف نام و پروتکل", "شناسه یکتا مثل internal-redis، پروتکل tcp/udp و توضیح را وارد کن. نام سرویس در فهرست قابل انتخاب است.", "ویرایش Stream با همان نام، تنظیمات ثبت‌شده قبلی در SQLite را به‌روزرسانی می‌کند.", "/admin/streams"),
            ("انتخاب Listener و مقصد", "Listen IP را به شکل IP مشخص مثل 127.0.0.1 و Port را در محدوده 1 تا 65535 وارد کن. Backend را IP:PORT بده. پورت‌های 80، 443 و 8787 و IP wildcard در حالت آزمایشی رد می‌شوند.", "سرویس فقط تعریف آزمایشی است؛ Bind واقعی یا Docker port mapping صورت نمی‌گیرد.", "/admin/streams"),
            ("Preview", "در جدول Streamها «ساخت Preview» را بزن تا server { listen ...; proxy_pass ...; } متناظر در تاریخچه preview ثبت شود.", "این fragment مخصوص context بالادستی stream {} است؛ در conf.d مربوط به HTTP نباید قرار گیرد.", "/admin/streams"),
            ("ویرایش/حذف", "روی «ویرایش» کلیک کن تا فیلدها وارد فرم شوند؛ با «حذف» و تأیید، فقط تعریف SQLite پاک می‌شود و نسخه‌های preview قبلی باقی می‌مانند.", "هیچ پورتی روی سرور بسته یا باز نمی‌شود و Nginx زنده تغییر نمی‌کند.", "/admin/streams"),
            ("پیش‌نیاز عملیاتی آینده", "پیش از واقعی شدن، باید ماژول nginx-stream، ساختار include مربوط به stream، تداخل پورت، قوانین فایروال و Publish پورت Docker جداگانه آزمایش شوند.", "پنل فعلی Stream را deploy، reload یا monitor نمی‌کند.", "/admin/streams"),
        ],
        "warnings": [
            "Streamهای TCP و UDP در Docker بدون تنظیم پورت/ماژول مناسب با متن کانفیگ صرف کار نمی‌کنند.",
            "ویرایش Stream موجود در پنل معادل اعمال تغییر شبکه نیست.",
        ],
    },
    "users": {
        "title": "کاربران، نقش‌ها و دسترسی",
        "summary": "ساخت کاربر دوم، نقش‌های Viewer/Editor/Admin، تغییر رمز، غیرفعال‌سازی و امنیت نشست.",
        "location": "/admin/users",
        "roles": "فقط Admin",
        "status": "مدیریت کاربران واقعی پنل V2",
        "scenario": "می‌خواهی همکار دوم بتواند Routeها را ویرایش کند ولی کاربران و IPهای مجاز را دست نزند.",
        "steps": [
            ("ورود مدیر", "با حساب admin وارد شو و /admin/users را باز کن. کاربران Editor و Viewer به این صفحه دسترسی ندارند.", "این صفحه فقط پس از اعتبارسنجی نشست و IP مجاز قابل مشاهده است.", "/admin/users"),
            ("ساخت کاربر", "نام کاربری ۳ تا ۳۲ کاراکتری و رمز ۱۲ کاراکتر یا بیشتر بده؛ رمز را برای دیگران در پیام یا log نفرست. برای همکار مسئول Route نقش Editor مناسب است.", "رمز به شکل salted hash ذخیره می‌شود؛ متن خام آن در دیتابیس نگهداری نمی‌شود.", "/admin/users"),
            ("انتخاب نقش", "Viewer فقط صفحات را می‌خواند؛ Editor می‌تواند تنظیمات دامنه/Route/Include/Stream و Draftها را تغییر دهد؛ Admin علاوه بر آن کاربران، allowlist و درخواست SSL/Deploy را مدیریت می‌کند.", "نقش Editor توان اجرای واقعی Deploy ندارد؛ اساساً Worker فعال نیست.", "/admin/users"),
            ("تغییر رمز یا نقش", "در ردیف کاربر، Role، Active یا Password تازه را تغییر و «اعمال تغییر» را بزن. تغییر مشخصات، نشست‌های قبلی آن کاربر را باطل می‌کند.", "کاربری که غیرفعال شده تا فعال‌سازی دوباره امکان ورود ندارد.", "/admin/users"),
            ("حفظ دسترسی مدیر", "آخرین Admin را غیرفعال یا تنزل رتبه نده؛ کد جلوی حذف مجوز Admin خودت را هم می‌گیرد. اگر رمز admin گم شد، بازیابی فقط از کنسول هاست انجام می‌شود.", "حذف فایل SQLite یا پاک کردن کاربران راه بازیابی رمز نیست.", "/admin/users"),
            ("محدودیت امنیتی فعلی", "ورود با HTTPS و ACL شبکه‌ای انجام می‌شود؛ MFA، قفل خودکار پس از تلاش‌های ناموفق و سیاست‌های کامل audit هنوز تکمیل نشده‌اند.", "پنل را در اینترنت عمومی منتشر نکن.", "/admin/users"),
        ],
        "warnings": [
            "به همکار صرفاً حداقل دسترسی لازم را بده. برای مشاهده گزارش‌ها Viewer کافی است.",
            "اگر رمز مدیر را روی سرور بازنشانی کنی، نشست‌های قبلی او باطل می‌شوند.",
        ],
    },
    "access": {
        "title": "IPهای مجاز و دسترسی مستقیم LAN",
        "summary": "مدیریت آدرس‌های خصوصی، CIDR، تفاوت 403 با Timeout، HTTPS و فایروال.",
        "location": "/admin/access",
        "roles": "فقط Admin",
        "status": "ACL برنامه فعال است؛ فایروال هاست مستقل است",
        "scenario": "می‌خواهی فقط 192.168.1.192 بتواند پنل را از شبکه داخلی باز کند.",
        "steps": [
            ("باز کردن صفحه ACL", "با مدیر وارد /admin/access شو. در نصب اولیه 192.168.1.192/32 و Loopbackهای 127.0.0.1/32 و ::1/128 ثبت شده‌اند.", "در شبکه فعلی، آدرس پنل https://192.168.1.205:8787/admin است، نه HTTP.", "/admin/access"),
            ("افزودن IP", "در فرم آدرس خصوصی دقیق مثل 192.168.1.193/32 را وارد کن و «افزودن» را بزن. /32 فقط یک دستگاه را شامل می‌شود؛ CIDR وسیع‌تر به افراد بیشتری دسترسی می‌دهد.", "پیش از تغییر، IP واقعی دستگاه را با ipconfig/route بررسی کن.", "/admin/access"),
            ("ملاحظه فایروال", "فهرست برنامه فقط بعد از برقراری اتصال TCP بررسی می‌شود. اگر کلاینت Timeout می‌گیرد، باید مسیر شبکه و فایروال بررسی شوند؛ فهرست مجاز به‌تنهایی پورت را در شبکه باز نمی‌کند.", "این پنل بدون تغییر NAT و بدون Forward به اینترنت باید در LAN بماند.", "/admin/access"),
            ("آزمون از کلاینت", "روی ویندوز از curl -k -I https://192.168.1.205:8787/admin یا PowerShell Test-NetConnection استفاده کن. پاسخ 302 برای کلاینت بدون نشست، طبیعی است.", "403 یعنی برنامه درخواست را رد کرده؛ Timeout معمولاً یعنی ارتباط TCP به برنامه نرسیده.", "/admin/access"),
            ("حذف محتاطانه", "IPهای غیرلازم را حذف کن، اما IP فعلی خودت را قبل از اضافه‌کردن مسیر جایگزین حذف نکن؛ ممکن است دسترسی وب از بین برود.", "Loopbackها از طریق پنل حذف نمی‌شوند و مسیر کنسول هاست برای بازیابی وجود دارد.", "/admin/access"),
            ("مرز اعتماد HTTPS", "گواهی اولیه پنل self-signed است و باید اثرانگشت آن پیش از اعتماد بررسی شود. هدر X-Forwarded-For برای دور زدن allowlist پذیرفته نمی‌شود.", "اتصال با HTTP به پنل LAN رد می‌شود؛ هرگز رمز عبور را روی HTTP وارد نکن.", "/admin/access"),
        ],
        "warnings": [
            "اضافه‌کردن یک شبکه بزرگ خصوصی به‌جای /32 سطح دسترسی را بیشتر می‌کند.",
            "تغییر قوانین Firewall/Docker/Router جزو عملیات این صفحه نیست و باید با کنترل جداگانه انجام شود.",
        ],
    },
    "jobs": {
        "title": "صف عملیات و وضعیت درخواست‌ها",
        "summary": "تفاوت pending با اجرا، صف SSL و Deploy، نحوه پیگیری و تشخیص وضعیت واقعی.",
        "location": "/manage",
        "roles": "مشاهده: همه | درخواست انتشار/SSL: Admin",
        "status": "ثبت در صف فعال؛ اجرای Worker متصل نیست",
        "scenario": "درخواست انتشار ثبت کرده‌ای و می‌خواهی بفهمی آیا Nginx واقعاً تغییر کرده است.",
        "steps": [
            ("بررسی جدول صف", "در /manage به «صف عملیات» برو. ستون‌ها شامل زمان، نوع درخواست، دامنه، Version، Status و Result هستند.", "زمان‌ها UTC هستند؛ آن‌ها را با ساعت محلی اشتباه نگیر.", "/manage"),
            ("تشخیص نوع درخواست", "deploy یعنی درخواست اعمال نسخه مشخص، issue-dedicated و issue-wildcard یعنی درخواست صدور SSL. این‌ها رکوردهای مدیریتی در دیتابیس‌اند.", "ورود یک رکورد به معنی صدور گواهی یا انتشار کانفیگ نیست.", "/manage"),
            ("خواندن Status", "pending یعنی در انتظار اجرای Worker؛ running/succeeded/failed/cancelled برای موتور اجرایی آینده پیش‌بینی شده‌اند. با نسخه فعلی درخواست‌ها معمولاً pending می‌مانند.", "لاگ عملیاتی و نتیجه Nginx هنوز از Worker واقعی دریافت نمی‌شود.", "/manage"),
            ("آمادگی پیش از درخواست", "برای deploy یک revision جدید و بازبینی‌شده با گواهی معتبر لازم است. live_snapshot و پیش‌نویس PENDING-SSL قابل انتشار از این مسیر نیستند.", "در حال حاضر حتی یک job پذیرفته‌شده نیز مستقیماً config را نمی‌نویسد.", "/manage"),
            ("برنامه انتشار ایمن آینده", "مسیر اجرایی آینده باید backup، اعتبارسنجی nginx -t، تغییر اتمیک، reload محدود، health check، گزارش نتیجه و rollback قابل اعتماد داشته باشد.", "تا آن زمان نتیجه موفقیت نباید در UI نمایش داده شود.", "/manage"),
        ],
        "warnings": [
            "تا تکمیل Worker، صف عملیات را به‌عنوان سیستم درخواست و برنامه‌ریزی در نظر بگیر، نه ابزار اجرای دستورات.",
            "SSL Request هیچ DNS TXT record، گواهی، Certbot یا acme.sh واقعی اجرا نمی‌کند.",
        ],
    },
    "troubleshooting": {
        "title": "عیب‌یابی و بررسی سلامت پنل",
        "summary": "تشخیص 401/403/Timeout، گواهی Self-signed، وضعیت سرویس، رمز مدیر و تست شبکه.",
        "location": "/admin",
        "roles": "بررسی وب: همه | بررسی هاست: مسئول سرور",
        "status": "فرآیند رفع مشکل پنل؛ بدون دستکاری Nginx عملیاتی",
        "scenario": "پنل باز نمی‌شود یا پس از کلیک روی لینکی دوباره صفحه ورود ظاهر می‌شود.",
        "steps": [
            ("تشخیص خطا", "اگر browser به صفحه ورود هدایت شد، نشست معتبر نیست؛ دوباره وارد شو. 403 به معنی عدم اجازه برنامه یا درخواست HTTP در حالت HTTPS-only است. Timeout معمولاً مشکل TCP/firewall است.", "خطای 403 و Timeout دو مشکل متفاوت‌اند و راه‌حلشان یکی نیست.", "/admin"),
            ("بررسی سرویس فقط‌خواندنی", "روی خود سرور، systemctl --user --no-pager status nginx-controlplane-v2 و ss -ltn '( sport = :8787 )' را بخوان. سرویس باید active و Listener روی 192.168.1.205:8787 باشد.", "برای عیب‌یابی نیازی به nginx reload یا docker restart نیست.", "/admin"),
            ("بررسی لاگ پنل", "اگر سرویس خطا داشت، journalctl --user -u nginx-controlplane-v2 -n 60 --no-pager را بررسی کن. از ارسال فایل کانفیگ کامل یا کلید خصوصی همراه لاگ خودداری کن.", "به‌ویژه خطاهای Flask، Gunicorn، دسترسی فایل DB و bind port مهم‌اند.", "/admin"),
            ("تست کلاینت ویندوزی", "از Windows CMD دستور curl -k -I --connect-timeout 5 https://192.168.1.205:8787/admin را اجرا کن. Test-NetConnection دستور PowerShell است، نه CMD؛ از powershell -NoProfile -Command استفاده کن.", "اگر Listener فعال است ولی کلاینت Timeout می‌گیرد، فایروال/مسیر LAN را بررسی کن.", "/admin"),
            ("عیب‌یابی SSL پنل", "گواهی اولیه self-signed است؛ هشدار اعتماد مرورگر را قبل از تطبیق fingerprint قبول نکن. HTTPS پنل با SSL وب‌سایت‌های Proxy شده تفاوت دارد.", "http://192.168.1.205:8787 مسیر معتبر ورود نیست؛ از https استفاده کن.", "/admin"),
            ("بازیابی رمز مدیر", "در کنسول سرور و همان محیط آزمایشی، python scripts/controlplane_lan.py reset-admin-password را اجرا کن و رمز جدید قوی تعیین کن.", "این عملیات فقط رمز پنل را تغییر می‌دهد و Nginx را دست نمی‌زند.", "/admin"),
            ("به‌روزرسانی کنترل‌شده کد", "بعد از git pull --ff-only و تست‌های pytest در پوشه lab، فقط سرویس کاربر را با systemctl --user restart nginx-controlplane-v2 دوباره راه‌اندازی کن.", "هرگز برای راه‌اندازی پنل، سرویس nginx-proxy یا Docker Compose را ریستارت نکن.", "/admin"),
        ],
        "warnings": [
            "پورت پنل نباید در MikroTik به اینترنت عمومی Forward شود.",
            "اگر IP دستگاه عوض شد، پیش از حذف IP قبلی از مسیر کنسول دسترسی لازم را بررسی کن.",
        ],
    },
}

GUIDE_ORDER = (
    "overview", "domains", "routes", "versions", "ssl", "security",
    "streams", "users", "access", "jobs", "troubleshooting"
)

STYLE = """
*{box-sizing:border-box}body{background:#f4f6fb;color:#16243d;font:15px/1.9 system-ui,sans-serif;margin:0}
a{color:#14578b;text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1220px;margin:24px auto;padding:0 16px}
.header{background:#142e4b;color:#fff;border-radius:15px;padding:22px}
.header a{color:#d9efff}.header h1{margin:0;font-size:24px}
.nav{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}
.nav a{padding:7px 12px;background:#fff;border:1px solid #dae3ee;border-radius:9px}
.main{background:#fff;border:1px solid #dce5ef;border-radius:14px;padding:20px;margin:14px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:13px}
.tile{background:#f7fafe;border:1px solid #dce8f4;border-radius:12px;padding:15px}
.tile h2{font-size:18px;margin:0 0 8px}.small{color:#586c82;font-size:13px}
.badge{display:inline-block;background:#e9eff7;border-radius:8px;padding:3px 9px;font-size:12px}
.warning{background:#fff8e9;border-right:4px solid #d5a54c;padding:12px 16px;margin:10px 0}
.good{background:#eaf6ef;border-right:4px solid #5d9872;padding:12px 16px;margin:12px 0}
.btn{display:inline-block;background:#174d7e;color:#fff;padding:9px 16px;border-radius:9px;margin:3px 0}
.btn:hover{color:white}.btn-lite{display:inline-block;border:1px solid #cbd7e5;padding:8px 14px;border-radius:9px}
.steps{list-style:none;padding:0;counter-reset:guide-step}
.steps li{counter-increment:guide-step;border:1px solid #e1e9f1;border-radius:11px;padding:13px 17px;margin:12px 0}
.steps li h3{font-size:17px;margin:0}.steps li h3::before{content:counter(guide-step) ". ";color:#14578b}
.steps li p{margin:7px 0}.actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
progress{width:100%;height:15px;accent-color:#1a5989}
code{direction:ltr;unicode-bidi:isolate;display:inline-block}
@media(max-width:720px){.wrap{padding:0 9px;margin:9px auto}.main,.header{padding:15px}}
"""

HTML = """
<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>راهنمای Nginx Control Plane V2</title><style>""" + STYLE + """</style></head>
<body><div class="wrap">
<header class="header">
<h1>راهنمای عملیاتی پنل Nginx V2</h1>
<p>راهنمای فارسی و تور مرحله‌به‌مرحله برای محیط آزمایشی کنترل‌پنل</p>
<div class="actions"><a href="/admin">بازگشت به داشبورد</a>
<a href="/manage">دامنه‌ها</a><a href="/help">همه راهنماها</a></div>
</header>
<nav class="nav">
{% for slug in guide_order %}
<a href="{{url_for('help.guide',section=slug)}}">{{guides[slug].title}}</a>
{% endfor %}
</nav>
{% if mode == 'index' %}
<section class="main">
<h2>از کجا شروع کنم؟</h2>
<div class="warning"><strong>مرز عملکرد پنل:</strong> تغییرات دامنه، Route، تاریخچه، امنیت، کاربر و ACL
در SQLite ذخیره می‌شوند. دکمه‌های Deploy و درخواست SSL فقط job در صف ایجاد می‌کنند.
تغییر فایل‌های Nginx زنده، صدور گواهی و Publish Stream هنوز انجام نمی‌شود.</div>
<p>اگر اولین بار است وارد پنل می‌شوی، «شروع کار» را انتخاب کن؛ برای هر بخش هم راهنمای کامل
و هم تور گام‌به‌گام در دسترس است. تمام تورها فقط صفحات راهنما را باز می‌کنند و هیچ تنظیمی را تغییر نمی‌دهند.</p>
<div class="grid">
{% for slug in guide_order %}
<div class="tile"><h2>{{guides[slug].title}}</h2><p>{{guides[slug].summary}}</p>
<div class="small">دسترسی: {{guides[slug].roles}}</div>
<div class="actions">
<a class="btn-lite" href="{{url_for('help.guide',section=slug)}}">مطالعه راهنما</a>
<a class="btn" href="{{url_for('help.tour',section=slug,step=1)}}">شروع تور</a>
</div></div>
{% endfor %}
</div>
</section>
{% elif mode == 'guide' %}
<section class="main">
<span class="badge">{{item.status}}</span>
<h2>{{item.title}}</h2><p>{{item.summary}}</p>
<p><strong>دسترسی:</strong> {{item.roles}}</p>
<p><strong>مثال کاربردی:</strong> {{item.scenario}}</p>
<div class="actions">
<a class="btn" href="{{url_for('help.tour',section=section,step=1)}}">شروع تور {{item.steps|length}} مرحله‌ای</a>
<a class="btn-lite" href="{{item.location}}">رفتن به صفحه مربوط</a>
</div>
</section>
<section class="main"><h2>مراحل عملیاتی</h2>
<ol class="steps">
{% for heading,body,verify,href in item.steps %}
<li><h3>{{heading}}</h3><p>{{body}}</p>
<div class="good"><strong>نکته بررسی:</strong> {{verify}}</div>
<a href="{{href}}">باز کردن صفحه مربوط</a></li>
{% endfor %}
</ol></section>
<section class="main"><h2>هشدارها و محدودیت‌ها</h2>
{% for warning in item.warnings %}<div class="warning">{{warning}}</div>{% endfor %}
</section>
{% else %}
<section class="main">
<div class="actions"><span class="badge">{{item.status}}</span>
<span class="small">گام {{step}} از {{total}}</span></div>
<progress value="{{step}}" max="{{total}}">{{step}}/{{total}}</progress>
<h2>{{heading}}</h2><p>{{body}}</p>
<div class="good"><strong>بررسی کن:</strong> {{verify}}</div>
<p class="small">مثال: {{item.scenario}}</p>
<div class="actions">
<a class="btn" href="{{href}}">باز کردن صفحه در پنل</a>
<a class="btn-lite" href="{{url_for('help.guide',section=section)}}">راهنمای کامل</a>
</div>
<hr>
<div class="actions">
{% if step > 1 %}<a class="btn-lite" href="{{url_for('help.tour',section=section,step=step-1)}}">مرحله قبل</a>{% endif %}
{% if step < total %}<a class="btn" href="{{url_for('help.tour',section=section,step=step+1)}}">مرحله بعد</a>
{% else %}<a class="btn" href="{{url_for('help.guide',section=section)}}">پایان تور و مرور راهنما</a>{% endif %}
<a class="btn-lite" href="/help">بازگشت به فهرست</a>
</div>
</section>
<div class="main"><h3>تمام مراحل این تور</h3>
<div class="nav">
{% for heading,body,verify,href in item.steps %}
<a href="{{url_for('help.tour',section=section,step=loop.index)}}" {% if step==loop.index %}aria-current="step"{% endif %}>
{{loop.index}}. {{heading}}</a>
{% endfor %}
</div></div>
{% endif %}
<footer class="small">این راهنما نسخه آزمایشی V2 را توصیف می‌کند. اجرای واقعی Nginx/Docker/ACME از این صفحات انجام نمی‌شود.</footer>
</div></body></html>
"""


@bp.get("/help")
def index():
    return render_template_string(HTML, mode="index", guides=GUIDES,
                                  guide_order=GUIDE_ORDER)


@bp.get("/help/<section>")
def guide(section: str):
    item = GUIDES.get(section)
    if item is None:
        abort(404)
    return render_template_string(
        HTML, mode="guide", guides=GUIDES, guide_order=GUIDE_ORDER,
        item=item, section=section
    )


@bp.get("/help/<section>/tour")
def tour(section: str):
    item = GUIDES.get(section)
    if item is None:
        abort(404)
    step = request.args.get("step", default=1, type=int)
    total = len(item["steps"])
    if not 1 <= step <= total:
        abort(404)
    heading, body, verify, href = item["steps"][step - 1]
    return render_template_string(
        HTML, mode="tour", guides=GUIDES, guide_order=GUIDE_ORDER,
        item=item, section=section, step=step, total=total,
        heading=heading, body=body, verify=verify, href=href,
    )
