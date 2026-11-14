"""Responsive inventory-focused administration pages. No privileged execution.

For security, user/session roles and network ACLs are verified by web.py
before every request, including all routes in this blueprint.
"""
from __future__ import annotations

import sqlite3

from flask import (
    Blueprint, flash, redirect, render_template_string, request,
    session, url_for
)

from .admin_features import (
    add_allowed_net, add_stream, allowed_networks, delete_stream, ensure_features,
    include_history, include_version_diff, recommended_zones, register_include,
    remove_allowed_net, save_include_revision, set_domain_include,
    set_security_options, stream_preview, user_update, user_upsert,
)
from .core import hostname, open_db
from .management import ensure_schema, queue_certificate

bp = Blueprint("settings", __name__)

STYLE = """
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;background:#f4f6fb;color:#17243c;font:15px/1.8 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:#154f89;text-decoration:none}a:hover{text-decoration:underline}
.shell{max-width:1380px;margin:auto;padding:22px}
.top{display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap;
background:#132844;color:#fff;padding:18px 24px;border-radius:16px}
.top a{color:#eaf4ff}.top strong{font-size:22px}
.nav{display:flex;gap:9px;flex-wrap:wrap;margin:16px 0}
.nav a{background:#fff;color:#224367;border:1px solid #dce4ef;border-radius:9px;padding:8px 12px}
.nav a.active{background:#dcecfb;border-color:#a5c9ec}
h1{font-size:22px;margin:0 0 12px}h2{font-size:18px;margin:0 0 8px}h3{font-size:16px}
.muted,small{color:#5f6e84;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}
.panel{background:#fff;border:1px solid #e0e6ee;border-radius:14px;padding:19px;margin-bottom:14px;box-shadow:0 2px 8px rgba(30,45,66,.035)}
.metric{font-size:30px;font-weight:750;line-height:1.2;color:#153f71}
.tag{display:inline-block;color:#365273;background:#e9f0f7;border-radius:8px;padding:1px 8px;font-size:12px}
.alert{background:#fff7e9;color:#6b4f1c;border:1px solid #f0dfba;border-radius:10px;padding:12px;margin-bottom:14px}
.ok{background:#e8f6ed;color:#24633a;border:1px solid #b8e1c4;border-radius:10px;padding:12px;margin-bottom:14px}
form{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;margin:8px 0}
label{display:flex;flex-direction:column;gap:4px;font-size:13px;color:#455773}
input,select,textarea{border:1px solid #c8d3df;border-radius:8px;padding:9px 10px;
background:#fff;color:#17243c;font:inherit;min-width:0}
input[type=checkbox]{width:18px;height:18px;vertical-align:middle}
button{padding:9px 15px;background:#194c80;border:1px solid #194c80;border-radius:8px;
color:#fff;font-weight:650;cursor:pointer}
button.secondary{background:#fff;border-color:#c4d4e4;color:#1c4e7c}
button.danger{background:#9a2c36;border-color:#9a2c36}
table{border-collapse:collapse;width:100%;direction:ltr;text-align:left;font-size:13px}
td,th{padding:9px;border-bottom:1px solid #e6ebf2;vertical-align:top}
.tablewrap{overflow:auto}
pre{background:#edf3f9;border:1px solid #dbe4f0;border-radius:10px;padding:14px;direction:ltr;
text-align:left;white-space:pre-wrap;word-break:break-word}
code{direction:ltr;unicode-bidi:isolate}
.note{font-size:13px;color:#5b6680}
@media(max-width:720px){.shell{padding:10px}.top{border-radius:12px}.panel{padding:13px}h1{font-size:20px}}
"""

PAGE = """
<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>کنترل‌پنل Nginx V2</title><style>""" + STYLE + """</style></head>
<body><div class="shell">
<header class="top"><div><strong>مرکز مدیریت Nginx</strong>
<div>پیش‌نمایش و نگهداری امن دامنه‌ها، SSL، سرویس‌ها و کاربران</div></div>
<div><small style="color:#b6cce5">حالت آزمایشی · بدون انتشار خودکار</small></div></header>
<nav class="nav">
<a href="/manage">دامنه‌ها و تاریخچه</a>
<a href="{{url_for('settings.dashboard')}}" class="{{'active' if page=='dashboard' else ''}}">نمای کلی</a>
<a href="{{url_for('settings.ssl')}}" class="{{'active' if page=='ssl' else ''}}">پیشنهادهای SSL</a>
<a href="{{url_for('settings.includes')}}" class="{{'active' if page=='includes' else ''}}">امنیت و Include</a>
<a href="{{url_for('settings.streams')}}" class="{{'active' if page=='streams' else ''}}">Streamها</a>
{% if session.get('role')=='admin' %}
<a href="{{url_for('settings.users')}}" class="{{'active' if page=='users' else ''}}">کاربران</a>
<a href="{{url_for('settings.access')}}" class="{{'active' if page=='access' else ''}}">IPهای مجاز</a>
{% endif %}
<a href="/">پنل اولیه</a>
</nav>
{% for category,msg in get_flashed_messages(with_categories=true) %}
<div class="{{'alert' if category=='error' else 'ok'}}">{{msg}}</div>{% endfor %}
<div class="alert">تمام ویرایش‌ها صرفاً در دیتابیس آزمایشی ذخیره می‌شوند. اجرای واقعی SSL، انتشار کانفیگ،
تغییر Includeهای سرور و Streamها هنوز به Worker جداگانه نیاز دارد.</div>

{% if page == 'dashboard' %}
<h1>نمای کلی</h1>
<div class="grid">
<div class="panel"><div class="muted">دامنه‌های ثبت‌شده</div><div class="metric">{{counts.domains}}</div><a href="/manage">مشاهده دامنه‌ها</a></div>
<div class="panel"><div class="muted">نسخه‌های بایگانی‌شده</div><div class="metric">{{counts.snapshots}}</div><a href="/manage">تاریخچه نسخه‌ها</a></div>
<div class="panel"><div class="muted">گروه‌های پیشنهادی Wildcard</div><div class="metric">{{counts.zones}}</div><a href="{{url_for('settings.ssl')}}">بررسی پوشش گواهی‌ها</a></div>
<div class="panel"><div class="muted">درخواست‌های معلق</div><div class="metric">{{counts.jobs}}</div><a href="/manage">مشاهده صف</a></div>
</div>
<section class="panel"><h2>شروع کار با پنل</h2>
<p>ابتدا روی <a href="/manage">یک دامنه</a> کلیک کن. Routeهای آن را ویرایش کن؛ تا دکمه
«ساخت نسخه جدید» را نزنی، متن کانفیگ ذخیره‌شده هم عوض نمی‌شود. بعد پیش‌نویس جدید و نسخه
بایگانی‌شده Nginx را مقایسه کن. درخواست انتشار فعلاً تنها در صف ثبت می‌شود.</p>
<p>در بخش <a href="{{url_for('settings.ssl')}}">SSL</a>، گروه‌های Wildcard پیشنهاد می‌شوند.
برای کاربر دوم به <a href="{{url_for('settings.users')}}">کاربران</a> و برای منابع خاص به
<a href="{{url_for('settings.includes')}}">Includeها</a> مراجعه کن.</p></section>

{% elif page == 'ssl' %}
<h1>گواهی‌های یکپارچه پیشنهادی</h1>
<p class="muted">هر درخواست Wildcard شامل نام اصلی zone و *.zone در SAN است. Wildcard فقط یک سطح از زیردامنه‌ها را پوشش می‌دهد.
این فهرست از نام‌های دیتابیس <strong>و server_name در کانفیگ‌های بایگانی‌شده</strong> پیشنهاد شده و به معنی تأیید مالکیت DNS در NSIN یا اعتبار گواهی‌های موجود نیست. نام فایل گواهی به معنی معتبر بودن آن نیست.</p>
<div class="grid">
{% for z in zones %}
<section class="panel">
<div class="tag">{{z.count}} نام در محدوده پوشش</div>
<h2 dir="ltr" style="text-align:left">{{z.zone}}</h2>
<div><strong dir="ltr">{{z.wildcard}}</strong> + <code>{{z.zone}}</code>
{% if z.nested_zone %}<span class="tag">پوشش زیردامنه چندسطحی</span>{% endif %}</div>
<p class="muted">گواهی‌های ارجاع‌شده در کانفیگ‌های قدیمی (اعتبار هنوز بررسی نشده):
{% if z.archived_cert_paths %}
{% for path in z.archived_cert_paths %}<code>{{path}}</code>{% if not loop.last %}، {% endif %}{% endfor %}
{% else %}در آرشیو دامنه‌های این گروه مسیر گواهی یافت نشد{% endif %}</p>
<p class="muted">پوشش پیشنهادی:
{% for d in z.covered %}<code>{{d}}</code>{% if not loop.last %}، {% endif %}{% endfor %}</p>
{% if z.not_covered %}
<div class="alert"><strong>زیر دامنه خارج از پوشش این Wildcard:</strong>
{% for d in z.not_covered %}<code>{{d}}</code>{% if not loop.last %}، {% endif %}{% endfor %}
<p>برای این نام‌ها گواهی اختصاصی یا wildcard در سطح عمیق‌تر لازم است.</p></div>
{% endif %}
<form method="post" action="{{url_for('settings.ssl_request')}}">
<input type="hidden" name="csrf" value="{{csrf}}">
<input type="hidden" name="zone" value="{{z.zone}}">
<input type="hidden" name="kind" value="wildcard">
<button>ثبت درخواست Wildcard</button></form>
<small>فقط یک کار pending ثبت می‌شود؛ DNS/ACME در این مرحله اجرا نمی‌شود.</small>
</section>
{% endfor %}
</div>
<section class="panel"><h2>گواهی اختصاصی برای یک نام</h2>
<form method="post" action="{{url_for('settings.ssl_request')}}">
<input type="hidden" name="csrf" value="{{csrf}}">
<label>دامنه / Subdomain <input name="zone" dir="ltr" placeholder="test.erp.micromodern.ir" required></label>
<input type="hidden" name="kind" value="dedicated">
<button>ثبت درخواست اختصاصی</button></form></section>

{% elif page == 'users' %}
<h1>کاربران و نقش‌ها</h1>
<section class="panel"><p>Admin: مدیریت کاربران، شبکه و درخواست‌ها. Editor: مدیریت تنظیمات و پیش‌نویس‌ها.
Viewer: مشاهده صرف. گذرواژه‌های کاربران به‌صورت Hash ذخیره می‌شوند.</p>
<div class="tablewrap"><table><tr><th>ID</th><th>User</th><th>Role</th><th>Active</th><th>Change</th></tr>
{% for u in users %}
<tr><td>{{u.id}}</td><td>{{u.username}}</td><td>{{u.role}}</td><td>{{u.active}}</td>
<td><form method="post" action="{{url_for('settings.user_change')}}">
<input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="id" value="{{u.id}}">
<select name="role"><option value="viewer" {{'selected' if u.role=='viewer' else ''}}>Viewer</option>
<option value="editor" {{'selected' if u.role=='editor' else ''}}>Editor</option>
<option value="admin" {{'selected' if u.role=='admin' else ''}}>Admin</option></select>
<select name="active"><option value="1" {{'selected' if u.active else ''}}>فعال</option>
<option value="0" {{'selected' if not u.active else ''}}>غیرفعال</option></select>
<input type="password" name="password" placeholder="رمز جدید (اختیاری)" autocomplete="new-password">
<button class="secondary">اعمال تغییر</button></form></td></tr>
{% endfor %}
</table></div></section>
<section class="panel"><h2>ایجاد کاربر دوم</h2>
<form method="post" action="{{url_for('settings.user_create')}}">
<input type="hidden" name="csrf" value="{{csrf}}">
<label>نام کاربری <input dir="ltr" name="username" minlength="3" maxlength="32" required></label>
<label>گذرواژه ۱۲ کاراکتر یا بیشتر <input type="password" name="password" minlength="12" required autocomplete="new-password"></label>
<label>نقش <select name="role"><option value="viewer">Viewer</option><option value="editor">Editor</option>
<option value="admin">Admin</option></select></label>
<button>ساخت کاربر</button></form></section>

{% elif page == 'access' %}
<h1>فهرست IPهای محلی مجاز</h1>
<section class="panel"><p>ورود فقط از IP واقعی اتصال شبکه کنترل می‌شود؛ هدرهای X-Forwarded-For برای تعیین مجوز پذیرفته نیستند.
پورت پنل همچنان روی 127.0.0.1 است مگر اینکه جداگانه، پشت HTTPS و فایروال محدود، مستقر شود.</p>
<div class="tablewrap"><table><tr><th>Local network (CIDR)</th><th>Action</th></tr>
{% for net in networks %}<tr><td><code>{{net}}</code></td>
<td>{% if net not in ('127.0.0.1/32','::1/128') %}
<form method="post" action="{{url_for('settings.access_remove')}}">
<input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="cidr" value="{{net}}">
<button class="danger">حذف</button></form>{% else %}الزامی{% endif %}</td></tr>{% endfor %}
</table></div>
<form method="post" action="{{url_for('settings.access_add')}}">
<input type="hidden" name="csrf" value="{{csrf}}">
<label>IP یا شبکه خصوصی <input name="cidr" dir="ltr" placeholder="192.168.1.192/32" required></label>
<button>افزودن به فهرست مجاز</button></form>
<p class="note">پیش‌فرض شامل 127.0.0.1 و ::1 و 192.168.1.192 است. این مجوز به‌تنهایی دسترسی شبکه یا پورت عمومی ایجاد نمی‌کند.</p>
</section>

{% elif page == 'includes' %}
<h1>تنظیمات امنیتی و Includeهای اختصاصی</h1>
<section class="panel">
<form action="{{url_for('settings.includes')}}" method="get">
<label>دامنه <select name="domain">
{% for d in domains %}<option value="{{d}}" {{'selected' if d==domain else ''}}>{{d}}</option>{% endfor %}
</select></label><button>انتخاب دامنه</button></form>
</section>
{% if domain %}
<section class="panel"><h2>هدرهای امنیتی برای <code>{{domain}}</code></h2>
<p class="muted">تغییر این گزینه‌ها فقط هنگام ساخت پیش‌نویس بعدی وارد Config می‌شود. HSTS ممکن است روی همه درخواست‌های HTTPS اثر بگذارد.</p>
<form method="post" action="{{url_for('settings.security_save')}}">
<input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="domain" value="{{domain}}">
<label><span>HSTS (بدون includeSubDomains)</span><input type="checkbox" name="hsts" {{'checked' if security.hsts else ''}}></label>
<label><span>X-Content-Type-Options</span><input type="checkbox" name="nosniff" {{'checked' if security.nosniff else ''}}></label>
<label><span>X-Frame-Options: SAMEORIGIN</span><input type="checkbox" name="xframe" {{'checked' if security.xframe else ''}}></label>
<button>ذخیره تنظیمات امنیتی</button></form>
</section>
<section class="panel"><h2>Includeهای اختصاصی</h2>
<p>فایل‌های معرفی‌شده در فهرست، صرفاً نام فایل‌های مورد انتظار در پوشه
<code>/etc/nginx/conf.d/includes/</code> هستند. ثبت نام فایل، آن را روی سرور ایجاد نمی‌کند.</p>
{% for filename in catalog %}
<form method="post" action="{{url_for('settings.include_toggle')}}">
<input type="hidden" name="csrf" value="{{csrf}}">
<input type="hidden" name="domain" value="{{domain}}">
<input type="hidden" name="filename" value="{{filename}}">
<label><input type="checkbox" name="enabled" {{'checked' if filename in selected_includes else ''}}>
<code>{{filename}}</code></label><button class="secondary">ذخیره وضعیت</button></form>
{% endfor %}
</section>
{% endif %}
<section class="panel"><h2>افزودن Include به کاتالوگ</h2>
<form method="post" action="{{url_for('settings.include_register')}}">
<input type="hidden" name="csrf" value="{{csrf}}">
<label>نام فایل (فقط .conf) <input dir="ltr" name="filename" placeholder="cors-custom.conf" required></label>
<label>توضیح <input name="description" maxlength="250" value="{{editing.description if editing else ''}}"></label>
<button>ثبت نام Include برای بررسی</button></form>
<p class="note">فایل جدید صرفاً در کاتالوگ ثبت می‌شود. می‌توانی نسخه‌های متنی آن را در فرم زیر ذخیره و مقایسه کنی؛ انتشار روی سرور هنوز انجام نمی‌شود.</p></section>
<section class="panel"><h2>ویرایش نسخه‌های Include (فقط Staging)</h2>
<form method="get" action="{{url_for('settings.includes')}}">
<input type="hidden" name="domain" value="{{domain}}">
<label>Include <select name="include">
{% for filename in catalog %}<option value="{{filename}}" {{'selected' if filename == snippet_filename else ''}}>{{filename}}</option>{% endfor %}
</select></label>
<button class="secondary">انتخاب Include</button></form>
{% if snippet_filename %}
<p class="muted">فایل <code>{{snippet_filename}}</code> فقط در SQLite نسخه‌بندی می‌شود؛
تا زمانی که سرویس اجرایی محدود و تأییدشده نداشته باشیم، فایل‌های Nginx روی سرور تغییر نمی‌کنند.</p>
<form method="post" action="{{url_for('settings.include_version_save')}}">
<input type="hidden" name="csrf" value="{{csrf}}">
<input type="hidden" name="filename" value="{{snippet_filename}}">
<label style="width:100%">متن کانفیگ Include
<textarea dir="ltr" name="body" rows="12" style="width:100%;font:13px monospace" spellcheck="false" required>{{snippet_body}}</textarea></label>
<label>توضیح تغییر <input name="note" maxlength="500"></label>
<button>ذخیره نسخه جدید Include</button></form>
<h3>تاریخچه Include</h3><div class="tablewrap"><table><tr><th>Version</th><th>UTC</th><th>SHA256</th><th>Note</th></tr>
{% for v in snippet_history %}
<tr><td><a href="{{url_for('settings.includes',domain=domain,include=snippet_filename,version=v.id)}}">{{v.id}}</a></td>
<td>{{v.created_at}}</td><td>{{v.sha256[:12]}}</td><td>{{v.note}}</td></tr>
{% endfor %}</table></div>
{% if snippet_diff %}<h3>Diff نسخه انتخاب‌شده</h3><pre>{{snippet_diff}}</pre>{% endif %}
{% endif %}
</section>

{% elif page == 'streams' %}
<h1>مدیریت Streamهای TCP / UDP</h1>
<div class="alert">Stream به context اصلی Nginx، ماژول stream و Publish پورت Docker نیاز دارد.
فعلاً فقط تعریف و Preview می‌شود و هیچ پورتی باز نمی‌شود.</div>
<section class="panel"><h2>تعریف Stream جدید یا ویرایش Stream موجود</h2>
<p>برای ویرایش، از جدول پایین «ویرایش» را انتخاب کن.</p>
<form method="post" action="{{url_for('settings.stream_save')}}">
<input type="hidden" name="csrf" value="{{csrf}}">
<label>شناسه <input dir="ltr" name="name" placeholder="internal-redis" value="{{editing.name if editing else ''}}" required></label>
<label>پروتکل <select name="protocol"><option value="tcp" {{'selected' if editing and editing.protocol=='tcp' else ''}}>TCP</option><option value="udp" {{'selected' if editing and editing.protocol=='udp' else ''}}>UDP</option></select></label>
<label>Listen IP <input dir="ltr" name="listen_host" value="{{editing.listen_host if editing else '127.0.0.1'}}" required></label>
<label>Listen port <input dir="ltr" name="listen_port" type="number" min="1" max="65535" value="{{editing.listen_port if editing else ''}}" required></label>
<label>Backend <input dir="ltr" name="target" placeholder="192.168.1.20:6379" value="{{editing.target if editing else ''}}" required></label>
<label>توضیح <input name="description" maxlength="250"></label>
<button>ثبت در دیتابیس</button></form></section>
<section class="panel"><h2>سرویس‌های ثبت‌شده</h2>
<div class="tablewrap"><table><tr><th>Name</th><th>Protocol</th><th>Listen</th><th>Backend</th><th>Status</th><th>Preview</th></tr>
{% for st in streams %}
<tr><td>{{st.name}}</td><td>{{st.protocol}}</td><td>{{st.listen_host}}:{{st.listen_port}}</td>
<td>{{st.target}}</td><td>Staged, not deployed</td>
<td><a href="{{url_for('settings.streams',edit=st.name)}}">ویرایش</a>
<form method="post" action="{{url_for('settings.stream_show')}}">
<input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="name" value="{{st.name}}">
<button class="secondary">ساخت Preview</button></form>
<form method="post" action="{{url_for('settings.stream_remove')}}">
<input type="hidden" name="csrf" value="{{csrf}}">
<input type="hidden" name="name" value="{{st.name}}">
<label><input type="checkbox" name="confirm" value="yes" required> حذف تعریف آزمایشی</label>
<button class="danger">حذف</button></form>
</td></tr>
{% endfor %}
</table></div></section>
{% if stream_body %}<section class="panel"><h2>Preview آماده‌شده</h2><pre>{{stream_body}}</pre></section>{% endif %}
{% endif %}
</div></body></html>
"""


def _connect():
    # Standard bootstrapping is done in web.py; ensure feature schema exists.
    from .management_ui import db_path
    conn = open_db(db_path())
    ensure_features(conn)
    ensure_schema(conn)
    return conn


def _render(page, **kwargs):
    return render_template_string(PAGE, page=page, csrf=session["csrf"], **kwargs)


def _try(action, redirect_to):
    try:
        with _connect() as db:
            action(db)
        flash("درخواست در دیتابیس ذخیره شد؛ هیچ تغییری روی Nginx اعمال نشده است.", "ok")
    except (ValueError, sqlite3.IntegrityError, TypeError, KeyError) as exc:
        flash(str(exc), "error")
    return redirect(redirect_to)


@bp.get("/admin")
def dashboard():
    with _connect() as db:
        counts = {
            "domains": db.execute("SELECT count(*) FROM domains").fetchone()[0],
            "snapshots": db.execute(
                "SELECT count(*) FROM config_versions WHERE origin='live_snapshot'"
            ).fetchone()[0],
            "zones": len(recommended_zones(db)),
            "jobs": db.execute(
                "SELECT count(*) FROM operator_jobs WHERE status='pending'"
            ).fetchone()[0],
        }
    return _render("dashboard", counts=counts)


@bp.get("/admin/ssl")
def ssl():
    with _connect() as db:
        zones = recommended_zones(db)
    return _render("ssl", zones=zones)


@bp.post("/admin/ssl/request")
def ssl_request():
    def act(db):
        queue_certificate(db, request.form["zone"], request.form["kind"])
    return _try(act, url_for("settings.ssl"))


@bp.get("/admin/users")
def users():
    with _connect() as db:
        rows = db.execute(
            "SELECT id, username, role, active, created_at FROM panel_users ORDER BY id"
        ).fetchall()
    return _render("users", users=rows)


@bp.post("/admin/users/create")
def user_create():
    return _try(
        lambda db: user_upsert(db, session["uid"], request.form["username"],
                               request.form["password"], request.form["role"]),
        url_for("settings.users")
    )


@bp.post("/admin/users/update")
def user_change():
    return _try(
        lambda db: user_update(
            db, session["uid"], int(request.form["id"]), request.form["role"],
            request.form["active"] == "1", request.form.get("password", "")
        ),
        url_for("settings.users")
    )


@bp.get("/admin/access")
def access():
    with _connect() as db:
        networks = allowed_networks(db)
    return _render("access", networks=networks)


@bp.post("/admin/access/add")
def access_add():
    return _try(
        lambda db: add_allowed_net(db, request.form["cidr"], str(session["uid"])),
        url_for("settings.access")
    )


@bp.post("/admin/access/delete")
def access_remove():
    return _try(
        lambda db: remove_allowed_net(db, request.form["cidr"], str(session["uid"])),
        url_for("settings.access")
    )


@bp.get("/admin/includes")
def includes():
    with _connect() as db:
        domains = [r["name"] for r in db.execute("SELECT name FROM domains ORDER BY name")]
        domain = request.args.get("domain", domains[0] if domains else "")
        if domain and domain not in domains:
            domain = domains[0] if domains else ""
        catalog = [r["filename"] for r in db.execute("SELECT filename FROM include_catalog ORDER BY filename")]
        selected = [
            r["filename"] for r in
            db.execute("SELECT filename FROM domain_includes WHERE domain=?", (domain,))
        ]
        snippet_filename = request.args.get("include", "")
        if snippet_filename not in catalog:
            snippet_filename = catalog[0] if catalog else ""
        snippet_history = include_history(db, snippet_filename) if snippet_filename else []
        snippet_body = ""
        snippet_diff = ""
        if snippet_history:
            requested = request.args.get("version", type=int)
            version_id = requested or snippet_history[0]["id"]
            try:
                version, snippet_diff = include_version_diff(db, snippet_filename, version_id)
                snippet_body = version["body"]
            except ValueError:
                version, snippet_diff = include_version_diff(db, snippet_filename,
                                                              snippet_history[0]["id"])
                snippet_body = version["body"]
        row = db.execute(
            "SELECT * FROM security_options WHERE domain=?", (domain,)
        ).fetchone() if domain else None
        security = dict(row) if row else {"hsts": 0, "nosniff": 0, "xframe": 0}
    return _render("includes", domains=domains, domain=domain, catalog=catalog,
                   selected_includes=selected, security=security,
                   snippet_filename=snippet_filename, snippet_history=snippet_history,
                   snippet_body=snippet_body, snippet_diff=snippet_diff)


@bp.post("/admin/includes/save")
def include_version_save():
    filename = request.form.get("filename", "")
    return _try(
        lambda db: save_include_revision(db, filename, request.form["body"],
                                          request.form.get("note", "")),
        url_for("settings.includes", include=filename)
    )


@bp.post("/admin/includes/register")
def include_register():
    return _try(
        lambda db: register_include(db, request.form["filename"],
                                     request.form.get("description", "")),
        url_for("settings.includes")
    )


@bp.post("/admin/includes/toggle")
def include_toggle():
    domain = request.form.get("domain", "")
    return _try(
        lambda db: set_domain_include(db, domain, request.form["filename"],
                                       request.form.get("enabled") == "on"),
        url_for("settings.includes", domain=domain)
    )


@bp.post("/admin/security/save")
def security_save():
    domain = request.form.get("domain", "")
    return _try(
        lambda db: set_security_options(
            db, domain, request.form.get("hsts") == "on",
            request.form.get("nosniff") == "on", request.form.get("xframe") == "on"
        ),
        url_for("settings.includes", domain=domain)
    )


@bp.get("/admin/streams")
def streams():
    with _connect() as db:
        entries = db.execute("SELECT * FROM stream_services ORDER BY name").fetchall()
        wanted = request.args.get("edit")
        editing = next((item for item in entries if item["name"] == wanted), None)
    return _render("streams", streams=entries, stream_body=None, editing=editing)


@bp.post("/admin/streams/save")
def stream_save():
    return _try(
        lambda db: add_stream(
            db, request.form["name"], request.form["protocol"],
            request.form["listen_host"], int(request.form["listen_port"]),
            request.form["target"], request.form.get("description", "")
        ),
        url_for("settings.streams")
    )


@bp.post("/admin/streams/preview")
def stream_show():
    with _connect() as db:
        try:
            body = stream_preview(db, request.form["name"])
            flash("نسخه Preview ذخیره شد؛ هیچ پورت جدیدی باز نشده است.", "ok")
        except ValueError as exc:
            flash(str(exc), "error")
            body = None
        entries = db.execute("SELECT * FROM stream_services ORDER BY name").fetchall()
    return _render("streams", streams=entries, stream_body=body, editing=None)


@bp.post("/admin/streams/delete")
def stream_remove():
    def action(db):
        if request.form.get("confirm") != "yes":
            raise ValueError("حذف Stream را تأیید کن")
        delete_stream(db, request.form["name"])
    return _try(action, url_for("settings.streams"))
