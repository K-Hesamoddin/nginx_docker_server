"""Staging-only authenticated interface for explicit config revisions and job requests.

The Flask worker has NO Docker, ACME or privilege capabilities.
All POSTs are protected by the host application's session/CSRF middleware.
"""
from __future__ import annotations

import os
from pathlib import Path

from flask import (
    Blueprint, flash, redirect, render_template_string,
    request, session, url_for,
)

from .core import audit, hostname, open_db, resolve_certificate, save_route
from .management import (
    config_history, ensure_schema, generate_revision, load_version,
    queue_certificate, queue_deployment, revision_diff, store_version,
)

bp = Blueprint("manager", __name__)

PAGE = """
<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nginx V2 | نسخه‌ها و عملیات</title>
<style>
*{box-sizing:border-box}
body{font:15px/1.8 system-ui;background:#f4f6fb;color:#182640;margin:0}
main{max-width:1380px;margin:20px auto;padding:0 16px}
header,section{background:white;border:1px solid #dce5ef;border-radius:14px;padding:20px;margin-bottom:15px;box-shadow:0 2px 9px rgba(20,38,66,.035)}
header{background:#142e4b;color:#fff}header a{color:#cce8ff}
h1{font-size:23px;margin:0 0 8px}h2{font-size:18px;margin:0 0 9px}
a{color:#16558e;text-decoration:none}a:hover{text-decoration:underline}
small{color:#64758b}
table{width:100%;border-collapse:collapse;direction:ltr;text-align:left;font-size:13px}
th,td{padding:9px;border-bottom:1px solid #e4e9f0;vertical-align:top}
.tablewrap{overflow:auto}
textarea{width:100%;min-height:360px;box-sizing:border-box;direction:ltr;text-align:left;font:13px/1.5 monospace}
button,input,select{padding:9px;border-radius:8px;border:1px solid #b7c3d5;background:#fff;max-width:100%}
button{background:#174d7e;color:white;border:0;cursor:pointer}
label{display:inline-flex;gap:8px;align-items:center;margin:8px;flex-wrap:wrap}
pre{direction:ltr;text-align:left;white-space:pre-wrap;overflow:auto;word-break:break-word;background:#eef4f9;padding:12px;border-radius:8px}
.notice{background:#fff8eb;color:#674d20;padding:11px;border-radius:8px;border:1px solid #ead7b1}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(255px,1fr));gap:13px}
.tile{background:#f7fafe;border:1px solid #dce7f2;border-radius:12px;padding:15px}
.tile strong{font-size:16px;direction:ltr;display:block}
.meta{color:#5d6b81;font-size:12px}
.search{display:flex;gap:10px;align-items:center}
.search input{min-width:240px;flex:1}
nav{display:flex;gap:15px;flex-wrap:wrap;margin-bottom:10px}
@media(max-width:720px){main{padding:8px}header,section{padding:13px}.search{flex-wrap:wrap}}
</style></head><body><main>
<header><h1>Nginx Control Plane V2 — مدیریت نسخه‌ها</h1>
<nav><a href="/admin">نمای کلی</a><a href="/manage">دامنه‌ها</a>
<a href="/admin/ssl">SSL یکپارچه</a><a href="/admin/includes">امنیت و Include</a>
<a href="/admin/streams">Stream</a>{% if session.get('role')=='admin' %}
<a href="/admin/users">کاربران</a><a href="/admin/access">IPهای مجاز</a>{% endif %}
<a href="/">پنل اولیه</a><a href="/help">راهنما و تورها</a></nav>
<p class="notice">محیط آزمایشی: دکمه درخواست انتشار یا SSL فقط یک کار در صف ثبت می‌کند.
هنوز هیچ سرویس اجرایی مجاز به تغییر Nginx یا صدور واقعی گواهی از این پنل متصل نشده است.</p>
</header>
{% for category,message in get_flashed_messages(with_categories=true) %}
<section><strong>{{message}}</strong></section>
{% endfor %}
{% if mode == "index" %}
<section>
<strong>راهنمای این صفحه:</strong>
<a href="/help/domains">دامنه‌ها</a> |
<a href="/help/routes">Route و Proxy</a> |
<a href="/help/versions">تاریخچه و Diff</a> |
<a href="/help/jobs">صف عملیات</a> |
<a href="/help/domains/tour?step=1">شروع تور دامنه‌ها</a>
</section>
<section><h2>دامنه‌ها و نسخه‌های کانفیگ</h2>
<form method="get" action="/manage" class="search">
<input type="search" name="q" value="{{q}}" placeholder="جست‌وجوی دامنه؛ مثل cloud یا micromodern">
<button>جست‌وجو</button>
{% if q %}<a href="/manage">نمایش همه</a>{% endif %}
</form>
<p class="meta">{{domains|length}} دامنه نمایش داده شده. فلگ‌های قدیمی فقط داده تاریخی‌اند؛
تغییر Routeها بدون زدن دکمه ساخت نسخه، کانفیگ را بازنویسی نمی‌کند.</p>
<div class="cards">
{% for item in domains %}
<div class="tile"><strong><a href="{{url_for('manager.detail', domain=item.name)}}">{{item.name}}</a></strong>
<div class="meta">{{item.routes}} Route · V1 flag: {{item.flag if item.flag is not none else '—'}}</div>
<div class="meta">Draft: {{item.draft if item.draft else 'ندارد'}} ·
V2 deployed: {{item.deployed if item.deployed else 'خیر'}}</div>
<div class="meta">SSL: {{item.ssl}}</div>
<a href="{{url_for('manager.detail',domain=item.name)}}">مدیریت این دامنه</a>
</div>{% endfor %}
</div></section>
<section><h2>صف عملیات</h2>
<table><tr><th>#</th><th>Time UTC</th><th>Action</th><th>Domain/Zone</th><th>Version</th><th>Status</th><th>Result</th></tr>
{% for job in jobs %}<tr><td>{{job.id}}</td><td>{{job.requested_at}}</td><td>{{job.kind}}</td><td>{{job.domain}}</td>
<td>{{job.version_id or '—'}}</td><td>{{job.status}}</td><td>{{job.result}}</td></tr>{% endfor %}</table>
</section>
{% else %}
<section>
<strong>راهنمای کاربردی این دامنه:</strong>
<a href="/help/routes">ویرایش Route</a> |
<a href="/help/versions">تولید، ویرایش، Diff و Rollback</a> |
<a href="/help/ssl">SSL</a> |
<a href="/help/routes/tour?step=1">تور Routeها</a> |
<a href="/help/versions/tour?step=1">تور تاریخچه</a>
</section>
<section><h2>{{domain}}</h2>
<p>SSL در دیتابیس V2: <strong>{{ssl}}</strong>. این وضعیت جای بررسی TLS زنده و ثبت گواهی‌های قدیمی را نمی‌گیرد.</p>
<p><a href="{{url_for('manager.detail',domain=domain,tls=1)}}">بررسی گواهی TLS واقعی از طریق 127.0.0.1:443 با SNI</a></p>
{% if tls_result %}<p><strong>Origin TLS:</strong> {{tls_result.status}} |
Expiry: {{tls_result.expires or 'unknown'}} |
SNI match: {{tls_result.matches_hostname}} |
Issuer: {{tls_result.issuer or 'unknown'}} |
Reason: {{tls_result.reason}}</p>
<p><small>این تست فقط Nginx محلی را بررسی می‌کند، نه اتصال عمومی یا لبه CDN.</small></p>{% endif %}
<p>نسخه پیش‌نویس: {{head.draft_version_id if head else 'ندارد'}} |
منتشرشده توسط V2: {{head.deployed_version_id if head and head.deployed_version_id else 'هیچ نسخه‌ای'}}.</p>
<p><a href="{{url_for('manager.preflight',domain=domain,version=selected.id if selected else None)}}">
<strong>بررسی آمادگی مهاجرت این دامنه (Preflight فقط‌خواندنی)</strong>
</a> — اختلاف‌ها، گواهی‌ها و موانع قبل از جایگزینی سیستم قدیمی</p>
<h2>Routeهای تعریف‌شده</h2>
<p>ویرایش یا حذف Route فقط در دیتابیس ثبت می‌شود؛ پیش‌نویس و کانفیگ زنده تا فشردن «ساخت نسخه جدید» تغییر نمی‌کند.</p>
{% for r in routes %}
<form method="post" action="{{url_for('manager.route_upsert',domain=domain)}}" class="row">
<input type="hidden" name="csrf" value="{{csrf}}">
<label>Location <input dir="ltr" name="path" value="{{r.path}}" readonly required></label>
<label>Upstream <input dir="ltr" name="target" value="{{r.target}}" required></label>
<label>Proxy URI <input dir="ltr" name="proxy_uri" value="{{r.proxy_uri if r.proxy_uri is not none else ''}}" placeholder="Use strip-prefix setting"></label>
<label><input type="checkbox" name="strip" {% if r.strip_prefix %}checked{% endif %}>Strip prefix</label>
<label><input type="checkbox" name="ws" {% if r.websocket %}checked{% endif %}>WebSocket</label>
<button>ذخیره Route</button>
</form>
<form method="post" action="{{url_for('manager.route_delete',domain=domain)}}">
<input type="hidden" name="csrf" value="{{csrf}}">
<input type="hidden" name="id" value="{{r.id}}">
<label><input type="checkbox" name="confirm" value="yes" required> حذف {{r.path}} را تأیید می‌کنم</label>
<button>حذف مسیر</button>
</form>
{% endfor %}
<h2>Route جدید</h2>
<form method="post" action="{{url_for('manager.route_upsert',domain=domain)}}" class="row">
<input type="hidden" name="csrf" value="{{csrf}}">
<label>Location <input dir="ltr" name="path" value="/" required></label>
<label>Backend <input dir="ltr" name="target" placeholder="192.168.1.178:3000" required></label>
<label>Proxy URI <input dir="ltr" name="proxy_uri" placeholder="e.g. /health; empty = default"></label>
<label><input type="checkbox" name="strip" checked>Strip prefix</label>
<label><input type="checkbox" name="ws">WebSocket</label>
<button>افزودن Route</button>
</form>
<form method="post" action="{{url_for('manager.generate',domain=domain)}}">
<input type="hidden" name="csrf" value="{{csrf}}">
<button>۱. ساخت نسخه جدید از Routeها</button>
</form>
<p><small>اگر SSL هنوز ثبت نشده باشد، تولیدکننده در پیش‌نویس PENDING-SSL می‌گذارد. چنین نسخه‌ای قابل انتشار نیست.</small></p>
</section>
<section><h2>ویرایش دستی کانفیگ</h2>
<p>نسخه انتخاب‌شده: {{selected.id if selected else '—'}} | نوع: {{selected.origin if selected else '—'}}
{% if selected %}| SHA256: <code>{{selected.sha256[:16]}}</code>{% endif %}</p>
<form method="post" action="{{url_for('manager.save',domain=domain)}}">
<input type="hidden" name="csrf" value="{{csrf}}">
<input type="hidden" name="if_match" value="{{head.draft_version_id if head and head.draft_version_id else 0}}">
<textarea name="body" spellcheck="false" maxlength="131072" required>{{selected.body if selected else ''}}</textarea>
<label>توضیح تغییر <input name="note" maxlength="500" placeholder="علت تغییر"></label>
<button>۲. ذخیره به‌عنوان نسخه جدید</button></form>
{% if selected and selected.origin != "live_snapshot" %}
<form method="post" action="{{url_for('manager.deploy_request',domain=domain)}}">
<input type="hidden" name="csrf" value="{{csrf}}">
<input type="hidden" name="version" value="{{selected.id}}">
<label><input type="checkbox" name="confirm" value="yes" required> نسخه {{selected.id}} را برای بررسی و انتشار انتخاب می‌کنم</label>
<button>۳. ثبت درخواست انتشار / بازگردانی این نسخه</button>
</form>
{% endif %}
</section>
<section><h2>تاریخچه نسخه‌ها</h2>
<table><tr><th>#</th><th>UTC</th><th>Source</th><th>Hash</th><th>Note</th><th></th></tr>
{% for r in versions %}<tr><td>{{r.id}}</td><td>{{r.created_at}}</td><td>{{r.origin}}</td>
<td>{{r.sha256[:12]}}</td><td>{{r.note}}</td>
<td><a href="{{url_for('manager.detail',domain=domain,version=r.id)}}">مشاهده / مقایسه</a></td></tr>{% endfor %}</table>
<h2>تفاوت نسخه انتخاب‌شده با نسخه قبلی</h2>
<pre>{{diff if diff else 'تغییری برای نمایش وجود ندارد'}}</pre>
<p><small>نسخه live_snapshot صرفاً بایگانی کانفیگ عملیاتی زمان برداشت است؛ به معنی Deploy شدن توسط V2 نیست.</small></p>
</section>
<section><h2>گواهی مشترک SSL برای Zone</h2>
<p>گواهی جدید برای هر Subdomain جدا صادر نمی‌کنیم؛ همه نام‌های یک‌سطحی از یک
Wildcard مشترک همان Zone استفاده خواهند کرد (شامل Apex و *.zone).</p>
<p><a href="/admin/ssl"><strong>رفتن به SSL یکپارچه: انتخاب Zone و DNS Provider و ثبت یک درخواست Wildcard</strong></a></p>
<p><small>از این صفحه درخواست اختصاصی صادر نمی‌شود. گواهی‌های قدیمی هنگام مهاجرت حفظ می‌شوند.
صدور واقعی DNS-01 هنوز به پنل متصل نیست؛ هیچ DNS یا Nginx تغییر نمی‌کند.</small></p>
</section>
{% endif %}
</main></body></html>
"""


def db_path() -> Path:
    return Path(os.environ.get("CONTROLPLANE_DB", "data/controlplane.sqlite3"))


def ssl_path() -> Path:
    return Path(os.environ.get("SSL_DIR", "ssl"))


def cert_status(conn, domain: str) -> str:
    """V2 registered cert status ONLY, never claim live server TLS is healthy."""
    try:
        info = resolve_certificate(conn, ssl_path(), domain, min_days=0)
        source = conn.execute(
            "SELECT kind FROM certificates WHERE stub=?", (info.stub,)
        ).fetchone()
        return f"{source['kind'] if source else 'registered'} / {info.expires.date()} / {info.stub}"
    except Exception:
        return "Not enrolled / unverifiable in V2"


@bp.get("/manage")
def index():
    q = (request.args.get("q") or "").strip().lower()[:100]
    with open_db(db_path()) as conn:
        ensure_schema(conn)
        rows = conn.execute(
            """SELECT d.name, f.first_flag, h.draft_version_id, h.deployed_version_id,
                      (SELECT count(*) FROM routes WHERE domain=d.name) AS routes
               FROM domains d LEFT JOIN config_heads h ON h.domain=d.name
               LEFT JOIN legacy_flags f ON f.domain=d.name
               ORDER BY d.name"""
        ).fetchall()
        domains = [
            dict(name=r["name"], flag=r["first_flag"], draft=r["draft_version_id"],
                 deployed=r["deployed_version_id"], routes=r["routes"],
                 ssl=cert_status(conn, r["name"]))
            for r in rows if not q or q in r["name"]
        ]
        jobs = conn.execute(
            "SELECT * FROM operator_jobs ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return render_template_string(PAGE, mode="index", domains=domains, jobs=jobs, q=q)


@bp.get("/manage/<domain>/preflight")
def preflight(domain):
    """Read-only lab review. Does not execute Docker/nginx/ACME."""
    from .preflight import review_revision
    domain = hostname(domain)
    requested = request.args.get("version", type=int)
    try:
        with open_db(db_path()) as conn:
            ensure_schema(conn)
            report = review_revision(conn, ssl_path(), domain, requested)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("manager.detail", domain=domain))
    return render_template_string("""
<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>پیش‌بررسی مهاجرت {{report.domain}}</title>
<style>
body{font:15px/1.9 system-ui,sans-serif;color:#1d2b45;background:#f4f6fb;margin:0}
main{max-width:1000px;margin:22px auto;padding:12px}
section{background:white;border:1px solid #dce4ee;border-radius:13px;padding:20px;margin-bottom:14px}
h1{font-size:23px}h2{font-size:18px}
a{color:#135b91}ul{padding-right:25px}
li{padding:5px 0}.warn{background:#fff7e7;border-right:4px solid #dbb05c}
.bad{background:#fff0f0;border-right:4px solid #ca4545}
.ok{background:#e9f7ee;border-right:4px solid #49a16a}
code{direction:ltr;unicode-bidi:isolate}
</style></head><body><main>
<section><a href="/manage/{{report.domain}}">بازگشت به دامنه</a> | <a href="/manage">فهرست دامنه‌ها</a> |
<a href="/help/versions">راهنمای نسخه‌ها</a>
<h1>بررسی آمادگی مهاجرت — <code>{{report.domain}}</code></h1>
<p>Revision: <code>{{report.revision_id or 'بدون Draft'}}</code></p>
<p><strong>این گزارش فقط از دیتابیس آزمایشی استفاده می‌کند.</strong> حتی اگر مانعی پیدا نشود، تا زمانی که
نسخه زنده مجدداً گرفته نشود، nginx -t و تست واقعی انجام نشده و مالکیت دامنه تأیید نشده باشد،
اجازه Deploy نیست. هیچ تغییری روی کانفیگ، گواهی یا Nginx ایجاد نمی‌شود.</p>
</section>
<section class="bad"><h2>موانع / نیازمند اصلاح یا تأیید انسانی ({{report.blockers|length}})</h2>
{% if report.blockers %}<ul>{% for x in report.blockers %}<li>{{x}}</li>{% endfor %}</ul>
{% else %}<p>در این بررسی اولیه مانع مشخصی مشاهده نشد؛ این به معنی آماده بودن انتشار نیست.</p>{% endif %}
</section>
<section class="warn"><h2>هشدارها ({{report.warnings|length}})</h2>
<ul>{% for x in report.warnings %}<li>{{x}}</li>{% endfor %}</ul></section>
<section class="ok"><h2>بررسی‌های گذرانده‌شده ({{report.checks|length}})</h2>
<ul>{% for x in report.checks %}<li>{{x}}</li>{% endfor %}</ul></section>
<section><h2>قدم اجرایی بعد از رفع موانع</h2>
<p>برای استقرار واقعی هنوز یک ابزار اجرایی کوچک با حداقل دسترسی لازم است:
نسخه ثابت و تأییدشده را روی فایل همان دامنه تست کند، از قبلی بکاپ بگیرد،
با <code>nginx -t</code> صحت نحوی را بررسی کند، Reload کند و امکان بازگشت داشته باشد.
این ابزار در این نسخه به پنل متصل نشده است.</p>
</section>
</main></body></html>
""", report=report)


@bp.get("/manage/<domain>")
def detail(domain):
    domain = hostname(domain)
    with open_db(db_path()) as conn:
        ensure_schema(conn)
        if conn.execute("SELECT 1 FROM domains WHERE name=?", (domain,)).fetchone() is None:
            flash("این دامنه در دیتابیس وجود ندارد", "error")
            return redirect(url_for("manager.index"))
        head = conn.execute("SELECT * FROM config_heads WHERE domain=?", (domain,)).fetchone()
        versions = config_history(conn, domain)
        selected_id = request.args.get("version", type=int)
        if not selected_id and head and head["draft_version_id"]:
            selected_id = head["draft_version_id"]
        if not selected_id and versions:
            selected_id = versions[0]["id"]
        selected = load_version(conn, domain, selected_id) if selected_id else None
        diff = revision_diff(conn, domain, selected_id) if selected_id else ""
        routes = conn.execute(
            "SELECT * FROM routes WHERE domain=? ORDER BY id", (domain,)
        ).fetchall()
        ssl = cert_status(conn, domain)
    tls_result = None
    if request.args.get("tls") == "1":
        from .tls_probe import probe_local_tls
        tls_result = probe_local_tls(domain)
    return render_template_string(
        PAGE, mode="detail", domain=domain, csrf=session["csrf"],
        selected=selected, versions=versions, head=head, routes=routes,
        ssl=ssl, diff=diff, tls_result=tls_result,
    )


def _post_action(domain, action):
    domain = hostname(domain)
    try:
        with open_db(db_path()) as conn:
            ensure_schema(conn)
            message = action(conn, domain)
        flash(message, "ok")
    except (ValueError, KeyError, TypeError) as exc:
        flash(str(exc), "error")
    return redirect(url_for("manager.detail", domain=domain))


@bp.post("/manage/<domain>/routes")
def route_upsert(domain):
    def action(conn, d):
        save_route(conn, d, request.form["path"], request.form["target"],
                   strip_prefix=request.form.get("strip") == "on",
                   websocket=request.form.get("ws") == "on",
                   proxy_uri=request.form.get("proxy_uri") or None)
        return "Route در دیتابیس ذخیره شد؛ پیش‌نویس قبلی و Nginx دست‌نخورده‌اند."
    return _post_action(domain, action)


@bp.post("/manage/<domain>/routes/delete")
def route_delete(domain):
    def action(conn, d):
        if request.form.get("confirm") != "yes":
            raise ValueError("حذف Route باید تأیید شود")
        route_id = int(request.form["id"])
        count = conn.execute(
            "SELECT count(*) FROM routes WHERE domain=?", (d,)
        ).fetchone()[0]
        if count < 2:
            raise ValueError("آخرین Route دامنه را نمی‌توان حذف کرد")
        with conn:
            deleted = conn.execute(
                "DELETE FROM routes WHERE id=? AND domain=?", (route_id, d)
            ).rowcount
            if not deleted:
                raise ValueError("Route مربوط به این دامنه پیدا نشد")
            audit(conn, "route-delete", f"{d} id:{route_id}")
        return "Route حذف شد؛ نسخه‌های ذخیره‌شده و Nginx تغییری نکرده‌اند."
    return _post_action(domain, action)


@bp.post("/manage/<domain>/generate")
def generate(domain):
    def action(conn, d):
        rid = generate_revision(conn, ssl_path(), d)
        return f"پیش‌نویس #{rid} تولید و در تاریخچه ذخیره شد؛ هنوز اعمال نشده است."
    return _post_action(domain, action)


@bp.post("/manage/<domain>/save")
def save(domain):
    def action(conn, d):
        head = conn.execute(
            "SELECT draft_version_id FROM config_heads WHERE domain=?", (d,)
        ).fetchone()
        actual = head["draft_version_id"] if head and head["draft_version_id"] else 0
        expected = int(request.form.get("if_match", "-1"))
        if expected != actual:
            raise ValueError("نسخه پیش‌نویس در تب دیگری تغییر کرده است؛ صفحه را بازخوانی کن.")
        rid = store_version(conn, d, request.form["body"], "manual",
                            request.form.get("note", ""))
        return f"ویرایش دستی در نسخه تغییرناپذیر #{rid} ذخیره شد."
    return _post_action(domain, action)


@bp.post("/manage/<domain>/request-deploy")
def deploy_request(domain):
    def action(conn, d):
        if request.form.get("confirm") != "yes":
            raise ValueError("انتخاب نسخه را تأیید کن")
        jid = queue_deployment(conn, d, int(request.form["version"]))
        return f"درخواست انتشار در صف #{jid} ثبت شد؛ هنوز به Nginx اعمال نشده است."
    return _post_action(domain, action)


@bp.post("/manage/<domain>/request-ssl")
def certificate_request(domain):
    """Legacy endpoint remains guarded but only accepts approved zone wildcard."""
    def action(conn, d):
        from .admin_features import recommended_zones
        zone = hostname(request.form["zone"])
        if request.form.get("kind") != "wildcard":
            raise ValueError("V2 فقط گواهی مشترک Wildcard قبول می‌کند.")
        if not any(zone == item["zone"] and
                   (d == zone or d.endswith("." + zone))
                   for item in recommended_zones(conn)):
            raise ValueError("برای انتخاب Zone صحیح وارد /admin/ssl شو.")
        jid = queue_certificate(conn, zone, "wildcard")
        return f"درخواست مشترک Zone در صف #{jid} ثبت شد؛ هنوز صادر نشده است."
    return _post_action(domain, action)
