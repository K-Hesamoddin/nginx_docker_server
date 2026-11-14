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

from .core import hostname, open_db, resolve_certificate
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
body{font:15px/1.8 system-ui;background:#f5f6f9;color:#172239;margin:0}
main{max-width:1280px;margin:20px auto;padding:0 18px}
header,section{background:white;border:1px solid #dae1e9;border-radius:12px;padding:18px;margin-bottom:16px}
h1{font-size:22px}h2{font-size:18px}a{color:#124a82}small{color:#667085}
table{width:100%;border-collapse:collapse;direction:ltr;text-align:left}
th,td{padding:8px;border-bottom:1px solid #e4e9ef}
textarea{width:100%;min-height:400px;box-sizing:border-box;direction:ltr;text-align:left;font:12px/1.45 monospace}
button,input,select{padding:9px;border-radius:6px;border:1px solid #b7c3d5}
button{background:#174d7e;color:white;cursor:pointer}
label{display:inline-block;margin:8px}
pre{direction:ltr;text-align:left;white-space:pre-wrap;overflow:auto;background:#f0f3f7;padding:12px;border-radius:8px}
.notice{background:#fff8eb;border:1px solid #ead7b1;padding:12px;border-radius:8px}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
</style></head><body><main>
<header><h1>Nginx Control Plane V2 — مدیریت نسخه‌ها</h1>
<div><a href="/">پنل دامنه‌ها و Routeها</a> | <a href="/manage">نسخه‌ها و درخواست‌ها</a></div>
<p class="notice">محیط آزمایشی: دکمه درخواست انتشار یا SSL فقط یک کار در صف ثبت می‌کند.
هنوز هیچ سرویس اجرایی مجاز به تغییر Nginx یا صدور واقعی گواهی از این پنل متصل نشده است.</p>
</header>
{% for category,message in get_flashed_messages(with_categories=true) %}
<section><strong>{{message}}</strong></section>
{% endfor %}
{% if mode == "index" %}
<section><h2>دامنه‌ها</h2>
<table><tr><th>Domain</th><th>Routes</th><th>Protected V1 flag</th><th>Draft version</th><th>V2 deployed</th><th>SSL inventory</th></tr>
{% for item in domains %}
<tr><td><a href="{{url_for('manager.detail', domain=item.name)}}">{{item.name}}</a></td>
<td>{{item.routes}}</td><td>{{item.flag if item.flag is not none else '—'}}</td>
<td>{{item.draft if item.draft else '—'}}</td>
<td>{{item.deployed if item.deployed else 'Not deployed by V2'}}</td>
<td>{{item.ssl}}</td></tr>
{% endfor %}</table></section>
<section><h2>صف عملیات</h2>
<table><tr><th>#</th><th>Time UTC</th><th>Action</th><th>Domain/Zone</th><th>Version</th><th>Status</th><th>Result</th></tr>
{% for job in jobs %}<tr><td>{{job.id}}</td><td>{{job.requested_at}}</td><td>{{job.kind}}</td><td>{{job.domain}}</td>
<td>{{job.version_id or '—'}}</td><td>{{job.status}}</td><td>{{job.result}}</td></tr>{% endfor %}</table>
</section>
{% else %}
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
<h2>Routeهای تعریف‌شده</h2>
<table><tr><th>Path</th><th>Upstream</th><th>Proxy URI</th><th>Strip prefix</th><th>WebSocket</th></tr>
{% for r in routes %}<tr><td>{{r.path}}</td><td>{{r.target}}</td><td>{{r.proxy_uri if r.proxy_uri is not none else 'default'}}</td><td>{{r.strip_prefix}}</td><td>{{r.websocket}}</td></tr>{% endfor %}</table>
<p>برای افزودن یا تغییر Route از <a href="/">فرم دامنه‌ها و Routeها</a> استفاده کن.
تغییر Routeها به‌تنهایی هیچ فایل کانفیگی نمی‌سازد.</p>
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
<section><h2>درخواست گواهی SSL</h2>
<form method="post" action="{{url_for('manager.certificate_request',domain=domain)}}">
<input type="hidden" name="csrf" value="{{csrf}}">
<label>دامنه یا Zone <input dir="ltr" name="zone" value="{{domain}}" required></label>
<label>نوع <select name="kind"><option value="dedicated">Dedicated (برای یک Host)</option>
<option value="wildcard">Wildcard (برای دامنه اصلی و *.zone)</option></select></label>
<button>ثبت درخواست SSL در صف</button>
</form>
<p><small>کلید NSIN و کلید خصوصی SSL در پنل وارد نمی‌شوند. درخواست فعلاً فقط در صف ثبت می‌شود؛
صدور واقعی بعداً توسط Worker جداگانه و DNS-01 انجام خواهد شد.</small></p>
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
            for r in rows
        ]
        jobs = conn.execute(
            "SELECT * FROM operator_jobs ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return render_template_string(PAGE, mode="index", domains=domains, jobs=jobs)


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
    def action(conn, d):
        _ = d
        jid = queue_certificate(conn, request.form["zone"], request.form["kind"])
        return f"درخواست گواهی در صف #{jid} ثبت شد؛ هنوز صادر نشده است."
    return _post_action(domain, action)
