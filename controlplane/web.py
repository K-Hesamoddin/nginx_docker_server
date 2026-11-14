"""Local-only authenticated domain and certificate inventory UI.

This UI stages changes in SQLite. It never runs Docker, certbot, acme.sh or
rewrites live Nginx files. Promotion is an explicit reviewed CLI operation.
"""
from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template_string, request, session, url_for
from .admin_features import (
    ROLE_ORDER, authenticate, ensure_features, get_session_user, is_allowed_peer,
)

from .core import (audit, hostname, inspect_certificate, open_db, save_certificate,
                   save_domain, save_route)

HTML = """
<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nginx Control Plane</title>
<style>
*{box-sizing:border-box}
body{font:15px/1.75 system-ui;background:#f4f6fb;color:#1b2943;margin:0}
main{max-width:1260px;margin:20px auto;padding:0 16px}
header,.card{background:#fff;border:1px solid #dde6ef;border-radius:14px;padding:18px;margin-bottom:14px;box-shadow:0 2px 9px rgba(20,38,66,.035)}
header{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;background:#142e4b;color:#fff}
header a{color:#d9efff}a{color:#1d5e99;text-decoration:none}a:hover{text-decoration:underline}
h1,h2{margin:0 0 10px}h1{font-size:23px}h2{font-size:17px}
small,.hint{color:#5d6d82}
header small{color:#c0d1e7}
table{width:100%;border-collapse:collapse;direction:ltr;text-align:left;font-size:13px}
th,td{padding:9px;border-bottom:1px solid #e8eaf0;word-break:break-word}
input,select{padding:9px;border:1px solid #bfc8d7;border-radius:8px;max-width:100%;background:#fff}
button{background:#1c4d7b;color:#fff;border:0;border-radius:8px;padding:9px 15px;cursor:pointer}
.inline{display:flex;gap:9px;flex-wrap:wrap;align-items:end}
form{margin:12px 0}
.error{color:#a12222}.note{background:#eef5fc;padding:9px;border-radius:8px}
code{direction:ltr;display:inline-block}
details summary{cursor:pointer;font-weight:650;padding:8px 0}
.tablewrap{overflow:auto}
.navlinks{display:flex;gap:13px;flex-wrap:wrap}
@media(max-width:720px){main{padding:0 8px}header,.card{padding:13px}}
</style></head><body><main>
<header><div><h1>Nginx Control Plane V2</h1><small>داشبورد داخلی | تغییرات ابتدا در دیتابیس ثبت می‌شوند و خودکار Deploy نمی‌شوند</small>
{% if session.get('auth') %}<nav class="navlinks">
<a href="/admin">نمای کلی</a><a href="/manage">دامنه‌ها و نسخه‌ها</a>
<a href="/admin/ssl">گواهی‌های Wildcard</a>
<a href="/admin/includes">امنیت و Includeها</a>
<a href="/admin/streams">Streamها</a>
{% if session.get('role')=='admin' %}<a href="/admin/users">کاربران</a><a href="/admin/access">IPهای مجاز</a>{% endif %}
</nav>{% endif %}</div>
{% if session.get('auth') %}
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{csrf}}"><button>خروج</button></form>
{% endif %}</header>
{% for category,msg in get_flashed_messages(with_categories=true) %}
<div class="card {{'error' if category=='error' else 'note'}}">{{msg}}</div>
{% endfor %}
{% if not session.get('auth') %}
<section class="card"><h2>ورود کاربران</h2><form method="post" action="/login">
<label>نام کاربری <input name="username" value="admin" autocomplete="username" required></label>
<label>گذرواژه <input type="password" name="password" required autocomplete="current-password"></label>
<button>ورود</button></form></section>
{% else %}
<section class="card"><h2>دامنه‌ها</h2><p><a href="/manage">برای مدیریت راحت هر دامنه و پیش‌نویس‌های آن اینجا کلیک کن</a>.</p><details><summary>نمایش جدول کامل دامنه‌ها</summary><div class="tablewrap"><table><tr><th>Domain</th><th>Legacy flags</th><th>WWW Redirect</th><th>Body (MB)</th><th>Security</th></tr>
{% for d in domains %}<tr><td>{{d.name}}</td><td>{{(d.first_flag ~ (' ' ~ d.second_flag if d.flag_count == 2 else '')) if d.flag_count else '—'}}</td><td>{{'yes' if d.redirect_www else 'no'}}</td><td>{{d.body_limit_mb}}</td><td>{{d.security_profile}}</td></tr>{% endfor %}</table></div></details>
<form method="post" action="/domains" class="inline"><input type="hidden" name="csrf" value="{{csrf}}">
<label>دامنه <input name="name" placeholder="example.com" required></label>
<label>حداکثر آپلود MB <input type="number" name="limit" value="50" min="1" max="500"></label>
<label>امنیت <select name="security"><option value="legacy">legacy</option><option value="baseline">baseline</option></select></label>
<label><input type="checkbox" name="www" value="1"> ریدایرکت www</label><button>ثبت / ویرایش</button></form></section>
<section class="card"><h2>مسیرها و Upstreamها</h2>
<p>برای کار روزمره از <a href="/manage">صفحه اختصاصی هر دامنه</a> استفاده کن.</p><details><summary>نمایش همه Routeهای قدیمی</summary><div class="tablewrap">
<table><tr><th>Domain</th><th>Location</th><th>Target</th><th>Proxy URI override</th><th>Strip prefix</th><th>WebSocket</th><th></th></tr>
{% for r in routes %}<tr><td>{{r.domain}}</td><td>{{r.path}}</td><td>{{r.target}}</td>
<td>{{r.proxy_uri if r.proxy_uri is not none else '—'}}</td><td>{{r.strip_prefix}}</td><td>{{r.websocket}}</td><td><form method="post" action="/routes/delete">
<input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="id" value="{{r.id}}"><button>حذف</button></form></td></tr>{% endfor %}</table></div></details>
<form method="post" action="/routes" class="inline"><input type="hidden" name="csrf" value="{{csrf}}">
<label>دامنه <select name="domain">{% for d in domains %}<option>{{d.name}}</option>{% endfor %}</select></label>
<label>Path <input name="path" value="/" required></label>
<label>Upstream <input name="target" placeholder="192.168.1.178:3000" required></label>
<label>Proxy URI اختیاری <input name="proxy_uri" placeholder="/health"></label>
<label><input type="checkbox" name="strip" checked> حذف prefix</label>
<label><input type="checkbox" name="ws"> WebSocket</label><button>ثبت مسیر</button></form></section>
<section class="card"><h2>گواهی‌ها</h2>
<p class="hint">گواهی اختصاصی معتبر اولویت دارد؛ اگر منقضی یا ناموجود باشد، Wildcard معتبرِ پوشش‌دهنده انتخاب می‌شود. بدون گواهی معتبر، تولید کانفیگ متوقف می‌شود.</p>
<table><tr><th>Zone</th><th>Kind</th><th>Stub</th><th>Status</th></tr>
{% for c in certs %}<tr><td>{{c.zone}}</td><td>{{c.kind}}</td><td>{{c.stub}}</td>
<td class="{{'error' if c.status!='valid' else ''}}">{{c.status}}</td></tr>{% endfor %}</table>
<form method="post" action="/certificates" class="inline"><input type="hidden" name="csrf" value="{{csrf}}">
<label>Zone <input name="zone" placeholder="example.com" required></label>
<label>نوع <select name="kind"><option value="dedicated">dedicated</option><option value="wildcard">wildcard</option></select></label>
<label>نام فایل بدون پسوند <input name="stub" placeholder="example.com" required></label>
<button>ثبت گواهی موجود</button></form>
<p class="hint">فایل‌های cert/key در پوشه SSL میزبان باید از قبل موجود باشند؛ کلید خصوصی در UI آپلود نمی‌شود.</p></section>
<section class="card"><h2>آخرین تغییرات</h2><details><summary>مشاهده لاگ‌ها</summary><div class="tablewrap">
<table><tr><th>Time UTC</th><th>Action</th><th>Detail</th></tr>
{% for a in audits %}<tr><td>{{a.occurred_at}}</td><td>{{a.action}}</td><td>{{a.detail}}</td></tr>{% endfor %}</table></div></details>
<p class="note">برای Preview و اعمال کنترل‌شده، از دستورهای CLI در مستندات استفاده کنید. هیچ دکمه Deploy عمومی فعال نشده است.</p>
</section>
{% endif %}
</main></body></html>
"""


def create_app():
    secret = os.environ.get("PANEL_SECRET_KEY")
    pwd_hash = os.environ.get("PANEL_PASSWORD_HASH")
    if not secret or len(secret) < 32 or not pwd_hash:
        raise RuntimeError("Configure PANEL_SECRET_KEY (>=32 chars) and PANEL_PASSWORD_HASH")
    app = Flask(__name__)
    app.secret_key = secret
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                      SESSION_COOKIE_SECURE=os.environ.get("PANEL_HTTPS_ONLY") == "1",
                      MAX_CONTENT_LENGTH=256 * 1024)
    db_file = Path(os.environ.get("CONTROLPLANE_DB", "data/controlplane.sqlite3"))
    ssl_dir = Path(os.environ.get("SSL_DIR", "ssl"))
    with open_db(db_file) as conn:
        ensure_features(conn, bootstrap_hash=pwd_hash)

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        return response

    @app.before_request
    def protect():
        # Direct socket IP only. Never accept client-supplied forwarding headers
        # to authorize LAN access. Default listener remains localhost.
        with open_db(db_file) as conn:
            if not is_allowed_peer(conn, request.remote_addr or ""):
                abort(403)
            user = get_session_user(conn, session)
        if app.config["SESSION_COOKIE_SECURE"] and not request.is_secure:
            # Credentials never traverse HTTP in the LAN-enabled mode.
            abort(403)
        if request.path == "/" and request.method == "GET":
            # A revoked user must not see the legacy inventory even if an
            # earlier signed session still carries auth=True.
            if user is None and session.get("auth"):
                session.clear()
            elif user is not None:
                session["role"] = user["role"]
            return
        if request.path == "/login" and request.method in ("GET", "POST"):
            return
        if user is None:
            session.clear()
            # A changed or stale session is normal after upgrading from the
            # old single-password panel. Browser navigation must reach login.
            if request.method in ("GET", "HEAD"):
                return redirect(url_for("index"))
            abort(401)
        session["role"] = user["role"]
        if request.method == "POST":
            if not hmac.compare_digest(str(session.get("csrf", "")),
                                       request.form.get("csrf", "")):
                abort(403)
            if request.path != "/logout" and ROLE_ORDER[user["role"]] < ROLE_ORDER["editor"]:
                abort(403)
        # Manage users and access networks only as a real DB admin.
        if request.path.startswith(("/admin/users", "/admin/access")) and user["role"] != "admin":
            abort(403)
        # Issuance and deployment approvals require administrator privileges.
        if request.method == "POST" and (
            request.path == "/admin/ssl/request" or
            (request.path.startswith("/manage/") and
             request.path.endswith(("/request-deploy", "/request-ssl")))
        ) and user["role"] != "admin":
            abort(403)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return redirect(url_for("index"))
        with open_db(db_file) as conn:
            user = authenticate(conn, request.form.get("username", "admin"),
                                request.form.get("password", ""))
        if user is not None:
            session.clear()
            session["auth"] = True
            session["uid"] = user["id"]
            session["epoch"] = user["auth_epoch"]
            session["role"] = user["role"]
            session["csrf"] = secrets.token_urlsafe(32)
            return redirect(url_for("settings.dashboard"))
        flash("نام کاربری یا رمز عبور نامعتبر است", "error")
        return redirect(url_for("index"))

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.get("/")
    def index():
        if not session.get("auth"):
            return render_template_string(HTML, csrf="")
        with open_db(db_file) as db:
            domains = db.execute("""SELECT d.*, f.flag_count, f.first_flag, f.second_flag FROM domains d LEFT JOIN legacy_flags f ON f.domain=d.name ORDER BY d.name""").fetchall()
            routes = db.execute("SELECT * FROM routes ORDER BY domain,LENGTH(path) DESC,path").fetchall()
            certs = []
            for c in db.execute("SELECT * FROM certificates ORDER BY zone,kind"):
                try:
                    meta = inspect_certificate(ssl_dir, c["stub"])
                    status = "valid until " + meta.expires.date().isoformat()
                except Exception as exc:
                    status = f"invalid / missing ({type(exc).__name__})"
                certs.append(dict(c) | {"status": status})
            audits = db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 30").fetchall()
        return render_template_string(HTML, csrf=session["csrf"], domains=domains, routes=routes,
                                      certs=certs, audits=audits)

    @app.post("/domains")
    def domains():
        try:
            with open_db(db_file) as db:
                save_domain(db, request.form["name"], request.form.get("www") == "1",
                            int(request.form.get("limit", "50")), request.form.get("security", "legacy"))
            flash("دامنه ذخیره شد", "ok")
        except (ValueError, KeyError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("index"))

    @app.post("/routes")
    def routes():
        try:
            with open_db(db_file) as db:
                save_route(db, request.form["domain"], request.form["path"], request.form["target"],
                           request.form.get("strip") == "on", request.form.get("ws") == "on",
                           request.form.get("proxy_uri") or None)
            flash("مسیر ذخیره شد", "ok")
        except (ValueError, KeyError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("index"))

    @app.post("/routes/delete")
    def delete_route():
        with open_db(db_file) as db:
            route_id = int(request.form["id"])
            db.execute("DELETE FROM routes WHERE id=?", (route_id,))
            audit(db, "route-delete", str(route_id))
            db.commit()
        return redirect(url_for("index"))

    @app.post("/certificates")
    def certificates():
        try:
            with open_db(db_file) as db:
                save_certificate(db, request.form["zone"], request.form["kind"], request.form["stub"])
            flash("گواهی ثبت شد؛ اعتبار فایل در جدول مشخص است", "ok")
        except (ValueError, KeyError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("index"))

    from .management_ui import bp as management_bp
    from .admin_ui import bp as settings_bp
    app.register_blueprint(management_bp)
    app.register_blueprint(settings_bp)
    return app
