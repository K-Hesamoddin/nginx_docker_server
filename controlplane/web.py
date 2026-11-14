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
from werkzeug.security import check_password_hash

from .core import (audit, hostname, inspect_certificate, open_db, save_certificate,
                   save_domain, save_route)

HTML = """
<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nginx Control Plane</title>
<style>
body{font:15px/1.8 system-ui;background:#f2f4f8;color:#172033;margin:0}
main{max-width:1180px;margin:30px auto;padding:0 18px}
header,.card{background:#fff;border:1px solid #dfe3ec;border-radius:14px;padding:18px;margin-bottom:15px}
header{display:flex;justify-content:space-between;align-items:center}
h1,h2{margin:0 0 10px} h1{font-size:23px} h2{font-size:18px}
small,.hint{color:#526079} table{width:100%;border-collapse:collapse;direction:ltr;text-align:left}
th,td{padding:7px;border-bottom:1px solid #e8eaf0;word-break:break-word}
input,select{padding:9px;border:1px solid #bfc8d7;border-radius:7px;max-width:100%}
button{background:#1c4375;color:white;border:0;border-radius:7px;padding:9px 15px;cursor:pointer}
.inline{display:flex;gap:9px;flex-wrap:wrap;align-items:end}
form{margin:12px 0}.error{color:#9f2020}.note{background:#f3f7ff;padding:9px;border-radius:6px}
code{direction:ltr;display:inline-block}
</style></head><body><main>
<header><div><h1>Nginx Control Plane V2</h1><small>داشبورد داخلی | تغییرات ابتدا در دیتابیس ثبت می‌شوند و خودکار Deploy نمی‌شوند</small>
{% if session.get('auth') %}<p><a href="/manage">مدیریت کانفیگ، نسخه‌ها، دیف‌ها و درخواست SSL</a></p>{% endif %}</div>
{% if session.get('auth') %}
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{csrf}}"><button>خروج</button></form>
{% endif %}</header>
{% for category,msg in get_flashed_messages(with_categories=true) %}
<div class="card {{'error' if category=='error' else 'note'}}">{{msg}}</div>
{% endfor %}
{% if not session.get('auth') %}
<section class="card"><h2>ورود مدیر</h2><form method="post" action="/login">
<input type="password" name="password" required autocomplete="current-password">
<button>ورود</button></form></section>
{% else %}
<section class="card"><h2>دامنه‌ها</h2><table><tr><th>Domain</th><th>Legacy flags</th><th>WWW Redirect</th><th>Body (MB)</th><th>Security</th></tr>
{% for d in domains %}<tr><td>{{d.name}}</td><td>{{(d.first_flag ~ (' ' ~ d.second_flag if d.flag_count == 2 else '')) if d.flag_count else '—'}}</td><td>{{'yes' if d.redirect_www else 'no'}}</td><td>{{d.body_limit_mb}}</td><td>{{d.security_profile}}</td></tr>{% endfor %}</table>
<form method="post" action="/domains" class="inline"><input type="hidden" name="csrf" value="{{csrf}}">
<label>دامنه <input name="name" placeholder="example.com" required></label>
<label>حداکثر آپلود MB <input type="number" name="limit" value="50" min="1" max="500"></label>
<label>امنیت <select name="security"><option value="legacy">legacy</option><option value="baseline">baseline</option></select></label>
<label><input type="checkbox" name="www" value="1"> ریدایرکت www</label><button>ثبت / ویرایش</button></form></section>
<section class="card"><h2>مسیرها و Upstreamها</h2>
<table><tr><th>Domain</th><th>Location</th><th>Target</th><th>Proxy URI override</th><th>Strip prefix</th><th>WebSocket</th><th></th></tr>
{% for r in routes %}<tr><td>{{r.domain}}</td><td>{{r.path}}</td><td>{{r.target}}</td>
<td>{{r.proxy_uri if r.proxy_uri is not none else '—'}}</td><td>{{r.strip_prefix}}</td><td>{{r.websocket}}</td><td><form method="post" action="/routes/delete">
<input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="id" value="{{r.id}}"><button>حذف</button></form></td></tr>{% endfor %}</table>
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
<section class="card"><h2>آخرین تغییرات</h2>
<table><tr><th>Time UTC</th><th>Action</th><th>Detail</th></tr>
{% for a in audits %}<tr><td>{{a.occurred_at}}</td><td>{{a.action}}</td><td>{{a.detail}}</td></tr>{% endfor %}</table>
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
                      MAX_CONTENT_LENGTH=256 * 1024)
    db_file = Path(os.environ.get("CONTROLPLANE_DB", "data/controlplane.sqlite3"))
    ssl_dir = Path(os.environ.get("SSL_DIR", "ssl"))

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
        # No external reverse-proxy trust. Run exclusively on loopback behind SSH tunnel.
        if request.method == "POST" and request.path != "/login":
            if not session.get("auth"):
                abort(401)
            if not hmac.compare_digest(str(session.get("csrf", "")), request.form.get("csrf", "")):
                abort(403)
        if request.path not in ("/", "/login") and not session.get("auth"):
            abort(401)

    @app.route("/login", methods=["POST"])
    def login():
        if check_password_hash(pwd_hash, request.form.get("password", "")):
            session.clear()
            session["auth"] = True
            session["csrf"] = secrets.token_urlsafe(32)
            return redirect(url_for("index"))
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
    app.register_blueprint(management_bp)
    return app
