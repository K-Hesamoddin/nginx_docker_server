"""Read-only migration preflight for one immutable Nginx V2 revision.

This is an INVENTORY review, not authorization to deploy. It does not access
Docker, the active Nginx tree, network services, DNS or ACME, or modify files.
A true deploy requires a separate, explicitly approved privileged operation.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
from pathlib import Path

from .audit import _parsed_locations
from .core import hostname, inspect_certificate
from .management import load_version

CERT_LINE = re.compile(r"(?m)^\s*ssl_certificate\s+([^;]+)\s*;")
KEY_LINE = re.compile(r"(?m)^\s*ssl_certificate_key\s+([^;]+)\s*;")
SSL_FILE = re.compile(r"^/etc/nginx/ssl/([a-zA-Z0-9][a-zA-Z0-9_.-]{0,127})\.(crt|key)$")
SERVER_NAME = re.compile(r"(?m)^\s*server_name\s+([^;]+)\s*;")
INCLUDE_LINE = re.compile(r"(?m)^\s*include\s+([^;]+)\s*;")
V2_MARKER = "# Managed by nginx-control-plane-v2: "


def review_revision(conn: sqlite3.Connection, ssl_dir: Path, domain: str,
                    revision_id: int | None = None) -> dict:
    """Explain exactly what is missing before *considering* a migration.

    All checks use archived lab data, never the active Nginx or origin TLS.
    An empty blocker list does NOT mean the config has passed nginx -t.
    """
    domain = hostname(domain)
    result = {
        "domain": domain, "revision_id": revision_id,
        "blockers": [], "warnings": [], "checks": [],
        "scope": "Lab-only read-only review. No live nginx -T, nginx -t, deployment or DNS checks.",
    }

    def block(message):
        result["blockers"].append(message)

    def warn(message):
        result["warnings"].append(message)

    def checked(message):
        result["checks"].append(message)

    if revision_id is None:
        head = conn.execute(
            "SELECT draft_version_id FROM config_heads WHERE domain=?", (domain,)
        ).fetchone()
        if not head or not head["draft_version_id"]:
            block("هنوز Draft وجود ندارد؛ ابتدا در صفحه دامنه «ساخت نسخه جدید» را بزن.")
            result["revision_id"] = None
            return result
        revision_id = head["draft_version_id"]
    row = load_version(conn, domain, revision_id)
    result["revision_id"] = row["id"]
    body = row["body"]
    if hashlib.sha256(body.encode("utf-8")).hexdigest() != row["sha256"]:
        block("SHA256 نسخه در دیتابیس با متن ذخیره‌شده یکسان نیست.")
    else:
        checked("SHA256 نسخه ذخیره‌شده معتبر است.")
    if row["origin"] == "live_snapshot":
        block("نسخه Live snapshot صرفاً مرجع است و نباید مستقیماً منتشر شود.")
    if f"{V2_MARKER}{domain}" not in body.splitlines()[:4]:
        block("نشانگر مالکیت V2 در ابتدای کانفیگ وجود ندارد.")
    if "PENDING-SSL-" in body:
        block("کانفیگ هنوز دارای PENDING-SSL است؛ گواهی معتبر باید شناسایی و نسخه دوباره ساخته شود.")

    served_names = set()
    for line in SERVER_NAME.findall(body):
        served_names.update(line.split())
    if domain not in served_names:
        block("نام دامنه در server_name نسخه انتخاب‌شده پیدا نشد.")
    else:
        checked("server_name حاوی نام دامنه موردنظر است.")

    cert_paths = set(CERT_LINE.findall(body))
    key_paths = set(KEY_LINE.findall(body))
    if not cert_paths or not key_paths:
        block("مسیر ssl_certificate یا ssl_certificate_key در Draft پیدا نشد.")
    cert_stubs, key_stubs = set(), set()
    invalid_paths = False
    for kind, entries, dest in (("crt", cert_paths, cert_stubs),
                                ("key", key_paths, key_stubs)):
        for p in entries:
            path = p.strip()
            match = SSL_FILE.fullmatch(path)
            if match is None or match.group(2) != kind:
                invalid_paths = True
                continue
            dest.add(match.group(1))
    if invalid_paths:
        block("یک یا چند مسیر SSL خارج از الگوی مجاز /etc/nginx/ssl/<name>.crt/.key است.")
    if cert_stubs != key_stubs:
        block("برای همه نام‌های فایل گواهی، کلید خصوصی متناظر در Draft وجود ندارد.")
    for stub in sorted(cert_stubs & key_stubs):
        try:
            metadata = inspect_certificate(ssl_dir, stub, min_days=14)
        except Exception:
            # Intentionally avoid echoing local paths/crypto errors or secrets.
            block(f"گواهی {stub}: از پوشه SSL آزمایشی V2 قابل اعتبارسنجی نیست؛ وضعیت گواهی Nginx زنده نامشخص است.")
            continue
        if not any(domain == n or (n.startswith("*.") and
                   domain.endswith(n[1:]) and
                   domain.count(".") == n.count(".")) for n in metadata.names):
            block(f"گواهی {stub} دامنه {domain} را در SAN پوشش نمی‌دهد.")
        else:
            checked(f"گواهی {stub} در مسیر آزمایشی از نظر اعتبار و پوشش SAN بررسی شد.")

    live = conn.execute(
        """SELECT id,body,created_at FROM config_versions
           WHERE domain=? AND origin='live_snapshot'
           ORDER BY id DESC LIMIT 1""", (domain,)
    ).fetchone()
    if live is None:
        block("برای این دامنه نسخه live_snapshot تاریخی وجود ندارد.")
    else:
        checked(f"snapshot تاریخی #{live['id']} از {live['created_at']} در دیتابیس موجود است.")
        old_routes, old_notes = _parsed_locations(live["body"])
        new_routes, new_notes = _parsed_locations(body)
        for note in old_notes + new_notes:
            block(f"عبارت Location نیازمند بررسی دستی: {note}")
        for path in sorted(old_routes.keys() | new_routes.keys()):
            if old_routes.get(path) != new_routes.get(path):
                block(f"تفاوت Route {path}: نسخه قبلی و Draft پراکسی یکسان ندارند؛ تأیید انسانی لازم است.")
        if old_routes == new_routes and not old_notes and not new_notes:
            checked("نگاشت Location / proxy_passهای قابل‌شناسایی با snapshot مطابقت دارد.")
        old_includes = set(INCLUDE_LINE.findall(live["body"]))
        new_includes = set(INCLUDE_LINE.findall(body))
        if old_includes != new_includes:
            block("Includeهای جدید و آرشیوی یکسان نیستند؛ قبل از مهاجرت باید مقایسه و تأیید شوند.")
        if live["body"].strip() != body.strip():
            warn("متن کلی کانفیگ با snapshot فرق دارد؛ هدرها، TLS، Rewrite، Redirect و سایر directiveها هنوز نیازمند بازبینی انسانی‌اند.")

    flags = conn.execute(
        "SELECT first_flag,second_flag FROM legacy_flags WHERE domain=?", (domain,)
    ).fetchone()
    if flags and "0" in (flags["first_flag"], flags["second_flag"]):
        warn("فلگ legacy برابر 0 است؛ کانفیگ دستی فعلی نباید بدون مالکیت‌گذاری صریح جایگزین شود.")
    if not conn.execute(
        "SELECT 1 FROM domains WHERE name=? AND enabled=1", (domain,)
    ).fetchone():
        block("دامنه در دیتابیس غیرفعال است.")

    warn("آخرین وضعیت Nginx زنده، فایل‌های SSL در Docker، صحت نحوی nginx -t و سلامت سرویس از این گزارش بررسی نمی‌شوند.")
    warn("دکمه Apply واقعی هنوز وجود ندارد؛ حتی گزارش بدون مانع نیز اجازه انتشار نیست.")
    return result
