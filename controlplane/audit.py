"""Read-only checks of running Nginx -T output against the imported domain routes.

This is intentionally a scoped audit, not a general-purpose Nginx parser.
Missing/unrecognized constructs are reported instead of silently 'fixed'.
No Docker calls, writes, certificate material or secrets are required.
"""
from __future__ import annotations

import re
import sqlite3

from .core import hostname, upstream, route_path

CONFIG_HEADER = re.compile(r"(?m)^# configuration file (?P<path>[^:\r\n]+):\s*$")
LOCATION = re.compile(r"(?m)^\s*location\s+([^\s{}]+)\s*\{")
PROXY_PASS = re.compile(r"(?m)^\s*proxy_pass\s+([^;]+);")
DIRECTIVE = re.compile(r"(?m)^\s*([a-z_][a-z0-9_]*)\s+([^;]*);")


def extract_live_block(dump: str, domain: str) -> str:
    domain = hostname(domain)
    wanted = f"/etc/nginx/conf.d/auto/{domain}.conf"
    headers = list(CONFIG_HEADER.finditer(dump))
    for i, m in enumerate(headers):
        if m.group("path") == wanted:
            end = headers[i + 1].start() if i + 1 < len(headers) else len(dump)
            return dump[m.end():end]
    raise ValueError(f"No configuration heading for {wanted} in nginx -T")


def _parsed_locations(block: str) -> tuple[dict[str, str], list[str]]:
    """Extract simple Nginx location blocks from the current generator format."""
    locations = {}
    warnings = []
    for m in LOCATION.finditer(block):
        candidate = m.group(1)
        try:
            path = route_path(candidate)
        except ValueError:
            warnings.append(f"Unsupported location expression: {candidate}")
            continue
        pos, depth = m.end(), 1
        cursor = pos
        while cursor < len(block) and depth:
            if block[cursor] == "{":
                depth += 1
            elif block[cursor] == "}":
                depth -= 1
            cursor += 1
        if depth:
            warnings.append(f"Unbalanced braces in location {path}")
            continue
        body = block[pos:cursor - 1]
        found = PROXY_PASS.findall(body)
        if len(found) != 1:
            warnings.append(f"Location {path} has {len(found)} proxy_pass directives")
            continue
        if path in locations:
            warnings.append(f"Duplicate location {path}")
            continue
        locations[path] = found[0].strip()
    return locations, warnings


def _review_item(kind: str, location: str, expected: str | None,
                 live: str | None) -> dict:
    """Produce structured differences for manual review. Never auto-apply."""
    return {
        "kind": kind, "location": location,
        "inventory_proxy_pass": expected,
        "live_proxy_pass": live,
        "requires_approval": True,
    }


def audit_live(conn: sqlite3.Connection, dump: str, domain: str) -> dict:
    """Return a report and an explicit pass/fail flag; no actual config changes."""
    domain = hostname(domain)
    if conn.execute("SELECT 1 FROM domains WHERE name=?", (domain,)).fetchone() is None:
        raise ValueError(f"No domain in inventory: {domain}")
    block = extract_live_block(dump, domain)
    live_routes, notes = _parsed_locations(block)
    mismatches = []
    review_items = []
    expected = {}
    for r in conn.execute("SELECT * FROM routes WHERE domain=? ORDER BY id", (domain,)):
        path, target = route_path(r["path"]), upstream(r["target"])
        suffix = r["proxy_uri"] if r["proxy_uri"] is not None else (
            "/" if r["strip_prefix"] else ""
        )
        expected[path] = f"http://{target}" + suffix
    for path, url in expected.items():
        if path not in live_routes:
            mismatches.append(f"Missing live location: {path}")
            review_items.append(_review_item("missing_live_location", path, url, None))
        elif live_routes[path] != url:
            actual = live_routes[path]
            mismatches.append(f"{path}: expected {url}, live {actual}")
            if (url.endswith("/") and url[:-1] == actual or
                    actual.endswith("/") and actual[:-1] == url):
                kind = "proxy_pass_uri_semantics"
            else:
                kind = "upstream_or_uri_changed"
            review_items.append(_review_item(kind, path, url, actual))
    for path in sorted(live_routes.keys() - expected.keys()):
        mismatches.append(f"Extra live location: {path}")
        review_items.append(_review_item("unmanaged_live_location", path, None, live_routes[path]))

    flags = {
        "http2": bool(re.search(r"(?m)^\s*http2\s+on\s*;", block)),
        "ipv6_ssl": bool(re.search(r"(?m)^\s*listen\s+\[::\]:443\s+ssl\s*;", block)),
        "security_include": "include /etc/nginx/conf.d/includes/security.conf;" in block,
        "buffer_include": "include /etc/nginx/conf.d/buffer.conf;" in block,
        "forwarded_host": "proxy_set_header X-Forwarded-Host $host;" in block,
        "forwarded_server": "proxy_set_header X-Forwarded-Server $host;" in block,
        "upgrade": "proxy_set_header Upgrade $http_upgrade;" in block,
        "connection_upgrade": 'proxy_set_header Connection "upgrade";' in block,
    }
    cert_refs = sorted(set(re.findall(
        r"(?m)^\s*ssl_certificate\s+(/etc/nginx/ssl/[a-zA-Z0-9_.-]+\.crt)\s*;", block
    )))
    return {
        "domain": domain,
        "expected_route_count": len(expected),
        "live_route_count": len(live_routes),
        "routes_match": not mismatches and not notes,
        "mismatches": mismatches,
        "review_items": review_items,
        "notes": notes,
        "live_features": flags,
        "live_cert_paths": cert_refs,
        "scope": "Read-only heuristic audit; does not compare TLS trust, full Nginx semantics or other includes.",
    }


def audit_all(conn: sqlite3.Connection, dump: str, include_matches: bool = False) -> dict:
    """Batch route inventory audit, one nginx -T capture, no config changes.

    A missing config heading is *unverified*, never assumed to be inactive.
    Any parser warning is considered a mismatch requiring a manual review.
    """
    if not CONFIG_HEADER.search(dump):
        raise ValueError("Input is not a complete-looking nginx -T dump: no config headers")
    domains = [
        row["name"] for row in
        conn.execute("SELECT name FROM domains WHERE enabled=1 ORDER BY name")
    ]
    if not domains:
        raise ValueError("No enabled domains in inventory")
    summary = {
        "total": len(domains),
        "matched": 0,
        "drift": 0,
        "unverified": 0,
        "findings": [],
        "scope": ("Read-only audit of simple location/proxy_pass mappings only. "
                  "A match does not verify all Nginx directives or TLS.")
    }
    for domain in domains:
        try:
            result = audit_live(conn, dump, domain)
        except ValueError as exc:
            summary["unverified"] += 1
            summary["findings"].append({
                "domain": domain, "status": "unverified",
                "reason": str(exc),
            })
            continue
        if result["routes_match"]:
            summary["matched"] += 1
            if include_matches:
                summary["findings"].append({
                    "domain": domain, "status": "matched",
                    "routes": result["expected_route_count"]
                })
        else:
            summary["drift"] += 1
            summary["findings"].append({
                "domain": domain, "status": "drift",
                "expected_routes": result["expected_route_count"],
                "live_routes": result["live_route_count"],
                "mismatches": result["mismatches"],
                "review_items": result["review_items"],
                "notes": result["notes"],
            })
    return summary
