"""Reviewable CLI for legacy import, certificate enrollment and guarded deployment."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .core import (audit, export_domains_list, hostname, import_domains_list,
                   inspect_certificate, open_db, render_config, save_certificate)


def paths():
    root = Path(os.environ.get("CONTROLPLANE_ROOT", ".")).resolve()
    return root, Path(os.environ.get("CONTROLPLANE_DB", root / "data/controlplane.sqlite3")), Path(
        os.environ.get("SSL_DIR", root / "ssl"))


def run(*args, env=None):
    subprocess.run(args, check=True, env=env)


def generated(conn, ssl_dir):
    configs = {}
    rows = conn.execute("SELECT name FROM domains WHERE enabled=1 ORDER BY name").fetchall()
    for row in rows:
        configs[row["name"] + ".conf"] = render_config(conn, ssl_dir, row["name"])
    if not configs:
        raise ValueError("No active domains. Refusing to deploy an empty set")
    return configs


def apply_config(conn, root, ssl_dir, allow_replace_v1=False):
    """Backup changed files; test before reload; rollback on test/reload failure.

    Never remove files belonging to other tools or domains.
    """
    configs = generated(conn, ssl_dir)
    out = root / "conf" / "auto"
    out.mkdir(parents=True, exist_ok=True)
    lock_file = root / "data" / "controlplane.deploy.lock"
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    with lock_file.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        # Keep backups present until validation and any necessary rollback finish.
        backup_dir = Path(tempfile.mkdtemp(prefix=".controlplane-backup-", dir=root))
        backups = {}
        try:
            for name, content in configs.items():
                target = out / name
                if target.exists():
                    existing = target.read_text()
                    if "Managed by nginx-control-plane-v2:" not in existing and not allow_replace_v1:
                        raise ValueError(
                            f"{target} is not managed by V2. Review diff and use --allow-replace-v1.")
                    saved = backup_dir / name
                    shutil.copy2(target, saved)
                    backups[target] = saved
                else:
                    backups[target] = None
                staging = out / (name + ".new")
                try:
                    staging.write_text(content)
                    os.chmod(staging, 0o644)
                    os.replace(staging, target)
                finally:
                    staging.unlink(missing_ok=True)
            run("docker", "exec", "nginx-proxy", "nginx", "-t")
            run("docker", "exec", "nginx-proxy", "nginx", "-s", "reload")
            audit(conn, "deploy", f"{len(configs)} configs")
            conn.commit()
        except Exception:
            for target, old in backups.items():
                if old is not None and old.exists():
                    shutil.copy2(old, target)
                elif old is None:
                    target.unlink(missing_ok=True)
            try:
                run("docker", "exec", "nginx-proxy", "nginx", "-t")
                run("docker", "exec", "nginx-proxy", "nginx", "-s", "reload")
            except Exception:
                print("CRITICAL: rollback/reload failed; manual intervention required!", file=sys.stderr)
            raise
        finally:
            shutil.rmtree(backup_dir, ignore_errors=True)


def issue_wildcard(conn, root, db_file, ssl_dir, zone, acme_bin):
    """DNS-01 wildcard, with a persistent acme.sh renewal/install hook."""
    from .renewal import configure_renewal_hook, has_valid_wildcard
    zone = hostname(zone)
    if not shutil.which(acme_bin):
        raise ValueError(f"acme.sh not installed: {acme_bin}")
    if not has_valid_wildcard(conn, ssl_dir, zone, min_days=30):
        if not os.environ.get("NSIN_Api_Key"):
            raise ValueError("NSIN_Api_Key missing; configure it securely in the acme.sh account")
        run(acme_bin, "--issue", "--server", "letsencrypt", "--dns", "dns_nsin",
            "--keylength", "ec-256", "-d", zone, "-d", f"*.{zone}")
    else:
        print(f"Valid wildcard already registered for {zone}; no new issuance requested.")
    configure_renewal_hook(root, db_file, ssl_dir, zone, acme_bin)
    print("ACME renewal hook configured. Live Nginx is unchanged unless the explicit")
    print("root-owned data/enable-auto-deploy marker is enabled and all configs are V2-managed.")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Nginx Control Plane V2 (no implicit production writes)")
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("init")
    imp = subs.add_parser("import-legacy"); imp.add_argument("--file", default="domains.list")
    exp = subs.add_parser("export-legacy"); exp.add_argument("--file")
    prev = subs.add_parser("preview"); prev.add_argument("--domain")
    apply = subs.add_parser("apply")
    apply.add_argument("--yes", action="store_true")
    apply.add_argument("--allow-replace-v1", action="store_true")
    issue = subs.add_parser("issue-wildcard")
    issue.add_argument("zone")
    issue.add_argument("--acme-bin", default="acme.sh")
    hook = subs.add_parser("configure-renewal-hook")
    hook.add_argument("zone")
    hook.add_argument("--acme-bin", default="acme.sh")
    sync = subs.add_parser("sync-renewed")
    sync.add_argument("zone")
    args = parser.parse_args(argv)
    root, db_file, ssl_dir = paths()
    try:
        with open_db(db_file) as conn:
            if args.command == "init":
                print(f"Initialized {db_file}")
            elif args.command == "import-legacy":
                result = import_domains_list(conn, root / args.file)
                print(result)
                if result["errors"]:
                    return 1
            elif args.command == "export-legacy":
                data = export_domains_list(conn)
                if args.file:
                    (root / args.file).write_text(data)
                else:
                    print(data, end="")
            elif args.command == "preview":
                configs = generated(conn, ssl_dir)
                for name, text in configs.items():
                    if not args.domain or name == args.domain + ".conf":
                        print(f"##### {name}\n{text}")
            elif args.command == "apply":
                if not args.yes:
                    parser.error("apply requires --yes after preview and backups")
                apply_config(conn, root, ssl_dir, args.allow_replace_v1)
            elif args.command == "issue-wildcard":
                issue_wildcard(conn, root, db_file, ssl_dir, args.zone, args.acme_bin)
            elif args.command == "configure-renewal-hook":
                from .renewal import configure_renewal_hook
                configure_renewal_hook(root, db_file, ssl_dir, args.zone, args.acme_bin)
            elif args.command == "sync-renewed":
                from .renewal import sync_renewed
                stub = sync_renewed(conn, root, ssl_dir, args.zone)
                print(f"Validated and registered renewed certificate: {stub}")
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
