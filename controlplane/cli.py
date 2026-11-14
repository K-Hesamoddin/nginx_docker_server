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


def issue_wildcard(conn, ssl_dir, zone, acme_bin):
    """DNS-01 issuance is explicit, never a silent fallback to self-signed.

    Certificates are copied into immutable fingerprinted filenames, not into
    Nginx's active paths. Registration does not modify any live server.
    """
    zone = hostname(zone)
    if not os.environ.get("NSIN_Api_Key"):
        raise ValueError("NSIN_Api_Key not present in environment (never commit it)")
    if not shutil.which(acme_bin):
        raise ValueError(f"acme.sh executable not found: {acme_bin}")
    ssl_dir.mkdir(parents=True, exist_ok=True)
    # acme.sh --install-cert stores renewal target paths. Use a *persistent* staging
    # directory instead of TemporaryDirectory, so later acme.sh renewals do not
    # target deleted files.
    staging = ssl_dir / ".acme" / zone
    staging.mkdir(parents=True, exist_ok=True, mode=0o700)
    crt, key = staging / "fullchain.pem", staging / "privkey.pem"
    run(acme_bin, "--issue", "--server", "letsencrypt", "--dns", "dns_nsin",
        "--keylength", "ec-256", "-d", zone, "-d", f"*.{zone}")
    run(acme_bin, "--install-cert", "-d", zone, "--ecc",
        "--fullchain-file", str(crt), "--key-file", str(key))
    # Inspect both actual SAN coverage and private-key match before publishing.
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_pem_x509_certificate(crt.read_bytes())
    public_key = serialization.load_pem_private_key(key.read_bytes(), password=None).public_key()
    if cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != \
       public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
        raise ValueError("ACME certificate/private key mismatch")
    names = set(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    if not {zone, f"*.{zone}"}.issubset(names):
        raise ValueError(f"ACME certificate SAN mismatch: {names}")
    if cert.not_valid_after_utc.timestamp() < __import__("time").time() + 14 * 86400:
        raise ValueError("ACME certificate expires in less than 14 days")
    fingerprint = hashlib.sha256(crt.read_bytes()).hexdigest()[:16]
    stub = f"wildcard.{zone}.{fingerprint}"
    # New immutable file names guarantee no active cert is overwritten by issuance.
    dest_crt, dest_key = ssl_dir / (stub + ".crt"), ssl_dir / (stub + ".key")
    if not dest_crt.exists():
        for src, dest, mode in ((crt, dest_crt, 0o644), (key, dest_key, 0o600)):
            with dest.open("xb") as output:
                output.write(src.read_bytes())
            os.chmod(dest, mode)
    inspect_certificate(ssl_dir, stub)
    save_certificate(conn, zone, "wildcard", stub)
    print(f"Registered {stub}. No Nginx config was deployed.")
    print("Note: ACME renewal staging files do NOT auto-promote to immutable live files.")
    print("Re-run issue-wildcard and deploy after renewal, until a verified renewal hook is configured.")


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
                issue_wildcard(conn, ssl_dir, args.zone, args.acme_bin)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
