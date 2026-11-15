"""Offline-only tests for explicit one-zone SSL staging (no real Docker writes)."""
from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from pathlib import Path

import pytest

from controlplane import cert_stage
from controlplane.core import open_db, save_certificate
from tests.test_controlplane import make_cert


@pytest.fixture
def staged(tmp_path, monkeypatch):
    lab = tmp_path / "lab"
    ssl = lab / "ssl"
    ssl.mkdir(parents=True)
    production = tmp_path / "production"
    for folder in ("ssl", "conf/auto"):
        (production / folder).mkdir(parents=True, exist_ok=True)
    (production / "conf/auto/example.com.conf").write_text("# live; do not modify\n")
    db = open_db(lab / "data" / "controlplane.sqlite3")
    monkeypatch.setenv("CONTROLPLANE_CA_BUNDLE", str(ssl / "test-ca-bundle.pem"))
    make_cert(ssl, "initial", ["example.com", "*.example.com"])
    crt = (ssl / "initial.crt").read_bytes()
    key = (ssl / "initial.key").read_bytes()
    stub = "wildcard.example.com." + hashlib.sha256(crt + key).hexdigest()[:20]
    (ssl / "initial.crt").rename(ssl / f"{stub}.crt")
    (ssl / "initial.key").rename(ssl / f"{stub}.key")
    save_certificate(db, "example.com", "wildcard", stub)
    monkeypatch.setattr(cert_stage, "_verify_mounts", lambda root: None)
    yield db, ssl, production, stub, crt, key
    db.close()


def run_plan(fixture):
    db, ssl, root, stub, _, _ = fixture
    return cert_stage.plan(db, ssl, root, "example.com", stub)


def run_stage(fixture, confirmation="example.com"):
    db, ssl, root, stub, _, _ = fixture
    return cert_stage.stage(db, ssl, root, "example.com", stub,
                            confirm_zone=confirmation)


def test_plan_is_read_only_and_reports_exact_copy(staged):
    db, ssl, root, stub, crt, key = staged
    before = (root / "conf/auto/example.com.conf").read_bytes()
    plan = run_plan(staged)
    assert plan["ready_to_stage"]
    assert plan["certificate_state"] == "missing"
    assert plan["private_key_state"] == "missing"
    assert plan["certificate_sha256"] == hashlib.sha256(crt).hexdigest()
    assert not list((root / "ssl").iterdir())
    assert (root / "conf/auto/example.com.conf").read_bytes() == before


def test_execute_publishes_verified_immutable_pair_and_never_touches_config(staged):
    db, ssl, root, stub, crt, key = staged
    config = root / "conf/auto/example.com.conf"
    old = config.read_bytes()
    result = run_stage(staged)
    assert "Staged and verified" in result["action"]
    assert (root / "ssl" / f"{stub}.crt").read_bytes() == crt
    assert (root / "ssl" / f"{stub}.key").read_bytes() == key
    assert stat.S_IMODE((root / "ssl" / f"{stub}.key").stat().st_mode) == 0o600
    assert stat.S_IMODE((root / "ssl" / f"{stub}.crt").stat().st_mode) == 0o644
    assert config.read_bytes() == old
    second = run_stage(staged)
    assert second["certificate_state"] == "verified-in-production"


def test_no_execution_without_exact_zone_confirmation(staged):
    with pytest.raises(ValueError, match="confirm-zone"):
        run_stage(staged, "other.example.com")
    assert not list((staged[2] / "ssl").glob("wildcard*"))


def test_wrong_existing_destination_refuses_to_replace(staged):
    db, ssl, root, stub, crt, key = staged
    target = root / "ssl" / f"{stub}.crt"
    target.write_text("previous certificate that must not be overwritten")
    with pytest.raises(ValueError, match="refusing overwrite"):
        run_stage(staged)
    assert target.read_text().startswith("previous certificate")
    assert not (root / "ssl" / f"{stub}.key").exists()


def test_symlinked_target_or_parent_is_forbidden(staged):
    db, ssl, root, stub, crt, key = staged
    target = root / "ssl" / f"{stub}.key"
    target.symlink_to(ssl / f"{stub}.key")
    with pytest.raises(ValueError, match="symlink"):
        run_stage(staged)
    target.unlink()
    (root / "ssl").rename(root / "ssl_original")
    (root / "ssl").symlink_to(root / "ssl_original", target_is_directory=True)
    with pytest.raises(ValueError, match="directory"):
        run_plan(staged)


def test_source_must_be_registered_wildcard_for_exact_zone(staged):
    db, ssl, root, stub, crt, key = staged
    with pytest.raises(ValueError, match="registered"):
        cert_stage.plan(db, ssl, root, "example.com",
                        "wildcard.example.com." + "1" * 20)
    db.execute("DELETE FROM certificates WHERE stub=?", (stub,))
    db.commit()
    with pytest.raises(ValueError, match="registered"):
        run_plan(staged)


def test_tampered_source_content_rejected_before_any_writes(staged):
    db, ssl, root, stub, crt, key = staged
    (ssl / f"{stub}.crt").write_bytes(crt + b"# modified")
    with pytest.raises(ValueError, match="immutable"):
        run_stage(staged)
    assert not list((root / "ssl").glob("wildcard*"))


def test_invalid_source_san_rejected(staged, monkeypatch):
    db, ssl, root, stub, crt, key = staged
    monkeypatch.setattr(cert_stage, "inspect_certificate",
                        lambda *args, **kwargs: type("FakeCert", (), {
                            "names": ("example.com",),
                            "expires": type("FakeExpiry", (), {
                                "isoformat": lambda self: "2027-02-01T00:00:00+00:00"
                            })(),
                        })())
    with pytest.raises(ValueError, match="must cover"):
        run_stage(staged)
    assert not list((root / "ssl").glob("wildcard*"))


def test_copy_failure_cleans_only_newly_created_files(staged, monkeypatch):
    db, ssl, root, stub, crt, key = staged
    original = cert_stage.os.link

    def fail_on_cert(src, dest, **kwargs):
        if str(dest).endswith(".crt"):
            raise OSError("simulated filesystem failure")
        return original(src, dest, **kwargs)

    monkeypatch.setattr(cert_stage.os, "link", fail_on_cert)
    with pytest.raises(OSError, match="filesystem"):
        run_stage(staged)
    assert not (root / "ssl" / f"{stub}.key").exists()
    assert not (root / "ssl" / f"{stub}.crt").exists()


def test_reject_unsafe_existing_private_key_permissions(staged):
    db, ssl, root, stub, crt, key = staged
    target = root / "ssl" / f"{stub}.key"
    target.write_bytes(key)
    target.chmod(0o644)
    with pytest.raises(ValueError, match="unsafe permissions"):
        run_stage(staged)
    assert target.stat().st_mode & 0o777 == 0o644
    assert not (root / "ssl" / f"{stub}.crt").exists()


def test_execute_checks_container_bind_mount_before_copy(staged, monkeypatch):
    def reject(root):
        raise ValueError("wrong Docker mount")
    monkeypatch.setattr(cert_stage, "_verify_mounts", reject)
    with pytest.raises(ValueError, match="wrong Docker mount"):
        run_stage(staged)
    assert not list((staged[2] / "ssl").glob("wildcard*"))
