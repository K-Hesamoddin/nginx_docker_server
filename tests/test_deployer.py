"""No Docker or production writes in dry-run; one-shot rollback tests use fakes."""
import hashlib
import subprocess

import pytest

from controlplane import deployer
from controlplane.core import open_db, render_config, save_certificate, save_domain, save_route
from controlplane.management import ensure_schema, queue_deployment, store_version
from tests.test_controlplane import make_cert


@pytest.fixture
def ready(tmp_path, monkeypatch):
    root = tmp_path / "production-copy"
    for name in ("conf/auto", "ssl"):
        (root / name).mkdir(parents=True)
    db_file = tmp_path / "lab" / "data" / "lab.sqlite3"
    db = open_db(db_file)
    ensure_schema(db)
    monkeypatch.setenv("CONTROLPLANE_CA_BUNDLE",
                       str(root / "ssl" / "test-ca-bundle.pem"))
    make_cert(root / "ssl", "shared", ["example.com", "*.example.com"])
    save_domain(db, "example.com", redirect_www=True)
    save_route(db, "example.com", "/", "192.0.2.11:3000")
    save_certificate(db, "example.com", "wildcard", "shared")
    body = render_config(db, root / "ssl", "example.com")
    store_version(db, "example.com", body, "live_snapshot")
    rid = store_version(db, "example.com", body + "\n# reviewed\n", "manual")
    job_id = queue_deployment(db, "example.com", rid)
    current = b"# old version\n" + body.encode()
    target = root / "conf" / "auto" / "example.com.conf"
    target.write_bytes(current)
    yield db, root, rid, job_id, target
    db.close()


def _plan(ready):
    db, root, rid, job_id, target = ready
    return deployer.plan_job(db, root, job_id)


def _execute(ready, **kwargs):
    db, root, rid, job_id, target = ready
    report = _plan(ready)
    opts = dict(
        expected_current_sha256=report["current_sha256"],
        expected_revision_sha256=report["revision_sha256"],
        confirm_domain="example.com", reviewed_diff=True,
    )
    opts.update(kwargs)
    return deployer.execute_job(db, root, job_id, **opts)


def test_plan_checks_shared_wildcard_and_does_not_touch_live_or_docker(ready, monkeypatch):
    db, root, rid, job_id, target = ready
    monkeypatch.setattr(deployer, "_docker", lambda *args: pytest.fail("No Docker in plan"))
    original = target.read_bytes()
    report = _plan(ready)
    assert report["eligible_for_operator_review"]
    assert report["blockers"] == []
    assert report["domain"] == "example.com"
    assert report["revision"] == rid
    assert report["current_sha256"] == hashlib.sha256(original).hexdigest()
    assert target.read_bytes() == original
    assert db.execute("SELECT status FROM operator_jobs WHERE id=?", (job_id,)).fetchone()[0] == "pending"
    assert not (db.execute("PRAGMA database_list").fetchone()[2] and
                deployer.Path(db.execute("PRAGMA database_list").fetchone()[2]).parent.joinpath("v2-deploy-backups").exists())


def test_plan_blocks_pending_ssl_and_wrong_cert_or_unsafe_target(ready):
    db, root, rid, job_id, target = ready
    record = db.execute("SELECT body FROM config_versions WHERE id=?", (rid,)).fetchone()[0]
    (root / "ssl" / "shared.crt").unlink()
    report = _plan(ready)
    assert not report["eligible_for_operator_review"]
    assert any("shared" in x for x in report["blockers"])
    (root / "ssl" / "shared.crt").write_text("not-a-cert")
    report = _plan(ready)
    assert not report["eligible_for_operator_review"]
    target.unlink()
    target.symlink_to(root / "ssl" / "shared.crt")
    with pytest.raises(ValueError, match="symlink"):
        _plan(ready)


def test_execute_requires_exact_hash_and_review_confirmation(ready, monkeypatch):
    monkeypatch.setattr(deployer, "_docker", lambda *args: pytest.fail("Should reject before Docker"))
    original = ready[4].read_bytes()
    with pytest.raises(ValueError, match="review"):
        _execute(ready, reviewed_diff=False)
    with pytest.raises(ValueError, match="SHA256"):
        _execute(ready, expected_current_sha256="0" * 64)
    with pytest.raises(ValueError, match="domain"):
        _execute(ready, confirm_domain="another.example.com")
    assert ready[4].read_bytes() == original


def test_execute_success_updates_only_approved_job_with_backup(ready, monkeypatch):
    db, root, rid, job_id, target = ready
    previous = target.read_bytes()
    calls = []
    monkeypatch.setattr(deployer, "_verify_mounts", lambda x: None)
    monkeypatch.setattr(deployer, "_probe", lambda host: 200)
    monkeypatch.setattr(deployer, "_docker", lambda *args: calls.append(args) or "")
    result = _execute(ready)
    assert result["status"] == "succeeded"
    assert target.read_text().endswith("# reviewed\n")
    assert not list((root / "conf" / "auto").glob("*.new"))
    assert (deployer.Path(result["backup"]) / "before.conf").read_bytes() == previous
    assert deployer.Path(result["backup"]).parent == deployer.Path(db.execute("PRAGMA database_list").fetchone()[2]).parent / "v2-deploy-backups"
    assert not (root / "data").exists()
    assert db.execute("SELECT status FROM operator_jobs WHERE id=?", (job_id,)).fetchone()[0] == "succeeded"
    assert db.execute("SELECT deployed_version_id FROM config_heads WHERE domain='example.com'").fetchone()[0] == rid
    assert calls.count(("exec", "nginx-proxy", "nginx", "-t")) == 2
    assert calls.count(("exec", "nginx-proxy", "nginx", "-s", "reload")) == 1


def test_execute_failed_new_nginx_test_restores_previous_file(ready, monkeypatch):
    db, root, rid, job_id, target = ready
    old = target.read_bytes()
    calls = []
    monkeypatch.setattr(deployer, "_verify_mounts", lambda x: None)
    monkeypatch.setattr(deployer, "_probe", lambda host: 200)
    def fake_docker(*args):
        calls.append(args)
        if args[-1] == "-t" and target.read_bytes() != old:
            raise subprocess.CalledProcessError(1, args)
        return ""
    monkeypatch.setattr(deployer, "_docker", fake_docker)
    with pytest.raises(subprocess.CalledProcessError):
        _execute(ready)
    assert target.read_bytes() == old
    assert calls.count(("exec", "nginx-proxy", "nginx", "-s", "reload")) == 1
    assert db.execute("SELECT status FROM operator_jobs WHERE id=?", (job_id,)).fetchone()[0] == "failed"
    assert db.execute("SELECT deployed_version_id FROM config_heads WHERE domain='example.com'").fetchone()[0] is None
    state_dir = deployer.Path(db.execute("PRAGMA database_list").fetchone()[2]).parent
    assert list((state_dir / "v2-deploy-backups").glob("*/before.conf"))



def test_failing_www_origin_rolls_back_and_logs_failure(ready, monkeypatch):
    db, root, rid, job_id, target = ready
    previous = target.read_bytes()
    seen = []
    monkeypatch.setattr(deployer, "_verify_mounts", lambda _: None)
    monkeypatch.setattr(deployer, "_docker", lambda *args: "")
    def check(host):
        seen.append(host)
        if host == "www.example.com":
            raise ValueError("Expired or failed www handshake")
        return 200
    monkeypatch.setattr(deployer, "_probe", check)
    with pytest.raises(ValueError, match="www"):
        _execute(ready)
    assert seen == ["example.com", "www.example.com"]
    assert target.read_bytes() == previous
    row = db.execute("SELECT status,result FROM operator_jobs WHERE id=?", (job_id,)).fetchone()
    assert row["status"] == "failed"
    assert "restored" in row["result"]



def test_reviewed_upstream_change_is_reported_separately_from_hard_ssl_blockers(ready):
    db, root, rid, job_id, target = ready
    original = db.execute("SELECT body FROM config_versions WHERE id=?", (rid,)).fetchone()[0]
    modified = original.replace("192.0.2.11:3000", "192.0.2.12:3000")
    assert modified != original
    new_revision = store_version(db, "example.com", modified, "manual", "approved backend move")
    new_job = queue_deployment(db, "example.com", new_revision)
    report = deployer.plan_job(db, root, new_job)
    assert report["eligible_for_operator_review"]
    assert report["blockers"] == []
    assert any("تفاوت Route" in s for s in report["review_required"])
    assert report["revision_sha256"] != _plan(ready)["revision_sha256"]


def test_execute_legacy_manual_domain_needs_separate_approval(ready, monkeypatch):
    db, root, rid, job_id, target = ready
    db.execute("""INSERT INTO legacy_flags(domain,flag_count,first_flag,second_flag)
                  VALUES('example.com',2,'0','0')""")
    db.commit()
    monkeypatch.setattr(deployer, "_docker", lambda *args: pytest.fail("Should reject"))
    with pytest.raises(ValueError, match="manual-legacy"):
        _execute(ready)
