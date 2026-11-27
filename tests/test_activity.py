"""Activity log: what gets recorded, encryption at rest, tamper evidence,
filters, export, backups and key changes."""
import csv
import io
import json
import sqlite3
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from conftest import ROOT, SETUP

from app import audit, backup, crypto, main
from app.store import Store

PASS = "quill-lantern-orbit-cedar-z"
PW = "pw-1234567890"
H = {"X-ScanVault": "1"}
PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"


def _reset():
    for t in (main.login_throttle, main.account_throttle, main.key_throttle, main.setup_throttle):
        t._fails.clear()


@pytest.fixture()
def vault(tmp_path):
    old = main.store
    main.store = Store(tmp_path / "data")
    main.vault.lock()
    main.activity.forget()
    main._state["setup_code"] = None
    main._state["maintenance"] = None
    _reset()
    try:
        with TestClient(main.app) as c:
            r = c.post("/api/setup", json={"username": "ryan", "password": PW, "passphrase": PASS}, headers=SETUP)
            assert r.status_code == 200, r.text
            j = r.json()
            yield c, {"Authorization": f"Bearer {j['token']}"}, j
    finally:
        main.store = old
        main.vault.lock()
        main.activity.forget()
        _reset()


def _acts(c, B, **params):
    r = c.get("/api/activity", params=params, headers=B)
    assert r.status_code == 200, r.text
    return r.json()["entries"]


def _actions(c, B, **params):
    return [e["action"] for e in _acts(c, B, **params)]


def test_records_who_did_what(vault, data_dir):
    c, B, _ = vault
    p = c.post("/api/patients", json={"name": "Jane Activity", "mrn": "MRN-ACT-77"}, headers=B).json()
    s = c.post(f"/api/patients/{p['id']}/studies", json={"title": "Knee MRI"}, headers=B).json()
    up = c.post(f"/api/studies/{s['id']}/files", files={"file": ("knee-report.pdf", PDF, "application/pdf")}, headers=B).json()
    fid = up[0]["id"]
    c.get(f"/api/studies/{s['id']}", headers=B)
    c.get(f"/api/studies/{s['id']}", headers=B)  # second view within 15 minutes is not logged again
    c.get(f"/api/files/{fid}/content", headers=B)
    c.get(f"/api/files/{fid}/content?download=1", headers=B)
    c.put(f"/api/patients/{p['id']}", json={"notes": "allergic to contrast"}, headers=B)
    c.put(f"/api/files/{fid}", json={"filename": "renamed.pdf"}, headers=B)
    c.delete(f"/api/files/{fid}", headers=B)
    c.delete(f"/api/patients/{p['id']}", headers=B)

    entries = _acts(c, B)
    acts = [e["action"] for e in entries]
    for a in ("auth.setup", "patient.create", "study.create", "file.upload", "study.view", "file.view", "file.download",
              "patient.update", "file.update", "file.delete", "patient.delete"):
        assert a in acts, a
    assert acts.count("study.view") == 1
    up_e = next(e for e in entries if e["action"] == "file.upload")
    assert up_e["username"] == "ryan" and up_e["patient_name"] == "Jane Activity" and up_e["study_title"] == "Knee MRI"
    assert up_e["details"]["filenames"] == ["knee-report.pdf"] and up_e["client"] == "api"
    pu = next(e for e in entries if e["action"] == "patient.update")
    assert pu["details"]["changed"] == ["notes"] and "allergic" not in json.dumps(pu)  # field names, not values
    # Readable after the patient is gone
    pd = next(e for e in entries if e["action"] == "patient.delete")
    assert pd["patient_name"] == "Jane Activity" and pd["details"]["studies"] == 1

    # Filters
    assert set(_actions(c, B, patient_id=p["id"])) >= {"patient.create", "file.upload", "patient.delete"}
    assert "auth.setup" not in _actions(c, B, patient_id=p["id"])
    assert set(_actions(c, B, study_id=s["id"])) >= {"study.create", "file.upload", "study.view"}
    assert set(_actions(c, B, action="file.")) == {"file.upload", "file.view", "file.download", "file.update", "file.delete"}
    assert set(_actions(c, B, q="renamed.pdf")) == {"file.update", "file.delete"}
    assert _actions(c, B, since="2000-01-01", until="2000-01-02") == []
    page = c.get("/api/activity", params={"limit": 3}, headers=B).json()
    assert len(page["entries"]) == 3 and page["next_before"]
    page2 = c.get("/api/activity", params={"limit": 3, "before": page["next_before"]}, headers=B).json()
    assert page2["entries"][0]["seq"] < page["entries"][-1]["seq"]
    f = c.get("/api/activity/filters", headers=B).json()
    assert any(u["username"] == "ryan" for u in f["users"]) and any(a["action"] == "file.upload" for a in f["actions"])

    # Nothing identifying is stored in the clear
    con = sqlite3.connect(main.store.db_path)
    raw = b"".join(r[0] for r in con.execute("SELECT blob FROM audit_log"))
    con.close()
    assert b"Jane Activity" not in raw and b"knee-report" not in raw and b"ryan" not in raw
    dbbytes = main.store.db_path.read_bytes() + (main.store.dir / "scanvault.db-wal").read_bytes()
    assert b"Jane Activity" not in dbbytes


def test_sign_ins_and_failures_logged_while_locked(vault):
    c, B, _ = vault
    assert c.post("/api/vault/lock", headers=B).status_code == 200
    assert c.post("/api/auth/login", json={"username": "ryan", "password": "wrong-password"}).status_code == 401
    assert c.post("/api/auth/login", json={"username": "nobody", "password": "wrong-password"}).status_code == 401
    tok = c.post("/api/auth/login", json={"username": "ryan", "password": PW}).json()["token"]
    B2 = {"Authorization": f"Bearer {tok}"}
    assert c.post("/api/vault/unlock", json={"passphrase": "not-the-key"}, headers=B2).status_code == 400
    assert c.post("/api/vault/unlock", json={"passphrase": PASS}, headers=B2).status_code == 200
    entries = _acts(c, B2)
    acts = [e["action"] for e in entries]
    assert acts[:6] == ["vault.unlock", "vault.unlock_failed", "auth.login", "auth.login_failed", "auth.login_failed", "vault.lock"]
    unknown = entries[3]
    assert unknown["details"]["attempted_username"] == "nobody" and unknown["outcome"] == "failed" and unknown["user_id"] is None
    # The entries written while locked were signed at unlock (covered by the newest signature)
    v = c.get("/api/activity/verify", headers=B2).json()
    assert v["ok"], v
    assert v["unsigned_tail"] == 0


def test_tampering_is_detected(vault):
    c, B, _ = vault
    for i in range(4):
        c.post("/api/patients", json={"name": f"P{i}"}, headers=B)
    assert c.get("/api/activity/verify", headers=B).json()["ok"]
    db = main.store.db_path

    def mutate(sql, *args):
        con = sqlite3.connect(db)
        con.execute(sql, args)
        con.commit()
        con.close()

    # Change who did something
    mutate("UPDATE audit_log SET user_id='someone-else' WHERE seq=2")
    v = c.get("/api/activity/verify", headers=B).json()
    assert not v["ok"] and any("changed" in p for p in v["problems"])
    mutate("UPDATE audit_log SET user_id=(SELECT user_id FROM audit_log WHERE seq=1) WHERE seq=2")
    assert c.get("/api/activity/verify", headers=B).json()["ok"]

    # Rewrite an entry and recompute the chain from there: the signatures catch it
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()
    prev = rows[1]["hash"]
    for r in rows[2:]:
        h = audit.chain_hash(prev, r["seq"], r["ts"], "patient.view" if r["seq"] == 3 else r["action"], r["user_id"], r["patient_id"], r["study_id"], r["blob"])
        con.execute("UPDATE audit_log SET action=?, prev=?, hash=? WHERE seq=?", ("patient.view" if r["seq"] == 3 else r["action"], prev, h, r["seq"]))
        prev = h
    con.commit()
    con.close()
    v = c.get("/api/activity/verify", headers=B).json()
    assert not v["ok"] and any("signature" in p for p in v["problems"])


def test_deleting_entries_is_detected(vault):
    c, B, _ = vault
    for i in range(3):
        c.post("/api/patients", json={"name": f"P{i}"}, headers=B)
    con = sqlite3.connect(main.store.db_path)
    last = con.execute("SELECT MAX(seq) FROM audit_log").fetchone()[0]
    con.execute("DELETE FROM audit_log WHERE seq=?", (last,))  # drop the newest entry
    con.commit()
    con.close()
    v = c.get("/api/activity/verify", headers=B).json()
    assert not v["ok"] and any("ends at" in p for p in v["problems"])

    con = sqlite3.connect(main.store.db_path)
    con.execute("DELETE FROM audit_log WHERE seq=2")
    con.commit()
    con.close()
    v = c.get("/api/activity/verify", headers=B).json()
    assert any("missing" in p for p in v["problems"])


def test_export_csv_and_json(vault):
    c, B, _ = vault
    c.post("/api/patients", json={"name": "=HYPERLINK(\"x\")"}, headers=B)
    r = c.get("/api/activity/export?format=csv", headers=B)
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert rows[0][:5] == ["seq", "at", "username", "user_id", "action"]
    assert any(row[4] == "patient.create" and row[7].startswith("'=") for row in rows[1:])  # formula neutralized
    j = c.get("/api/activity/export?format=json&action=patient.", headers=B).json()
    assert j["verification"]["ok"] and {e["action"] for e in j["entries"]} == {"patient.create"}
    assert "activity.export" in _actions(c, B)


def test_rekey_keeps_log_readable_and_signed(vault):
    c, B, _ = vault
    c.post("/api/patients", json={"name": "Before"}, headers=B)
    r = c.post("/api/vault/rekey", json={"passphrase": PASS}, headers=B)
    assert r.status_code == 200, r.text
    c.post("/api/patients", json={"name": "After"}, headers=B)
    entries = _acts(c, B)
    assert all(e["readable"] for e in entries)
    assert {"vault.rekey", "patient.create"} <= {e["action"] for e in entries}
    assert c.get("/api/activity/verify", headers=B).json()["ok"]
    # Lock and unlock with the same passphrase: keys re-open under the new master key
    c.post("/api/vault/lock", headers=B)
    assert c.post("/api/vault/unlock", json={"passphrase": PASS}, headers=B).status_code == 200
    assert c.get("/api/activity/verify", headers=B).json()["ok"]


def test_backup_carries_log_and_restore_is_logged(vault, tmp_path):
    c, B, setup = vault
    c.post("/api/patients", json={"name": "Backed Up"}, headers=B)
    svb = tmp_path / "b.svb"
    r = c.get("/api/backups/download", headers=B)
    assert r.status_code == 200
    svb.write_bytes(r.content)
    assert "backup.download" in _actions(c, B)

    # Offline restore tool decrypts the log too
    keyf = tmp_path / "key.txt"
    keyf.write_text(setup["recovery_key"])
    out = tmp_path / "out"
    cp = subprocess.run([sys.executable, str(ROOT / "tools" / "restore.py"), "--backup", str(svb), "--key", str(keyf), "--out", str(out)], capture_output=True, text=True)
    assert cp.returncode == 0, cp.stderr
    log = json.loads((out / "activity-log.json").read_text())
    assert log["chain_ok"] and any(e["details"] and e["details"].get("patient_name") == "Backed Up" for e in log["entries"])

    # Restoring over the running vault keeps the local log and adds an entry
    n_before = len(_acts(c, B, limit=200))
    r = c.post("/api/backups/restore", files={"backup_file": ("b.svb", svb.read_bytes())}, data={"confirm": "REPLACE"}, headers=B)
    assert r.status_code == 200, r.text
    entries = _acts(c, B, limit=200)
    assert entries[0]["action"] == "backup.restore" and len(entries) == n_before + 1
    assert c.get("/api/activity/verify", headers=B).json()["ok"]


def test_fresh_install_restore_brings_log_back(vault, tmp_path):
    c, B, setup = vault
    c.post("/api/patients", json={"name": "Moved Patient"}, headers=B)
    svb = tmp_path / "b.svb"
    svb.write_bytes(c.get("/api/backups/download", headers=B).content)
    main.store = Store(tmp_path / "fresh")
    main.vault.lock()
    main.activity.forget()
    r = c.post(
        "/api/setup/restore",
        files={"backup_file": ("b.svb", svb.read_bytes())},
        data={"username": "ryan2", "password": PW, "recovery_key": setup["recovery_key"]},
        headers=SETUP,
    )
    assert r.status_code == 200, r.text
    B2 = {"Authorization": f"Bearer {r.json()['token']}"}
    entries = _acts(c, B2, limit=200)
    assert entries[0]["action"] == "backup.restore" and entries[0]["username"] == "ryan2"
    assert any(e["action"] == "patient.create" and e["patient_name"] == "Moved Patient" for e in entries)
    assert c.get("/api/activity/verify", headers=B2).json()["ok"]


def test_locked_vault_cannot_read_log(vault):
    c, B, _ = vault
    c.post("/api/vault/lock", headers=B)
    assert c.get("/api/activity", headers=B).status_code == 423
    c.cookies.clear()
    assert c.get("/api/activity").status_code == 401


def test_record_never_raises(vault, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(main.activity, "_append", boom)
    c, B, _ = vault
    assert c.post("/api/patients", json={"name": "Still works"}, headers=B).status_code == 200


def test_unit_encrypt_roundtrip():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    k = X25519PrivateKey.generate()
    pub = audit._raw_pub(k.public_key())
    blob = audit.encrypt_details(pub, {"a": 1}, 7)
    assert audit.decrypt_details(k, blob, 7) == {"a": 1}
    with pytest.raises(crypto.CryptoError):
        audit.decrypt_details(k, blob, 8)  # bound to its sequence number
