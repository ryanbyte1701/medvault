"""Regression tests for the security review and QA findings."""
import io
import json
import os
import sqlite3
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from conftest import SETUP, make_dicom

from app import backup, crypto, main, media, targets
from app.spool import Spool
from app.store import Store

PASS = "lantern-orbit-cedar-quill-x"
PW = "pw-1234567890"
PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"


def _reset_throttles():
    for t in (main.login_throttle, main.account_throttle, main.key_throttle, main.setup_throttle):
        t._fails.clear()


@pytest.fixture()
def vault(tmp_path):
    """A brand-new vault in its own data dir. Yields (client, bearer headers, setup response)."""
    old = main.store
    main.store = Store(tmp_path / "data")
    main.vault.lock()
    main._state["setup_code"] = None
    main._state["maintenance"] = None
    main._clear_caches()
    _reset_throttles()
    try:
        with TestClient(main.app) as c:
            r = c.post("/api/setup", json={"username": "ryan", "password": PW, "passphrase": PASS}, headers=SETUP)
            assert r.status_code == 200, r.text
            j = r.json()
            yield c, {"Authorization": f"Bearer {j['token']}"}, j
    finally:
        main.store = old
        main.vault.lock()
        _reset_throttles()


def _patient(c, B, name="Pat"):
    return c.post("/api/patients", json={"name": name}, headers=B).json()


# ------------------------------------------------------------------ setup and auth

def test_setup_needs_code_and_json(tmp_path):
    old = main.store
    main.store = Store(tmp_path / "d")
    main._state["setup_code"] = None
    _reset_throttles()
    try:
        with TestClient(main.app) as c:
            body = {"username": "a", "password": PW, "passphrase": PASS}
            assert c.post("/api/setup", json=body).status_code == 403
            assert c.post("/api/setup", json=body, headers={"X-Setup-Code": "WRONG-CODE"}).json()["code"] == "setup_code"
            # a cross-site form can only send text/plain
            r = c.post("/api/setup", content=json.dumps(body), headers={**SETUP, "Content-Type": "text/plain"})
            assert r.status_code == 415
            assert c.post("/api/setup", json={**body, "username": 5}, headers=SETUP).status_code == 400
            assert c.post("/api/setup", json={**body, "passphrase": " leading-space-key"}, headers=SETUP).status_code == 400
            # the code is not case or dash sensitive
            assert c.post("/api/setup", json=body, headers={"X-Setup-Code": "test code 0001"}).status_code == 200
            assert c.post("/api/setup", json=body, headers=SETUP).status_code == 409
    finally:
        main.store = old
        main.vault.lock()


def test_csrf_and_token_handling(vault):
    c, B, j = vault
    # browser sign-in: token only in the HttpOnly cookie, never in the body
    r = c.post("/api/auth/login", json={"username": "ryan", "password": PW}, headers={"X-ScanVault": "1"})
    assert r.status_code == 200 and "token" not in r.json()
    assert "httponly" in r.headers["set-cookie"].lower()
    # API client sign-in still gets the token
    assert "token" in c.post("/api/auth/login", json={"username": "ryan", "password": PW}).json()
    # cookie + a non-Bearer Authorization header must not skip the CSRF check
    r = c.post("/api/patients", json={"name": "x"}, headers={"Authorization": "Basic Zm9vOmJhcg=="})
    assert r.status_code == 403 and r.json()["code"] == "csrf"
    assert c.post("/api/patients", json={"name": "x"}, headers={"X-ScanVault": "1"}).status_code == 200
    # logout via cookie also needs the header
    assert c.post("/api/auth/logout").status_code == 403
    c.cookies.clear()


def test_login_throttling(vault):
    c, B, j = vault
    c.cookies.clear()
    codes = [c.post("/api/auth/login", json={"username": "ryan", "password": "wrong-password"}).status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[5] == 429
    r = c.post("/api/auth/login", json={"username": "ryan", "password": PW})
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0
    _reset_throttles()
    assert c.post("/api/auth/login", json={"username": "ryan", "password": PW}).status_code == 200
    # unknown users answer the same way
    assert c.post("/api/auth/login", json={"username": "nobody", "password": "x" * 12}).status_code == 401


def test_unlock_throttling(vault):
    c, B, j = vault
    codes = [c.post("/api/vault/unlock", json={"passphrase": f"nope-{i}"}, headers=B).status_code for i in range(6)]
    assert codes[:5] == [400] * 5 and codes[5] == 429
    _reset_throttles()


def test_password_change_revokes_other_sessions(vault):
    c, B, j = vault
    other = c.post("/api/auth/login", json={"username": "ryan", "password": PW}).json()["token"]
    O = {"Authorization": f"Bearer {other}"}
    assert c.get("/api/patients", headers=O).status_code == 200
    # can't reuse the encryption key as the password
    assert c.post("/api/auth/password", json={"current": PW, "new": PASS}, headers=B).status_code == 400
    r = c.post("/api/auth/password", json={"current": PW, "new": "brand-new-password"}, headers=B)
    assert r.status_code == 200 and r.json()["signed_out"] >= 1
    assert c.get("/api/patients", headers=O).status_code == 401
    assert c.get("/api/patients", headers=B).status_code == 200


def test_idle_sessions_expire(vault):
    c, B, j = vault
    tok = B["Authorization"][7:]
    main.store.conn().execute("UPDATE sessions SET last_seen=?, created_at=? WHERE token_hash=?", (time.time() - 40 * 86400, time.time() - 40 * 86400, main._th(tok)))
    assert c.get("/api/patients", headers=B).status_code == 401


def test_body_limits_and_error_format(vault):
    c, B, j = vault
    big = {"name": "x" * (2 * 1024 * 1024)}
    assert c.post("/api/patients", json=big, headers=B).status_code == 413
    r = c.get("/api/files/x/render?wc=abc", headers=B)
    assert r.status_code == 404 and "error" in r.json()
    # unauthenticated uploads are refused before the body is read
    c.cookies.clear()
    assert c.post("/api/patients/x/import", files={"file": ("a.png", b"x" * 1000)}).status_code == 401
    assert c.get("/api/files/doesnotexist").status_code == 401  # auth before lookup
    assert c.delete("/api/patients/doesnotexist", headers=B).status_code == 404
    assert c.delete("/api/studies/doesnotexist", headers=B).status_code == 404
    assert c.post("/api/patients", json={"name": "D", "date_of_birth": "not-a-date"}, headers=B).status_code == 400
    assert c.get("/api/docs").status_code == 404
    st = c.get("/api/status").json()
    assert st["vault_id"] is None  # not revealed without signing in
    assert "default-src" in c.get("/").headers["content-security-policy"]


# ------------------------------------------------------------------ data at rest

def test_spool_never_holds_plaintext(tmp_path):
    secret = b"PATIENT-NAME-ZEBULON " * 50000
    with Spool(tmp_path) as sp:
        sp.write(secret)
        sp.finish()
        assert not list(tmp_path.iterdir())  # unlinked right away
        raw = os.pread(sp._fd, sp.size + 1000, 0)
        assert b"ZEBULON" not in raw
        with sp.open() as f:
            f.seek(len(secret) - 10)
            assert f.read() == secret[-10:]
            f.seek(0)
            assert f.read() == secret


def test_file_digest_is_keyed_and_tmp_stays_empty(vault, tmp_path):
    c, B, j = vault
    p = _patient(c, B)
    s = c.post(f"/api/patients/{p['id']}/studies", json={"title": "Reports"}, headers=B).json()
    f = c.post(f"/api/studies/{s['id']}/files", files=[("file", ("report.pdf", PDF, "application/pdf"))], headers=B).json()[0]
    import hashlib

    real = hashlib.sha256(PDF).hexdigest()
    assert f["sha256"] == real
    col = main.store.conn().execute("SELECT sha256 FROM files WHERE id=?", (f["id"],)).fetchone()[0]
    assert col.startswith("h1:") and real not in col
    assert list(main.store.tmp_dir.iterdir()) == []
    # duplicates are still detected
    again = c.post(f"/api/studies/{s['id']}/files", files=[("file", ("copy.pdf", PDF, "application/pdf"))], headers=B).json()[0]
    assert again.get("duplicate")


def test_old_plain_digests_are_migrated_on_unlock(vault):
    c, B, j = vault
    p = _patient(c, B)
    s = c.post(f"/api/patients/{p['id']}/studies", json={"title": "R"}, headers=B).json()
    f = c.post(f"/api/studies/{s['id']}/files", files=[("file", ("r.pdf", PDF))], headers=B).json()[0]
    mk = main.vault.master_key
    row = main.store.conn().execute("SELECT blob FROM files WHERE id=?", (f["id"],)).fetchone()
    d = crypto.open_json(mk, row[0], f"file:{f['id']}")
    d.pop("sha256")
    main.store.conn().execute("UPDATE files SET sha256=?, blob=? WHERE id=?", (f["sha256"], crypto.seal_json(mk, d, f"file:{f['id']}"), f["id"]))
    c.post("/api/vault/lock", headers=B)
    assert c.post("/api/vault/unlock", json={"passphrase": PASS}, headers=B).status_code == 200
    col = main.store.conn().execute("SELECT sha256 FROM files WHERE id=?", (f["id"],)).fetchone()[0]
    assert col.startswith("h1:")
    assert c.get(f"/api/files/{f['id']}", headers=B).json()["sha256"] == f["sha256"]


def test_keystore_upgraded_to_stronger_kdf(vault):
    c, B, j = vault
    ks = main.store.keystore()
    assert ks["kdf"]["n"] == 2**17
    weak = dict(ks)
    old_n = crypto.SCRYPT_N
    try:
        crypto.SCRYPT_N = 2**15
        weak = crypto.wrap_master_key(main.vault.master_key, PASS, ks["vault_id"])
    finally:
        crypto.SCRYPT_N = old_n
    main.store.write_keystore({**weak, "created": ks.get("created")})
    c.post("/api/vault/lock", headers=B)
    assert c.post("/api/vault/unlock", json={"passphrase": PASS}, headers=B).status_code == 200
    assert main.store.keystore()["kdf"]["n"] == 2**17


# ------------------------------------------------------------------ uploads

def _zip(entries):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    return b.getvalue()


def test_zip_handling(vault, tmp_path):
    c, B, j = vault
    p = _patient(c, B)
    d1 = make_dicom(tmp_path / "IM1", study_uid="9.9.9", instance=1).read_bytes()
    d2 = make_dicom(tmp_path / "IM2", study_uid="9.9.9", instance=2).read_bytes()
    logo = io.BytesIO()
    Image.new("RGB", (8, 8)).save(logo, "PNG")
    inner = _zip([("IM2", d2)])
    cd = _zip([
        ("DICOM/IM1", d1),
        ("REPORTS/report.pdf", PDF),
        ("Viewer/logo.png", logo.getvalue()),
        ("nested/more.zip", inner),
        ("DICOMDIR", b"x"),
    ])
    r = c.post(f"/api/patients/{p['id']}/import", files=[("file", ("cd.zip", cd)), ("file", ("loose.pdf", PDF + b"%x"))], headers=B)
    assert r.status_code == 200, r.text
    res = r.json()
    assert len(res["studies"]) == 1, res["studies"]  # the PDFs joined the CD's study
    names = sorted(f["filename"] for f in res["files"])
    assert names == ["IM1", "IM2", "loose.pdf", "report.pdf"]
    assert any("Viewer/logo.png" in s for s in res["skipped"])
    # damaged zip -> clean 400
    r = c.post(f"/api/patients/{p['id']}/import", files=[("file", ("bad.zip", cd[: len(cd) // 2]))], headers=B)
    assert r.status_code == 400 and "ZIP" in r.json()["error"]
    # empty file
    r = c.post(f"/api/patients/{p['id']}/import", files=[("file", ("zero.dcm", b""))], headers=B)
    assert r.status_code == 400


def test_zip_bomb_is_refused(vault, monkeypatch):
    c, B, j = vault
    p = _patient(c, B)
    monkeypatch.setattr(main, "MAX_UPLOAD", 2 * 1024 * 1024)
    bomb = _zip([("a.png", b"\x89PNG" + b"\0" * (5 * 1024 * 1024))])
    assert len(bomb) < 100_000
    r = c.post(f"/api/patients/{p['id']}/import", files=[("file", ("bomb.zip", bomb))], headers=B)
    assert r.status_code == 413
    assert list(main.store.tmp_dir.iterdir()) == []


def test_filenames_are_cleaned(vault):
    c, B, j = vault
    p = _patient(c, B)
    s = c.post(f"/api/patients/{p['id']}/studies", json={"title": "R"}, headers=B).json()
    f = c.post(f"/api/studies/{s['id']}/files", files=[("file", ("..\\..\\win\\x.pdf", PDF))], headers=B).json()[0]
    assert f["filename"] == "x.pdf"
    f = c.put(f"/api/files/{f['id']}", json={"filename": "evil\r\nX-Injected: 1.pdf"}, headers=B).json()
    assert "\r" not in f["filename"] and "\n" not in f["filename"]
    r = c.get(f"/api/files/{f['id']}/content", headers=B)
    assert r.status_code == 200 and r.content == PDF


def _ybr_jpeg_dicom(path):
    from pydicom.dataset import FileDataset, FileMetaDataset
    from pydicom.encaps import encapsulate
    from pydicom.uid import JPEGBaseline8Bit, SecondaryCaptureImageStorage, generate_uid

    b = io.BytesIO()
    Image.new("RGB", (32, 32), (255, 0, 0)).save(b, "JPEG", quality=95, subsampling=2)
    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = SecondaryCaptureImageStorage
    meta.MediaStorageSOPInstanceUID = generate_uid()
    meta.TransferSyntaxUID = JPEGBaseline8Bit
    ds = FileDataset(str(path), {}, file_meta=meta, preamble=b"\0" * 128)
    ds.SOPClassUID, ds.SOPInstanceUID = meta.MediaStorageSOPClassUID, meta.MediaStorageSOPInstanceUID
    ds.StudyInstanceUID, ds.SeriesInstanceUID, ds.Modality = "7.7.7", "7.7.7.1", "XC"
    ds.Rows = ds.Columns = 32
    ds.SamplesPerPixel, ds.PhotometricInterpretation, ds.PlanarConfiguration = 3, "YBR_FULL_422", 0
    ds.BitsAllocated, ds.BitsStored, ds.HighBit, ds.PixelRepresentation = 8, 8, 7, 0
    ds.PixelData = encapsulate([b.getvalue()])
    ds["PixelData"].is_undefined_length = True
    ds.save_as(str(path), enforce_file_format=True)
    return path


def test_colour_dicom_and_render_edge_cases(vault, tmp_path):
    c, B, j = vault
    p = _patient(c, B)
    f = c.post(f"/api/patients/{p['id']}/import", files=[("file", ("c.dcm", _ybr_jpeg_dicom(tmp_path / "c.dcm").read_bytes()))], headers=B).json()["files"][0]
    r = c.get(f"/api/files/{f['id']}/render", headers=B)
    assert r.status_code == 200 and r.headers["x-rgb"] == "1"
    px = Image.open(io.BytesIO(r.content)).convert("RGB").getpixel((16, 16))
    assert px[0] > 200 and px[1] < 60 and px[2] < 60, px  # red, not green
    g = c.post(f"/api/patients/{p['id']}/import", files=[("file", ("g.dcm", make_dicom(tmp_path / "g.dcm", study_uid="5.5").read_bytes()))], headers=B).json()["files"][0]
    for q in ("wc=0&ww=0", "wc=100&ww=1", "wc=10&ww=-5"):
        r = c.get(f"/api/files/{g['id']}/render?{q}", headers=B)
        assert r.status_code == 200 and float(r.headers["x-window-width"]) >= 1
    assert c.get(f"/api/files/{g['id']}/render?wc=nan&ww=nan", headers=B).status_code == 400
    assert c.get(f"/api/files/{g['id']}/thumbnail", headers=B).headers["cache-control"] == "private, no-store"


def test_dicom_decompression_bomb_is_refused(tmp_path):
    d = make_dicom(tmp_path / "big.dcm")
    import pydicom

    ds = pydicom.dcmread(d)
    ds.Rows = ds.Columns = 60000
    ds.save_as(str(d))
    with open(d, "rb") as fp, pytest.raises(media.MediaError):
        media.dicom_pixels(fp)


def test_preambleless_dicom_detected(tmp_path):
    import pydicom
    from pydicom.filebase import DicomBytesIO
    from pydicom.filewriter import write_dataset

    ds = pydicom.dcmread(make_dicom(tmp_path / "x.dcm"))
    del ds.file_meta
    fp = DicomBytesIO()
    fp.is_little_endian, fp.is_implicit_VR = True, True
    write_dataset(fp, ds)
    bare = fp.getvalue()  # old CDs: no preamble, no DICM marker, no file meta, no extension
    assert bare[:2] == b"\x08\x00"
    assert media.sniff(io.BytesIO(bare), "IM000003")[0] == "dicom"
    assert media.sniff(io.BytesIO(b"\x08\x00hello world" * 10), "IM000004")[0] == "other"


# ------------------------------------------------------------------ backups and restore

def test_backup_header_and_wrapped_key(vault, tmp_path):
    c, B, j = vault
    _patient(c, B, "Zebulon")
    svb = tmp_path / "b.svb"
    svb.write_bytes(c.get("/api/backups/download", headers=B).content)
    hdr = backup.read_header(svb)
    assert "keystore" not in hdr and hdr["format"] == 2
    vid = main.store.keystore()["vault_id"]
    with pytest.raises(crypto.CryptoError, match="recovery key"):
        backup.master_key_for(svb, passphrase=PASS)
    assert backup.master_key_for(svb, recovery_text=j["recovery_key"])
    # tampering with the readable header breaks decryption
    raw = svb.read_bytes()
    bad = tmp_path / "bad.svb"
    bad.write_bytes(raw.replace(vid.encode(), b"SV-EVIL0", 1))
    with pytest.raises(crypto.CryptoError):
        backup.extract_archive(bad, main.vault.master_key, tmp_path / "x")
    # opt in: passphrase restore
    assert c.put("/api/vault/settings", json={"passphrase_restore": True}, headers=B).json()["passphrase_restore"]
    svb.write_bytes(c.get("/api/backups/download", headers=B).content)
    assert backup.master_key_for(svb, passphrase=PASS) == main.vault.master_key
    # sessions never leave the server
    td = tmp_path / "ex"
    backup.extract_archive(svb, main.vault.master_key, td)
    assert sqlite3.connect(td / "scanvault.db").execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


def test_restore_keeps_sessions_key_and_destinations(vault, tmp_path):
    c, B, j = vault
    lost_phone = c.post("/api/auth/login", json={"username": "ryan", "password": PW}).json()["token"]
    L = {"Authorization": f"Bearer {lost_phone}"}
    t_old = c.post("/api/backups/targets", json={"type": "sftp", "name": "old", "config": {"host": "h", "username": "u"}}, headers=B).json()
    _patient(c, B, "Keep Me")
    svb = c.get("/api/backups/download", headers=B).content
    # afterwards: revoke the phone, change the passphrase, delete a destination, add a new one
    c.post("/api/auth/logout", headers=L)
    assert c.post("/api/vault/passphrase", json={"current": PASS, "new": "a-newer-passphrase-1"}, headers=B).status_code == 200
    c.delete(f"/api/backups/targets/{t_old['id']}", headers=B)
    t_new = c.post("/api/backups/targets", json={"type": "sftp", "name": "new", "config": {"host": "h2", "username": "u"}}, headers=B).json()
    r = c.post("/api/backups/restore", files={"backup_file": ("b.svb", svb)}, data={"confirm": "REPLACE"}, headers=B)
    assert r.status_code == 200, r.text
    assert c.get("/api/patients", headers=B).status_code == 200  # restorer still signed in
    assert c.get("/api/patients", headers=L).status_code == 401  # revoked session stays revoked
    names = [t["name"] for t in c.get("/api/backups/targets", headers=B).json()]
    assert names == ["new"]
    c.post("/api/vault/lock", headers=B)
    assert c.post("/api/vault/unlock", json={"passphrase": "a-newer-passphrase-1"}, headers=B).status_code == 200


def test_setup_restore_pauses_destinations(vault, tmp_path):
    c, B, j = vault
    c.post("/api/backups/targets", json={"type": "sftp", "name": "nas", "config": {"host": "h", "username": "u"}}, headers=B)
    svb = c.get("/api/backups/download", headers=B).content
    old = main.store
    main.store = Store(tmp_path / "fresh")
    main.vault.lock()
    main._state["setup_code"] = None
    try:
        r = c.post("/api/setup/restore", files={"backup_file": ("b.svb", svb)}, data={"username": "n", "password": PW, "recovery_key": j["recovery_key"]}, headers=SETUP)
        assert r.status_code == 200, r.text
        T = {"Authorization": f"Bearer {r.json()['token']}"}
        assert [t["enabled"] for t in c.get("/api/backups/targets", headers=T).json()] == [False]
    finally:
        main.store = old


def test_deletes_during_backup_are_deferred(tmp_path):
    s = Store(tmp_path / "d")
    fid = "ab" * 16
    bp = s.blob_path(fid)
    bp.parent.mkdir(parents=True)
    bp.write_bytes(b"x")
    with s.backup_guard():
        s.remove_blobs(fid)
        assert bp.exists()
    assert not bp.exists()


def test_prune_only_touches_own_vault(tmp_path):
    d = tmp_path / "backups"
    os.environ["SCANVAULT_LOCAL_BACKUP_ROOT"] = str(d)
    try:
        mine = targets.make("local", {"path": "shared", "require_mount": False}, vault_id="SV-AAAA0000")
        theirs = targets.make("local", {"path": "shared", "require_mount": False}, vault_id="SV-BBBB1111")
        src = tmp_path / "a.svb"
        src.write_bytes(b"x")
        for ts in (1, 2, 3):
            mine.upload(src, backup.backup_name("SV-AAAA0000", 1_700_000_000 + ts))
            theirs.upload(src, backup.backup_name("SV-BBBB1111", 1_700_000_000 + ts))
        assert mine.prune(1) == 2
        left = sorted(p.name for p in (d / "shared").iterdir())
        assert sum("SV-AAAA0000" in n for n in left) == 1 and sum("SV-BBBB1111" in n for n in left) == 3
    finally:
        os.environ.pop("SCANVAULT_LOCAL_BACKUP_ROOT", None)


def test_unique_backup_names():
    names = {backup.backup_name("SV-X", 1_700_000_000) for _ in range(50)}
    assert len(names) > 40


def test_scheduler_retries_failures_sooner():
    now = time.time()
    row = {"last_run": now - 2 * 3600, "schedule_hours": 24, "last_status": "error"}
    assert main._due(row, now)
    assert not main._due({**row, "last_status": "ok"}, now)


def test_merge_config_secrets(vault):
    cfg = main._merge_config("sftp", {"host": "h", "port": None, "password": "p", "host_key": "SHA256:x"}, {"port": 22, "password": ""})
    assert cfg["password"] == "p" and cfg["host_key"] == "SHA256:x"  # same port: pin kept
    cfg = main._merge_config("sftp", cfg, {"password": None})
    assert "password" not in cfg  # null clears a secret
    cfg = main._merge_config("sftp", cfg, {"password": "  spaced  "})
    assert cfg["password"] == "  spaced  "


# ------------------------------------------------------------------ key rotation

def test_rekey(vault, tmp_path):
    c, B, j = vault
    p = _patient(c, B, "Rekey Patient")
    s = c.post(f"/api/patients/{p['id']}/studies", json={"title": "R"}, headers=B).json()
    f = c.post(f"/api/studies/{s['id']}/files", files=[("file", ("r.pdf", PDF))], headers=B).json()[0]
    t = c.post("/api/backups/targets", json={"type": "sftp", "name": "nas", "config": {"host": "h", "username": "u", "password": "pw"}}, headers=B).json()
    old_mk = main.vault.master_key
    r = c.post("/api/vault/rekey", json={"passphrase": PASS, "new_passphrase": "rotated-passphrase-9"}, headers=B)
    assert r.status_code == 200, r.text
    new_rec = r.json()["recovery_key"]
    assert main.vault.master_key != old_mk
    assert c.get(f"/api/files/{f['id']}/content", headers=B).content == PDF
    assert c.get("/api/patients", headers=B).json()[0]["name"] == "Rekey Patient"
    assert c.get("/api/backups/targets", headers=B).json()[0]["secrets_set"]["password"]
    assert c.get("/api/status", headers=B).json()["recovery_key_saved"] is False
    c.post("/api/vault/lock", headers=B)
    assert c.post("/api/vault/unlock", json={"recovery_key": j["recovery_key"]}, headers=B).status_code == 400
    assert c.post("/api/vault/unlock", json={"passphrase": PASS}, headers=B).status_code == 400
    assert c.post("/api/vault/unlock", json={"recovery_key": new_rec}, headers=B).status_code == 200
    assert c.post("/api/vault/recovery-key", json={"passphrase": "rotated-passphrase-9"}, headers=B).status_code == 200
    assert not list(main.store.dir.glob("rekey*"))


def test_rekey_crash_recovery(vault):
    c, B, j = vault
    # a journal without a committed DB change is rolled back
    jid = "deadbeef"
    work, nks, journal = main._rekey_paths(jid)
    (work / "files").mkdir(parents=True)
    nks.write_text("{}")
    journal.write_text(json.dumps({"id": jid}))
    main._recover_rekey()
    assert not work.exists() and not nks.exists() and not journal.exists()


def test_passphrase_file_edge_cases(vault, tmp_path, monkeypatch, caplog):
    c, B, j = vault
    main.vault.lock()
    d = tmp_path / "secret-dir"
    d.mkdir()
    monkeypatch.setenv("SCANVAULT_PASSPHRASE_FILE", str(d))
    main._auto_unlock()  # a directory (missing bind-mount source) must not crash
    assert not main.vault.unlocked
    monkeypatch.setenv("SCANVAULT_PASSPHRASE_FILE", str(tmp_path / "missing"))
    main._auto_unlock()
    assert "does not exist" in caplog.text
    pf = tmp_path / "pass.txt"
    pf.write_text(PASS + "\r\n")
    monkeypatch.setenv("SCANVAULT_PASSPHRASE_FILE", str(pf))
    main._auto_unlock()
    assert main.vault.unlocked
