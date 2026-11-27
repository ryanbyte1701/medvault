"""ScanVault server."""
from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import os
import secrets
import shutil
import tempfile
import threading
import time
import zipfile
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.background import BackgroundTask

from . import backup, crypto, media, sso, targets
from .store import Store, seal, unseal

VERSION = "0.1.0"
log = logging.getLogger("scanvault")
logging.basicConfig(level=os.environ.get("SCANVAULT_LOG_LEVEL", "INFO"))

SESSION_DAYS = 30
MAX_UPLOAD = int(os.environ.get("SCANVAULT_MAX_UPLOAD_MB", "2048")) * 1024 * 1024
PUBLIC_URL = os.environ.get("SCANVAULT_PUBLIC_URL", "").rstrip("/")
COOKIE_SECURE = os.environ.get("SCANVAULT_COOKIE_SECURE", "auto")
MIN_PASSPHRASE = 12

app = FastAPI(title="ScanVault", version=VERSION, docs_url="/api/docs", openapi_url="/api/openapi.json")
store = Store()
vault = crypto.Vault()
backup_lock = threading.Lock()


class ApiError(Exception):
    def __init__(self, status: int, msg: str, code: str | None = None):
        self.status, self.msg, self.code = status, msg, code


@app.exception_handler(ApiError)
async def _api_error(_, exc: ApiError):
    body = {"error": exc.msg}
    if exc.code:
        body["code"] = exc.code
    return JSONResponse(body, status_code=exc.status)


@app.exception_handler(crypto.CryptoError)
async def _crypto_error(_, exc):
    return JSONResponse({"error": str(exc)}, status_code=400)


@app.exception_handler(targets.TargetError)
async def _target_error(_, exc):
    return JSONResponse({"error": str(exc)}, status_code=502)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    if request.url.path.startswith("/api/"):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


# =================================================================== helpers

def iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None


def setup_complete() -> bool:
    return store.keystore() is not None and store.get_config("setup_complete", False)


def mk() -> bytes:
    if not vault.unlocked:
        raise ApiError(423, "Vault is locked", "locked")
    return vault.master_key  # type: ignore[return-value]


def _token_from(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.cookies.get("sv_session")


def current_user(request: Request) -> dict | None:
    tok = _token_from(request)
    if not tok:
        return None
    th = hashlib.sha256(tok.encode()).hexdigest()
    r = store.conn().execute(
        "SELECT u.id, u.username, u.role, s.expires_at, s.created_at AS session_created, s.identity_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",
        (th,),
    ).fetchone()
    if not r or r["expires_at"] < time.time():
        return None
    return dict(r)


def require_user(request: Request) -> dict:
    if not setup_complete():
        raise ApiError(409, "ScanVault has not been set up yet", "setup_required")
    u = current_user(request)
    if not u:
        raise ApiError(401, "Not signed in", "unauthenticated")
    # Cookie-authenticated state-changing requests must carry the CSRF header.
    if request.method not in ("GET", "HEAD") and not request.headers.get("authorization"):
        if request.headers.get("x-scanvault") != "1":
            raise ApiError(403, "Missing X-ScanVault header", "csrf")
    return u


def data_access(request: Request) -> bytes:
    require_user(request)
    return mk()


def new_session(user_id: str, identity_id: str | None = None) -> tuple[str, float]:
    tok = secrets.token_urlsafe(32)
    exp = time.time() + SESSION_DAYS * 86400
    store.conn().execute(
        "INSERT INTO sessions(token_hash,user_id,created_at,expires_at,identity_id) VALUES(?,?,?,?,?)",
        (hashlib.sha256(tok.encode()).hexdigest(), user_id, time.time(), exp, identity_id),
    )
    return tok, exp


def _secure(request: Request) -> bool:
    if COOKIE_SECURE == "auto":
        return request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    return COOKIE_SECURE.lower() in ("1", "true", "yes")


def session_response(request: Request, body: dict, tok: str, exp: float) -> JSONResponse:
    resp = JSONResponse(body)
    resp.set_cookie("sv_session", tok, max_age=SESSION_DAYS * 86400, httponly=True, samesite="strict", secure=_secure(request))
    return resp


async def body_json(request: Request) -> dict:
    try:
        j = await request.json()
    except Exception:
        raise ApiError(400, "Expected a JSON body")
    if not isinstance(j, dict):
        raise ApiError(400, "Expected a JSON object")
    return j


def _str(v, maxlen=2000) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s[:maxlen] if s else None


def recovery_text(master_key: bytes) -> str:
    ks = store.keystore()
    return crypto.recovery_file_text(master_key, ks["vault_id"], ks.get("created", ""))


# =================================================================== status/setup

@app.get("/api/health")
def health():
    return {"status": "ok", "version": VERSION}


@app.get("/api/status")
def status(request: Request):
    ks = store.keystore()
    u = current_user(request) if setup_complete() else None
    return {
        "setup_complete": setup_complete(),
        "unlocked": vault.unlocked,
        "authenticated": bool(u),
        "username": u["username"] if u else None,
        "vault_id": ks["vault_id"] if ks else None,
        "fingerprint": ks["fingerprint"] if (ks and u) else None,
        "recovery_key_saved": bool(store.get_config("recovery_key_saved", False)) if u else None,
        "local_login": local_login_enabled(),
        "sso": [_sso_public(p) for p in _sso_providers()] if setup_complete() else [],
        "version": VERSION,
    }


def _validate_new_account(username: str, password: str) -> None:
    if not username or len(username) > 64:
        raise ApiError(400, "Choose a username")
    if len(password) < 10:
        raise ApiError(400, "Password must be at least 10 characters")


@app.post("/api/setup")
async def setup(request: Request):
    if setup_complete():
        raise ApiError(409, "Already set up")
    j = await body_json(request)
    username = (j.get("username") or "").strip()
    password = j.get("password") or ""
    passphrase = j.get("passphrase") or ""
    _validate_new_account(username, password)
    if len(passphrase) < MIN_PASSPHRASE:
        raise ApiError(400, f"Encryption key must be at least {MIN_PASSPHRASE} characters")
    if passphrase == password:
        raise ApiError(400, "Use a different value for the encryption key and the sign-in password")
    master = crypto.new_master_key()
    vault_id = "SV-" + secrets.token_hex(4).upper()
    ks = crypto.wrap_master_key(master, passphrase, vault_id)
    ks["created"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    store.write_keystore(ks)
    c = store.conn()
    uid = crypto.random_id()
    c.execute("DELETE FROM user_identities")
    c.execute("DELETE FROM users")
    c.execute(
        "INSERT INTO users(id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)",
        (uid, username, crypto.hash_password(password), "admin", time.time()),
    )
    store.set_config("setup_complete", True)
    store.set_config("recovery_key_saved", False)
    vault.master_key = master
    tok, exp = new_session(uid)
    return session_response(
        request,
        {"token": tok, "expires_at": iso(exp), "vault_id": vault_id, "fingerprint": ks["fingerprint"], "recovery_key": recovery_text(master)},
        tok,
        exp,
    )


@app.post("/api/setup/restore")
async def setup_restore(
    request: Request,
    backup_file: UploadFile = File(...),
    username: str = Form(...),
    password: str = Form(...),
    passphrase: Optional[str] = Form(None),
    recovery_file: Optional[UploadFile] = File(None),
    recovery_key: Optional[str] = Form(None),
):
    """Fresh install: restore a .svb backup, then create/replace the admin login."""
    if setup_complete():
        raise ApiError(409, "Already set up. Restoring over an existing vault is done from Backups > Restore.")
    username = username.strip()
    _validate_new_account(username, password)
    rec_text = recovery_key or (await recovery_file.read()).decode("utf-8", "replace") if (recovery_key or recovery_file) else None
    archive = await _save_upload(backup_file)
    try:
        master = backup.master_key_for(archive, passphrase=passphrase, recovery_text=rec_text)
        header = backup.restore_into_store(store, archive, master)
    finally:
        archive.unlink(missing_ok=True)
    c = store.conn()
    c.execute("DELETE FROM sessions")
    c.execute("DELETE FROM user_identities")  # SSO links belonged to the replaced login
    c.execute("DELETE FROM users")
    _sso_save({**_sso_cfg(), "local_login": True})
    uid = crypto.random_id()
    c.execute(
        "INSERT INTO users(id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)",
        (uid, username, crypto.hash_password(password), "admin", time.time()),
    )
    store.set_config("setup_complete", True)
    vault.master_key = master
    tok, exp = new_session(uid)
    counts = _counts()
    return session_response(request, {"token": tok, "expires_at": iso(exp), "restored": header["created"], **counts}, tok, exp)


# =================================================================== auth

@app.post("/api/auth/login")
async def login(request: Request):
    if not setup_complete():
        raise ApiError(409, "ScanVault has not been set up yet", "setup_required")
    if not local_login_enabled():
        raise ApiError(403, "Password sign-in is turned off. Use single sign-on.", "local_login_disabled")
    j = await body_json(request)
    r = store.conn().execute("SELECT * FROM users WHERE username=?", ((j.get("username") or "").strip(),)).fetchone()
    if not r or not crypto.verify_password(j.get("password") or "", r["password_hash"]):
        await asyncio.sleep(0.5)
        raise ApiError(401, "Wrong username or password")
    tok, exp = new_session(r["id"])
    return session_response(request, {"token": tok, "expires_at": iso(exp), "unlocked": vault.unlocked}, tok, exp)


@app.post("/api/auth/logout")
def logout(request: Request):
    tok = _token_from(request)
    if tok:
        store.conn().execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(tok.encode()).hexdigest(),))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("sv_session")
    return resp


@app.post("/api/auth/password")
async def change_password(request: Request):
    u = require_user(request)
    j = await body_json(request)
    r = store.conn().execute("SELECT password_hash FROM users WHERE id=?", (u["id"],)).fetchone()
    if not crypto.verify_password(j.get("current") or "", r["password_hash"]):
        raise ApiError(400, "Current password is wrong")
    new = j.get("new") or ""
    _validate_new_account(u["username"], new)
    store.conn().execute("UPDATE users SET password_hash=? WHERE id=?", (crypto.hash_password(new), u["id"]))
    return {"ok": True}


# =================================================================== vault

@app.post("/api/vault/unlock")
async def unlock(request: Request):
    require_user(request)
    j = await body_json(request)
    ks = store.keystore()
    if j.get("recovery_key"):
        master = crypto.parse_recovery_file(j["recovery_key"])
        if crypto.fingerprint(master) != ks["fingerprint"]:
            raise ApiError(400, "That recovery key belongs to a different vault")
    else:
        try:
            master = crypto.unwrap_master_key(ks, j.get("passphrase") or "")
        except crypto.CryptoError:
            await asyncio.sleep(0.5)
            raise ApiError(400, "Wrong encryption key")
    vault.master_key = master
    return {"unlocked": True}


@app.post("/api/vault/lock")
def lock(request: Request):
    require_user(request)
    vault.lock()
    return {"unlocked": False}


@app.post("/api/vault/recovery-key")
async def get_recovery_key(request: Request):
    """Re-download the recovery key file. Requires the encryption passphrase."""
    require_user(request)
    j = await body_json(request)
    try:
        master = crypto.unwrap_master_key(store.keystore(), j.get("passphrase") or "")
    except crypto.CryptoError:
        await asyncio.sleep(0.5)
        raise ApiError(400, "Wrong encryption key")
    return PlainTextResponse(recovery_text(master), headers={"Content-Disposition": 'attachment; filename="scanvault-recovery-key.txt"'})


@app.post("/api/vault/recovery-key/confirm")
async def confirm_recovery_key(request: Request):
    """The user proves they saved the file by pasting/uploading it back."""
    require_user(request)
    j = await body_json(request)
    if j.get("recovery_key"):
        master = crypto.parse_recovery_file(j["recovery_key"])
        if crypto.fingerprint(master) != store.keystore()["fingerprint"]:
            raise ApiError(400, "That key file belongs to a different vault")
    elif not j.get("skip"):
        raise ApiError(400, "Upload the recovery key file to confirm")
    store.set_config("recovery_key_saved", bool(j.get("recovery_key")))
    return {"ok": True}


@app.post("/api/vault/passphrase")
async def change_passphrase(request: Request):
    """Re-wrap the master key under a new passphrase. Data and backups stay
    valid and the recovery key file does not change."""
    require_user(request)
    j = await body_json(request)
    ks = store.keystore()
    try:
        master = crypto.unwrap_master_key(ks, j.get("current") or "")
    except crypto.CryptoError:
        raise ApiError(400, "Current encryption key is wrong")
    new = j.get("new") or ""
    if len(new) < MIN_PASSPHRASE:
        raise ApiError(400, f"Encryption key must be at least {MIN_PASSPHRASE} characters")
    nks = crypto.wrap_master_key(master, new, ks["vault_id"])
    nks["created"] = ks.get("created")
    store.write_keystore(nks)
    return {"ok": True}


# =================================================================== patients

def _patient_out(row, master: bytes, counts: dict | None = None) -> dict:
    d = unseal(master, row["blob"], f"patient:{row['id']}")
    out = {
        "id": row["id"],
        "name": d.get("name"),
        "date_of_birth": d.get("date_of_birth"),
        "mrn": d.get("mrn"),
        "sex": d.get("sex"),
        "notes": d.get("notes"),
        "created_at": iso(row["created_at"]),
        "updated_at": iso(row["updated_at"]),
    }
    if counts is not None:
        out.update(counts.get(row["id"], {"study_count": 0, "file_count": 0, "last_study_date": None}))
    return out


def _patient_fields(j: dict, existing: dict | None = None) -> dict:
    d = dict(existing or {})
    for k in ("name", "date_of_birth", "mrn", "sex", "notes"):
        if k in j:
            d[k] = _str(j[k], 5000 if k == "notes" else 200)
    if not d.get("name"):
        raise ApiError(400, "Patient name is required")
    return d


def _patient_counts(master: bytes) -> dict:
    c = store.conn()
    out: dict = {}
    for r in c.execute("SELECT patient_id, COUNT(*) n FROM studies GROUP BY patient_id"):
        out.setdefault(r["patient_id"], {"study_count": 0, "file_count": 0, "last_study_date": None})["study_count"] = r["n"]
    for r in c.execute("SELECT patient_id, COUNT(*) n FROM files GROUP BY patient_id"):
        out.setdefault(r["patient_id"], {"study_count": 0, "file_count": 0, "last_study_date": None})["file_count"] = r["n"]
    for r in c.execute("SELECT id, patient_id, blob FROM studies"):
        sd = unseal(master, r["blob"], f"study:{r['id']}").get("study_date")
        e = out.setdefault(r["patient_id"], {"study_count": 0, "file_count": 0, "last_study_date": None})
        if sd and (not e["last_study_date"] or sd > e["last_study_date"]):
            e["last_study_date"] = sd
    return out


@app.get("/api/patients")
def list_patients(request: Request):
    master = data_access(request)
    counts = _patient_counts(master)
    rows = store.conn().execute("SELECT * FROM patients").fetchall()
    out = [_patient_out(r, master, counts) for r in rows]
    out.sort(key=lambda p: (p["name"] or "").lower())
    return out


@app.post("/api/patients")
async def create_patient(request: Request):
    master = data_access(request)
    d = _patient_fields(await body_json(request))
    pid, now = crypto.random_id(), time.time()
    store.conn().execute(
        "INSERT INTO patients(id,created_at,updated_at,blob) VALUES(?,?,?,?)", (pid, now, now, seal(master, d, f"patient:{pid}"))
    )
    return _get_patient(pid, master)


def _get_patient(pid: str, master: bytes) -> dict:
    r = store.conn().execute("SELECT * FROM patients WHERE id=?", (pid,)).fetchone()
    if not r:
        raise ApiError(404, "Patient not found")
    return _patient_out(r, master, _patient_counts(master))


@app.get("/api/patients/{pid}")
def get_patient(pid: str, request: Request):
    return _get_patient(pid, data_access(request))


@app.put("/api/patients/{pid}")
async def update_patient(pid: str, request: Request):
    master = data_access(request)
    r = store.conn().execute("SELECT * FROM patients WHERE id=?", (pid,)).fetchone()
    if not r:
        raise ApiError(404, "Patient not found")
    d = _patient_fields(await body_json(request), unseal(master, r["blob"], f"patient:{pid}"))
    store.conn().execute("UPDATE patients SET blob=?, updated_at=? WHERE id=?", (seal(master, d, f"patient:{pid}"), time.time(), pid))
    return _get_patient(pid, master)


@app.delete("/api/patients/{pid}")
def delete_patient(pid: str, request: Request):
    data_access(request)
    for f in store.conn().execute("SELECT id FROM files WHERE patient_id=?", (pid,)).fetchall():
        _remove_blobs(f["id"])
    store.conn().execute("DELETE FROM patients WHERE id=?", (pid,))
    return {"ok": True}


# =================================================================== studies

STUDY_KEYS = ("title", "modality", "study_date", "facility", "description", "study_uid", "accession", "body_part", "referring_physician")


def _study_out(row, master: bytes, file_count: int | None = None) -> dict:
    d = unseal(master, row["blob"], f"study:{row['id']}")
    out = {"id": row["id"], "patient_id": row["patient_id"], "created_at": iso(row["created_at"])}
    for k in STUDY_KEYS:
        out[k] = d.get(k)
    if file_count is None:
        file_count = store.conn().execute("SELECT COUNT(*) FROM files WHERE study_id=?", (row["id"],)).fetchone()[0]
    out["file_count"] = file_count
    return out


def _study_fields(j: dict, existing: dict | None = None) -> dict:
    d = dict(existing or {})
    for k in STUDY_KEYS:
        if k in j:
            d[k] = _str(j[k], 2000 if k == "description" else 200)
    if not d.get("title"):
        parts = [d.get("modality"), d.get("description") or d.get("body_part")]
        d["title"] = " ".join(p for p in parts if p) or "Imaging study"
    return d


def _insert_study(pid: str, d: dict, master: bytes) -> str:
    sid = crypto.random_id()
    store.conn().execute(
        "INSERT INTO studies(id,patient_id,created_at,blob) VALUES(?,?,?,?)", (sid, pid, time.time(), seal(master, d, f"study:{sid}"))
    )
    return sid


@app.get("/api/patients/{pid}/studies")
def list_studies(pid: str, request: Request):
    master = data_access(request)
    _get_patient(pid, master)
    counts = {r["study_id"]: r["n"] for r in store.conn().execute("SELECT study_id, COUNT(*) n FROM files WHERE patient_id=? GROUP BY study_id", (pid,))}
    rows = store.conn().execute("SELECT * FROM studies WHERE patient_id=?", (pid,)).fetchall()
    out = [_study_out(r, master, counts.get(r["id"], 0)) for r in rows]
    out.sort(key=lambda s: (s["study_date"] or "", s["created_at"] or ""), reverse=True)
    return out


@app.post("/api/patients/{pid}/studies")
async def create_study(pid: str, request: Request):
    master = data_access(request)
    _get_patient(pid, master)
    sid = _insert_study(pid, _study_fields(await body_json(request)), master)
    return _get_study(sid, master)


def _study_row(sid: str):
    r = store.conn().execute("SELECT * FROM studies WHERE id=?", (sid,)).fetchone()
    if not r:
        raise ApiError(404, "Study not found")
    return r


def _get_study(sid: str, master: bytes) -> dict:
    return _study_out(_study_row(sid), master)


@app.get("/api/studies/{sid}")
def get_study(sid: str, request: Request):
    return _get_study(sid, data_access(request))


@app.put("/api/studies/{sid}")
async def update_study(sid: str, request: Request):
    master = data_access(request)
    r = _study_row(sid)
    d = _study_fields(await body_json(request), unseal(master, r["blob"], f"study:{sid}"))
    store.conn().execute("UPDATE studies SET blob=? WHERE id=?", (seal(master, d, f"study:{sid}"), sid))
    return _get_study(sid, master)


@app.delete("/api/studies/{sid}")
def delete_study(sid: str, request: Request):
    data_access(request)
    for f in store.conn().execute("SELECT id FROM files WHERE study_id=?", (sid,)).fetchall():
        _remove_blobs(f["id"])
    store.conn().execute("DELETE FROM studies WHERE id=?", (sid,))
    return {"ok": True}


# =================================================================== files

KIND_MAP = {"pdf": "report", "image": "image", "dicom": "dicom"}


def _file_out(row, master: bytes) -> dict:
    d = unseal(master, row["blob"], f"file:{row['id']}")
    out = {
        "id": row["id"],
        "study_id": row["study_id"],
        "patient_id": row["patient_id"],
        "filename": d.get("filename"),
        "content_type": d.get("content_type"),
        "size_bytes": row["size"],
        "kind": row["kind"],
        "sha256": row["sha256"],
        "has_thumbnail": bool(row["has_preview"]),
        "uploaded_at": iso(row["created_at"]),
    }
    if d.get("dicom"):
        out["dicom"] = d["dicom"]
    return out


async def _save_upload(up: UploadFile) -> Path:
    fd, name = tempfile.mkstemp(dir=store.tmp_dir)
    total = 0
    with os.fdopen(fd, "wb") as f:
        while chunk := await up.read(1 << 20):
            total += len(chunk)
            if total > MAX_UPLOAD:
                f.close()
                os.unlink(name)
                raise ApiError(413, f"File too large (limit {MAX_UPLOAD // (1024 * 1024)} MB)")
            f.write(chunk)
    return Path(name)


def _ingest(path: Path, filename: str, pid: str, sid: str | None, master: bytes, kind_hint: str | None = None) -> dict:
    """Encrypt a plaintext temp file into the vault. If sid is None the study is
    chosen automatically (DICOM StudyInstanceUID, else 'Uploads <date>')."""
    kind_raw, mime = media.sniff(path, filename)
    kind = KIND_MAP.get(kind_raw, "other")
    if kind_hint in ("image", "report", "dicom", "other") and kind == "other":
        kind = kind_hint
    meta = media.dicom_meta(path) if kind == "dicom" else {}
    if sid is None:
        sid = _auto_study(pid, meta, master)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while b := f.read(1 << 20):
            h.update(b)
    digest = h.hexdigest()
    dup = store.conn().execute("SELECT id FROM files WHERE study_id=? AND sha256=?", (sid, digest)).fetchone()
    if dup:
        return {"duplicate": True, **_file_out(store.conn().execute("SELECT * FROM files WHERE id=?", (dup["id"],)).fetchone(), master)}
    fid = crypto.random_id() + crypto.random_id()
    bp = store.blob_path(fid)
    bp.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "rb") as src, open(bp, "wb") as dst:
        size = crypto.encrypt_stream(master, src, dst, f"file:{fid}".encode())
    preview = media.render_preview(path, kind_raw)
    if preview:
        pp = store.preview_path(fid)
        pp.parent.mkdir(parents=True, exist_ok=True)
        with open(pp, "wb") as dst:
            crypto.encrypt_stream(master, io.BytesIO(preview), dst, f"preview:{fid}".encode())
    blob = {"filename": os.path.basename(filename) or "file", "content_type": mime}
    if meta:
        blob["dicom"] = {k: v for k, v in meta.items() if v}
    store.conn().execute(
        "INSERT INTO files(id,study_id,patient_id,kind,size,sha256,has_preview,created_at,blob) VALUES(?,?,?,?,?,?,?,?,?)",
        (fid, sid, pid, kind, size, digest, 1 if preview else 0, time.time(), seal(master, blob, f"file:{fid}")),
    )
    return _file_out(store.conn().execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone(), master)


def _auto_study(pid: str, meta: dict, master: bytes) -> str:
    rows = store.conn().execute("SELECT * FROM studies WHERE patient_id=?", (pid,)).fetchall()
    if meta.get("study_uid"):
        for r in rows:
            if unseal(master, r["blob"], f"study:{r['id']}").get("study_uid") == meta["study_uid"]:
                return r["id"]
        return _insert_study(
            pid,
            _study_fields(
                {
                    "modality": meta.get("modality"),
                    "study_date": meta.get("study_date"),
                    "facility": meta.get("institution"),
                    "description": meta.get("study_description"),
                    "study_uid": meta.get("study_uid"),
                    "accession": meta.get("accession"),
                    "body_part": meta.get("body_part"),
                    "referring_physician": meta.get("referring_physician"),
                    "title": " ".join(x for x in (meta.get("modality"), meta.get("study_description") or meta.get("body_part")) if x) or None,
                }
            ),
            master,
        )
    today = datetime.now().strftime("%Y-%m-%d")
    title = f"Uploads {today}"
    for r in rows:
        d = unseal(master, r["blob"], f"study:{r['id']}")
        if d.get("title") == title and not d.get("study_uid"):
            return r["id"]
    return _insert_study(pid, {"title": title, "study_date": today}, master)


def _expand_and_ingest(path: Path, filename: str, pid: str, sid: str | None, master: bytes, kind: str | None, res: dict) -> None:
    kind_raw, _ = media.sniff(path, filename)
    if kind_raw != "zip":
        f = _ingest(path, filename, pid, sid, master, kind)
        res["files"].append(f)
        if f["study_id"] not in res["_sids"]:
            res["_sids"].append(f["study_id"])
        return
    with zipfile.ZipFile(path) as z:
        members = [m for m in z.infolist() if not m.is_dir()]
        if len(members) > 20000:
            raise ApiError(400, "ZIP has too many entries")
        for m in members:
            base = os.path.basename(m.filename)
            if not base or base.startswith(".") or "__MACOSX" in m.filename or base.upper() in ("DICOMDIR", "AUTORUN.INF", "LOCKFILE", "VERSION"):
                res["skipped"].append(m.filename)
                continue
            if base.lower().endswith((".exe", ".dll", ".ini", ".inf", ".htm", ".html", ".js", ".css", ".xml", ".jar", ".class", ".bat", ".sh", ".cmd")):
                res["skipped"].append(m.filename)
                continue
            fd, tmp = tempfile.mkstemp(dir=store.tmp_dir)
            try:
                with os.fdopen(fd, "wb") as out, z.open(m) as src:
                    shutil.copyfileobj(src, out)
                k, _ = media.sniff(Path(tmp), base)
                if k in ("other", "zip"):
                    res["skipped"].append(m.filename)
                    continue
                f = _ingest(Path(tmp), base, pid, sid, master, None)
                res["files"].append(f)
                if f["study_id"] not in res["_sids"]:
                    res["_sids"].append(f["study_id"])
            finally:
                os.unlink(tmp)


@app.post("/api/studies/{sid}/files")
async def upload_files(sid: str, request: Request, file: list[UploadFile] = File(...), kind: Optional[str] = Form(None)):
    master = data_access(request)
    st = _study_row(sid)
    res = {"files": [], "skipped": [], "_sids": []}
    for up in file:
        p = await _save_upload(up)
        try:
            await asyncio.to_thread(_expand_and_ingest, p, up.filename or "file", st["patient_id"], sid, master, kind, res)
        finally:
            p.unlink(missing_ok=True)
    res.pop("_sids")
    return res["files"] if request.query_params.get("format") != "full" else res


@app.post("/api/patients/{pid}/import")
async def import_files(pid: str, request: Request, file: list[UploadFile] = File(...)):
    master = data_access(request)
    _get_patient(pid, master)
    res = {"files": [], "skipped": [], "_sids": []}
    saved = []
    try:
        for up in file:
            saved.append((await _save_upload(up), up.filename or "file"))
        # DICOM and CD/zip exports first; if they all belong to one study, the
        # loose reports/photos uploaded alongside them join that study.
        imaging = [(p, n) for p, n in saved if media.sniff(p, n)[0] in ("dicom", "zip")]
        loose = [(p, n) for p, n in saved if (p, n) not in imaging]
        for p, n in imaging:
            await asyncio.to_thread(_expand_and_ingest, p, n, pid, None, master, None, res)
        target = res["_sids"][0] if len(res["_sids"]) == 1 else None
        for p, n in loose:
            await asyncio.to_thread(_expand_and_ingest, p, n, pid, target, master, None, res)
    finally:
        for p, _ in saved:
            p.unlink(missing_ok=True)
    res["studies"] = [_get_study(s, master) for s in res.pop("_sids")]
    return res


@app.get("/api/studies/{sid}/files")
def list_files(sid: str, request: Request):
    master = data_access(request)
    _study_row(sid)
    rows = store.conn().execute("SELECT * FROM files WHERE study_id=? ORDER BY created_at", (sid,)).fetchall()
    out = [_file_out(r, master) for r in rows]

    def key(f):
        d = f.get("dicom") or {}
        try:
            inst = int(d.get("instance_number") or 0)
        except ValueError:
            inst = 0
        return ({"report": 0, "dicom": 2}.get(f["kind"], 1), d.get("series_description") or "", inst, f["filename"] or "")

    out.sort(key=key)
    return out


def _file_row(fid: str):
    r = store.conn().execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
    if not r:
        raise ApiError(404, "File not found")
    return r


@app.get("/api/files/{fid}")
def file_meta(fid: str, request: Request):
    return _file_out(_file_row(fid), data_access(request))


def _stream(path: Path, master: bytes, aad: bytes):
    def gen():
        with open(path, "rb") as f:
            yield from crypto.decrypt_stream_iter(master, f, aad)

    return gen()


@app.get("/api/files/{fid}/content")
def file_content(fid: str, request: Request, download: int = 0):
    master = data_access(request)
    row = _file_row(fid)
    f = _file_out(row, master)
    ctype = f["content_type"] or "application/octet-stream"
    inline_ok = ctype.startswith("image/") and ctype != "image/svg+xml" or ctype == "application/pdf"
    if not inline_ok:
        download = 1
        if ctype.startswith("text/") or "xml" in ctype or "html" in ctype or "javascript" in ctype:
            ctype = "application/octet-stream"
    disp = "attachment" if download else "inline"
    safe = (f["filename"] or "file").replace('"', "")
    ascii_name = safe.encode("ascii", "replace").decode()
    from urllib.parse import quote

    headers = {
        "Content-Disposition": f"{disp}; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(safe)}",
        "Content-Length": str(row["size"]),
        "Content-Security-Policy": "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; object-src 'self'",
        "Cache-Control": "private, no-store",
    }
    return StreamingResponse(_stream(store.blob_path(fid), master, f"file:{fid}".encode()), media_type=ctype, headers=headers)


@app.get("/api/files/{fid}/thumbnail")
def file_thumb(fid: str, request: Request):
    master = data_access(request)
    row = _file_row(fid)
    if not row["has_preview"]:
        raise ApiError(404, "No thumbnail for this file")
    return StreamingResponse(_stream(store.preview_path(fid), master, f"preview:{fid}".encode()), media_type="image/jpeg", headers={"Cache-Control": "private, max-age=3600"})


_pix_cache: "OrderedDict[tuple, tuple]" = OrderedDict()
_pix_lock = threading.Lock()
PIX_CACHE_BYTES = int(os.environ.get("SCANVAULT_RENDER_CACHE_MB", "256")) * 1024 * 1024


def _decoded(fid: str, master: bytes, frame: int | None):
    """Decrypt + decode a DICOM, keeping a few recent ones in memory (never on disk)."""
    key = (fid, frame)
    with _pix_lock:
        if key in _pix_cache:
            _pix_cache.move_to_end(key)
            return _pix_cache[key]
    fd, tmp = tempfile.mkstemp(dir=store.tmp_dir)
    try:
        with os.fdopen(fd, "wb") as out, open(store.blob_path(fid), "rb") as src:
            crypto.decrypt_stream(master, src, out, f"file:{fid}".encode())
        val = media.dicom_pixels(Path(tmp), frame)
    finally:
        os.unlink(tmp)
    with _pix_lock:
        _pix_cache[key] = val
        while sum(v[0].nbytes for v in _pix_cache.values()) > PIX_CACHE_BYTES and len(_pix_cache) > 1:
            _pix_cache.popitem(last=False)
    return val


@app.get("/api/files/{fid}/render")
async def file_render(fid: str, request: Request, wc: Optional[float] = None, ww: Optional[float] = None, frame: Optional[int] = None, invert: int = 0, size: int = 2048):
    """Render a DICOM image with a window center/width in modality units (HU for CT).
    Response headers report the window used, the file's default and its value range."""
    master = data_access(request)
    row = _file_row(fid)
    if row["kind"] != "dicom":
        raise ApiError(400, "Only DICOM files can be rendered with window/level")
    try:
        arr, info = await asyncio.to_thread(_decoded, fid, master, frame)
        jpg = await asyncio.to_thread(media.render_window, arr, info, wc, ww, bool(invert), max(256, min(4096, size)))
    except Exception as exc:
        log.info("Render failed for %s: %s", fid, exc)
        raise ApiError(422, "This DICOM's pixel data can't be rendered here (unsupported compression?). Download the original for a full DICOM viewer.")
    h = {"Cache-Control": "private, max-age=600", "X-Frames": str(info.get("frames", 1)), "X-Frame": str(info.get("frame", 0)), "X-Rgb": "1" if info.get("rgb") else "0"}
    if not info.get("rgb"):
        h.update({
            "X-Window-Center": str(info["default_center"] if wc is None else wc),
            "X-Window-Width": str(info["default_width"] if ww is None else ww),
            "X-Default-Center": str(info["default_center"]),
            "X-Default-Width": str(info["default_width"]),
            "X-Min": str(info["min"]),
            "X-Max": str(info["max"]),
            "X-Modality": info.get("modality", ""),
        })
    h["Access-Control-Expose-Headers"] = ", ".join(h)
    return Response(jpg, media_type="image/jpeg", headers=h)


# =================================================================== per-user preferences

PREF_KEYS = {"theme": ("system", "light", "dark")}


@app.get("/api/prefs")
def get_prefs(request: Request):
    u = require_user(request)
    return {"theme": "system", "dark_color": "#0d1416", **store.get_config(f"prefs:{u['id']}", {})}


@app.put("/api/prefs")
async def put_prefs(request: Request):
    u = require_user(request)
    j = await body_json(request)
    cur = store.get_config(f"prefs:{u['id']}", {})
    if "theme" in j:
        if j["theme"] not in PREF_KEYS["theme"]:
            raise ApiError(400, "theme must be system, light or dark")
        cur["theme"] = j["theme"]
    if "dark_color" in j:
        import re

        if not re.fullmatch(r"#[0-9a-fA-F]{6}", str(j["dark_color"])):
            raise ApiError(400, "dark_color must look like #0d1416")
        cur["dark_color"] = str(j["dark_color"]).lower()
    store.set_config(f"prefs:{u['id']}", cur)
    return {"theme": "system", "dark_color": "#0d1416", **cur}


@app.put("/api/files/{fid}")
async def update_file(fid: str, request: Request):
    master = data_access(request)
    row = _file_row(fid)
    j = await body_json(request)
    if "study_id" in j:
        st = _study_row(str(j["study_id"]))
        if st["patient_id"] != row["patient_id"]:
            raise ApiError(400, "Can only move a file to a study of the same patient")
        store.conn().execute("UPDATE files SET study_id=? WHERE id=?", (st["id"], fid))
    if j.get("filename"):
        d = unseal(master, row["blob"], f"file:{fid}")
        d["filename"] = _str(j["filename"], 255)
        store.conn().execute("UPDATE files SET blob=? WHERE id=?", (seal(master, d, f"file:{fid}"), fid))
    return _file_out(_file_row(fid), master)


def _remove_blobs(fid: str) -> None:
    store.blob_path(fid).unlink(missing_ok=True)
    store.preview_path(fid).unlink(missing_ok=True)


@app.delete("/api/files/{fid}")
def delete_file(fid: str, request: Request):
    data_access(request)
    _file_row(fid)
    _remove_blobs(fid)
    store.conn().execute("DELETE FROM files WHERE id=?", (fid,))
    return {"ok": True}


def _counts() -> dict:
    c = store.conn()
    return {
        "patients": c.execute("SELECT COUNT(*) FROM patients").fetchone()[0],
        "studies": c.execute("SELECT COUNT(*) FROM studies").fetchone()[0],
        "files": c.execute("SELECT COUNT(*) FROM files").fetchone()[0],
        "bytes": c.execute("SELECT COALESCE(SUM(size),0) FROM files").fetchone()[0],
    }


@app.get("/api/stats")
def stats(request: Request):
    data_access(request)
    last = store.conn().execute("SELECT MAX(finished_at) FROM backup_runs WHERE status='ok'").fetchone()[0]
    return {**_counts(), "last_backup_at": iso(last)}


# =================================================================== backups

def _target_row(tid: str):
    r = store.conn().execute("SELECT * FROM backup_targets WHERE id=?", (tid,)).fetchone()
    if not r:
        raise ApiError(404, "Backup target not found")
    return r


def _target_config(row, master: bytes) -> dict:
    return unseal(master, row["config"], f"target:{row['id']}")


def _save_target_config(tid: str, master: bytes):
    def save(cfg: dict) -> None:
        store.conn().execute("UPDATE backup_targets SET config=? WHERE id=?", (seal(master, cfg, f"target:{tid}"), tid))

    return save


def _target_out(row, master: bytes) -> dict:
    cfg = _target_config(row, master)
    cls = targets.TYPES[row["type"]]
    public = {k: v for k, v in cfg.items() if k not in cls.secret_fields and not k.startswith("_")}
    secrets_set = {k: bool(cfg.get(k)) for k in cls.secret_fields}
    connected = not targets.needs_connect(row["type"], cfg)
    return {
        "id": row["id"],
        "type": row["type"],
        "name": row["name"],
        "enabled": bool(row["enabled"]),
        "schedule_hours": row["schedule_hours"],
        "keep_last": row["keep_last"],
        "config": public,
        "secrets_set": secrets_set,
        "connected": connected,
        "last_run": iso(row["last_run"]),
        "last_status": row["last_status"],
    }


def _merge_config(type_: str, old: dict, new: dict) -> dict:
    cls = targets.TYPES[type_]
    cfg = dict(old)
    for k, v in (new or {}).items():
        if k.startswith("_"):
            continue
        if k in cls.secret_fields and (v is None or v == ""):
            continue  # blank = keep existing secret
        cfg[k] = v.strip() if isinstance(v, str) and k not in ("private_key", "service_account_json", "password", "secret_access_key", "client_secret", "app_secret") else v
    if type_ == "sftp":
        if old.get("host") and (cfg.get("host") != old.get("host") or str(cfg.get("port")) != str(old.get("port"))):
            if new.get("host_key") in (None, old.get("host_key")):
                cfg["host_key"] = ""  # host changed: re-pin
    return cfg


TARGET_NAMES = {"gdrive": "Google Drive", "box": "Box", "dropbox": "Dropbox", "onedrive": "OneDrive", "s3": "S3 storage", "webdav": "WebDAV", "sftp": "SFTP server", "smb": "Network share", "local": "USB / local disk"}


@app.get("/api/backups/targets")
def list_targets(request: Request):
    master = data_access(request)
    return [_target_out(r, master) for r in store.conn().execute("SELECT * FROM backup_targets ORDER BY created_at")]


@app.post("/api/backups/targets")
async def create_target(request: Request):
    master = data_access(request)
    j = await body_json(request)
    t = j.get("type")
    if t not in targets.TYPES:
        raise ApiError(400, "type must be one of " + ", ".join(targets.TYPES))
    tid = crypto.random_id()
    cfg = _merge_config(t, {}, j.get("config") or {})
    store.conn().execute(
        "INSERT INTO backup_targets(id,type,name,enabled,schedule_hours,keep_last,config,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (
            tid,
            t,
            _str(j.get("name"), 100) or TARGET_NAMES[t],
            1 if j.get("enabled", True) else 0,
            max(0, int(j.get("schedule_hours", 24) or 0)),
            max(0, int(j.get("keep_last", 14) or 0)),
            seal(master, cfg, f"target:{tid}"),
            time.time(),
        ),
    )
    return _target_out(_target_row(tid), master)


@app.put("/api/backups/targets/{tid}")
async def update_target(tid: str, request: Request):
    master = data_access(request)
    row = _target_row(tid)
    j = await body_json(request)
    cfg = _merge_config(row["type"], _target_config(row, master), j.get("config") or {})
    store.conn().execute(
        "UPDATE backup_targets SET name=?, enabled=?, schedule_hours=?, keep_last=?, config=? WHERE id=?",
        (
            _str(j.get("name"), 100) or row["name"],
            (1 if j.get("enabled") else 0) if "enabled" in j else row["enabled"],
            max(0, int(j.get("schedule_hours", row["schedule_hours"]) or 0)),
            max(0, int(j.get("keep_last", row["keep_last"]) or 0)),
            seal(master, cfg, f"target:{tid}"),
            tid,
        ),
    )
    return _target_out(_target_row(tid), master)


@app.delete("/api/backups/targets/{tid}")
def delete_target(tid: str, request: Request):
    data_access(request)
    store.conn().execute("DELETE FROM backup_targets WHERE id=?", (tid,))
    return {"ok": True}


@app.post("/api/backups/targets/{tid}/test")
async def test_target(tid: str, request: Request):
    master = data_access(request)
    row = _target_row(tid)
    tgt = targets.make(row["type"], _target_config(row, master), _save_target_config(tid, master))
    msg = await asyncio.to_thread(tgt.test)
    return {"ok": True, "message": msg, "target": _target_out(_target_row(tid), master)}


def run_backup(tid: str | None, master: bytes, trigger: str = "manual") -> dict:
    """Build an encrypted archive and push it to one target (or all enabled)."""
    with backup_lock:
        rows = (
            [_target_row(tid)]
            if tid
            else store.conn().execute("SELECT * FROM backup_targets WHERE enabled=1").fetchall()
        )
        if not rows:
            raise ApiError(400, "No backup targets configured")
        name = backup.backup_name()
        archive = store.tmp_dir / name
        results = []
        try:
            backup.create_archive(store, master, archive, VERSION)
            size = archive.stat().st_size
            for row in rows:
                rid, started = crypto.random_id(), time.time()
                store.conn().execute(
                    "INSERT INTO backup_runs(id,target_id,started_at,status,filename,size) VALUES(?,?,?,?,?,?)",
                    (rid, row["id"], started, "running", name, size),
                )
                try:
                    tgt = targets.make(row["type"], _target_config(row, master), _save_target_config(row["id"], master))
                    tgt.upload(archive, name)
                    pruned = tgt.prune(row["keep_last"])
                    status, msg = "ok", f"Uploaded {name} ({size:,} bytes)" + (f", removed {pruned} old backup(s)" if pruned else "")
                except Exception as exc:
                    log.exception("Backup to %s failed", row["name"])
                    status, msg = "error", str(exc)[:500]
                now = time.time()
                store.conn().execute("UPDATE backup_runs SET finished_at=?, status=?, message=? WHERE id=?", (now, status, msg, rid))
                store.conn().execute("UPDATE backup_targets SET last_run=?, last_status=? WHERE id=?", (now, status, row["id"]))
                results.append({"target_id": row["id"], "name": row["name"], "status": status, "message": msg})
        finally:
            archive.unlink(missing_ok=True)
        return {"filename": name, "results": results, "trigger": trigger}


@app.post("/api/backups/targets/{tid}/run")
async def run_target(tid: str, request: Request):
    master = data_access(request)
    _target_row(tid)
    return await asyncio.to_thread(run_backup, tid, master)


@app.post("/api/backups/run")
async def run_all(request: Request):
    master = data_access(request)
    return await asyncio.to_thread(run_backup, None, master)


@app.get("/api/backups/runs")
def list_runs(request: Request, limit: int = 50):
    data_access(request)
    rows = store.conn().execute(
        "SELECT r.*, t.name AS target_name, t.type AS target_type FROM backup_runs r LEFT JOIN backup_targets t ON t.id=r.target_id ORDER BY started_at DESC LIMIT ?",
        (min(limit, 500),),
    ).fetchall()
    return [
        {
            "id": r["id"],
            "target_id": r["target_id"],
            "target_name": r["target_name"] or ("Local download" if not r["target_id"] else "(deleted)"),
            "target_type": r["target_type"],
            "started_at": iso(r["started_at"]),
            "finished_at": iso(r["finished_at"]),
            "status": r["status"],
            "message": r["message"],
            "size": r["size"],
            "filename": r["filename"],
        }
        for r in rows
    ]


@app.get("/api/backups/download")
async def download_backup(request: Request):
    """Build an encrypted .svb archive and download it directly."""
    master = data_access(request)
    name = backup.backup_name()
    path = store.tmp_dir / name
    await asyncio.to_thread(backup.create_archive, store, master, path, VERSION)
    store.conn().execute(
        "INSERT INTO backup_runs(id,target_id,started_at,finished_at,status,message,size,filename) VALUES(?,?,?,?,?,?,?,?)",
        (crypto.random_id(), None, time.time(), time.time(), "ok", "Downloaded to device", path.stat().st_size, name),
    )
    return FileResponse(path, filename=name, media_type="application/octet-stream", background=BackgroundTask(path.unlink, missing_ok=True))


@app.get("/api/backups/targets/{tid}/remote")
async def list_remote(tid: str, request: Request):
    master = data_access(request)
    row = _target_row(tid)
    tgt = targets.make(row["type"], _target_config(row, master), _save_target_config(tid, master))
    items = await asyncio.to_thread(tgt.list_backups)
    return [{"name": n, "handle": h} for n, h in reversed(items)]


@app.post("/api/backups/restore")
async def restore_existing(request: Request, backup_file: Optional[UploadFile] = File(None), target_id: Optional[str] = Form(None), handle: Optional[str] = Form(None), confirm: str = Form("")):
    """Restore over the current vault from an uploaded .svb or a remote backup.
    Uses the current master key; the backup must belong to this vault."""
    master = data_access(request)
    if confirm != "REPLACE":
        raise ApiError(400, "Type REPLACE to confirm restoring over current data")
    if backup_file is not None:
        archive = await _save_upload(backup_file)
    elif target_id and handle:
        row = _target_row(target_id)
        tgt = targets.make(row["type"], _target_config(row, master), _save_target_config(target_id, master))
        archive = store.tmp_dir / f"restore-{crypto.random_id()}.svb"
        await asyncio.to_thread(tgt.download, handle, archive)
    else:
        raise ApiError(400, "Upload a backup file or choose a remote backup")
    try:
        hdr = backup.read_header(archive)
        if hdr["fingerprint"] != crypto.fingerprint(master):
            raise ApiError(400, "This backup was made with a different encryption key. Use a fresh install and the recovery key instead.")
        # keep current logins, SSO links and backup targets across the restore
        users = [dict(r) for r in store.conn().execute("SELECT * FROM users")]
        idents = [dict(r) for r in store.conn().execute("SELECT * FROM user_identities")]
        sso_cfg = store.get_config("sso")
        tg = [dict(r) for r in store.conn().execute("SELECT * FROM backup_targets")]
        header = await asyncio.to_thread(backup.restore_into_store, store, archive, master)
        c = store.conn()
        for u in users:
            c.execute("INSERT OR REPLACE INTO users(id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)", tuple(u[k] for k in ("id", "username", "password_hash", "role", "created_at")))
        c.execute("DELETE FROM user_identities")
        for i in idents:
            c.execute(f"INSERT INTO user_identities({','.join(i.keys())}) VALUES({','.join('?' * len(i))})", tuple(i.values()))
        if sso_cfg is not None:
            store.set_config("sso", sso_cfg)
        for t in tg:
            cols = ",".join(t.keys())
            c.execute(f"INSERT OR REPLACE INTO backup_targets({cols}) VALUES({','.join('?' * len(t))})", tuple(t.values()))
        store.set_config("setup_complete", True)
    finally:
        archive.unlink(missing_ok=True)
    return {"ok": True, "restored": header["created"], **_counts()}


# =================================================================== OAuth (Drive/Box)

_oauth_states: dict[str, tuple[str, float]] = {}


def _redirect_uri(request: Request, provider: str) -> str:
    base = PUBLIC_URL or str(request.base_url).rstrip("/")
    return f"{base}/api/oauth/{provider}/callback"


@app.get("/api/oauth/{provider}/start")
def oauth_start(provider: str, target_id: str, request: Request):
    master = data_access(request)
    row = _target_row(target_id)
    if row["type"] != provider or provider not in targets.OAUTH_TYPES:
        raise ApiError(400, "Provider mismatch")
    cfg = _target_config(row, master)
    if not targets.oauth_client_id(provider, cfg):
        raise ApiError(400, "Enter the app's client ID and secret first, then Save")
    state = secrets.token_urlsafe(24)
    _oauth_states[state] = (target_id, time.time())
    return RedirectResponse(targets.oauth_auth_url(provider, cfg, _redirect_uri(request, provider), state))


@app.get("/api/oauth/{provider}/redirect-uri")
def oauth_redirect_uri(provider: str, request: Request):
    require_user(request)
    return {"redirect_uri": _redirect_uri(request, provider)}


@app.get("/api/oauth/{provider}/callback")
def oauth_callback(provider: str, request: Request, state: str = "", code: str = "", error: str = ""):
    entry = _oauth_states.pop(state, None)
    if error or not entry or time.time() - entry[1] > 900:
        return RedirectResponse(f"/#/backups?oauth=error&msg={error or 'expired'}")
    master = mk()
    tid = entry[0]
    row = _target_row(tid)
    tgt = targets.make(row["type"], _target_config(row, master), _save_target_config(tid, master))
    try:
        tgt.exchange_code(code, _redirect_uri(request, provider))  # type: ignore[attr-defined]
    except targets.TargetError as exc:
        log.warning("OAuth exchange failed: %s", exc)
        return RedirectResponse("/#/backups?oauth=error&msg=exchange")
    return RedirectResponse("/#/backups?oauth=ok")


# =================================================================== single sign-on (OIDC)
# SSO only proves who is signing in. It never touches the vault encryption key:
# a locked vault still has to be unlocked with the encryption key or recovery
# key file afterwards, exactly like after a password sign-in.

oidc = sso.OIDC()
_sso_requests = sso.PendingStore(ttl=600)   # state -> pending authorization request
_sso_tickets = sso.PendingStore(ttl=120)    # one-time ticket -> signed-in user
SSO_COOKIE = "sv_sso"
SSO_COOKIE_PATH = "/api/auth/sso"
FORCE_LOCAL_LOGIN = os.environ.get("SCANVAULT_FORCE_LOCAL_LOGIN", "").lower() in ("1", "true", "yes")


def _sso_cfg() -> dict:
    return {"providers": [], "local_login": True, **(store.get_config("sso", {}) or {})}


def _sso_save(cfg: dict) -> None:
    store.set_config("sso", {"providers": cfg.get("providers", []), "local_login": bool(cfg.get("local_login", True))})


def _sso_providers(include_disabled: bool = False) -> list[dict]:
    ps = []
    env = sso.env_provider()
    if env:
        ps.append(env)
    ps += _sso_cfg()["providers"]
    return [p for p in ps if include_disabled or p.get("enabled", True)]


def _sso_provider(pid: str, include_disabled: bool = False) -> dict:
    for p in _sso_providers(include_disabled):
        if p["id"] == pid:
            return p
    raise ApiError(404, "Unknown sign-in provider")


def _sso_public(p: dict) -> dict:
    return {"id": p["id"], "name": p["name"], "preset": p.get("preset", "generic")}


def _sso_admin_out(p: dict) -> dict:
    return {
        "id": p["id"], "name": p["name"], "preset": p.get("preset", "generic"), "issuer": p.get("issuer", ""),
        "fields": p.get("fields") or {}, "resolved_issuer": sso.resolve_issuer(p), "client_id": p.get("client_id", ""),
        "has_secret": bool(p.get("client_secret")), "scopes": p.get("scopes") or sso.DEFAULT_SCOPES,
        "enabled": p.get("enabled", True), "managed": p.get("managed"),
    }


def _linked_identity_count() -> int:
    ids = {p["id"] for p in _sso_providers()}
    rows = store.conn().execute("SELECT provider_id FROM user_identities").fetchall()
    return sum(1 for r in rows if r["provider_id"] in ids)


def local_login_enabled() -> bool:
    """Password sign-in can be turned off only while some SSO link can still sign in."""
    if FORCE_LOCAL_LOGIN or _sso_cfg()["local_login"]:
        return True
    return _linked_identity_count() == 0


def _require_admin(request: Request) -> dict:
    u = require_user(request)
    if u["role"] != "admin":
        raise ApiError(403, "Only an administrator can change sign-in settings")
    return u


def _sso_redirect_uri(request: Request) -> str:
    base = PUBLIC_URL or str(request.base_url).rstrip("/")
    return f"{base}/api/auth/sso/callback"


REAUTH_SECONDS = 600


def _recent_sso(u: dict) -> bool:
    return bool(u.get("identity_id")) and time.time() - (u.get("session_created") or 0) < REAUTH_SECONDS


def _reauth(u: dict, j: dict) -> None:
    """Changes that add a way to sign in need the password, or an SSO sign-in in
    the last 10 minutes, so a stolen session can't plant a backdoor."""
    if _recent_sso(u):
        return
    r = store.conn().execute("SELECT password_hash FROM users WHERE id=?", (u["id"],)).fetchone()
    if not r or not crypto.verify_password(str(j.get("password") or ""), r["password_hash"]):
        time.sleep(0.5)
        raise ApiError(403, "Enter your ScanVault password to confirm this change", "reauth_required")


def _revoke_identity_sessions(where: str, args: tuple) -> None:
    store.conn().execute(f"DELETE FROM sessions WHERE identity_id IN (SELECT id FROM user_identities WHERE {where})", args)


_start_hits: dict[str, list[float]] = {}
START_LIMIT = (30, 600)  # sign-in starts per client per 10 minutes


def _start_rate_ok(request: Request) -> bool:
    ip = request.client.host if request.client else "?"
    now = time.time()
    hits = [t for t in _start_hits.get(ip, []) if now - t < START_LIMIT[1]]
    if len(_start_hits) > 10000:
        _start_hits.clear()
    ok = len(hits) < START_LIMIT[0]
    if ok:
        hits.append(now)
    _start_hits[ip] = hits
    return ok


def _sso_flow(request: Request, p: dict, mode: str, user_id: str | None = None, app: dict | None = None) -> tuple[str, str | None]:
    """Start an authorization request. Returns (provider URL, browser binding cookie)."""
    verifier, challenge = sso.pkce_pair()
    nonce = secrets.token_urlsafe(24)
    binding = None if app else secrets.token_urlsafe(24)
    redirect_uri = _sso_redirect_uri(request)
    state = _sso_requests.put({
        "mode": mode, "pid": p["id"], "user_id": user_id, "verifier": verifier, "nonce": nonce,
        "binding": sso.sha(binding) if binding else None, "app": app, "redirect_uri": redirect_uri,
    })
    try:
        # Apps: make the provider show which account is used instead of silently reusing a session.
        prompt = "select_account" if app and p.get("preset") in ("google", "microsoft") else None
        url = oidc.authorization_url(p, redirect_uri, state, nonce, challenge, prompt=prompt)
    except sso.SSOError as exc:
        _sso_requests.pop(state)
        raise ApiError(502, str(exc), "sso_provider") from exc
    return url, binding


def _set_binding(request: Request, resp: Response, binding: str | None) -> Response:
    if binding:
        # Lax, not Strict: the browser must send it on the top-level redirect back from the provider.
        resp.set_cookie(SSO_COOKIE, binding, max_age=600, httponly=True, samesite="lax", secure=_secure(request), path=SSO_COOKIE_PATH)
    return resp


def _binding_ok(request: Request, expected_hash: str | None) -> bool:
    got = request.cookies.get(SSO_COOKIE)
    return bool(expected_hash and got and secrets.compare_digest(sso.sha(got), expected_hash))


def _app_redirect(app: dict, **params) -> RedirectResponse:
    uri = app["redirect"]
    q = {k: v for k, v in params.items() if v is not None}
    if app.get("state"):
        q["state"] = app["state"]
    return RedirectResponse(uri + ("&" if "?" in uri else "?") + urlencode(q))


def _web_redirect(path: str, **params) -> RedirectResponse:
    return RedirectResponse(f"/#/{path}?{urlencode(params)}" if params else f"/#/{path}")


@app.get("/api/auth/sso/{pid}/start")
def sso_start(pid: str, request: Request, app_redirect: str = "", app_state: str = "", code_challenge: str = ""):
    """Begin SSO sign-in. Browsers navigate here directly. Mobile apps open it in a
    browser tab with ``app_redirect`` (e.g. ``scanvault://sso``) and a PKCE
    ``code_challenge``; the ticket comes back to ``app_redirect``."""
    app_ctx = None
    if app_redirect:
        if not sso.app_redirect_allowed(app_redirect):
            raise ApiError(400, "app_redirect is not allowed (see SCANVAULT_SSO_APP_REDIRECTS)")
        if not (43 <= len(code_challenge) <= 128) or not all(c.isalnum() or c in "-_" for c in code_challenge):
            raise ApiError(400, "A PKCE code_challenge (S256, base64url) is required")
        app_ctx = {"redirect": app_redirect, "state": app_state[:500] or None, "challenge": code_challenge}
    if not setup_complete():
        return _app_redirect(app_ctx, error="setup_required") if app_ctx else _web_redirect("")
    if not _start_rate_ok(request):
        raise ApiError(429, "Too many sign-in attempts. Wait a few minutes.")
    try:
        p = _sso_provider(pid)
        url, binding = _sso_flow(request, p, "login", app=app_ctx)
    except ApiError as exc:
        log.warning("SSO start failed: %s", exc.msg)
        return _app_redirect(app_ctx, error=exc.msg) if app_ctx else _web_redirect("", sso_error=exc.msg)
    return _set_binding(request, RedirectResponse(url), binding)


@app.post("/api/auth/sso/{pid}/link")
async def sso_link_start(pid: str, request: Request):
    """Signed-in user links an identity-provider account. Returns the URL to open.
    Body: ``{password}`` (not needed within 10 minutes of an SSO sign-in)."""
    u = require_user(request)
    try:
        j = await request.json()
    except Exception:
        j = {}
    _reauth(u, j if isinstance(j, dict) else {})
    p = _sso_provider(pid)
    url, binding = _sso_flow(request, p, "link", user_id=u["id"])
    return _set_binding(request, JSONResponse({"url": url}), binding)


@app.get("/api/auth/sso/callback")
def sso_callback(request: Request, state: str = "", code: str = "", error: str = "", error_description: str = ""):
    resp_iss = request.query_params.get("iss", "")
    entry = _sso_requests.pop(state)
    if not entry:
        return _web_redirect("", sso_error="This sign-in link expired. Try again.")
    app_ctx = entry["app"]
    back = "settings" if entry["mode"] == "link" else ""

    def fail(msg: str):
        log.info("SSO %s failed: %r", entry["mode"], msg)
        resp = _app_redirect(app_ctx, error=msg) if app_ctx else _web_redirect(back, sso_error=msg)
        resp.delete_cookie(SSO_COOKIE, path=SSO_COOKIE_PATH)
        return resp

    if not app_ctx and not _binding_ok(request, entry["binding"]):
        return fail("This sign-in was started in a different browser. Try again.")
    if error:
        return fail((error_description or error)[:300])
    try:
        p = _sso_provider(entry["pid"])
        # RFC 9207: if the provider names itself in the response, it must be the one we asked.
        doc = oidc.discover(sso.resolve_issuer(p))
        if resp_iss and doc["issuer"] != sso.MS_TEMPLATE and resp_iss.rstrip("/") != doc["issuer"].rstrip("/"):
            return fail("The sign-in response came from a different provider.")
        tokens = oidc.exchange_code(p, code, entry["redirect_uri"], entry["verifier"])
        claims = oidc.validate_id_token(p, tokens["id_token"], entry["nonce"])
    except (sso.SSOError, ApiError) as exc:
        return fail(getattr(exc, "msg", None) or str(exc))
    iss, sub = claims["iss"], str(claims["sub"])
    if resp_iss and doc["issuer"] == sso.MS_TEMPLATE and resp_iss.rstrip("/") != iss.rstrip("/"):
        return fail("The sign-in response came from a different provider.")
    email = claims.get("email") if claims.get("email_verified", True) not in (False, "false") else None
    email = email or claims.get("preferred_username")
    c = store.conn()
    row = c.execute("SELECT * FROM user_identities WHERE issuer=? AND subject=?", (iss, sub)).fetchone()

    if entry["mode"] == "link":
        if row and row["user_id"] != entry["user_id"]:
            return fail(f"That {p['name']} account is already linked to another ScanVault login.")
        if row:
            if row["provider_id"] != p["id"]:
                c.execute("DELETE FROM sessions WHERE identity_id=?", (row["id"],))
            c.execute("UPDATE user_identities SET provider_id=?, email=? WHERE id=?", (p["id"], email, row["id"]))
        else:
            c.execute(
                "INSERT INTO user_identities(id,user_id,provider_id,issuer,subject,email,created_at) VALUES(?,?,?,?,?,?,?)",
                (crypto.random_id(), entry["user_id"], p["id"], iss, sub, email, time.time()),
            )
        resp = _web_redirect("settings", sso="linked")
        resp.delete_cookie(SSO_COOKIE, path=SSO_COOKIE_PATH)
        return resp

    if row and row["provider_id"] != p["id"]:
        row = None  # an identity only signs in through the provider it was linked with
    if not row or not c.execute("SELECT 1 FROM users WHERE id=?", (row["user_id"],)).fetchone():
        return fail(f"This {p['name']} account isn't linked to ScanVault yet. Sign in with your password, then link it under Settings > Single sign-on.")
    c.execute("UPDATE user_identities SET last_login=?, email=? WHERE id=?", (time.time(), email, row["id"]))
    grant = {
        "user_id": row["user_id"],
        "identity_id": row["id"],
        "binding": entry["binding"],
        "challenge": app_ctx["challenge"] if app_ctx else None,
    }
    if app_ctx:
        # Anything on the phone can open /start with its own scanvault:// redirect,
        # so the person confirms on a page served by ScanVault before an app gets a ticket.
        cid = _sso_confirms.put({"grant": grant, "app": app_ctx, "email": email, "provider": p["name"]})
        return _app_confirm_page(cid, email, p["name"])
    # The session itself is issued by POST /api/auth/sso/exchange, a same-origin
    # request, so the SameSite=Strict session cookie is set reliably.
    return _web_redirect("sso", ticket=_sso_tickets.put(grant))


_sso_confirms = sso.PendingStore(ttl=300)


def _app_confirm_page(cid: str, email: str | None, provider: str) -> HTMLResponse:
    from html import escape

    who = escape(email or "your account")
    body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to the ScanVault app?</title><style>
body{{font:16px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f4f7f7;color:#13201f}}
main{{max-width:420px;margin:24px;padding:28px;background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.08)}}
h1{{font-size:22px;margin:0 0 12px}}p{{margin:0 0 14px}}.row{{display:flex;gap:10px;margin-top:20px}}
button{{flex:1;font:inherit;font-weight:600;padding:12px;border-radius:10px;border:1px solid #c9d6d5;background:#fff;cursor:pointer}}
button.go{{background:#0b5d63;color:#fff;border-color:#0b5d63}}.warn{{font-size:14px;color:#6b4b00;background:#fff6dc;padding:10px 12px;border-radius:10px}}
@media (prefers-color-scheme:dark){{body{{background:#0d1416;color:#e6eeee}}main{{background:#162024}}button{{background:#162024;color:#e6eeee;border-color:#2b3a3e}}.warn{{background:#3a2f12;color:#ffe3a3}}}}
</style></head><body><main><h1>Sign in to the ScanVault app?</h1>
<p>You signed in with {escape(provider)} as <b>{who}</b>. Continuing gives the app that opened this page access to your ScanVault for 30 days.</p>
<p class="warn">Only continue if you just tapped <b>Continue with {escape(provider)}</b> in the ScanVault app yourself.</p>
<form method="post" action="/api/auth/sso/app-confirm"><input type="hidden" name="cid" value="{escape(cid)}">
<div class="row"><button name="action" value="cancel">Cancel</button><button class="go" name="action" value="allow">Continue</button></div></form>
</main></body></html>"""
    return HTMLResponse(body, headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'", "Cache-Control": "no-store"})


@app.post("/api/auth/sso/app-confirm")
def sso_app_confirm(request: Request, cid: str = Form(""), action: str = Form("")):
    c = _sso_confirms.pop(cid)
    if not c:
        return HTMLResponse("<!doctype html><p>This sign-in expired. Go back to the ScanVault app and try again.</p>", status_code=400)
    if action != "allow":
        return RedirectResponse(_app_redirect(c["app"], error="cancelled").headers["location"], status_code=303)
    ticket = _sso_tickets.put(c["grant"])
    return RedirectResponse(_app_redirect(c["app"], ticket=ticket).headers["location"], status_code=303)


@app.post("/api/auth/sso/exchange")
async def sso_exchange(request: Request):
    """Trade a one-time SSO ticket for a session. Browsers are matched by the
    binding cookie; apps must send the PKCE ``code_verifier`` they started with."""
    j = await body_json(request)
    t = _sso_tickets.pop(str(j.get("ticket") or ""))
    if not t:
        raise ApiError(400, "This sign-in link expired. Try again.", "sso_expired")
    if t["challenge"]:
        if not secrets.compare_digest(sso.pkce_challenge(str(j.get("code_verifier") or "")), t["challenge"]):
            raise ApiError(400, "code_verifier does not match", "sso_pkce")
    elif not _binding_ok(request, t["binding"]):
        raise ApiError(400, "This sign-in was started in a different browser. Try again.", "sso_binding")
    tok, exp = new_session(t["user_id"], t.get("identity_id"))
    resp = session_response(request, {"token": tok, "expires_at": iso(exp), "unlocked": vault.unlocked}, tok, exp)
    resp.delete_cookie(SSO_COOKIE, path=SSO_COOKIE_PATH)
    return resp


# ---- administration

@app.get("/api/sso/config")
def sso_config(request: Request):
    u = require_user(request)
    cfg = _sso_cfg()
    names = {p["id"]: p["name"] for p in _sso_providers(include_disabled=True)}
    idents = [
        {"id": r["id"], "provider_id": r["provider_id"], "provider_name": names.get(r["provider_id"], "Removed provider"),
         "email": r["email"], "linked_at": iso(r["created_at"]), "last_login": iso(r["last_login"])}
        for r in store.conn().execute("SELECT * FROM user_identities WHERE user_id=? ORDER BY created_at", (u["id"],))
    ]
    return {
        "providers": [_sso_admin_out(p) for p in _sso_providers(include_disabled=True)],
        "local_login": cfg["local_login"],
        "local_login_effective": local_login_enabled(),
        "local_login_forced": FORCE_LOCAL_LOGIN,
        "reauth_fresh": _recent_sso(u),
        "redirect_uri": _sso_redirect_uri(request),
        "presets": sso.PRESETS,
        "identities": idents,
    }


def _sso_provider_from(j: dict, old: dict | None = None) -> dict:
    p = dict(old or {})
    preset = j.get("preset", p.get("preset", "generic"))
    if preset not in sso.PRESETS:
        raise ApiError(400, "Unknown provider type")
    p["preset"] = preset
    p["name"] = _str(j.get("name"), 60) or p.get("name") or sso.PRESETS[preset]["name"]
    if "issuer" in j:
        p["issuer"] = (_str(j["issuer"], 500) or "").rstrip("/") if preset == "generic" else ""
    if "fields" in j:
        keys = {f["key"] for f in sso.PRESETS[preset]["fields"]}
        p["fields"] = {k: _str(v, 300) or "" for k, v in (j.get("fields") or {}).items() if k in keys}
    if "client_id" in j:
        p["client_id"] = _str(j["client_id"], 300) or ""
    if j.get("client_secret"):
        p["client_secret"] = str(j["client_secret"]).strip()[:2000]
    if j.get("clear_secret"):
        p.pop("client_secret", None)
    if "scopes" in j:
        scopes = (_str(j["scopes"], 300) or sso.DEFAULT_SCOPES).split()
        p["scopes"] = " ".join(["openid"] + [s for s in scopes if s != "openid"])
    if "enabled" in j:
        p["enabled"] = bool(j["enabled"])
    if not p.get("client_id"):
        raise ApiError(400, "Enter the client ID from your identity provider")
    issuer = sso.resolve_issuer(p)
    if not issuer:
        raise ApiError(400, "Enter the issuer URL" if preset == "generic" else "Fill in every field of the provider")
    try:
        sso.validate_issuer_url(issuer)
        oidc.discover(issuer, force=True)
    except sso.SSOError as exc:
        raise ApiError(400, f"Could not read the provider's OpenID configuration: {exc}", "sso_discovery") from exc
    return p


@app.post("/api/sso/providers")
async def sso_create_provider(request: Request):
    u = _require_admin(request)
    j = await body_json(request)
    _reauth(u, j)
    p = _sso_provider_from(j)
    p["id"] = crypto.random_id()
    p.setdefault("enabled", True)
    cfg = _sso_cfg()
    cfg["providers"].append(p)
    _sso_save(cfg)
    return _sso_admin_out(p)


@app.put("/api/sso/providers/{pid}")
async def sso_update_provider(pid: str, request: Request):
    u = _require_admin(request)
    j = await body_json(request)
    _reauth(u, j)
    cfg = _sso_cfg()
    for i, old in enumerate(cfg["providers"]):
        if old["id"] == pid:
            cfg["providers"][i] = p = _sso_provider_from(j, old)
            _sso_save(cfg)
            c = store.conn()
            if sso.resolve_issuer(p) != sso.resolve_issuer(old) or p["client_id"] != old.get("client_id"):
                # A different provider behind the same entry: its old links no longer mean anything.
                _revoke_identity_sessions("provider_id=?", (pid,))
                c.execute("DELETE FROM user_identities WHERE provider_id=?", (pid,))
            elif not p.get("enabled", True):
                _revoke_identity_sessions("provider_id=?", (pid,))
            return _sso_admin_out(p)
    if pid == "env":
        raise ApiError(409, "This provider is configured with SCANVAULT_OIDC_* environment variables")
    raise ApiError(404, "Unknown sign-in provider")


@app.delete("/api/sso/providers/{pid}")
def sso_delete_provider(pid: str, request: Request):
    _require_admin(request)
    if pid == "env":
        raise ApiError(409, "This provider is configured with SCANVAULT_OIDC_* environment variables")
    cfg = _sso_cfg()
    cfg["providers"] = [p for p in cfg["providers"] if p["id"] != pid]
    _sso_save(cfg)
    _revoke_identity_sessions("provider_id=?", (pid,))
    store.conn().execute("DELETE FROM user_identities WHERE provider_id=?", (pid,))
    return {"ok": True, "local_login": local_login_enabled()}


@app.post("/api/sso/providers/{pid}/test")
def sso_test_provider(pid: str, request: Request):
    _require_admin(request)
    p = _sso_provider(pid, include_disabled=True)
    try:
        doc = oidc.discover(sso.resolve_issuer(p), force=True)
    except sso.SSOError as exc:
        raise ApiError(502, str(exc), "sso_discovery") from exc
    return {"ok": True, "issuer": doc["issuer"], "authorization_endpoint": doc["authorization_endpoint"]}


@app.put("/api/sso/settings")
async def sso_settings(request: Request):
    u = _require_admin(request)
    j = await body_json(request)
    cfg = _sso_cfg()
    if "local_login" in j:
        want = bool(j["local_login"])
        if not want and cfg["local_login"]:
            _reauth(u, j)
        if not want:
            ids = {p["id"] for p in _sso_providers()}
            mine = [r for r in store.conn().execute("SELECT provider_id FROM user_identities WHERE user_id=?", (u["id"],)) if r["provider_id"] in ids]
            if not mine:
                raise ApiError(400, "Link an SSO account to your login first, so you can still sign in.")
        cfg["local_login"] = want
    _sso_save(cfg)
    return {"ok": True, "local_login": local_login_enabled()}


@app.delete("/api/sso/identities/{iid}")
def sso_unlink(iid: str, request: Request):
    u = require_user(request)
    _revoke_identity_sessions("id=? AND user_id=?", (iid, u["id"]))
    store.conn().execute("DELETE FROM user_identities WHERE id=? AND user_id=?", (iid, u["id"]))
    if _linked_identity_count() == 0 and not _sso_cfg()["local_login"]:
        cfg = _sso_cfg()
        cfg["local_login"] = True  # never leave the vault without a way to sign in
        _sso_save(cfg)
    return {"ok": True, "local_login": local_login_enabled()}


# =================================================================== scheduler

async def scheduler():
    while True:
        await asyncio.sleep(60)
        try:
            if not vault.unlocked or not setup_complete():
                continue
            now = time.time()
            due = [
                r["id"]
                for r in store.conn().execute("SELECT * FROM backup_targets WHERE enabled=1 AND schedule_hours>0")
                if not r["last_run"] or now - r["last_run"] >= r["schedule_hours"] * 3600
            ]
            for tid in due:
                await asyncio.to_thread(run_backup, tid, vault.master_key, "schedule")
        except Exception:
            log.exception("Scheduled backup failed")


async def _startup():
    for p in store.tmp_dir.glob("*"):
        if p.is_file():
            p.unlink(missing_ok=True)
    pf = os.environ.get("SCANVAULT_PASSPHRASE_FILE")
    if pf and Path(pf).exists() and setup_complete():
        try:
            vault.master_key = crypto.unwrap_master_key(store.keystore(), Path(pf).read_text().strip())
            log.info("Vault auto-unlocked from SCANVAULT_PASSPHRASE_FILE")
        except crypto.CryptoError:
            log.error("SCANVAULT_PASSPHRASE_FILE does not unlock the vault")
    return asyncio.create_task(scheduler())


@asynccontextmanager
async def lifespan(_app):
    task = await _startup()
    yield
    task.cancel()


app.router.lifespan_context = lifespan


# =================================================================== static UI

STATIC = Path(__file__).parent / "static"


@app.get("/sw.js")
def sw():
    return FileResponse(STATIC / "sw.js", media_type="application/javascript", headers={"Cache-Control": "no-cache"})


@app.get("/manifest.webmanifest")
def manifest():
    return FileResponse(STATIC / "manifest.webmanifest", media_type="application/manifest+json")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})


app.mount("/static", StaticFiles(directory=STATIC), name="static")
