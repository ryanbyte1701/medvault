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

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.background import BackgroundTask

from . import backup, crypto, media, targets
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
        "SELECT u.id, u.username, u.role, s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",
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


def new_session(user_id: str) -> tuple[str, float]:
    tok = secrets.token_urlsafe(32)
    exp = time.time() + SESSION_DAYS * 86400
    store.conn().execute(
        "INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",
        (hashlib.sha256(tok.encode()).hexdigest(), user_id, time.time(), exp),
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
    c.execute("DELETE FROM users")
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
    connected = True
    if row["type"] in ("gdrive", "box") and cfg.get("auth_mode", "oauth") == "oauth":
        connected = bool(cfg.get("refresh_token"))
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
        cfg[k] = v.strip() if isinstance(v, str) and k not in ("private_key", "service_account_json") else v
    if type_ == "sftp":
        if old.get("host") and (cfg.get("host") != old.get("host") or str(cfg.get("port")) != str(old.get("port"))):
            if new.get("host_key") in (None, old.get("host_key")):
                cfg["host_key"] = ""  # host changed: re-pin
    return cfg


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
        raise ApiError(400, "type must be gdrive, box or sftp")
    tid = crypto.random_id()
    cfg = _merge_config(t, {}, j.get("config") or {})
    store.conn().execute(
        "INSERT INTO backup_targets(id,type,name,enabled,schedule_hours,keep_last,config,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (
            tid,
            t,
            _str(j.get("name"), 100) or {"gdrive": "Google Drive", "box": "Box", "sftp": "SFTP server"}[t],
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
        # keep current logins and backup targets across the restore
        users = [dict(r) for r in store.conn().execute("SELECT * FROM users")]
        tg = [dict(r) for r in store.conn().execute("SELECT * FROM backup_targets")]
        header = await asyncio.to_thread(backup.restore_into_store, store, archive, master)
        c = store.conn()
        for u in users:
            c.execute("INSERT OR REPLACE INTO users(id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)", tuple(u[k] for k in ("id", "username", "password_hash", "role", "created_at")))
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
    if row["type"] != provider or provider not in ("gdrive", "box"):
        raise ApiError(400, "Provider mismatch")
    cfg = _target_config(row, master)
    if not cfg.get("client_id") or not cfg.get("client_secret"):
        raise ApiError(400, "Enter the OAuth client ID and secret first, then Save")
    state = secrets.token_urlsafe(24)
    _oauth_states[state] = (target_id, time.time())
    cls = targets.TYPES[provider]
    return RedirectResponse(cls.auth_url(cfg["client_id"], _redirect_uri(request, provider), state))  # type: ignore[attr-defined]


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
