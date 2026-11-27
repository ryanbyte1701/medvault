"""Storage: SQLite metadata (sensitive fields sealed with the master key) and
encrypted file blobs on disk."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path

from . import crypto

DATA_DIR = Path(os.environ.get("SCANVAULT_DATA", "/data"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'admin', created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS patients (
  id TEXT PRIMARY KEY, created_at REAL NOT NULL, updated_at REAL NOT NULL, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS studies (
  id TEXT PRIMARY KEY, patient_id TEXT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  created_at REAL NOT NULL, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY, study_id TEXT NOT NULL REFERENCES studies(id) ON DELETE CASCADE,
  patient_id TEXT NOT NULL, kind TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
  has_preview INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL, blob BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS files_study ON files(study_id);
CREATE INDEX IF NOT EXISTS files_patient ON files(patient_id);
CREATE INDEX IF NOT EXISTS studies_patient ON studies(patient_id);
CREATE TABLE IF NOT EXISTS backup_targets (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
  schedule_hours INTEGER NOT NULL DEFAULT 24, keep_last INTEGER NOT NULL DEFAULT 14,
  config BLOB NOT NULL, last_run REAL, last_status TEXT, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS backup_runs (
  id TEXT PRIMARY KEY, target_id TEXT, started_at REAL NOT NULL, finished_at REAL,
  status TEXT NOT NULL, message TEXT, size INTEGER, filename TEXT);
CREATE TABLE IF NOT EXISTS user_identities (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL, issuer TEXT NOT NULL, subject TEXT NOT NULL, email TEXT,
  created_at REAL NOT NULL, last_login REAL, UNIQUE(issuer, subject));
"""


class Store:
    def __init__(self, data_dir: Path = DATA_DIR):
        self.dir = Path(data_dir)
        self.files_dir = self.dir / "files"
        self.preview_dir = self.dir / "previews"
        self.tmp_dir = self.dir / "tmp"
        for d in (self.dir, self.files_dir, self.preview_dir, self.tmp_dir):
            d.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self.db_path = self.dir / "scanvault.db"
        self.keystore_path = self.dir / "keystore.json"
        self._local = threading.local()
        self.generation = 0  # bumped on restore so every thread reopens the DB
        self.lock = threading.RLock()
        with self.conn() as c:
            c.executescript(SCHEMA)

    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "c", None)
        if c is not None and getattr(self._local, "gen", -1) != self.generation:
            c.close()
            c = None
        if c is None:
            c = sqlite3.connect(self.db_path, check_same_thread=False, isolation_level=None)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("PRAGMA journal_mode=WAL")
            # A restored backup may predate newer tables; create any that are missing.
            c.executescript(SCHEMA)
            self._local.c = c
            self._local.gen = self.generation
        return c

    def reopen(self) -> None:
        """Invalidate connections in all threads (called around a restore)."""
        c = getattr(self._local, "c", None)
        if c is not None:
            c.close()
            self._local.c = None
        self.generation += 1

    # ---- config
    def get_config(self, key: str, default=None):
        r = self.conn().execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
        return json.loads(r["value"]) if r else default

    def set_config(self, key: str, value) -> None:
        self.conn().execute(
            "INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )

    # ---- keystore
    def keystore(self) -> dict | None:
        if not self.keystore_path.exists():
            return None
        return json.loads(self.keystore_path.read_text())

    def write_keystore(self, ks: dict) -> None:
        tmp = self.keystore_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(ks, indent=2))
        os.chmod(tmp, 0o600)
        tmp.replace(self.keystore_path)

    # ---- blobs
    def blob_path(self, file_id: str) -> Path:
        return self.files_dir / file_id[:2] / f"{file_id}.enc"

    def preview_path(self, file_id: str) -> Path:
        return self.preview_dir / file_id[:2] / f"{file_id}.enc"

    def now(self) -> float:
        return time.time()


def seal(mk: bytes, obj, ctx: str) -> bytes:
    return crypto.seal_json(mk, obj, ctx)


def unseal(mk: bytes, blob: bytes, ctx: str):
    return crypto.open_json(mk, blob, ctx)
