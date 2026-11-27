"""Activity log: who did what, and when.

Every entry is one row of the ``audit_log`` table. The details (names,
file names, client address, browser) are encrypted; only the sequence
number, time, action name and the random ids of the user, patient and study
stay in the clear, like the ids the other tables already keep, so the log can
be filtered without decrypting all of it.

Encryption
----------
Sign-ins, failed sign-ins and failed unlocks happen while the vault is
locked, so the log cannot use the master key to write. Instead the log has
its own X25519 key pair. Each entry is encrypted to the public key (an
ephemeral key per entry, HKDF-SHA256, AES-256-GCM); the private key, sealed
with the master key, is needed to read it. The private key and the MAC key
below are stored once, sealed under the master key, in ``config`` under
``audit_keys`` and are re-sealed on a master key change.

Tamper evidence
---------------
Entries form a hash chain: ``hash = SHA-256(prev hash | seq, time, action,
ids | encrypted details)``. While the vault is unlocked every new entry also
gets ``mac = HMAC-SHA256(mac key, hash)``, and ``config.audit_head`` holds a
MAC over the newest sequence number and hash. The MAC key is sealed with the
master key, so someone with only disk access cannot rewrite, reorder, drop
or truncate signed history without ``verify`` noticing. Entries written while
the vault was locked are covered by the chain and get signed by the next
signed entry (or the checkpoint written at unlock).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import threading
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import crypto

log = logging.getLogger("scanvault.audit")

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
  seq INTEGER PRIMARY KEY, ts REAL NOT NULL, action TEXT NOT NULL,
  user_id TEXT, patient_id TEXT, study_id TEXT,
  blob BLOB NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL, mac TEXT);
CREATE INDEX IF NOT EXISTS audit_user ON audit_log(user_id, seq);
CREATE INDEX IF NOT EXISTS audit_patient ON audit_log(patient_id, seq);
CREATE INDEX IF NOT EXISTS audit_study ON audit_log(study_id, seq);
CREATE INDEX IF NOT EXISTS audit_ts ON audit_log(ts);
"""

GENESIS = "0" * 64
KEYS_CFG = "audit_keys"
HEAD_CFG = "audit_head"
MAX_PENDING = 2000

# Short descriptions for the UI and exports. Unknown actions still show,
# by name, so other features can add their own without touching this list.
LABELS = {
    "auth.setup": "Set up the vault",
    "auth.login": "Signed in",
    "auth.login_failed": "Failed sign-in",
    "auth.sso_login": "Signed in with single sign-on",
    "auth.sso_failed": "Failed single sign-on",
    "auth.logout": "Signed out",
    "auth.logout_others": "Signed out other devices",
    "auth.password_changed": "Changed sign-in password",
    "auth.sso_linked": "Linked a single sign-on account",
    "auth.sso_unlinked": "Unlinked a single sign-on account",
    "vault.unlock": "Unlocked the vault",
    "vault.unlock_failed": "Failed to unlock the vault",
    "vault.lock": "Locked the vault",
    "vault.auto_lock": "Vault locked after inactivity",
    "vault.auto_unlock": "Vault unlocked at startup",
    "vault.recovery_key_downloaded": "Downloaded the recovery key",
    "vault.recovery_key_confirmed": "Confirmed the recovery key",
    "vault.passphrase_changed": "Changed the encryption key passphrase",
    "vault.rekey": "Rotated the master key",
    "vault.settings": "Changed vault settings",
    "patient.create": "Added a patient",
    "patient.update": "Edited a patient",
    "patient.delete": "Deleted a patient",
    "patient.view": "Viewed a patient",
    "study.create": "Added a study",
    "study.update": "Edited a study",
    "study.delete": "Deleted a study",
    "study.view": "Viewed a study",
    "study.compare": "Opened study comparison",
    "file.upload": "Uploaded files",
    "file.update": "Edited a file",
    "file.move": "Moved a file",
    "file.delete": "Deleted a file",
    "file.view": "Viewed a file",
    "file.download": "Downloaded a file",
    "backup.target_create": "Added a backup destination",
    "backup.target_update": "Changed a backup destination",
    "backup.target_delete": "Removed a backup destination",
    "backup.target_test": "Tested a backup destination",
    "backup.run": "Ran a backup",
    "backup.download": "Downloaded a backup",
    "backup.restore": "Restored from a backup",
    "sso.provider_create": "Added a sign-in provider",
    "sso.provider_update": "Changed a sign-in provider",
    "sso.provider_delete": "Removed a sign-in provider",
    "sso.settings": "Changed sign-in settings",
    "lab.upload": "Uploaded a lab report",
    "lab.create": "Added lab results",
    "lab.save": "Saved reviewed lab results",
    "lab.update": "Edited lab results",
    "lab.delete": "Deleted lab results",
    "lab.export": "Exported lab results",
    "activity.export": "Exported the activity log",
    "activity.verify": "Checked the activity log",
}

CATEGORIES = {
    "auth": "Sign-in",
    "vault": "Encryption and keys",
    "patient": "Patients",
    "study": "Studies",
    "file": "Files",
    "backup": "Backups",
    "sso": "Sign-in settings",
    "activity": "Activity log",
    "ai": "AI",
    "lab": "Labs",
}


def label(action: str) -> str:
    return LABELS.get(action) or action.replace(".", ": ").replace("_", " ").capitalize()


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def _entry_key(shared: bytes, epk: bytes, pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=epk + pub, info=b"scanvault-audit-v1").derive(shared)


def _raw_pub(k: X25519PublicKey) -> bytes:
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def encrypt_details(pub: bytes, obj: dict, seq: int) -> bytes:
    """``b"A1" | ephemeral public key (32) | nonce (12) | AES-GCM``."""
    eph = X25519PrivateKey.generate()
    epk = _raw_pub(eph.public_key())
    key = _entry_key(eph.exchange(X25519PublicKey.from_public_bytes(pub)), epk, pub)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(obj, separators=(",", ":")).encode(), f"audit:{seq}".encode())
    return b"A1" + epk + nonce + ct


def decrypt_details(priv: X25519PrivateKey, blob: bytes, seq: int) -> dict:
    if blob[:2] != b"A1" or len(blob) < 2 + 32 + 12 + 16:
        raise crypto.CryptoError("Unknown activity record format")
    epk, nonce, ct = blob[2:34], blob[34:46], blob[46:]
    pub = _raw_pub(priv.public_key())
    key = _entry_key(priv.exchange(X25519PublicKey.from_public_bytes(epk)), epk, pub)
    try:
        return json.loads(AESGCM(key).decrypt(nonce, ct, f"audit:{seq}".encode()))
    except Exception as exc:
        raise crypto.CryptoError("Could not decrypt activity record") from exc


def chain_hash(prev: str, seq: int, ts: float, action: str, user_id, patient_id, study_id, blob: bytes) -> str:
    head = json.dumps([seq, repr(float(ts)), action, user_id, patient_id, study_id], separators=(",", ":")).encode()
    h = hashlib.sha256(b"scanvault-audit-chain-v1\0")
    h.update(prev.encode() + b"\0" + head + b"\0")
    h.update(blob)
    return h.hexdigest()


def _mac(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


def _cfg_get(c, key):
    r = c.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
    return json.loads(r["value"] if hasattr(r, "keys") else r[0]) if r else None


def _cfg_set(c, key, value) -> None:
    c.execute(
        "INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, json.dumps(value)),
    )


class AuditLog:
    def __init__(self, store):
        # ``store`` is a Store or a function returning the current one (the
        # app's store can be swapped, e.g. in tests).
        self._store = store
        self._lock = threading.RLock()
        self._priv: X25519PrivateKey | None = None
        self._mac_key: bytes | None = None
        self._pub: str | None = None
        self._pending: list[tuple] = []  # entries from before the log had keys (first start after an upgrade)
        self._recent: dict[tuple, float] = {}

    @property
    def store(self):
        return self._store() if callable(self._store) else self._store

    # ------------------------------------------------------------ keys
    def _keys_current(self, cfg: dict | None) -> bool:
        """The keys in memory belong to this database's log."""
        return bool(cfg) and self._priv is not None and cfg.get("pub") == self._pub

    def unlocked(self) -> bool:
        return self._keys_current(_cfg_get(self.store.conn(), KEYS_CFG))

    def load(self, master: bytes) -> None:
        """Called whenever the vault is unlocked (or its database replaced):
        open the log's keys, creating them on first use, then sign the
        entries written while the vault was locked."""
        with self._lock:
            c = self.store.conn()
            cfg = _cfg_get(c, KEYS_CFG)
            if cfg:
                d = crypto.open_json(master, _unb64(cfg["sealed"]), "audit-keys")
                priv = X25519PrivateKey.from_private_bytes(_unb64(d["priv"]))
                mac_key = _unb64(d["mac"])
            else:
                priv, mac_key = X25519PrivateKey.generate(), secrets.token_bytes(32)
                cfg = self._sealed(master, priv, mac_key)
                _cfg_set(c, KEYS_CFG, cfg)
            self._priv, self._mac_key, self._pub = priv, mac_key, cfg["pub"]
            pending, self._pending = self._pending, []
            for p in pending:
                self._append(*p)
            self._checkpoint(c)

    def forget(self) -> None:
        with self._lock:
            self._priv = None
            self._mac_key = None
            self._pub = None

    @staticmethod
    def _sealed(master: bytes, priv: X25519PrivateKey, mac_key: bytes) -> dict:
        raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        return {
            "version": 1,
            "pub": _b64(_raw_pub(priv.public_key())),
            "sealed": _b64(crypto.seal_json(master, {"priv": _b64(raw), "mac": _b64(mac_key)}, "audit-keys")),
        }

    def reseal(self, c, old: bytes, new: bytes) -> None:
        """Master key change: re-seal the log's keys under the new key (run
        inside the key change's transaction). Entries need no change."""
        cfg = _cfg_get(c, KEYS_CFG)
        if not cfg:
            return
        d = crypto.open_json(old, _unb64(cfg["sealed"]), "audit-keys")
        _cfg_set(c, KEYS_CFG, {**cfg, "sealed": _b64(crypto.seal_json(new, d, "audit-keys"))})

    # ------------------------------------------------------------ writing
    def record(self, action: str, *, user_id=None, patient_id=None, study_id=None, details: dict | None = None, dedupe: float = 0) -> None:
        """Append one entry. Never raises: a failure to log is reported in the
        server log but does not break the request that caused it."""
        try:
            now = time.time()
            if dedupe:
                key = (action, user_id, patient_id, study_id, (details or {}).get("file_id"))
                with self._lock:
                    last = self._recent.get(key)
                    if last and now - last < dedupe:
                        return
                    if len(self._recent) > 5000:
                        self._recent = {k: t for k, t in self._recent.items() if now - t < 3600}
                    self._recent[key] = now
            clean = {k: v for k, v in (details or {}).items() if v is not None and v != ""}
            with self._lock:
                if _cfg_get(self.store.conn(), KEYS_CFG) is None:
                    if len(self._pending) < MAX_PENDING:
                        self._pending.append((now, action, user_id, patient_id, study_id, clean))
                    return
                self._append(now, action, user_id, patient_id, study_id, clean)
        except Exception:
            log.exception("Could not write activity log entry %s", action)

    def _append(self, ts, action, user_id, patient_id, study_id, details) -> None:
        c = self.store.conn()
        cfg = _cfg_get(c, KEYS_CFG)
        pub = _unb64(cfg["pub"])
        last = c.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        seq = (last[0] + 1) if last else 1
        prev = last[1] if last else GENESIS
        blob = encrypt_details(pub, details, seq)
        h = chain_hash(prev, seq, ts, action, user_id, patient_id, study_id, blob)
        signing = self._keys_current(cfg)
        mac = _mac(self._mac_key, f"entry:{seq}:{h}") if signing else None
        c.execute(
            "INSERT INTO audit_log(seq,ts,action,user_id,patient_id,study_id,blob,prev,hash,mac) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (seq, ts, action, user_id, patient_id, study_id, blob, prev, h, mac),
        )
        if signing:
            _cfg_set(c, HEAD_CFG, {"seq": seq, "hash": h, "mac": _mac(self._mac_key, f"head:{seq}:{h}")})

    def _checkpoint(self, c) -> None:
        """Sign the newest entry (covering everything before it)."""
        if not self._mac_key:
            return
        last = c.execute("SELECT seq, hash, mac FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        if not last:
            return
        seq, h = last[0], last[1]
        if not last[2]:
            c.execute("UPDATE audit_log SET mac=? WHERE seq=?", (_mac(self._mac_key, f"entry:{seq}:{h}"), seq))
        _cfg_set(c, HEAD_CFG, {"seq": seq, "hash": h, "mac": _mac(self._mac_key, f"head:{seq}:{h}")})

    # ------------------------------------------------------------ reading
    def query(self, *, user_id=None, patient_id=None, study_id=None, action=None, since=None, until=None, before=None, q=None, limit=50):
        """Newest first. ``action`` matches a full name or a prefix ending in
        a dot ("file." for every file action). Returns (entries, next_before)."""
        if not self.unlocked():
            raise crypto.CryptoError("Vault is locked")
        where, args = [], []
        for col, v in (("user_id", user_id), ("patient_id", patient_id), ("study_id", study_id)):
            if v:
                where.append(f"{col}=?")
                args.append(v)
        if action:
            acts = [a for a in str(action).split(",") if a]
            ors = []
            for a in acts:
                if a.endswith("."):
                    ors.append("action LIKE ? ESCAPE '\\'")
                    args.append(a.replace("_", "\\_") + "%")
                else:
                    ors.append("action=?")
                    args.append(a)
            if ors:
                where.append("(" + " OR ".join(ors) + ")")
        if since is not None:
            where.append("ts>=?")
            args.append(since)
        if until is not None:
            where.append("ts<?")
            args.append(until)
        needle = (q or "").strip().lower()
        out: list[dict] = []
        c = self.store.conn()
        cursor = before
        while True:
            w, a = list(where), list(args)
            if cursor is not None:
                w.append("seq<?")
                a.append(cursor)
            sql = "SELECT * FROM audit_log" + (" WHERE " + " AND ".join(w) if w else "") + " ORDER BY seq DESC LIMIT ?"
            rows = c.execute(sql, (*a, 200)).fetchall()
            for r in rows:
                cursor = r["seq"]
                e = self._row_out(r)
                if needle and needle not in _haystack(e):
                    continue
                out.append(e)
                if len(out) >= limit:
                    more = c.execute(
                        "SELECT 1 FROM audit_log WHERE " + " AND ".join([*where, "seq<?"]) + " LIMIT 1", (*args, cursor)
                    ).fetchone()
                    return out, (cursor if more else None)
            if len(rows) < 200:
                return out, None

    def iter_all(self, **filters):
        before = None
        while True:
            page, before = self.query(before=before, limit=500, **filters)
            yield from page
            if before is None:
                return

    def _row_out(self, r) -> dict:
        try:
            d = decrypt_details(self._priv, r["blob"], r["seq"])
            ok = True
        except crypto.CryptoError:
            d, ok = {}, False
        return {
            "seq": r["seq"],
            "at": r["ts"],
            "action": r["action"],
            "label": label(r["action"]),
            "category": r["action"].split(".", 1)[0],
            "user_id": r["user_id"],
            "patient_id": r["patient_id"],
            "study_id": r["study_id"],
            "details": d,
            "signed": bool(r["mac"]),
            "readable": ok,
            "hash": r["hash"],
        }

    def users(self) -> list[str]:
        return [r[0] for r in self.store.conn().execute("SELECT DISTINCT user_id FROM audit_log WHERE user_id IS NOT NULL")]

    def actions(self) -> list[str]:
        return [r[0] for r in self.store.conn().execute("SELECT DISTINCT action FROM audit_log ORDER BY action")]

    # ------------------------------------------------------------ verifying
    def verify(self) -> dict:
        """Walk the whole chain. Needs the vault unlocked (for the MAC key)."""
        if not self.unlocked():
            raise crypto.CryptoError("Vault is locked")
        c = self.store.conn()
        problems: list[str] = []
        prev, expect, n = GENESIS, 1, 0
        last_signed = 0
        last_hash = None
        for r in c.execute("SELECT * FROM audit_log ORDER BY seq"):
            n += 1
            seq = r["seq"]
            if seq != expect:
                problems.append(f"Entries {expect} to {seq - 1} are missing")
            if r["prev"] != prev:
                problems.append(f"Entry {seq} does not link to the entry before it")
            h = chain_hash(r["prev"], seq, r["ts"], r["action"], r["user_id"], r["patient_id"], r["study_id"], r["blob"])
            if h != r["hash"]:
                problems.append(f"Entry {seq} was changed after it was written")
            if r["mac"]:
                if hmac.compare_digest(r["mac"], _mac(self._mac_key, f"entry:{seq}:{r['hash']}")):
                    last_signed = seq
                else:
                    problems.append(f"Entry {seq} has an invalid signature")
            prev, expect, last_hash = r["hash"], seq + 1, r["hash"]
            if len(problems) > 50:
                problems.append("Stopped after 50 problems")
                break
        head = _cfg_get(c, HEAD_CFG)
        if head:
            if not hmac.compare_digest(str(head.get("mac", "")), _mac(self._mac_key, f"head:{head.get('seq')}:{head.get('hash')}")):
                problems.append("The record of the newest signed entry has an invalid signature")
            else:
                row = c.execute("SELECT hash FROM audit_log WHERE seq=?", (head["seq"],)).fetchone()
                if not row:
                    problems.append(f"Signed entries up to {head['seq']} existed but the log now ends at {expect - 1}")
                elif row[0] != head["hash"]:
                    problems.append(f"Entry {head['seq']} does not match the signed record of it")
        elif last_signed:
            problems.append("The record of the newest signed entry is missing")
        return {
            "ok": not problems,
            "entries": n,
            "signed_through": last_signed,
            "unsigned_tail": max(0, (expect - 1) - last_signed),
            "head_hash": last_hash,
            "problems": problems,
            "checked_at": time.time(),
        }


def _haystack(e: dict) -> str:
    parts = [e["action"], e["label"]]
    for v in e["details"].values():
        if isinstance(v, (str, int, float)):
            parts.append(str(v))
        elif isinstance(v, list):
            parts.extend(str(x) for x in v[:50])
    return " ".join(parts).lower()
