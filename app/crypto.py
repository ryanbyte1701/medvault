"""ScanVault cryptography.

Key hierarchy
-------------
* Master key (MK): 32 random bytes generated at setup. Everything is encrypted
  under keys derived from it. It never touches disk in plaintext.
* Passphrase key (KEK): derived from the user's passphrase with scrypt. It wraps
  the MK with AES-256-GCM; the wrapped MK lives in ``keystore.json``.
* Recovery key file: a text file holding the MK itself (base32). With that file
  alone any ScanVault backup can be decrypted, even without the app
  (see ``tools/restore.py``).

Stream format (files at rest and backup archives)
-------------------------------------------------
``b"SVE1" | salt(16) | chunk*`` where each chunk is
``len(4, big endian) | AES-256-GCM(ciphertext+tag)``.
A per-stream key is derived with HKDF-SHA256(MK, salt). The nonce is an
11-byte counter followed by a 1-byte "final chunk" flag, so truncation,
reordering and chunk swapping are all detected.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"SVE1"
CHUNK = 1024 * 1024
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
RECOVERY_BEGIN = "-----BEGIN SCANVAULT RECOVERY KEY-----"
RECOVERY_END = "-----END SCANVAULT RECOVERY KEY-----"


class CryptoError(Exception):
    pass


# --------------------------------------------------------------------------- keys

def _kek(passphrase: str, salt: bytes, n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def fingerprint(master_key: bytes) -> str:
    h = hashlib.sha256(b"scanvault-fingerprint" + master_key).hexdigest()[:16].upper()
    return "-".join(h[i : i + 4] for i in range(0, 16, 4))


def new_master_key() -> bytes:
    return secrets.token_bytes(32)


def wrap_master_key(master_key: bytes, passphrase: str, vault_id: str) -> dict:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    wrapped = AESGCM(_kek(passphrase, salt)).encrypt(nonce, master_key, b"scanvault-mk:" + vault_id.encode())
    return {
        "version": 1,
        "vault_id": vault_id,
        "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": _b64(salt)},
        "nonce": _b64(nonce),
        "wrapped_key": _b64(wrapped),
        "fingerprint": fingerprint(master_key),
    }


def unwrap_master_key(keystore: dict, passphrase: str) -> bytes:
    kdf = keystore["kdf"]
    kek = _kek(passphrase, _unb64(kdf["salt"]), kdf["n"], kdf["r"], kdf["p"])
    try:
        mk = AESGCM(kek).decrypt(
            _unb64(keystore["nonce"]),
            _unb64(keystore["wrapped_key"]),
            b"scanvault-mk:" + keystore["vault_id"].encode(),
        )
    except Exception as exc:  # InvalidTag
        raise CryptoError("Wrong passphrase") from exc
    return mk


# ------------------------------------------------------------------ recovery file

def recovery_file_text(master_key: bytes, vault_id: str, created: str) -> str:
    b32 = base64.b32encode(master_key + hashlib.sha256(master_key).digest()[:4]).decode().rstrip("=")
    groups = " ".join(b32[i : i + 4] for i in range(0, len(b32), 4))
    lines = [groups[i : i + 40].strip() for i in range(0, len(groups), 40)]
    return "\n".join(
        [
            "SCANVAULT EMERGENCY RECOVERY KEY",
            "================================",
            "",
            f"Vault ID:         {vault_id}",
            f"Key fingerprint:  {fingerprint(master_key)}",
            f"Created:          {created}",
            "",
            "This file can decrypt EVERY ScanVault backup of this vault, including",
            "backups stored on Google Drive, Box or SFTP servers. Anyone who holds it",
            "can read the medical records inside. Print it or store it offline",
            "(password manager, safe, USB key in a drawer). Do not email it and do not",
            "store it in the same cloud account as your backups.",
            "",
            RECOVERY_BEGIN,
            *lines,
            RECOVERY_END,
            "",
            "To restore:",
            "  1. In a fresh ScanVault install choose 'Restore from backup' and upload",
            "     the backup file plus this key file, or",
            "  2. Without ScanVault at all:",
            "       python3 tools/restore.py --key scanvault-recovery-key.txt \\",
            "              --backup scanvault-backup-XXXX.svb --out ./restored",
            "",
        ]
    )


def parse_recovery_file(text: str) -> bytes:
    text = text.upper()
    if RECOVERY_BEGIN in text and RECOVERY_END in text:
        body = text.split(RECOVERY_BEGIN, 1)[1].split(RECOVERY_END, 1)[0]
    else:
        body = text
    b32 = "".join(ch for ch in body if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    b32 += "=" * (-len(b32) % 8)
    try:
        raw = base64.b32decode(b32)
    except Exception as exc:
        raise CryptoError("Recovery key is not valid base32") from exc
    if len(raw) != 36:
        raise CryptoError("Recovery key has the wrong length")
    mk, check = raw[:32], raw[32:]
    if not hmac.compare_digest(hashlib.sha256(mk).digest()[:4], check):
        raise CryptoError("Recovery key checksum mismatch (typo?)")
    return mk


# ------------------------------------------------------------- small blobs (DB)

def _subkey(master_key: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(master_key)


def seal_json(master_key: bytes, obj, context: str) -> bytes:
    """Encrypt a small JSON-able object for storage in the database."""
    key = _subkey(master_key, b"", b"scanvault-db-v1")
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, json.dumps(obj).encode(), context.encode())


def open_json(master_key: bytes, blob: bytes, context: str):
    key = _subkey(master_key, b"", b"scanvault-db-v1")
    try:
        return json.loads(AESGCM(key).decrypt(blob[:12], blob[12:], context.encode()))
    except Exception as exc:
        raise CryptoError("Could not decrypt record") from exc


# ------------------------------------------------------------------ streams

def _nonce(counter: int, final: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\x01" if final else b"\x00")


def encrypt_stream(master_key: bytes, src: BinaryIO, dst: BinaryIO, aad: bytes = b"") -> int:
    """Encrypt src into dst. Returns plaintext byte count."""
    salt = secrets.token_bytes(16)
    aes = AESGCM(_subkey(master_key, salt, b"scanvault-stream-v1"))
    dst.write(MAGIC + salt)
    total = 0
    counter = 0
    cur = src.read(CHUNK)
    while True:
        nxt = src.read(CHUNK)
        final = not nxt
        ct = aes.encrypt(_nonce(counter, final), cur, aad)
        dst.write(struct.pack(">I", len(ct)) + ct)
        total += len(cur)
        counter += 1
        if final:
            return total
        cur = nxt


def decrypt_stream_iter(master_key: bytes, src: BinaryIO, aad: bytes = b"") -> Iterator[bytes]:
    head = src.read(20)
    if len(head) != 20 or head[:4] != MAGIC:
        raise CryptoError("Not a ScanVault encrypted stream")
    aes = AESGCM(_subkey(master_key, head[4:], b"scanvault-stream-v1"))
    counter = 0
    while True:
        lb = src.read(4)
        if len(lb) != 4:
            raise CryptoError("Encrypted stream is truncated")
        (n,) = struct.unpack(">I", lb)
        if n > CHUNK + 16:
            raise CryptoError("Corrupt chunk length")
        ct = src.read(n)
        if len(ct) != n:
            raise CryptoError("Encrypted stream is truncated")
        # Peek: is there more data after this chunk?
        try:
            pt = aes.decrypt(_nonce(counter, False), ct, aad)
            final = False
        except Exception:
            try:
                pt = aes.decrypt(_nonce(counter, True), ct, aad)
                final = True
            except Exception as exc:
                raise CryptoError("Decryption failed: wrong key or tampered data") from exc
        yield pt
        counter += 1
        if final:
            if src.read(1):
                raise CryptoError("Trailing data after final chunk")
            return


def decrypt_stream(master_key: bytes, src: BinaryIO, dst: BinaryIO, aad: bytes = b"") -> int:
    total = 0
    for pt in decrypt_stream_iter(master_key, src, aad):
        dst.write(pt)
        total += len(pt)
    return total


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


@dataclass
class Vault:
    """In-memory unlocked state."""

    master_key: bytes | None = None

    @property
    def unlocked(self) -> bool:
        return self.master_key is not None

    def lock(self) -> None:
        self.master_key = None


def random_id() -> str:
    return secrets.token_hex(8)


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    h = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode())
    return f"scrypt$16384$8$1${_b64(salt)}${_b64(h)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, h = stored.split("$")
        calc = Scrypt(salt=_unb64(salt), length=32, n=int(n), r=int(r), p=int(p)).derive(password.encode())
        return hmac.compare_digest(calc, _unb64(h))
    except Exception:
        return False
