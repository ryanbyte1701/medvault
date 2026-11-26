"""Encrypted backup archives (.svb).

Layout::

    b"SVB1" | header_len(4, BE) | header JSON | SVE1 encrypted stream of a tar

The JSON header is NOT secret: vault id, created time, key fingerprint and the
passphrase-wrapped master key (so a backup can be restored with either the
passphrase or the recovery key file). The tar holds the SQLite database
(patient metadata sealed per-row), the already-encrypted file blobs and
previews, and the keystore.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import struct
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from . import crypto

MAGIC = b"SVB1"
AAD = b"scanvault-backup-v1"


def backup_name(ts: float | None = None) -> str:
    dt = datetime.fromtimestamp(ts or time.time(), tz=timezone.utc)
    return f"scanvault-backup-{dt.strftime('%Y%m%d-%H%M%S')}Z.svb"


def create_archive(store, master_key: bytes, out_path: Path, app_version: str) -> dict:
    ks = store.keystore()
    with tempfile.TemporaryDirectory(dir=store.tmp_dir) as td:
        td = Path(td)
        snap = td / "scanvault.db"
        src = sqlite3.connect(store.db_path)
        dst = sqlite3.connect(snap)
        with dst:
            src.backup(dst)
        src.close()
        dst.close()
        manifest = {
            "format": 1,
            "app_version": app_version,
            "vault_id": ks["vault_id"],
            "created": datetime.now(timezone.utc).isoformat(),
        }
        tar_path = td / "vault.tar"
        with tarfile.open(tar_path, "w") as tar:
            _add_bytes(tar, "manifest.json", json.dumps(manifest, indent=2).encode())
            tar.add(snap, "scanvault.db")
            tar.add(store.keystore_path, "keystore.json")
            if store.files_dir.exists():
                tar.add(store.files_dir, "files")
            if store.preview_dir.exists():
                tar.add(store.preview_dir, "previews")
        header = {
            "format": 1,
            "vault_id": ks["vault_id"],
            "fingerprint": ks["fingerprint"],
            "created": manifest["created"],
            "app_version": app_version,
            "keystore": ks,
        }
        hb = json.dumps(header).encode()
        tmp_out = out_path.with_suffix(".partial")
        with open(tar_path, "rb") as src_f, open(tmp_out, "wb") as out:
            out.write(MAGIC + struct.pack(">I", len(hb)) + hb)
            crypto.encrypt_stream(master_key, src_f, out, AAD)
        tmp_out.replace(out_path)
    return header


def read_header(path: Path) -> dict:
    with open(path, "rb") as f:
        return _read_header(f)


def _read_header(f) -> dict:
    if f.read(4) != MAGIC:
        raise crypto.CryptoError("Not a ScanVault backup (.svb) file")
    (n,) = struct.unpack(">I", f.read(4))
    if n > 1_000_000:
        raise crypto.CryptoError("Corrupt backup header")
    return json.loads(f.read(n))


def master_key_for(path: Path, passphrase: str | None = None, recovery_text: str | None = None) -> bytes:
    header = read_header(path)
    if recovery_text:
        mk = crypto.parse_recovery_file(recovery_text)
    elif passphrase:
        mk = crypto.unwrap_master_key(header["keystore"], passphrase)
    else:
        raise crypto.CryptoError("Provide the passphrase or the recovery key file")
    if crypto.fingerprint(mk) != header["fingerprint"]:
        raise crypto.CryptoError(
            f"This key (fingerprint {crypto.fingerprint(mk)}) does not match the backup (fingerprint {header['fingerprint']})"
        )
    return mk


def extract_archive(path: Path, master_key: bytes, dest: Path) -> dict:
    """Decrypt and untar into dest (a fresh directory). Returns the header."""
    dest.mkdir(parents=True, exist_ok=True)
    tar_path = dest / ".vault.tar"
    with open(path, "rb") as f:
        header = _read_header(f)
        with open(tar_path, "wb") as out:
            crypto.decrypt_stream(master_key, f, out, AAD)
    with tarfile.open(tar_path, "r") as tar:
        tar.extractall(dest, filter="data")
    tar_path.unlink()
    return header


def restore_into_store(store, archive: Path, master_key: bytes) -> dict:
    """Replace the store's data with the archive's contents."""
    with tempfile.TemporaryDirectory(dir=store.tmp_dir) as td:
        td = Path(td)
        header = extract_archive(archive, master_key, td)
        if not (td / "scanvault.db").exists() or not (td / "keystore.json").exists():
            raise crypto.CryptoError("Backup is missing its database or keystore")
        store.reopen()
        for name in ("scanvault.db-wal", "scanvault.db-shm"):
            p = store.dir / name
            if p.exists():
                p.unlink()
        shutil.move(str(td / "scanvault.db"), store.db_path)
        shutil.move(str(td / "keystore.json"), store.keystore_path)
        os.chmod(store.keystore_path, 0o600)
        for sub, target in (("files", store.files_dir), ("previews", store.preview_dir)):
            if target.exists():
                shutil.rmtree(target)
            if (td / sub).exists():
                shutil.move(str(td / sub), target)
            else:
                target.mkdir(parents=True)
        store.reopen()
    return header


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    import io

    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(data))
