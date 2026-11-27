#!/usr/bin/env python3
"""ScanVault emergency restore: decrypt a backup WITHOUT running ScanVault.

    pip install cryptography
    python3 tools/restore.py --key scanvault-recovery-key.txt \
        --backup scanvault-backup-20261126-213000Z.svb --out ./restored

Instead of --key you can pass --passphrase (you will be prompted). That only
works for backups made with "passphrase restore" turned on in Settings.

Output:
    restored/
      patients.json                 # every patient, study and file record
      Jane Doe (1980-04-02)/
        2026-03-14 MR Knee - Lakeside Imaging/
          report.pdf
          IM000001.dcm ...
Add --vault-only to just extract the encrypted vault (to import into a new
ScanVault via setup > Restore instead).
"""
from __future__ import annotations

import argparse
import getpass
import json
import re
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import backup, crypto  # noqa: E402


def safe(name: str) -> str:
    name = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", name or "").strip(" .")
    return name[:120] or "unnamed"


def unique(p: Path) -> Path:
    if not p.exists():
        return p
    i = 2
    while True:
        q = p.with_name(f"{p.stem} ({i}){p.suffix}")
        if not q.exists():
            return q
        i += 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backup", required=True, type=Path)
    ap.add_argument("--key", type=Path, help="recovery key text file")
    ap.add_argument("--passphrase", action="store_true", help="prompt for the encryption key instead (only if the backup allows it)")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--vault-only", action="store_true")
    a = ap.parse_args()
    try:
        return restore(ap, a)
    except crypto.CryptoError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: {exc.filename or exc}: file not found", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


def restore(ap, a) -> int:
    hdr = backup.read_header(a.backup)
    print(f"Backup of vault {hdr['vault_id']} made {hdr['created']} (key fingerprint {hdr['fingerprint']})")
    if a.key:
        mk = backup.master_key_for(a.backup, recovery_text=a.key.read_text(errors="replace"))
    elif a.passphrase:
        mk = backup.master_key_for(a.backup, passphrase=getpass.getpass("Encryption key: "))
    else:
        ap.error("give --key FILE or --passphrase")

    a.out.mkdir(parents=True, exist_ok=True)
    # The extracted vault is still encrypted (sealed records, .enc blobs), so
    # it is kept next to the output rather than in the system temp dir.
    work = a.out / ".vault" if a.vault_only else Path(tempfile.mkdtemp(prefix=".sv-restore-", dir=a.out))
    try:
        backup.extract_archive(a.backup, mk, work)
        if a.vault_only:
            print(f"Encrypted vault extracted to {work}")
            return 0
        return export(mk, work, a.out)
    finally:
        if not a.vault_only:
            shutil.rmtree(work, ignore_errors=True)


def export(mk: bytes, work: Path, out: Path) -> int:
    db = sqlite3.connect(work / "scanvault.db")
    db.row_factory = sqlite3.Row
    index, failed = [], []
    n = 0
    try:
        for p in db.execute("SELECT * FROM patients"):
            try:
                pd = crypto.open_json(mk, p["blob"], f"patient:{p['id']}")
            except crypto.CryptoError as exc:
                failed.append(f"patient {p['id']}: {exc}")
                continue
            pdir = out / safe(f"{pd.get('name')}" + (f" ({pd['date_of_birth']})" if pd.get("date_of_birth") else ""))
            prec = {**pd, "id": p["id"], "studies": []}
            for s in db.execute("SELECT * FROM studies WHERE patient_id=?", (p["id"],)):
                try:
                    sd = crypto.open_json(mk, s["blob"], f"study:{s['id']}")
                except crypto.CryptoError as exc:
                    failed.append(f"study {s['id']}: {exc}")
                    continue
                label = " ".join(x for x in (sd.get("study_date") or sd.get("uploaded"), sd.get("title")) if x)
                if sd.get("facility"):
                    label += f" - {sd['facility']}"
                sdir = pdir / safe(label)
                sdir.mkdir(parents=True, exist_ok=True)
                srec = {**sd, "id": s["id"], "files": []}
                for f in db.execute("SELECT * FROM files WHERE study_id=?", (s["id"],)):
                    dst = None
                    try:
                        fd = crypto.open_json(mk, f["blob"], f"file:{f['id']}")
                        src = work / "files" / f["id"][:2] / f"{f['id']}.enc"
                        dst = unique(sdir / safe(fd.get("filename") or f["id"]))
                        with open(src, "rb") as i, open(dst, "wb") as o:
                            crypto.decrypt_stream(mk, i, o, f"file:{f['id']}".encode())
                    except (crypto.CryptoError, OSError) as exc:
                        if dst is not None:
                            dst.unlink(missing_ok=True)
                        failed.append(f"file {f['id']} ({sd.get('title')}): {exc}")
                        continue
                    sha = fd.get("sha256") or (f["sha256"] if not str(f["sha256"]).startswith("h1:") else None)
                    srec["files"].append({**fd, "id": f["id"], "kind": f["kind"], "sha256": sha, "path": str(dst.relative_to(out))})
                    n += 1
                prec["studies"].append(srec)
            index.append(prec)
    finally:
        db.close()
        (out / "patients.json").write_text(json.dumps(index, indent=2))
    print(f"Restored {len(index)} patients and {n} files to {out}")
    if failed:
        print(f"{len(failed)} item(s) could not be restored:", file=sys.stderr)
        for line in failed:
            print("  " + line, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
