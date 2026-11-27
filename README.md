# ScanVault

Self-hosted, encrypted vault for medical imaging. Upload the DICOM studies,
film photos and PDF reports that imaging centers hand you, keep organized
local copies per patient, and back them up **encrypted** to Google Drive,
OneDrive, Dropbox, Box, S3-compatible storage (AWS, Backblaze B2, Wasabi,
Cloudflare R2, Synology C2, MinIO), SFTP/SCP, SMB shares, WebDAV/Nextcloud or
a USB disk.

- **Multi-patient**: one record per person (you, kids, parents), each with a
  timeline of studies.
- **Any upload**: single DICOMs, whole CD/zip exports (DICOMDIR, viewers and
  autorun junk are skipped), JPG/PNG/HEIC photos, PDF reports. DICOMs are grouped
  into studies by `StudyInstanceUID`. Date, modality, center and description are
  filled in from the tags. Reports uploaded together with one DICOM study join it.
- **Viewer**: true window/level on the original DICOM pixel values (drag
  sideways for window and up/down for level, or type values; CT presets for
  brain, subdural, stroke, soft tissue, mediastinum, liver, lung and bone). It
  also has zoom toward the cursor, Ctrl+scroll, pinch, double-tap, pan, invert,
  scroll or slider through a series, a frame slider for multi-frame files,
  fullscreen and keyboard shortcuts. Photos get the same tools in the browser.
  PDFs open inline.
- **Themes**: light, dark or match device, with a choice of dark color (six
  presets or any custom color). Saved per account, so it follows you across
  devices.
- **Mobile and web**: responsive UI, installable as a PWA (Add to Home Screen),
  with a "Take photo" button for paper reports and films. A REST API with
  Bearer tokens serves native clients.
- **Encrypted at rest**: every file, preview, patient/study record and stored
  cloud credential is encrypted with AES-256-GCM.
- **Encrypted backups**: one archive per run, encrypted before it leaves the
  box, with schedule and retention per destination.
- **Your key**: you set the encryption key at first run and download a
  **recovery key file** for emergency restore. `tools/restore.py` decrypts
  any backup into plain folders without ScanVault running at all.

## Quick start

```bash
git clone https://github.com/ryanbyte1701/scanvault && cd scanvault
docker compose up -d --build
open http://localhost:8080
```

First run walks you through:

1. **Sign-in**: username and password for the web/mobile UI.
2. **Encryption key**: a passphrase of 12+ characters (or click *Generate*
   for six random words). It is separate from the sign-in password.
3. **Recovery key file**: download `scanvault-recovery-key.txt`, then
   upload it back to prove you saved it. Print it or keep it offline.

Data lives in the `scanvault-data` volume (`/data` in the container).

**Synology NAS:** see [deploy/synology/README.md](deploy/synology/README.md)
for a Container Manager project with `/volume1` paths, PUID/PGID, a DSM reverse
proxy with HTTPS, and backup tips. Prebuilt multi-arch images (amd64 and arm64)
are published to `ghcr.io/ryanbyte1701/scanvault` on every merge to `main`.

The container starts as root only to set the owner of `/data` to
`PUID:PGID` (default `10001`), then drops to that user.

### Locking and restarts

The master key only lives in memory. After a container restart the vault is
**locked**: sign in, then enter the encryption key (or upload the recovery
key file) to unlock. Scheduled backups pause while locked.

For unattended servers you can opt into auto-unlock with a Docker secret
(`SCANVAULT_PASSPHRASE_FILE`, see `docker-compose.yml`). The trade-off is that
anyone who has the host disk also has the key.

### Phones

Open the server's address on the phone and use **Add to Home Screen**. Outside
your LAN, put ScanVault behind HTTPS (Caddy, Traefik, Tailscale Serve,
Cloudflare Tunnel) and set `SCANVAULT_PUBLIC_URL`.

## Backup destinations

Every backup is a single `scanvault-backup-YYYYMMDD-HHMMSSZ.svb` file,
encrypted with your master key before upload. Each destination has its own
schedule (hours, `0` = manual) and retention (keep last N).

| Destination | Auth options | Notes |
|---|---|---|
| **Google Drive** | Google account (OAuth, `drive.file` scope) or service account JSON | For OAuth create a *Web application* client in Google Cloud Console, enable the Drive API, add the redirect URI shown in the form, then click *Connect*. Service accounts need a Shared Drive folder shared with them. Uploads are resumable in 8 MiB chunks. |
| **Box** | Box account (OAuth 2.0) or Custom App with Client Credentials Grant | Rotating refresh tokens are persisted after each use. Files over 50 MB use chunked upload sessions with SHA-1 digests. |
| **OneDrive** | Microsoft account or work/school (Entra ID app, delegated `Files.ReadWrite offline_access`) | Register an app, add the redirect URI shown in the form as a *Web* platform, create a client secret, then click *Connect*. Upload sessions in 10 MiB chunks. Rotated refresh tokens are saved. |
| **Dropbox** | Dropbox app (scoped, App folder or Full Dropbox), offline refresh token | Permissions: `files.content.write`, `files.content.read`, `files.metadata.read`. Files over 150 MB use upload sessions. |
| **S3 / object storage** | Access key + secret | Presets for Amazon S3, Backblaze B2, Wasabi, Cloudflare R2, Synology C2 and MinIO, or any endpoint URL. Multipart uploads, optional storage class and prefix. Bucket versioning or object lock is recommended. |
| **SFTP / SCP** | Password and/or private key (Ed25519, ECDSA, RSA) | The host key is pinned on the first successful *Test*. A changed key blocks the connection. SFTP uploads to `.part` and then renames atomically. |
| **SMB share** | Username + password (`DOMAIN\user` supported) | SMB 2/3 to Windows, Synology, QNAP, TrueNAS or Samba, with optional required SMB3 encryption. Writes `.part` then renames. |
| **WebDAV / Nextcloud** | Username + password or app password | Nextcloud/ownCloud (`…/remote.php/dav/files/USER`), Synology WebDAV Server, Koofr, pCloud and others. Creates folders and uploads `.part` then MOVE. |
| **USB / local disk** | None | Any folder mounted into the container under `/backups` (USB drive, second disk, NFS mount). It can refuse to run if the disk isn't mounted. |

You can also click **Download backup** to save an encrypted `.svb` locally.

## Emergency restore

**Into ScanVault**: on a fresh install choose *Restore from a backup*, upload
the `.svb` and your recovery key file (or type the encryption key), and choose a
new sign-in.

**Without ScanVault** (e.g. years later, server gone):

```bash
pip install cryptography
python3 tools/restore.py --backup scanvault-backup-20261126-213000Z.svb \
    --key scanvault-recovery-key.txt --out ./restored
```

This writes `restored/<Patient (DOB)>/<date title - center>/<files>` plus a
`patients.json` index. Use `--passphrase` instead of `--key` to be prompted for
the encryption key.

## Security design

- **Master key (MK)**: 32 random bytes. The passphrase is stretched with scrypt
  (N=2^15, r=8, p=1) and wraps the MK with AES-256-GCM in `keystore.json`.
  Changing the passphrase re-wraps the MK, so data, backups and the recovery file
  stay valid.
- **Recovery key file**: the MK in base32 with a 4-byte checksum and a
  fingerprint, so typos and mismatched vaults are caught.
- **Files**: streamed AES-256-GCM in 1 MiB chunks with a per-file HKDF subkey.
  The nonce encodes the chunk counter and a final-chunk flag, which detects
  truncation and reordering. The file id is bound as associated data, so blobs
  can't be swapped between records.
- **Metadata**: patient names, DOB, MRN, notes, study details, file names and
  DICOM tags are sealed per row (bound to the row id). The SQLite file holds no
  plaintext PHI.
- **Web**: HttpOnly SameSite=Strict session cookie plus a required
  `X-ScanVault` header on state-changing requests. Uploaded content is served
  inline only for images and PDFs; everything else is forced to download. The
  service worker never caches `/api/` responses. The container runs as a
  non-root user.

### HIPAA and privacy notes

- Keeping your own or your family's records generally isn't covered by HIPAA.
  If a covered entity (a practice, clinic or billing service) uses ScanVault for
  patients, it is responsible for HIPAA's administrative, physical and technical
  safeguards. That includes a BAA with Google or Box even though they only
  receive ciphertext, plus access logging, its own risk analysis and backups of
  the recovery key.
- Cloud providers see backup sizes, times and file names (which contain no PHI).
- There is no key escrow. If you lose both the encryption key and the recovery
  key file, the data cannot be recovered.

## API (for the Android app and scripts)

Interactive docs: `http://localhost:8080/api/docs`. Authenticate with
`POST /api/auth/login {username, password}` → `{token, expires_at}`, then send
`Authorization: Bearer <token>`. Errors are `{"error": "...", "code"?: "..."}`.
A locked vault returns **423** `{code: "locked"}`; unlock with
`POST /api/vault/unlock {passphrase}`.

| Method | Path | |
|---|---|---|
| GET | `/api/health`, `/api/status` | liveness; setup/lock/auth state |
| GET/POST | `/api/patients` | list (with `study_count`, `file_count`) / create `{name, date_of_birth?, sex?, mrn?, notes?}` |
| GET/PUT/DELETE | `/api/patients/{id}` | |
| GET/POST | `/api/patients/{id}/studies` | `{title, modality?, study_date?, facility?, description?}` |
| POST | `/api/patients/{id}/import` | multipart `file` (repeatable). Auto-groups DICOM, expands zips. |
| GET/PUT/DELETE | `/api/studies/{id}` | |
| GET/POST | `/api/studies/{id}/files` | list / multipart `file` (repeatable) |
| GET | `/api/files/{id}`, `/content`, `/thumbnail` | metadata, decrypted bytes, JPEG preview |
| GET | `/api/files/{id}/render?wc=&ww=&frame=` | DICOM rendered with a window center/width in modality units (HU for CT). `X-Window-*`, `X-Default-*`, `X-Min/Max`, `X-Frames`, `X-Modality` headers |
| GET/PUT | `/api/prefs` | `{theme: system\|light\|dark, dark_color: "#rrggbb"}` per user |
| GET/POST/PUT/DELETE | `/api/backups/targets[/{id}]` | destinations (secrets are write-only) |
| POST | `/api/backups/run`, `/api/backups/targets/{id}/run`, `/test` | |
| GET | `/api/backups/runs`, `/api/backups/download` | history; encrypted `.svb` download |

Files: `{id, study_id, patient_id, filename, content_type, size_bytes, kind: image|report|dicom|other, has_thumbnail, sha256, uploaded_at, dicom?}`.

## Development

```bash
pip install -r requirements-dev.txt
SCANVAULT_DATA=./data uvicorn app.main:app --reload --port 8080
pytest -q                     # crypto, API, restore tool, every backup destination
python3 tools/build_demo.py preview/index.html   # self-contained clickable demo, sample data only
```
