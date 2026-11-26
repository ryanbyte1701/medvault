# ScanVault on a Synology NAS

Tested layout for DSM 7.2+ with **Container Manager**. It works on Intel/AMD
models (DS920+, DS923+, DS1522+, ...) and ARM64 models (DS223, DS423, DS124, ...).
The image is multi-arch.

## 1. Create the folders

In **File Station**, inside the `docker` shared folder (Container Manager
creates it), make:

```
/volume1/docker/scanvault/
├── docker-compose.yml   ← copy deploy/synology/docker-compose.yml here
└── data/                ← empty; the encrypted vault lives here
```

## 2. Edit the compose file

Open `docker-compose.yml` in Text Editor and set:

| Setting | What to put |
|---|---|
| `PUID` / `PGID` | Owner of the `data` folder. SSH in and run `id yourDSMuser`. The first admin account is usually `uid=1026`, `gid=100` (users). |
| `TZ` | Your time zone, e.g. `America/Chicago`. Backup schedules and file names use it. |
| `SCANVAULT_PUBLIC_URL` | The HTTPS address from step 4, e.g. `https://scans.yourname.synology.me`. |
| `ports` | `8765:8080` by default. Change the left number if 8765 is taken. |

### Image access

The image is published to `ghcr.io/ryanbyte1701/scanvault` by GitHub Actions
on every merge to `main`. If the repository is private, the image is private too.
Either:

- make the package public under GitHub › Your profile › Packages ›
  scanvault › Package settings (it contains no data or secrets), **or**
- in Container Manager › Registry › Settings › Add, add `https://ghcr.io` with
  your GitHub username and a personal access token that has `read:packages`, **or**
- build on the NAS: copy the repo to `/volume1/docker/scanvault/src`, then
  replace the `image:` line with `build: /volume1/docker/scanvault/src`.

## 3. Create the project

**Container Manager › Project › Create**

- Project name: `scanvault`
- Path: `/volume1/docker/scanvault`
- Source: *Use existing docker-compose.yml*
- Skip the Web Station portal page and click **Done**.

Container Manager pulls the image and starts it. Open
`http://<nas-ip>:8765` on your LAN and run the first-time setup: create a
sign-in, set the encryption key, and download the recovery key file. **Store the
recovery key file somewhere other than this NAS.**

## 4. HTTPS and phone access (recommended)

Health data should only travel over HTTPS.

1. **Control Panel › External Access › DDNS**: add a `yourname.synology.me`
   hostname (free), or use your own domain.
2. **Control Panel › Security › Certificate**: *Add › Get a certificate from
   Let's Encrypt* for `scans.yourname.synology.me`.
3. **Control Panel › Login Portal › Advanced › Reverse Proxy › Create**:
   - Source: HTTPS, hostname `scans.yourname.synology.me`, port 443, enable HSTS
   - Destination: HTTP, `localhost`, port `8765`
   - Custom Header tab: *Create › WebSocket* (adds the Upgrade headers)
4. **Control Panel › Security › Certificate › Settings**: assign the new
   certificate to the reverse proxy entry.
5. Only port 443 should be forwarded on your router, never 8765. For access
   without opening any ports, use **Tailscale** (in Package Center) and open
   `http://<nas-tailscale-name>:8765` from your phone.

Then on your phone, open the HTTPS address and use **Add to Home Screen**.

### Big uploads

DSM's reverse proxy allows large bodies by default. If uploads of CD images
fail around 1 to 2 GB, raise `SCANVAULT_MAX_UPLOAD_MB`, or upload the CD as
several zips.

## 5. Backups

Inside ScanVault › Backups, add destinations. Good Synology-friendly setups:

- **SFTP to a second NAS or off-site box**: enable *Control Panel › File
  Services › FTP › SFTP* on the target, create a user with access only to its
  backup folder, and use key auth. The host key is pinned on first test.
- **Google Drive / Box**: encrypted before upload, so the providers only hold
  ciphertext.
- **Hyper Backup / Snapshot Replication** can also back up
  `/volume1/docker/scanvault/data`. Everything in it is already encrypted, but
  a restore from it still needs your encryption key or recovery key file.

## 6. Restarts and locking

After a NAS reboot or a container update, ScanVault starts **locked**.
Sign in and enter your encryption key to resume scheduled backups. For
unattended unlock you can add a passphrase file (see the commented lines in the
compose file), but anyone with access to the NAS disks could then read the
vault.

## Updating

Container Manager › Project › scanvault › Action › **Build** (it re-pulls
`latest`). Or set up the *Image* tab's update notification. Your data in
`data/` is untouched.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Container restarts with `Permission denied` on `/data` | `PUID`/`PGID` don't match the folder owner. Fix them, or let the container chown it by restarting it once. |
| "Connect Google account" says redirect mismatch | `SCANVAULT_PUBLIC_URL` must exactly match the address in your browser, and the same `…/api/oauth/gdrive/callback` URL must be in the Google OAuth client. |
| `exec format error` | Wrong CPU architecture image: pull again, since the published image includes both amd64 and arm64. |
| Logs | Container Manager › Container › scanvault › Log |
