# MedVault on a Synology NAS

Tested layout for DSM 7.2+ with **Container Manager**. It works on Intel/AMD
models (DS920+, DS923+, DS1522+, ...) and ARM64 models (DS223, DS423, DS124, ...).
The image is multi-arch.

## 1. Create the folders

In **File Station**, inside the `docker` shared folder (Container Manager
creates it), make:

```
/volume1/docker/medvault/
├── docker-compose.yml   ← copy deploy/synology/docker-compose.yml here
└── data/                ← empty; the encrypted vault lives here
```

## 2. Edit the compose file

Open `docker-compose.yml` in Text Editor and set:

| Setting | What to put |
|---|---|
| `PUID` / `PGID` | Owner of the `data` folder. SSH in and run `id yourDSMuser`. The first admin account is usually `uid=1026`, `gid=100` (users). |
| `TZ` | Your time zone, e.g. `America/Chicago`. Backup schedules and file names use it. |
| `MEDVAULT_PUBLIC_URL` | The HTTPS address from step 4, e.g. `https://scans.yourname.synology.me`. |
| `ports` | `127.0.0.1:8765:8080` by default: only the NAS itself (its reverse proxy) can reach the container. Change 8765 if it's taken, but keep `127.0.0.1:`. |
| `FORWARDED_ALLOW_IPS` | Leave `172.16.0.0/12`: only DSM's reverse proxy, which reaches the container through the Docker bridge, may say the visitor used HTTPS. |

### Image access

The image is published to `ghcr.io/ryanbyte1701/medvault` by GitHub Actions
on every merge to `main`. If the repository is private, the image is private too.
Either:

- make the package public under GitHub › Your profile › Packages ›
  medvault › Package settings (it contains no data or secrets), **or**
- in Container Manager › Registry › Settings › Add, add `https://ghcr.io` with
  your GitHub username and a personal access token that has `read:packages`, **or**
- build on the NAS: copy the repo to `/volume1/docker/medvault/src`, then
  replace the `image:` line with `build: /volume1/docker/medvault/src/server`.

## 3. Create the project

**Container Manager › Project › Create**

- Project name: `medvault`
- Path: `/volume1/docker/medvault`
- Source: *Use existing docker-compose.yml*
- Skip the Web Station portal page and click **Done**.

Container Manager pulls the image and starts it. The container only listens on
the NAS itself, so set up HTTPS (step 4) before the first-time setup.

## 4. HTTPS (required)

Health data, your password and your encryption key should only travel over
HTTPS. The compose file therefore doesn't expose MedVault on the LAN at all;
DSM's reverse proxy is the only way in.

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
   without opening any ports, install **Tailscale** (Package Center), turn on
   HTTPS certificates in the Tailscale admin console, and on the NAS run
   `tailscale serve --bg --https=443 http://127.0.0.1:8765`; then open
   `https://<nas-name>.<tailnet>.ts.net` from your devices.

## 5. First-time setup

1. Open **Container Manager › Container › medvault › Log**. Near the top it
   shows a box with the **first-run setup code**, e.g. `K7QM-2XPA-9DWN`. It
   proves you own the NAS: nobody else on your network can claim the vault
   before you do. (It changes on every restart until setup is done.)
2. Open `https://scans.yourname.synology.me`, choose *Create a new vault*,
   enter the setup code, create a sign-in, and set the encryption key. *Generate
   one for me* makes a six-word key (about 77 bits).
3. Download the recovery key file and confirm it. **Store it somewhere other
   than this NAS.** If you leave this step, MedVault keeps reminding you.

Then on your phone, open the HTTPS address and use **Add to Home Screen**.

### Big uploads

DSM's reverse proxy allows large bodies by default. If uploads of CD images
fail around 1 to 2 GB, raise `MEDVAULT_MAX_UPLOAD_MB`, or upload the CD as
several zips.

## 6. Backups

Inside MedVault › Backups, add destinations. Good Synology-friendly setups:

- **SFTP to a second NAS or off-site box**: enable *Control Panel › File
  Services › FTP › SFTP* on the target, create a user with access only to its
  backup folder, and use key auth. The host key is pinned on first test.
- **Google Drive / Box**: encrypted before upload, so the providers only hold
  ciphertext.
- **Synology C2 Object Storage, Backblaze B2 or Wasabi**: choose *S3 /
  object storage* and pick the provider. These are cheap, off-site, and
  support object lock against ransomware.
- **USB drive on the NAS**: uncomment the `/volumeUSB1/usbshare:/backups/usb1`
  line in the compose file, rebuild the project, then add a *USB / local disk*
  destination at `/backups/usb1/medvault`. Destinations must be under
  `/backups`. "Fail if the disk isn't mounted" is on by default, so an
  unplugged drive doesn't silently fill `/volume1`.
- **A share on another NAS or PC**: use *Network share (SMB)* (SMB3
  encryption is required unless you turn it off), or *WebDAV* over HTTPS
  (Synology's WebDAV Server package, Nextcloud). For a self-signed WebDAV
  certificate tick *self-signed certificate*: it is pinned on the first Test.
- **Hyper Backup / Snapshot Replication** can also back up
  `/volume1/docker/medvault/data`. Everything in it is encrypted, including
  uploads and images while they are being processed (they go through
  encrypted scratch files with a key that only exists in memory). A restore
  from it still needs your encryption key or recovery key file.

By default a backup file can only be restored with the **recovery key file**:
it doesn't carry a passphrase-protected copy of the key, so someone who gets a
backup can't try to guess your passphrase offline. Settings › Encryption can
turn passphrase restore on.

Several MedVault servers can share one destination folder: backup names
include the vault ID and each server only prunes its own. Backups made by
version 0.1 (names without a vault ID) are never pruned automatically; delete
them by hand once you have newer ones.

## 7. Restarts and locking

After a NAS reboot or a container update, MedVault starts **locked**.
Sign in and enter your encryption key to resume scheduled backups. For
unattended unlock you can add a passphrase file (see the commented lines in the
compose file), but anyone with access to the NAS disks could then read the
vault. An unreadable or missing passphrase file is logged and the vault simply
stays locked.

`MEDVAULT_AUTO_LOCK_MINUTES` locks the vault after that many idle minutes
(scheduled backups then wait until you unlock it again). Sign-in sessions end
after 14 days without use (`MEDVAULT_SESSION_IDLE_DAYS`) and after 30 days at
most; changing your password signs out every other device.

## Updating

Container Manager › Project › medvault › Action › **Build** (it re-pulls
`latest`). Or set up the *Image* tab's update notification. Your data in
`data/` is untouched.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Container restarts with `Permission denied` on `/data` | `PUID`/`PGID` don't match the folder owner. Fix them, or let the container chown it by restarting it once. |
| "Connect Google account" says redirect mismatch | `MEDVAULT_PUBLIC_URL` must exactly match the address in your browser, and the same `…/api/oauth/gdrive/callback` URL must be in the Google OAuth client. |
| `exec format error` | Wrong CPU architecture image: pull again, since the published image includes both amd64 and arm64. |
| Logs | Container Manager › Container › medvault › Log |
| Can't open `http://<nas-ip>:8765` | By design: the port only listens on the NAS. Use the HTTPS reverse-proxy address (step 4). |
| "Too many attempts" | Sign-in and unlock attempts are rate limited after 5 failures. Wait the time shown and try again. |
| Setup says "Wrong setup code" | Copy the code from the container log again; it changes every time the container restarts. |
