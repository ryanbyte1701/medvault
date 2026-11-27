"""Backup destinations: Google Drive, Box, SFTP and SCP.

Every archive handed to these classes is already encrypted with the vault
master key (see backup.py). Providers only ever see ciphertext and an
opaque file name.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import os
import posixpath
import shutil
import time
from pathlib import Path
from typing import Callable

import requests

log = logging.getLogger("scanvault.targets")
PREFIX = "scanvault-backup-"
SUFFIX = ".svb"
TIMEOUT = 60


class TargetError(Exception):
    pass


class Target:
    type = ""
    # Secrets are write-only in the UI: never returned by the API.
    secret_fields: tuple[str, ...] = ()

    def __init__(self, config: dict, save_config: Callable[[dict], None] | None = None):
        self.config = config
        self._save = save_config or (lambda c: None)

    def test(self) -> str:
        raise NotImplementedError

    def upload(self, path: Path, name: str) -> None:
        raise NotImplementedError

    def list_backups(self) -> list[tuple[str, str]]:
        """[(name, handle)] sorted oldest first."""
        raise NotImplementedError

    def delete(self, handle: str) -> None:
        raise NotImplementedError

    def download(self, handle: str, dest: Path) -> None:
        raise NotImplementedError

    def prune(self, keep_last: int) -> int:
        if keep_last <= 0:
            return 0
        items = [i for i in self.list_backups() if i[0].startswith(PREFIX) and i[0].endswith(SUFFIX)]
        items.sort(key=lambda i: i[0])
        doomed = items[:-keep_last] if len(items) > keep_last else []
        for _, handle in doomed:
            self.delete(handle)
        return len(doomed)


def _raise(resp: requests.Response, what: str) -> None:
    if resp.status_code >= 400:
        try:
            detail = resp.json()
        except Exception:
            detail = resp.text[:300]
        raise TargetError(f"{what} failed ({resp.status_code}): {detail}")


# ============================================================ Google Drive
class GoogleDrive(Target):
    """auth_mode 'oauth' (client id/secret + refresh token, works with personal
    Drive) or 'service_account' (JSON key, use with a Shared Drive)."""

    type = "gdrive"
    secret_fields = ("client_secret", "refresh_token", "service_account_json")
    API = "https://www.googleapis.com/drive/v3"
    UPLOAD = "https://www.googleapis.com/upload/drive/v3/files"
    TOKEN = "https://oauth2.googleapis.com/token"
    SCOPE = "https://www.googleapis.com/auth/drive.file"

    def _token(self) -> str:
        c = self.config
        if c.get("auth_mode") == "service_account":
            from google.auth.transport.requests import Request
            from google.oauth2 import service_account

            try:
                info = json.loads(c.get("service_account_json") or "{}")
            except json.JSONDecodeError as exc:
                raise TargetError("Service account JSON is not valid JSON") from exc
            creds = service_account.Credentials.from_service_account_info(info, scopes=["https://www.googleapis.com/auth/drive"])
            creds.refresh(Request())
            return creds.token
        if not c.get("refresh_token"):
            raise TargetError("Google Drive is not connected yet: click 'Connect Google account'")
        r = requests.post(
            self.TOKEN,
            data={
                "client_id": c.get("client_id", ""),
                "client_secret": c.get("client_secret", ""),
                "refresh_token": c["refresh_token"],
                "grant_type": "refresh_token",
            },
            timeout=TIMEOUT,
        )
        _raise(r, "Google token refresh")
        return r.json()["access_token"]

    def _h(self) -> dict:
        return {"Authorization": f"Bearer {self._token()}"}

    def _q_params(self) -> dict:
        return {"supportsAllDrives": "true", "includeItemsFromAllDrives": "true"}

    def test(self) -> str:
        h = self._h()
        folder = self.config.get("folder_id") or "root"
        r = requests.get(f"{self.API}/files/{folder}", headers=h, params={"fields": "id,name", "supportsAllDrives": "true"}, timeout=TIMEOUT)
        _raise(r, "Google Drive folder lookup")
        return f"Connected. Backups go to folder '{r.json().get('name')}'."

    def upload(self, path: Path, name: str) -> None:
        h = self._h()
        meta = {"name": name, "mimeType": "application/octet-stream"}
        if self.config.get("folder_id"):
            meta["parents"] = [self.config["folder_id"]]
        size = path.stat().st_size
        r = requests.post(
            self.UPLOAD,
            params={"uploadType": "resumable", "supportsAllDrives": "true"},
            headers={**h, "Content-Type": "application/json; charset=UTF-8", "X-Upload-Content-Length": str(size)},
            data=json.dumps(meta),
            timeout=TIMEOUT,
        )
        _raise(r, "Google Drive upload start")
        url = r.headers["Location"]
        chunk = 32 * 256 * 1024  # 8 MiB, multiple of 256 KiB
        with open(path, "rb") as f:
            offset = 0
            while offset < size or size == 0:
                data = f.read(chunk)
                end = offset + len(data) - 1
                rng = f"bytes {offset}-{end}/{size}" if data else f"bytes */{size}"
                r = requests.put(url, headers={"Content-Range": rng}, data=data, timeout=300)
                if r.status_code in (200, 201):
                    return
                if r.status_code != 308:
                    _raise(r, "Google Drive upload")
                offset = end + 1
                if size == 0:
                    break
        raise TargetError("Google Drive upload did not complete")

    def list_backups(self):
        h = self._h()
        q = f"name contains '{PREFIX}' and trashed = false"
        if self.config.get("folder_id"):
            q += f" and '{self.config['folder_id']}' in parents"
        out, token = [], None
        while True:
            params = {**self._q_params(), "q": q, "fields": "nextPageToken,files(id,name)", "pageSize": 1000}
            if token:
                params["pageToken"] = token
            r = requests.get(f"{self.API}/files", headers=h, params=params, timeout=TIMEOUT)
            _raise(r, "Google Drive list")
            j = r.json()
            out += [(f["name"], f["id"]) for f in j.get("files", [])]
            token = j.get("nextPageToken")
            if not token:
                return sorted(out)

    def delete(self, handle: str) -> None:
        r = requests.delete(f"{self.API}/files/{handle}", headers=self._h(), params={"supportsAllDrives": "true"}, timeout=TIMEOUT)
        if r.status_code not in (204, 404):
            _raise(r, "Google Drive delete")

    def download(self, handle: str, dest: Path) -> None:
        with requests.get(f"{self.API}/files/{handle}", headers=self._h(), params={"alt": "media", "supportsAllDrives": "true"}, stream=True, timeout=300) as r:
            _raise(r, "Google Drive download")
            with open(dest, "wb") as f:
                for b in r.iter_content(1 << 20):
                    f.write(b)

    # OAuth helpers
    @staticmethod
    def auth_url(client_id: str, redirect_uri: str, state: str) -> str:
        from urllib.parse import urlencode

        return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": GoogleDrive.SCOPE,
                "access_type": "offline",
                "prompt": "consent",
                "state": state,
            }
        )

    def exchange_code(self, code: str, redirect_uri: str) -> None:
        r = requests.post(
            self.TOKEN,
            data={
                "client_id": self.config.get("client_id", ""),
                "client_secret": self.config.get("client_secret", ""),
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            },
            timeout=TIMEOUT,
        )
        _raise(r, "Google code exchange")
        tok = r.json().get("refresh_token")
        if not tok:
            raise TargetError("Google did not return a refresh token; remove ScanVault's access in your Google account and try again")
        self.config["refresh_token"] = tok
        self._save(self.config)


# ============================================================ Box
class Box(Target):
    """auth_mode 'oauth' (3-legged, refresh token rotates on every use) or
    'ccg' (Client Credentials Grant, for a Box Custom App)."""

    type = "box"
    secret_fields = ("client_secret", "refresh_token")
    API = "https://api.box.com/2.0"
    UPLOAD = "https://upload.box.com/api/2.0"
    TOKEN = "https://api.box.com/oauth2/token"
    CHUNKED_MIN = 50 * 1024 * 1024

    def _token(self) -> str:
        c = self.config
        if c.get("auth_mode") == "ccg":
            data = {
                "grant_type": "client_credentials",
                "client_id": c.get("client_id", ""),
                "client_secret": c.get("client_secret", ""),
                "box_subject_type": c.get("subject_type") or "user",
                "box_subject_id": c.get("subject_id", ""),
            }
            r = requests.post(self.TOKEN, data=data, timeout=TIMEOUT)
            _raise(r, "Box token")
            return r.json()["access_token"]
        if not c.get("refresh_token"):
            raise TargetError("Box is not connected yet: click 'Connect Box account'")
        r = requests.post(
            self.TOKEN,
            data={
                "grant_type": "refresh_token",
                "refresh_token": c["refresh_token"],
                "client_id": c.get("client_id", ""),
                "client_secret": c.get("client_secret", ""),
            },
            timeout=TIMEOUT,
        )
        _raise(r, "Box token refresh")
        j = r.json()
        # Box refresh tokens are single-use: persist the new one immediately.
        if j.get("refresh_token"):
            c["refresh_token"] = j["refresh_token"]
            self._save(c)
        return j["access_token"]

    def _folder(self) -> str:
        return self.config.get("folder_id") or "0"

    def test(self) -> str:
        h = {"Authorization": f"Bearer {self._token()}"}
        r = requests.get(f"{self.API}/folders/{self._folder()}", headers=h, params={"fields": "name"}, timeout=TIMEOUT)
        _raise(r, "Box folder lookup")
        return f"Connected. Backups go to folder '{r.json().get('name')}'."

    def upload(self, path: Path, name: str) -> None:
        h = {"Authorization": f"Bearer {self._token()}"}
        size = path.stat().st_size
        if size < self.CHUNKED_MIN:
            with open(path, "rb") as f:
                r = requests.post(
                    f"{self.UPLOAD}/files/content",
                    headers=h,
                    files={
                        "attributes": (None, json.dumps({"name": name, "parent": {"id": self._folder()}})),
                        "file": (name, f, "application/octet-stream"),
                    },
                    timeout=600,
                )
            _raise(r, "Box upload")
            return
        r = requests.post(
            f"{self.UPLOAD}/files/upload_sessions",
            headers=h,
            json={"folder_id": self._folder(), "file_size": size, "file_name": name},
            timeout=TIMEOUT,
        )
        _raise(r, "Box upload session")
        sess = r.json()
        part_size = sess["part_size"]
        parts, whole = [], hashlib.sha1()
        with open(path, "rb") as f:
            offset = 0
            while offset < size:
                data = f.read(part_size)
                whole.update(data)
                digest = base64.b64encode(hashlib.sha1(data).digest()).decode()
                rr = requests.put(
                    sess["session_endpoints"]["upload_part"],
                    headers={
                        **h,
                        "Digest": f"sha={digest}",
                        "Content-Range": f"bytes {offset}-{offset + len(data) - 1}/{size}",
                        "Content-Type": "application/octet-stream",
                    },
                    data=data,
                    timeout=600,
                )
                _raise(rr, "Box upload part")
                parts.append(rr.json()["part"])
                offset += len(data)
        rr = requests.post(
            sess["session_endpoints"]["commit"],
            headers={**h, "Digest": "sha=" + base64.b64encode(whole.digest()).decode()},
            json={"parts": parts},
            timeout=600,
        )
        _raise(rr, "Box upload commit")

    def list_backups(self):
        h = {"Authorization": f"Bearer {self._token()}"}
        out, offset = [], 0
        while True:
            r = requests.get(
                f"{self.API}/folders/{self._folder()}/items",
                headers=h,
                params={"fields": "id,name,type", "limit": 1000, "offset": offset},
                timeout=TIMEOUT,
            )
            _raise(r, "Box list")
            j = r.json()
            entries = j.get("entries", [])
            out += [(e["name"], e["id"]) for e in entries if e.get("type") == "file" and e["name"].startswith(PREFIX)]
            offset += len(entries)
            if not entries or offset >= j.get("total_count", 0):
                return sorted(out)

    def delete(self, handle: str) -> None:
        h = {"Authorization": f"Bearer {self._token()}"}
        r = requests.delete(f"{self.API}/files/{handle}", headers=h, timeout=TIMEOUT)
        if r.status_code not in (204, 404):
            _raise(r, "Box delete")

    def download(self, handle: str, dest: Path) -> None:
        h = {"Authorization": f"Bearer {self._token()}"}
        with requests.get(f"{self.API}/files/{handle}/content", headers=h, stream=True, timeout=300) as r:
            _raise(r, "Box download")
            with open(dest, "wb") as f:
                for b in r.iter_content(1 << 20):
                    f.write(b)

    @staticmethod
    def auth_url(client_id: str, redirect_uri: str, state: str) -> str:
        from urllib.parse import urlencode

        return "https://account.box.com/api/oauth2/authorize?" + urlencode(
            {"client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code", "state": state}
        )

    def exchange_code(self, code: str, redirect_uri: str) -> None:
        r = requests.post(
            self.TOKEN,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": self.config.get("client_id", ""),
                "client_secret": self.config.get("client_secret", ""),
                "redirect_uri": redirect_uri,
            },
            timeout=TIMEOUT,
        )
        _raise(r, "Box code exchange")
        self.config["refresh_token"] = r.json()["refresh_token"]
        self._save(self.config)


# ============================================================ SFTP / SCP
class SSHTarget(Target):
    """protocol 'sftp' or 'scp'. Password or private key auth. The server host
    key is pinned on first successful test (trust on first use) and enforced
    afterwards."""

    type = "sftp"
    secret_fields = ("password", "private_key", "key_passphrase")

    def _connect(self):
        import paramiko

        c = self.config
        client = paramiko.SSHClient()
        pinned = (c.get("host_key") or "").strip()

        class Policy(paramiko.MissingHostKeyPolicy):
            def missing_host_key(inner, client_, hostname, key):  # noqa: N805
                fp = _ssh_fp(key)
                if pinned and fp != pinned:
                    raise TargetError(f"Host key mismatch! Expected {pinned}, server sent {fp}. Possible MITM; refusing to connect.")
                c["_seen_host_key"] = fp

        client.set_missing_host_key_policy(Policy())
        pkey = None
        if c.get("private_key"):
            pkey = _load_pkey(c["private_key"], c.get("key_passphrase") or None)
        try:
            client.connect(
                c["host"],
                port=int(c.get("port") or 22),
                username=c.get("username"),
                password=c.get("password") or None,
                pkey=pkey,
                look_for_keys=False,
                allow_agent=False,
                timeout=20,
                banner_timeout=20,
                auth_timeout=20,
            )
        except TargetError:
            raise
        except Exception as exc:
            raise TargetError(f"SSH connection failed: {exc}") from exc
        if not pinned and c.get("_seen_host_key"):
            c["host_key"] = c.pop("_seen_host_key")
            self._save(c)
        c.pop("_seen_host_key", None)
        return client

    def _dir(self) -> str:
        return self.config.get("remote_dir") or "."

    def _proto(self) -> str:
        return self.config.get("protocol") or "sftp"

    def test(self) -> str:
        client = self._connect()
        try:
            if self._proto() == "sftp":
                sftp = client.open_sftp()
                _sftp_mkdirs(sftp, self._dir())
                sftp.listdir(self._dir())
            else:
                _exec(client, f"mkdir -p {_q(self._dir())} && test -w {_q(self._dir())}")
        finally:
            client.close()
        return f"Connected over {self._proto().upper()}. Host key pinned: {self.config.get('host_key')}"

    def upload(self, path: Path, name: str) -> None:
        client = self._connect()
        try:
            remote = posixpath.join(self._dir(), name)
            if self._proto() == "sftp":
                sftp = client.open_sftp()
                _sftp_mkdirs(sftp, self._dir())
                tmp = remote + ".part"
                sftp.put(str(path), tmp, confirm=True)
                sftp.posix_rename(tmp, remote)
            else:
                from scp import SCPClient

                _exec(client, f"mkdir -p {_q(self._dir())}")
                with SCPClient(client.get_transport(), socket_timeout=120) as scp:
                    scp.put(str(path), remote)
        finally:
            client.close()

    def list_backups(self):
        client = self._connect()
        try:
            if self._proto() == "sftp":
                names = client.open_sftp().listdir(self._dir())
            else:
                names = _exec(client, f"ls -1 {_q(self._dir())}").splitlines()
        finally:
            client.close()
        return sorted((n, n) for n in names if n.startswith(PREFIX) and n.endswith(SUFFIX))

    def delete(self, handle: str) -> None:
        if "/" in handle:
            raise TargetError("bad name")
        client = self._connect()
        try:
            remote = posixpath.join(self._dir(), handle)
            if self._proto() == "sftp":
                client.open_sftp().remove(remote)
            else:
                _exec(client, f"rm -f {_q(remote)}")
        finally:
            client.close()

    def download(self, handle: str, dest: Path) -> None:
        client = self._connect()
        try:
            remote = posixpath.join(self._dir(), handle)
            if self._proto() == "sftp":
                client.open_sftp().get(remote, str(dest))
            else:
                from scp import SCPClient

                with SCPClient(client.get_transport()) as scp:
                    scp.get(remote, str(dest))
        finally:
            client.close()


def _q(s: str) -> str:
    import shlex

    return shlex.quote(s)


def _exec(client, cmd: str) -> str:
    _, out, err = client.exec_command(cmd, timeout=60)
    code = out.channel.recv_exit_status()
    if code != 0:
        raise TargetError(f"Remote command failed ({code}): {err.read().decode(errors='replace')[:300]}")
    return out.read().decode(errors="replace")


def _sftp_mkdirs(sftp, path: str) -> None:
    if path in ("", ".", "/"):
        return
    cur = "/" if path.startswith("/") else ""
    for part in [p for p in path.split("/") if p]:
        cur = posixpath.join(cur, part) if cur else part
        try:
            sftp.stat(cur)
        except IOError:
            sftp.mkdir(cur)


def _ssh_fp(key) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def _load_pkey(text: str, passphrase: str | None):
    import paramiko

    errors = []
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text), password=passphrase)
        except Exception as exc:
            errors.append(f"{cls.__name__}: {exc}")
    raise TargetError("Could not load private key (" + "; ".join(errors) + ")")


# ============================================================ S3 and S3-compatible
S3_PRESETS = {
    # provider -> endpoint template ({region} filled in); "" = AWS default
    "aws": "",
    "b2": "https://s3.{region}.backblazeb2.com",
    "wasabi": "https://s3.{region}.wasabisys.com",
    "r2": "https://{account_id}.r2.cloudflarestorage.com",
    "c2": "https://{region}.s3.synologyc2.net",
    "minio": "",
    "other": "",
}


class S3(Target):
    """Amazon S3 and anything speaking its API: Backblaze B2, Wasabi,
    Cloudflare R2, Synology C2 Object Storage, MinIO, Ceph, Garage..."""

    type = "s3"
    secret_fields = ("secret_access_key",)

    def _client(self):
        import boto3
        from botocore.config import Config

        c = self.config
        prov = c.get("provider") or "aws"
        endpoint = (c.get("endpoint_url") or "").strip()
        region = (c.get("region") or "").strip() or ("auto" if prov == "r2" else "us-east-1")
        if not endpoint and S3_PRESETS.get(prov):
            endpoint = S3_PRESETS[prov].format(region=region, account_id=c.get("account_id", ""))
        if not c.get("bucket"):
            raise TargetError("Bucket name is required")
        return boto3.client(
            "s3",
            aws_access_key_id=c.get("access_key_id") or None,
            aws_secret_access_key=c.get("secret_access_key") or None,
            region_name=region,
            endpoint_url=endpoint or None,
            config=Config(
                signature_version="s3v4",
                s3={"addressing_style": "path" if c.get("path_style") or prov == "minio" else "auto"},
                retries={"max_attempts": 5, "mode": "standard"},
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )

    def _key(self, name: str) -> str:
        pre = (self.config.get("prefix") or "").strip("/")
        return f"{pre}/{name}" if pre else name

    def _wrap(self, what, fn):
        try:
            return fn()
        except TargetError:
            raise
        except Exception as exc:
            raise TargetError(f"S3 {what} failed: {exc}") from exc

    def test(self) -> str:
        cl = self._client()
        b = self.config["bucket"]
        self._wrap("bucket check", lambda: cl.head_bucket(Bucket=b))
        k = self._key(".scanvault-write-test")
        self._wrap("write test", lambda: cl.put_object(Bucket=b, Key=k, Body=b"ok"))
        self._wrap("delete test", lambda: cl.delete_object(Bucket=b, Key=k))
        return f"Connected. Backups go to s3://{b}/{self._key('')}"

    def upload(self, path: Path, name: str) -> None:
        from boto3.s3.transfer import TransferConfig

        cl = self._client()
        extra = {"ContentType": "application/octet-stream"}
        if self.config.get("storage_class"):
            extra["StorageClass"] = self.config["storage_class"]
        cfg = TransferConfig(multipart_threshold=64 * 1024 * 1024, multipart_chunksize=64 * 1024 * 1024, max_concurrency=4)
        self._wrap("upload", lambda: cl.upload_file(str(path), self.config["bucket"], self._key(name), ExtraArgs=extra, Config=cfg))

    def list_backups(self):
        cl = self._client()
        out = []
        pag = cl.get_paginator("list_objects_v2")

        def run():
            for page in pag.paginate(Bucket=self.config["bucket"], Prefix=self._key(PREFIX)):
                for o in page.get("Contents", []):
                    out.append((o["Key"].rsplit("/", 1)[-1], o["Key"]))

        self._wrap("list", run)
        return sorted(out)

    def delete(self, handle: str) -> None:
        cl = self._client()
        self._wrap("delete", lambda: cl.delete_object(Bucket=self.config["bucket"], Key=handle))

    def download(self, handle: str, dest: Path) -> None:
        cl = self._client()
        self._wrap("download", lambda: cl.download_file(self.config["bucket"], handle, str(dest)))


# ============================================================ Dropbox
class Dropbox(Target):
    """Dropbox app (scoped access, App folder or Full Dropbox) with OAuth
    offline refresh token."""

    type = "dropbox"
    secret_fields = ("app_secret", "refresh_token")
    API = "https://api.dropboxapi.com/2"
    CONTENT = "https://content.dropboxapi.com/2"
    TOKEN = "https://api.dropboxapi.com/oauth2/token"
    CHUNK = 64 * 1024 * 1024

    def _token(self) -> str:
        c = self.config
        if not c.get("refresh_token"):
            raise TargetError("Dropbox is not connected yet: click 'Connect Dropbox account'")
        r = requests.post(self.TOKEN, data={"grant_type": "refresh_token", "refresh_token": c["refresh_token"]}, auth=(c.get("app_key", ""), c.get("app_secret", "")), timeout=TIMEOUT)
        _raise(r, "Dropbox token refresh")
        return r.json()["access_token"]

    def _folder(self) -> str:
        f = "/" + (self.config.get("folder") or "ScanVault").strip("/")
        return "" if f == "/" else f

    def _rpc(self, tok, ep, body, ok404=False):
        r = requests.post(f"{self.API}/{ep}", headers={"Authorization": f"Bearer {tok}"}, json=body, timeout=TIMEOUT)
        if ok404 and r.status_code == 409:
            return None
        _raise(r, f"Dropbox {ep}")
        return r.json()

    def test(self) -> str:
        tok = self._token()
        acct = self._rpc(tok, "users/get_current_account", None)
        if self._folder():
            r = requests.post(f"{self.API}/files/create_folder_v2", headers={"Authorization": f"Bearer {tok}"}, json={"path": self._folder()}, timeout=TIMEOUT)
            if r.status_code not in (200, 409):  # 409 = already exists
                _raise(r, "Dropbox create folder")
        return f"Connected as {acct.get('email') or acct.get('name', {}).get('display_name', 'Dropbox user')}. Backups go to {self._folder() or '/'}"

    def upload(self, path: Path, name: str) -> None:
        tok = self._token()
        h = {"Authorization": f"Bearer {tok}", "Content-Type": "application/octet-stream"}
        dest = f"{self._folder()}/{name}"
        size = path.stat().st_size
        commit = {"path": dest, "mode": "add", "autorename": False, "mute": True}
        with open(path, "rb") as f:
            if size <= 150 * 1024 * 1024:
                r = requests.post(f"{self.CONTENT}/files/upload", headers={**h, "Dropbox-API-Arg": json.dumps(commit)}, data=f, timeout=600)
                _raise(r, "Dropbox upload")
                return
            r = requests.post(f"{self.CONTENT}/files/upload_session/start", headers={**h, "Dropbox-API-Arg": json.dumps({"close": False})}, data=f.read(self.CHUNK), timeout=600)
            _raise(r, "Dropbox upload start")
            sid, offset = r.json()["session_id"], f.tell()
            while True:
                data = f.read(self.CHUNK)
                cursor = {"session_id": sid, "offset": offset}
                if f.tell() >= size:
                    r = requests.post(f"{self.CONTENT}/files/upload_session/finish", headers={**h, "Dropbox-API-Arg": json.dumps({"cursor": cursor, "commit": commit})}, data=data, timeout=600)
                    _raise(r, "Dropbox upload finish")
                    return
                r = requests.post(f"{self.CONTENT}/files/upload_session/append_v2", headers={**h, "Dropbox-API-Arg": json.dumps({"cursor": cursor, "close": False})}, data=data, timeout=600)
                _raise(r, "Dropbox upload append")
                offset += len(data)

    def list_backups(self):
        tok = self._token()
        j = self._rpc(tok, "files/list_folder", {"path": self._folder(), "limit": 2000}, ok404=True)
        out = []
        while j:
            out += [(e["name"], e["path_lower"]) for e in j.get("entries", []) if e.get(".tag") == "file" and e["name"].startswith(PREFIX)]
            j = self._rpc(tok, "files/list_folder/continue", {"cursor": j["cursor"]}) if j.get("has_more") else None
        return sorted(out)

    def delete(self, handle: str) -> None:
        self._rpc(self._token(), "files/delete_v2", {"path": handle}, ok404=True)

    def download(self, handle: str, dest: Path) -> None:
        tok = self._token()
        with requests.post(f"{self.CONTENT}/files/download", headers={"Authorization": f"Bearer {tok}", "Dropbox-API-Arg": json.dumps({"path": handle})}, stream=True, timeout=600) as r:
            _raise(r, "Dropbox download")
            with open(dest, "wb") as f:
                for b in r.iter_content(1 << 20):
                    f.write(b)

    @staticmethod
    def auth_url(client_id: str, redirect_uri: str, state: str) -> str:
        from urllib.parse import urlencode

        return "https://www.dropbox.com/oauth2/authorize?" + urlencode(
            {"client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code", "token_access_type": "offline", "state": state}
        )

    def exchange_code(self, code: str, redirect_uri: str) -> None:
        r = requests.post(self.TOKEN, data={"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri}, auth=(self.config.get("app_key", ""), self.config.get("app_secret", "")), timeout=TIMEOUT)
        _raise(r, "Dropbox code exchange")
        self.config["refresh_token"] = r.json()["refresh_token"]
        self._save(self.config)


# ============================================================ OneDrive
class OneDrive(Target):
    """OneDrive personal or OneDrive for Business / SharePoint through Microsoft
    Graph, with an Entra ID (Azure AD) app registration."""

    type = "onedrive"
    secret_fields = ("client_secret", "refresh_token")
    GRAPH = "https://graph.microsoft.com/v1.0"
    SCOPE = "offline_access Files.ReadWrite"
    CHUNK = 320 * 1024 * 32  # 10 MiB, must be a multiple of 320 KiB

    def _tenant(self) -> str:
        return (self.config.get("tenant") or "common").strip()

    def _token(self) -> str:
        c = self.config
        if not c.get("refresh_token"):
            raise TargetError("OneDrive is not connected yet: click 'Connect OneDrive account'")
        r = requests.post(
            f"https://login.microsoftonline.com/{self._tenant()}/oauth2/v2.0/token",
            data={"client_id": c.get("client_id", ""), "client_secret": c.get("client_secret", ""), "grant_type": "refresh_token", "refresh_token": c["refresh_token"], "scope": self.SCOPE},
            timeout=TIMEOUT,
        )
        _raise(r, "OneDrive token refresh")
        j = r.json()
        if j.get("refresh_token") and j["refresh_token"] != c["refresh_token"]:
            c["refresh_token"] = j["refresh_token"]
            self._save(c)
        return j["access_token"]

    def _folder(self) -> str:
        return (self.config.get("folder") or "ScanVault").strip("/")

    def _item(self, name: str = "") -> str:
        p = "/".join(x for x in (self._folder(), name) if x)
        from urllib.parse import quote

        return f"{self.GRAPH}/me/drive/root:/{quote(p)}:" if p else f"{self.GRAPH}/me/drive/root"

    def test(self) -> str:
        h = {"Authorization": f"Bearer {self._token()}"}
        d = requests.get(f"{self.GRAPH}/me/drive", headers=h, timeout=TIMEOUT)
        _raise(d, "OneDrive drive lookup")
        r = requests.get(self._item(), headers=h, timeout=TIMEOUT)
        if r.status_code == 404:
            parent, _, leaf = self._folder().rpartition("/")
            base = f"{self.GRAPH}/me/drive/root" + (f":/{parent}:" if parent else "")
            r = requests.post(f"{base}/children", headers=h, json={"name": leaf, "folder": {}, "@microsoft.graph.conflictBehavior": "replace"}, timeout=TIMEOUT)
        _raise(r, "OneDrive folder")
        owner = (d.json().get("owner") or {}).get("user", {}).get("displayName", "")
        return f"Connected{(' as ' + owner) if owner else ''}. Backups go to /{self._folder()}"

    def upload(self, path: Path, name: str) -> None:
        h = {"Authorization": f"Bearer {self._token()}"}
        r = requests.post(f"{self._item(name)}/createUploadSession", headers=h, json={"item": {"@microsoft.graph.conflictBehavior": "fail"}}, timeout=TIMEOUT)
        _raise(r, "OneDrive upload session")
        url = r.json()["uploadUrl"]
        size = path.stat().st_size
        with open(path, "rb") as f:
            offset = 0
            while offset < size:
                data = f.read(self.CHUNK)
                rr = requests.put(url, headers={"Content-Range": f"bytes {offset}-{offset + len(data) - 1}/{size}", "Content-Length": str(len(data))}, data=data, timeout=600)
                if rr.status_code not in (200, 201, 202):
                    _raise(rr, "OneDrive upload")
                offset += len(data)
        if size == 0:
            raise TargetError("Refusing to upload an empty backup")

    def list_backups(self):
        h = {"Authorization": f"Bearer {self._token()}"}
        url, out = f"{self._item()}/children?$select=id,name,file&$top=999", []
        while url:
            r = requests.get(url, headers=h, timeout=TIMEOUT)
            if r.status_code == 404:
                return []
            _raise(r, "OneDrive list")
            j = r.json()
            out += [(i["name"], i["id"]) for i in j.get("value", []) if "file" in i and i["name"].startswith(PREFIX)]
            url = j.get("@odata.nextLink")
        return sorted(out)

    def delete(self, handle: str) -> None:
        r = requests.delete(f"{self.GRAPH}/me/drive/items/{handle}", headers={"Authorization": f"Bearer {self._token()}"}, timeout=TIMEOUT)
        if r.status_code not in (204, 404):
            _raise(r, "OneDrive delete")

    def download(self, handle: str, dest: Path) -> None:
        with requests.get(f"{self.GRAPH}/me/drive/items/{handle}/content", headers={"Authorization": f"Bearer {self._token()}"}, stream=True, timeout=600) as r:
            _raise(r, "OneDrive download")
            with open(dest, "wb") as f:
                for b in r.iter_content(1 << 20):
                    f.write(b)

    def auth_url_for(self, redirect_uri: str, state: str) -> str:
        from urllib.parse import urlencode

        return f"https://login.microsoftonline.com/{self._tenant()}/oauth2/v2.0/authorize?" + urlencode(
            {"client_id": self.config.get("client_id", ""), "redirect_uri": redirect_uri, "response_type": "code", "scope": self.SCOPE, "state": state, "prompt": "select_account"}
        )

    def exchange_code(self, code: str, redirect_uri: str) -> None:
        r = requests.post(
            f"https://login.microsoftonline.com/{self._tenant()}/oauth2/v2.0/token",
            data={"client_id": self.config.get("client_id", ""), "client_secret": self.config.get("client_secret", ""), "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri, "scope": self.SCOPE},
            timeout=TIMEOUT,
        )
        _raise(r, "OneDrive code exchange")
        self.config["refresh_token"] = r.json()["refresh_token"]
        self._save(self.config)


# ============================================================ WebDAV / Nextcloud
class WebDAV(Target):
    """Any WebDAV server: Nextcloud, ownCloud, Synology WebDAV Server, QNAP,
    Apache/nginx, Koofr, pCloud, Seafile, 4shared..."""

    type = "webdav"
    secret_fields = ("password",)

    def _base(self) -> str:
        url = (self.config.get("url") or "").rstrip("/")
        if not url.startswith(("https://", "http://")):
            raise TargetError("WebDAV URL must start with https://")
        folder = (self.config.get("folder") or "").strip("/")
        return f"{url}/{folder}" if folder else url

    def _auth(self):
        return (self.config.get("username", ""), self.config.get("password", ""))

    def _verify(self):
        return not self.config.get("insecure_tls")

    def _req(self, method, url, **kw):
        try:
            return requests.request(method, url, auth=self._auth(), verify=self._verify(), timeout=kw.pop("timeout", TIMEOUT), **kw)
        except requests.RequestException as exc:
            raise TargetError(f"WebDAV {method} failed: {exc}") from exc

    def _mkdirs(self) -> None:
        url = (self.config.get("url") or "").rstrip("/")
        for part in [p for p in (self.config.get("folder") or "").strip("/").split("/") if p]:
            url += "/" + requests.utils.quote(part)
            r = self._req("MKCOL", url + "/")
            if r.status_code not in (201, 405, 301, 302):  # 405 = exists
                _raise(r, "WebDAV create folder")

    def test(self) -> str:
        self._mkdirs()
        r = self._req("PROPFIND", self._base() + "/", headers={"Depth": "0"})
        if r.status_code not in (207, 200):
            _raise(r, "WebDAV folder check")
        probe = self._base() + "/.scanvault-write-test"
        _raise(self._req("PUT", probe, data=b"ok"), "WebDAV write test")
        self._req("DELETE", probe)
        return f"Connected. Backups go to {self._base()}/"

    def upload(self, path: Path, name: str) -> None:
        self._mkdirs()
        tmp = f"{self._base()}/{name}.part"
        with open(path, "rb") as f:
            r = self._req("PUT", tmp, data=f, headers={"Content-Type": "application/octet-stream", "Content-Length": str(path.stat().st_size)}, timeout=3600)
        if r.status_code not in (200, 201, 204):
            _raise(r, "WebDAV upload")
        r = self._req("MOVE", tmp, headers={"Destination": f"{self._base()}/{name}", "Overwrite": "F"})
        if r.status_code not in (201, 204):
            _raise(r, "WebDAV rename")

    def list_backups(self):
        import xml.etree.ElementTree as ET
        from urllib.parse import unquote, urlparse

        r = self._req("PROPFIND", self._base() + "/", headers={"Depth": "1", "Content-Type": "application/xml"},
                      data=b'<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>')
        if r.status_code == 404:
            return []
        if r.status_code != 207:
            _raise(r, "WebDAV list")
        out = []
        for resp in ET.fromstring(r.content).iter("{DAV:}response"):
            href = resp.findtext("{DAV:}href") or ""
            name = unquote(urlparse(href).path.rstrip("/").rsplit("/", 1)[-1])
            if name.startswith(PREFIX) and name.endswith(SUFFIX):
                out.append((name, name))
        return sorted(out)

    def delete(self, handle: str) -> None:
        if "/" in handle:
            raise TargetError("bad name")
        r = self._req("DELETE", f"{self._base()}/{handle}")
        if r.status_code not in (200, 204, 404):
            _raise(r, "WebDAV delete")

    def download(self, handle: str, dest: Path) -> None:
        r = self._req("GET", f"{self._base()}/{handle}", stream=True, timeout=3600)
        _raise(r, "WebDAV download")
        with open(dest, "wb") as f:
            for b in r.iter_content(1 << 20):
                f.write(b)


# ============================================================ SMB / Windows share
class SMB(Target):
    """SMB2/3 share: Windows, Synology/QNAP/TrueNAS shares, Samba. Uses SMB3
    encryption when the server supports it."""

    type = "smb"
    secret_fields = ("password",)

    def _root(self) -> str:
        c = self.config
        host, share = (c.get("host") or "").strip(), (c.get("share") or "").strip("\\/ ")
        if not host or not share:
            raise TargetError("Server and share name are required")
        folder = (c.get("folder") or "").strip("\\/").replace("/", "\\")
        return f"\\\\{host}\\{share}" + (f"\\{folder}" if folder else "")

    def _session(self):
        import smbclient

        c = self.config
        try:
            smbclient.register_session(
                c["host"].strip(), username=c.get("username") or None, password=c.get("password") or None,
                port=int(c.get("port") or 445), encrypt=bool(c.get("require_encryption")), connection_timeout=20,
            )
        except Exception as exc:
            raise TargetError(f"SMB connection failed: {exc}") from exc
        return smbclient

    def _wrap(self, what, fn):
        try:
            return fn()
        except TargetError:
            raise
        except Exception as exc:
            raise TargetError(f"SMB {what} failed: {exc}") from exc

    def test(self) -> str:
        sc = self._session()
        root = self._root()
        self._wrap("create folder", lambda: sc.makedirs(root, exist_ok=True))
        probe = root + "\\.scanvault-write-test"

        def w():
            with sc.open_file(probe, mode="wb") as f:
                f.write(b"ok")
            sc.remove(probe)

        self._wrap("write test", w)
        return f"Connected. Backups go to {root}"

    def upload(self, path: Path, name: str) -> None:
        sc = self._session()
        root = self._root()

        def up():
            sc.makedirs(root, exist_ok=True)
            tmp, dst = f"{root}\\{name}.part", f"{root}\\{name}"
            with open(path, "rb") as src, sc.open_file(tmp, mode="wb") as out:
                shutil.copyfileobj(src, out, 4 * 1024 * 1024)
            sc.rename(tmp, dst)

        self._wrap("upload", up)

    def list_backups(self):
        sc = self._session()
        try:
            names = sc.listdir(self._root())
        except FileNotFoundError:
            return []
        except Exception as exc:
            raise TargetError(f"SMB list failed: {exc}") from exc
        return sorted((n, n) for n in names if n.startswith(PREFIX) and n.endswith(SUFFIX))

    def delete(self, handle: str) -> None:
        if "\\" in handle or "/" in handle:
            raise TargetError("bad name")
        sc = self._session()
        self._wrap("delete", lambda: sc.remove(f"{self._root()}\\{handle}"))

    def download(self, handle: str, dest: Path) -> None:
        sc = self._session()

        def dl():
            with sc.open_file(f"{self._root()}\\{handle}", mode="rb") as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out, 4 * 1024 * 1024)

        self._wrap("download", dl)


# ============================================================ Local folder (USB / NFS / mounted disk)
class LocalFolder(Target):
    """A folder inside the container: mount a USB disk, a second internal
    drive or an NFS/CIFS mount from the host to /backups (see docker-compose)."""

    type = "local"
    secret_fields = ()
    ROOT = Path(os.environ.get("SCANVAULT_LOCAL_BACKUP_ROOT", "/backups"))

    def _dir(self) -> Path:
        p = Path(self.config.get("path") or str(self.ROOT)).expanduser()
        if not p.is_absolute():
            p = self.ROOT / p
        p = p.resolve()
        data = Path(os.environ.get("SCANVAULT_DATA", "/data")).resolve()
        if p == data or data in p.parents:
            raise TargetError("Pick a folder outside the vault's own data folder")
        return p

    def test(self) -> str:
        d = self._dir()
        if self.config.get("require_mount") and _mount_root(d) == Path("/"):
            raise TargetError(f"{d} is not on a mounted disk. Is the USB drive plugged in and mounted into the container?")
        try:
            d.mkdir(parents=True, exist_ok=True)
            probe = d / ".scanvault-write-test"
            probe.write_bytes(b"ok")
            probe.unlink()
        except OSError as exc:
            raise TargetError(f"Can't write to {d}: {exc.strerror or exc}") from exc
        free = shutil.disk_usage(d).free
        return f"Writable. {free / 1e9:,.1f} GB free in {d}"

    def upload(self, path: Path, name: str) -> None:
        self.test()
        d = self._dir()
        tmp = d / f"{name}.part"
        try:
            shutil.copyfile(path, tmp)
            with open(tmp, "rb") as f:
                os.fsync(f.fileno())
            tmp.replace(d / name)
        except OSError as exc:
            tmp.unlink(missing_ok=True)
            raise TargetError(f"Copy to {d} failed: {exc.strerror or exc}") from exc

    def list_backups(self):
        d = self._dir()
        if not d.exists():
            return []
        return sorted((p.name, p.name) for p in d.iterdir() if p.is_file() and p.name.startswith(PREFIX) and p.name.endswith(SUFFIX))

    def delete(self, handle: str) -> None:
        if "/" in handle or handle.startswith("."):
            raise TargetError("bad name")
        (self._dir() / handle).unlink(missing_ok=True)

    def download(self, handle: str, dest: Path) -> None:
        if "/" in handle:
            raise TargetError("bad name")
        shutil.copyfile(self._dir() / handle, dest)


def _mount_root(p: Path) -> Path:
    p = p if p.exists() else p.parent
    while not os.path.ismount(p) and p != p.parent:
        p = p.parent
    return p


TYPES: dict[str, type[Target]] = {
    "gdrive": GoogleDrive,
    "box": Box,
    "dropbox": Dropbox,
    "onedrive": OneDrive,
    "s3": S3,
    "webdav": WebDAV,
    "sftp": SSHTarget,
    "smb": SMB,
    "local": LocalFolder,
}

OAUTH_TYPES = {"gdrive", "box", "dropbox", "onedrive"}


def oauth_client_id(type_: str, cfg: dict) -> str:
    return cfg.get("app_key" if type_ == "dropbox" else "client_id", "")


def oauth_auth_url(type_: str, cfg: dict, redirect_uri: str, state: str) -> str:
    if type_ == "onedrive":
        return OneDrive(cfg).auth_url_for(redirect_uri, state)
    return TYPES[type_].auth_url(oauth_client_id(type_, cfg), redirect_uri, state)  # type: ignore[attr-defined]


def needs_connect(type_: str, cfg: dict) -> bool:
    if type_ not in OAUTH_TYPES:
        return False
    mode = cfg.get("auth_mode", "oauth")
    return mode == "oauth" and not cfg.get("refresh_token")



def make(type_: str, config: dict, save: Callable[[dict], None] | None = None) -> Target:
    if type_ not in TYPES:
        raise TargetError(f"Unknown target type {type_}")
    return TYPES[type_](config, save)
