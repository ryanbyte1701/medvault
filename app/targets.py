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


TYPES: dict[str, type[Target]] = {"gdrive": GoogleDrive, "box": Box, "sftp": SSHTarget}


def make(type_: str, config: dict, save: Callable[[dict], None] | None = None) -> Target:
    if type_ not in TYPES:
        raise TargetError(f"Unknown target type {type_}")
    return TYPES[type_](config, save)
