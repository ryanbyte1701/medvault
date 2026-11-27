"""S3 (moto), Dropbox and OneDrive (mocked HTTP), WebDAV (real WsgiDAV server),
SMB (smbclient faked over a temp dir) and local folder targets."""
import json
import os
import threading
from pathlib import Path

import pytest
import responses

from app import targets

NAMES = [f"scanvault-backup-2026010{i}-000000Z.svb" for i in range(4)]


def _roundtrip(t, tmp_path, keep=2):
    src = tmp_path / "a.svb"
    src.write_bytes(os.urandom(300_000))
    for n in NAMES:
        t.upload(src, n)
    assert [n for n, _ in t.list_backups()] == NAMES
    assert t.prune(keep) == len(NAMES) - keep
    left = t.list_backups()
    assert [n for n, _ in left] == NAMES[-keep:]
    dst = tmp_path / "dl.svb"
    t.download(left[-1][1], dst)
    assert dst.read_bytes() == src.read_bytes()


# ------------------------------------------------------------------ S3
def test_s3_moto(tmp_path, monkeypatch):
    from moto import mock_aws
    import boto3

    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="vault")
        t = targets.make("s3", {"provider": "aws", "bucket": "vault", "prefix": "nas/scanvault", "access_key_id": "AK", "secret_access_key": "SK", "region": "us-east-1"})
        assert "s3://vault/nas/scanvault/" in t.test()
        _roundtrip(t, tmp_path)
        keys = [o["Key"] for o in boto3.client("s3", region_name="us-east-1").list_objects_v2(Bucket="vault")["Contents"]]
        assert all(k.startswith("nas/scanvault/scanvault-backup-") for k in keys)
        bad = targets.make("s3", {"provider": "aws", "bucket": "nope", "access_key_id": "AK", "secret_access_key": "SK"})
        with pytest.raises(targets.TargetError):
            bad.test()


def test_s3_provider_endpoints():
    for prov, region, extra, expect in [
        ("b2", "us-west-004", {}, "https://s3.us-west-004.backblazeb2.com"),
        ("wasabi", "eu-central-1", {}, "https://s3.eu-central-1.wasabisys.com"),
        ("r2", "", {"account_id": "abc123"}, "https://abc123.r2.cloudflarestorage.com"),
        ("c2", "us-001", {}, "https://us-001.s3.synologyc2.net"),
        ("minio", "", {"endpoint_url": "http://nas.local:9000"}, "http://nas.local:9000"),
    ]:
        cl = targets.make("s3", {"provider": prov, "region": region, "bucket": "b", "access_key_id": "a", "secret_access_key": "s", **extra})._client()
        assert cl.meta.endpoint_url == expect, prov


# ------------------------------------------------------------------ Dropbox
@responses.activate
def test_dropbox_chunked_upload_list_prune(tmp_path):
    responses.post("https://api.dropboxapi.com/oauth2/token", json={"access_token": "AT"})
    responses.post("https://content.dropboxapi.com/2/files/upload_session/start", json={"session_id": "S1"})
    responses.post("https://content.dropboxapi.com/2/files/upload_session/append_v2", json=None)
    responses.post("https://content.dropboxapi.com/2/files/upload_session/finish", json={"name": "x"})
    entries = [{".tag": "file", "name": n, "path_lower": "/scanvault/" + n} for n in NAMES] + [{".tag": "folder", "name": "other", "path_lower": "/scanvault/other"}]
    responses.post("https://api.dropboxapi.com/2/files/list_folder", json={"entries": entries[:2], "cursor": "C", "has_more": True})
    responses.post("https://api.dropboxapi.com/2/files/list_folder/continue", json={"entries": entries[2:], "cursor": "C", "has_more": False})
    responses.post("https://api.dropboxapi.com/2/files/delete_v2", json={})
    t = targets.make("dropbox", {"app_key": "k", "app_secret": "s", "refresh_token": "R", "folder": "ScanVault"})
    p = tmp_path / "big.svb"
    with open(p, "wb") as f:
        f.truncate(200 * 1024 * 1024)
    t.upload(p, NAMES[0])
    fin = [c for c in responses.calls if c.request.url.endswith("/finish")][0]
    arg = json.loads(fin.request.headers["Dropbox-API-Arg"])
    assert arg["commit"]["path"] == "/ScanVault/" + NAMES[0] and arg["cursor"]["offset"] == 192 * 1024 * 1024
    assert t.prune(2) == 2
    dels = [json.loads(c.request.body)["path"] for c in responses.calls if c.request.url.endswith("/delete_v2")]
    assert dels == ["/scanvault/" + NAMES[0], "/scanvault/" + NAMES[1]]


def test_dropbox_needs_connect():
    assert targets.needs_connect("dropbox", {"app_key": "k"})
    assert "token_access_type=offline" in targets.oauth_auth_url("dropbox", {"app_key": "k"}, "https://x/cb", "st")


# ------------------------------------------------------------------ OneDrive
@responses.activate
def test_onedrive_upload_session_and_token_rotation(tmp_path):
    responses.post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token", json={"access_token": "AT", "refresh_token": "R2"})
    responses.post("https://graph.microsoft.com/v1.0/me/drive/root:/Backups/ScanVault/" + NAMES[0] + ":/createUploadSession", json={"uploadUrl": "https://up.example/s"})
    responses.put("https://up.example/s", status=202, json={})
    responses.put("https://up.example/s", status=201, json={"id": "F"})
    responses.get("https://graph.microsoft.com/v1.0/me/drive/root:/Backups/ScanVault:/children", json={"value": [{"id": f"id{i}", "name": n, "file": {}} for i, n in enumerate(NAMES)]})
    for i in range(3):
        responses.delete(f"https://graph.microsoft.com/v1.0/me/drive/items/id{i}", status=204)
    saved = {}
    t = targets.make("onedrive", {"client_id": "c", "client_secret": "s", "refresh_token": "R1", "tenant": "consumers", "folder": "Backups/ScanVault"}, saved.update)
    p = tmp_path / "b.svb"
    p.write_bytes(b"\1" * (12 * 1024 * 1024))
    t.upload(p, NAMES[0])
    assert saved["refresh_token"] == "R2"
    puts = [c for c in responses.calls if c.request.method == "PUT"]
    assert puts[0].request.headers["Content-Range"] == f"bytes 0-{10 * 1024 * 1024 - 1}/{12 * 1024 * 1024}"
    assert t.prune(1) == 3
    assert "login.microsoftonline.com/consumers/" in targets.oauth_auth_url("onedrive", {"client_id": "c", "tenant": "consumers"}, "https://x/cb", "s")


# ------------------------------------------------------------------ WebDAV (real server)
@pytest.fixture()
def dav_server(tmp_path):
    from cheroot import wsgi
    from wsgidav.wsgidav_app import WsgiDAVApp

    root = tmp_path / "dav"
    root.mkdir()
    app = WsgiDAVApp({
        "provider_mapping": {"/remote.php/dav/files/ryan": str(root)},
        "simple_dc": {"user_mapping": {"*": {"ryan": {"password": "pw"}}}},
        "http_authenticator": {"accept_basic": True, "accept_digest": False, "default_to_digest": False},
        "verbose": 0, "logging": {"enable": False},
    })
    srv = wsgi.Server(("127.0.0.1", 0), app)
    srv.prepare()
    th = threading.Thread(target=srv.serve, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{srv.bind_addr[1]}/remote.php/dav/files/ryan", root
    srv.stop()


def test_webdav_nextcloud_style(tmp_path, dav_server):
    url, root = dav_server
    t = targets.make("webdav", {"url": url, "username": "ryan", "password": "pw", "folder": "Backups/ScanVault"})
    assert "Connected" in t.test()
    _roundtrip(t, tmp_path)
    assert sorted(p.name for p in (root / "Backups" / "ScanVault").iterdir()) == NAMES[-2:]
    bad = targets.make("webdav", {"url": url, "username": "ryan", "password": "nope"})
    with pytest.raises(targets.TargetError):
        bad.test()


# ------------------------------------------------------------------ SMB (smbclient faked)
class FakeSMB:
    def __init__(self, root):
        self.root, self.sessions = Path(root), []

    def _p(self, unc):
        parts = unc.lstrip("\\").split("\\")
        return self.root.joinpath(*parts)

    def register_session(self, host, **kw):
        if kw.get("password") != "pw":
            raise PermissionError("STATUS_LOGON_FAILURE")
        self.sessions.append((host, kw))

    def makedirs(self, p, exist_ok=False):
        self._p(p).mkdir(parents=True, exist_ok=exist_ok)

    def open_file(self, p, mode="rb"):
        return open(self._p(p), mode)

    def remove(self, p):
        self._p(p).unlink()

    def rename(self, a, b):
        self._p(a).rename(self._p(b))

    def listdir(self, p):
        q = self._p(p)
        if not q.exists():
            raise FileNotFoundError(p)
        return os.listdir(q)


def test_smb(tmp_path, monkeypatch):
    import sys
    import types

    fake = FakeSMB(tmp_path / "smb")
    mod = types.ModuleType("smbclient")
    for name in ("register_session", "makedirs", "open_file", "remove", "rename", "listdir"):
        setattr(mod, name, getattr(fake, name))
    monkeypatch.setitem(sys.modules, "smbclient", mod)
    t = targets.make("smb", {"host": "nas.local", "share": "backup", "folder": "scanvault/nightly", "username": "u", "password": "pw", "require_encryption": True})
    assert "\\\\nas.local\\backup\\scanvault\\nightly" in t.test()
    _roundtrip(t, tmp_path)
    assert fake.sessions[0][1]["encrypt"] is True
    assert not list((tmp_path / "smb").rglob("*.part"))
    with pytest.raises(targets.TargetError, match="LOGON"):
        targets.make("smb", {"host": "nas.local", "share": "backup", "password": "bad"}).test()


# ------------------------------------------------------------------ local folder
def test_local_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(targets.LocalFolder, "ROOT", tmp_path / "backups")
    t = targets.make("local", {"path": "usb1/scanvault"})
    assert "free" in t.test()
    _roundtrip(t, tmp_path)
    assert (tmp_path / "backups" / "usb1" / "scanvault" / NAMES[-1]).exists()
    monkeypatch.setenv("SCANVAULT_DATA", str(tmp_path / "data"))
    with pytest.raises(targets.TargetError, match="outside"):
        targets.make("local", {"path": str(tmp_path / "data" / "x")}).test()
    monkeypatch.setattr(targets, "_mount_root", lambda p: Path("/"))  # e.g. USB disk not mounted
    with pytest.raises(targets.TargetError, match="mounted"):
        targets.make("local", {"path": str(tmp_path / "nomount"), "require_mount": True}).test()
