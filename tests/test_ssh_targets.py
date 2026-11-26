import shutil
import subprocess

import paramiko
import pytest

from app import targets
from ssh_server import SSHTestServer


@pytest.mark.parametrize("protocol", ["sftp", "scp"])
def test_ssh_upload_list_prune_download(tmp_path, protocol):
    if protocol == "scp" and not shutil.which("scp"):
        pytest.skip("scp binary not installed")
    root = tmp_path / "remote"
    root.mkdir()
    keyfile = tmp_path / "id"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(keyfile), "-q"], check=True)
    pub = paramiko.Ed25519Key.from_private_key_file(str(keyfile))
    srv = SSHTestServer(root, password="Backup-Pass-123", pubkey=pub)
    saved = {}
    cfg = {"protocol": protocol, "host": "127.0.0.1", "port": srv.port, "username": "u", "private_key": keyfile.read_text(), "remote_dir": "nested/backups"}
    t = targets.make("sftp", cfg, saved.update)
    msg = t.test()
    assert "Connected" in msg and saved["host_key"].startswith("SHA256:")
    src = tmp_path / "a.bin"
    src.write_bytes(b"ciphertext" * 1000)
    for i in range(4):
        t.upload(src, f"scanvault-backup-2026010{i}-000000Z.svb")
    assert len(t.list_backups()) == 4
    assert t.prune(2) == 2
    names = [n for n, _ in t.list_backups()]
    assert names == ["scanvault-backup-20260102-000000Z.svb", "scanvault-backup-20260103-000000Z.svb"]
    dst = tmp_path / "dl.svb"
    t.download(names[-1], dst)
    assert dst.read_bytes() == src.read_bytes()
    # password auth too
    t2 = targets.make("sftp", {**cfg, "private_key": "", "password": "Backup-Pass-123"}, None)
    assert "Connected" in t2.test()
    # host key pinning: wrong pin refuses
    bad = targets.make("sftp", {**cfg, "host_key": "SHA256:AAAA"}, None)
    with pytest.raises(targets.TargetError, match="mismatch"):
        bad.test()
    srv.close()
