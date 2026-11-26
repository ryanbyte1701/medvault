"""Tiny in-process SSH server for tests: SFTP subsystem rooted at a temp dir
plus exec support (mkdir/ls/rm/test/scp -t) so the SCP path can be exercised."""
from __future__ import annotations

import os
import socket
import subprocess
import threading

import paramiko
from paramiko import SFTPAttributes, SFTPHandle, SFTPServer, SFTPServerInterface, SFTP_OK


class _Handle(SFTPHandle):
    def stat(self):
        return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()) if hasattr(self, "readfile") else os.fstat(self.writefile.fileno()))


class _SFTP(SFTPServerInterface):
    root = "/"

    def _p(self, path):
        path = os.path.normpath("/" + path).lstrip("/")
        return os.path.join(self.root, path)

    def list_folder(self, path):
        out = []
        for n in os.listdir(self._p(path)):
            a = SFTPAttributes.from_stat(os.stat(os.path.join(self._p(path), n)))
            a.filename = n
            out.append(a)
        return out

    def stat(self, path):
        try:
            return SFTPAttributes.from_stat(os.stat(self._p(path)))
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    lstat = stat

    def open(self, path, flags, attr):
        p = self._p(path)
        try:
            fd = os.open(p, flags, 0o600)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        mode = "wb" if flags & os.O_WRONLY else ("r+b" if flags & os.O_RDWR else "rb")
        f = os.fdopen(fd, mode)
        h = _Handle(flags)
        h.filename = p
        h.readfile = f
        h.writefile = f
        return h

    def remove(self, path):
        os.remove(self._p(path))
        return SFTP_OK

    def rename(self, a, b):
        os.rename(self._p(a), self._p(b))
        return SFTP_OK

    posix_rename = rename

    def mkdir(self, path, attr):
        os.mkdir(self._p(path))
        return SFTP_OK


class _Server(paramiko.ServerInterface):
    def __init__(self, password, pubkey, root):
        self.password, self.pubkey, self.root = password, pubkey, root
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, u, p):
        return paramiko.AUTH_SUCCESSFUL if p == self.password else paramiko.AUTH_FAILED

    def check_auth_publickey(self, u, key):
        return paramiko.AUTH_SUCCESSFUL if self.pubkey and key.asbytes() == self.pubkey.asbytes() else paramiko.AUTH_FAILED

    def get_allowed_auths(self, u):
        return "password,publickey"

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode()

        def run():
            proc = subprocess.Popen(cmd, shell=True, cwd=self.root, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            def pump_in():
                try:
                    while True:
                        d = channel.recv(65536)
                        if not d:
                            break
                        proc.stdin.write(d)
                        proc.stdin.flush()
                except Exception:
                    pass
                try:
                    proc.stdin.close()
                except Exception:
                    pass

            threading.Thread(target=pump_in, daemon=True).start()
            while True:
                d = os.read(proc.stdout.fileno(), 65536)
                if not d:
                    break
                channel.sendall(d)
            err = proc.stderr.read()
            if err:
                channel.sendall_stderr(err)
            channel.send_exit_status(proc.wait())
            channel.close()

        threading.Thread(target=run, daemon=True).start()
        return True


class SSHTestServer:
    def __init__(self, root, password="pw", pubkey=None):
        self.root = str(root)
        self.password, self.pubkey = password, pubkey
        self.host_key = paramiko.Ed25519Key.from_private_key_file(_hostkey_path())
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(10)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(self.host_key)
            sftp_root = self.root

            class S(_SFTP):
                root = sftp_root

            t.set_subsystem_handler("sftp", SFTPServer, S)
            t.start_server(server=_Server(self.password, self.pubkey, self.root))

    def close(self):
        self.sock.close()


def _hostkey_path():
    import tempfile

    p = os.path.join(tempfile.gettempdir(), "sv-test-hostkey")
    if not os.path.exists(p):
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", p, "-q"], check=True)
    return p
