"""Encrypted scratch files.

Uploads, zip members and DICOMs being decoded need a seekable file while they
are processed (pydicom, zipfile and Pillow all seek). A ``Spool`` is a temp
file that is

* encrypted with a random AES-256-GCM key that only ever lives in memory, so
  nothing readable is left on disk, in snapshots or in deleted blocks, and
* unlinked as soon as it is created, so a crash leaves no named file behind.

Readers get a normal seekable binary file object (``Spool.open()``).
"""
from __future__ import annotations

import io
import os
import tempfile
import threading
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CH = 256 * 1024
TAG = 16


class SpoolFull(Exception):
    pass


class Spool:
    def __init__(self, directory: Path | str | None = None, limit: int | None = None):
        fd, name = tempfile.mkstemp(dir=directory, prefix=".spool-")
        try:
            os.unlink(name)
        except OSError:  # pragma: no cover - e.g. Windows
            pass
        self._fd = fd
        self._aes = AESGCM(AESGCM.generate_key(256))
        self._buf = bytearray()
        self._chunks = 0
        self.size = 0
        self.limit = limit
        self.closed = False
        self._finished = False
        self._lock = threading.Lock()

    # ------------------------------------------------------------- writing
    def write(self, data: bytes) -> int:
        if self._finished:
            raise ValueError("spool already finished")
        if self.limit is not None and self.size + len(data) > self.limit:
            raise SpoolFull(self.limit)
        self._buf += data
        self.size += len(data)
        while len(self._buf) >= CH:
            self._emit(bytes(self._buf[:CH]))
            del self._buf[:CH]
        return len(data)

    def _emit(self, chunk: bytes) -> None:
        ct = self._aes.encrypt(self._chunks.to_bytes(12, "big"), chunk, None)
        os.pwrite(self._fd, ct, self._chunks * (CH + TAG))
        self._chunks += 1

    def finish(self) -> "Spool":
        if not self._finished:
            if self._buf:
                self._emit(bytes(self._buf))
                self._buf.clear()
            self._finished = True
        return self

    # ------------------------------------------------------------- reading
    def _chunk(self, i: int) -> bytes:
        n = min(CH, self.size - i * CH)
        if n <= 0:
            return b""
        ct = os.pread(self._fd, n + TAG, i * (CH + TAG))
        return self._aes.decrypt(i.to_bytes(12, "big"), ct, None)

    def open(self) -> io.BufferedReader:
        self.finish()
        return io.BufferedReader(_Reader(self), buffer_size=CH)

    def read_head(self, n: int) -> bytes:
        with self.open() as f:
            return f.read(n)

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            os.close(self._fd)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class _Reader(io.RawIOBase):
    def __init__(self, spool: Spool):
        self._s = spool
        self._pos = 0
        self._ci = -1
        self._cb = b""
        self.name = "<encrypted scratch>"

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, off: int, whence: int = 0) -> int:
        if whence == 0:
            p = off
        elif whence == 1:
            p = self._pos + off
        else:
            p = self._s.size + off
        if p < 0:
            raise ValueError("negative seek position")
        self._pos = p
        return p

    def readinto(self, b) -> int:
        if self._pos >= self._s.size:
            return 0
        i, off = divmod(self._pos, CH)
        if i != self._ci:
            self._cb, self._ci = self._s._chunk(i), i
        n = min(len(b), len(self._cb) - off)
        b[:n] = self._cb[off : off + n]
        self._pos += n
        return n
