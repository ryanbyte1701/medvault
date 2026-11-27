import io

import pytest

from app import crypto


def test_stream_roundtrip_and_tamper():
    mk = crypto.new_master_key()
    for size in (0, 1, crypto.CHUNK - 1, crypto.CHUNK, crypto.CHUNK * 2 + 5):
        data = bytes(range(256)) * (size // 256) + b"x" * (size % 256)
        enc = io.BytesIO()
        crypto.encrypt_stream(mk, io.BytesIO(data), enc, b"ctx")
        out = io.BytesIO()
        enc.seek(0)
        crypto.decrypt_stream(mk, enc, out, b"ctx")
        assert out.getvalue() == data
    raw = bytearray(enc.getvalue())
    raw[40] ^= 1
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_stream(mk, io.BytesIO(bytes(raw)), io.BytesIO(), b"ctx")
    # truncation: drop final chunk
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_stream(mk, io.BytesIO(enc.getvalue()[: 20 + 4 + crypto.CHUNK + 16]), io.BytesIO(), b"ctx")
    # wrong aad (swapping files between records)
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_stream(mk, io.BytesIO(enc.getvalue()), io.BytesIO(), b"other")


def test_wrap_and_recovery():
    mk = crypto.new_master_key()
    ks = crypto.wrap_master_key(mk, "correct horse battery", "SV-1")
    assert crypto.unwrap_master_key(ks, "correct horse battery") == mk
    with pytest.raises(crypto.CryptoError):
        crypto.unwrap_master_key(ks, "wrong")
    text = crypto.recovery_file_text(mk, "SV-1", "now")
    assert crypto.parse_recovery_file(text) == mk
    assert crypto.parse_recovery_file(text.lower()) == mk  # case-insensitive when typed
    head, body = text.split(crypto.RECOVERY_BEGIN)
    ch = body[3]
    typo = head + crypto.RECOVERY_BEGIN + body[:3] + ("A" if ch != "A" else "B") + body[4:]
    with pytest.raises(crypto.CryptoError):
        crypto.parse_recovery_file(typo)
