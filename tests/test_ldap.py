"""Directory (LDAPS) sign-in: TLS checks against a local TLS server, and the
sign-in logic against ldap3's in-memory mock directory."""
import datetime
import hashlib
import ipaddress
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from ldap3 import MOCK_SYNC, OFFLINE_SLAPD_2_4, Connection, Server

from app import crypto, ldapauth, main
from app.store import Store

H = {"X-ScanVault": "1"}
PASS = "orbit-cedar-lantern-quill"
PW = "pw-1234567890"
BASE = "dc=home,dc=lan"
USER_DN = "uid=ryan,ou=people,dc=home,dc=lan"
GROUP = "cn=scanvault,ou=groups,dc=home,dc=lan"
UUID = "7c9e6679-7425-40de-944b-e07fc1f90ae7"


# ---------------------------------------------------------------- mock directory

def make_directory():
    srv = Server("mock", get_info=OFFLINE_SLAPD_2_4)
    c = Connection(srv, client_strategy=MOCK_SYNC)
    add = c.strategy.add_entry
    add(BASE, {"objectClass": ["top", "domain"], "dc": "home"})
    add("ou=people,dc=home,dc=lan", {"objectClass": ["top", "organizationalUnit"], "ou": "people"})
    add("ou=groups,dc=home,dc=lan", {"objectClass": ["top", "organizationalUnit"], "ou": "groups"})
    add("cn=svc,dc=home,dc=lan", {"objectClass": "person", "sn": "svc", "userPassword": "svc-secret"})
    add(USER_DN, {"objectClass": ["inetOrgPerson", "posixAccount"], "uid": "ryan", "cn": "Ryan", "sn": "R", "mail": "ryan@home.lan",
                  "entryUUID": UUID, "userPassword": "dir-pass-1"})
    add("uid=sam,ou=people,dc=home,dc=lan", {"objectClass": ["inetOrgPerson", "posixAccount"], "uid": "sam", "cn": "Sam", "sn": "S",
                                            "entryUUID": "16fd2706-8baf-433b-82eb-8c7fada847da", "userPassword": "sam-pass-1"})
    add(GROUP, {"objectClass": "groupOfNames", "cn": "scanvault", "member": [USER_DN]})
    return srv


@pytest.fixture()
def directory(monkeypatch):
    srv = make_directory()
    opened = []

    def fake_open(cfg, user, password):
        ldapauth.parse_url(cfg["url"])  # same URL rules as the real thing
        conn = Connection(srv, user=user, password=password, client_strategy=MOCK_SYNC)
        conn.open()
        conn.sv_fingerprint = "f" * 64
        opened.append((user, password))
        return conn

    monkeypatch.setattr(ldapauth, "_open", fake_open)
    return srv, opened


@pytest.fixture()
def env(monkeypatch, directory):
    d = Path(tempfile.mkdtemp(prefix="sv-ldap-"))
    monkeypatch.setattr(main, "store", Store(d))
    monkeypatch.setattr(main, "vault", crypto.Vault())
    for t in (main.login_throttle, main.account_throttle, main.device_throttle):
        t._fails.clear()
    with TestClient(main.app, base_url="https://sv.example.com") as c:
        st = c.get("/api/status").json()
        body = {"username": "ryan", "password": PW, "passphrase": PASS}
        if st.get("setup_code_required"):
            body["setup_code"] = main._state["setup_code"]
        r = c.post("/api/setup", json=body, headers=H)
        assert r.status_code == 200, r.text
        tok = r.cookies.get("sv_session") or r.json().get("token")
        c.cookies.clear()
        yield c, {"Authorization": f"Bearer {tok}", **H}, directory[1]


CFG = {"preset": "openldap", "url": "ldaps://dir.home.lan", "verify": "pin", "pin_sha256": "AB" * 32,
       "bind_dn": "cn=svc,dc=home,dc=lan", "bind_password": "svc-secret", "base_dn": BASE, "groups": [GROUP], "password": PW}


def configure(c, B, **kw):
    r = c.put("/api/ldap/config", json={**CFG, **kw}, headers=B)
    assert r.status_code == 200, r.text
    return r.json()


def link(c, B, user="ryan", pw="dir-pass-1"):
    return c.post("/api/ldap/link", json={"directory_username": user, "directory_password": pw, "password": PW}, headers=B)


def login(c, user, pw):
    c.cookies.clear()
    return c.post("/api/auth/login", json={"username": user, "password": pw}, headers={"User-Agent": "ScanVault-Android"})


def bearer(r):
    return {"Authorization": "Bearer " + (r.json().get("token") or r.cookies.get("sv_session")), **H}


# ---------------------------------------------------------------- tests

def test_configure_link_and_sign_in(env):
    c, B, opened = env
    assert c.get("/api/status").json()["ldap"] is None
    # re-auth is required to add a way into the vault
    assert c.put("/api/ldap/config", json={**CFG, "password": ""}, headers=B).json()["code"] == "reauth_required"
    out = configure(c, B)
    assert out["has_bind_password"] and "bind_password" not in out and out["pin_sha256"] == "ab" * 32
    assert "svc-secret" not in c.get("/api/ldap/config", headers=B).text
    assert c.get("/api/status").json()["ldap"] == {"name": "OpenLDAP"}

    # a correct directory password is not enough before the account is linked
    assert login(c, "ryan.dir", "dir-pass-1").status_code == 401
    assert login(c, "ryan", "dir-pass-1").status_code == 401

    assert link(c, B, pw="wrong").status_code == 400
    r = link(c, B)
    assert r.status_code == 200, r.text
    ids = c.get("/api/sso/config", headers=B).json()["identities"]
    assert ids[0]["provider_id"] == "ldap" and ids[0]["provider_name"] == "OpenLDAP" and ids[0]["email"] == "ryan@home.lan"

    # restart: vault locked; the directory password signs in (also for apps), the vault stays locked
    main.vault.lock()
    r = login(c, "ryan", "dir-pass-1")
    assert r.status_code == 200, r.text
    S = bearer(r)
    c.cookies.clear()
    assert c.get("/api/status", headers=S).json()["authenticated"]
    assert c.get("/api/patients", headers=S).status_code == 423
    assert c.post("/api/vault/unlock", json={"passphrase": PASS}, headers=S).status_code == 200
    # the user bind used the DN found by the search, with the typed password
    assert (USER_DN, "dir-pass-1") in opened
    # the ScanVault password still works too
    assert login(c, "ryan", PW).status_code == 200


def test_group_allow_list(env, directory):
    c, B, _ = env
    configure(c, B)
    # sam has a valid password but is not in the allowed group
    r = c.post("/api/ldap/link", json={"directory_username": "sam", "directory_password": "sam-pass-1", "password": PW}, headers=B)
    assert r.status_code == 400
    # ...and can link once groups are not required
    configure(c, B, groups=[])
    assert link(c, B, "sam", "sam-pass-1").status_code == 200
    configure(c, B, groups=[GROUP])
    assert login(c, "sam", "sam-pass-1").status_code == 401  # removed from the allow list: no sign-in


def test_filter_injection_and_empty_password(env):
    c, B, opened = env
    configure(c, B, groups=[])
    link(c, B)
    for u in ("*", "ryan)(uid=*", "r*", "ryan\x00"):
        assert login(c, u, "dir-pass-1").status_code == 401, u
    n = len(opened)
    assert login(c, "ryan", "").status_code in (400, 401)
    assert all(pw for _, pw in opened[n:] if _ and _.startswith("uid=")), "no unauthenticated user bind"
    with pytest.raises(ldapauth.BadCredentials):
        ldapauth.authenticate({**CFG, "groups": []}, "ryan", "")


def test_password_sign_in_off_keeps_directory(env):
    c, B, _ = env
    configure(c, B)
    # can't turn off password sign-in before a link exists
    assert c.put("/api/sso/settings", json={"local_login": False, "password": PW}, headers=B).status_code == 400
    link(c, B)
    assert c.put("/api/sso/settings", json={"local_login": False, "password": PW}, headers=B).status_code == 200
    st = c.get("/api/status").json()
    assert st["local_login"] is False and st["ldap"]
    assert login(c, "ryan", PW).status_code == 401  # ScanVault password no longer accepted
    assert login(c, "ryan", "dir-pass-1").status_code == 200
    # removing the directory turns password sign-in back on (no lockout)
    assert c.delete("/api/ldap/config", headers=B).json()["local_login"] is True


def test_changes_revoke_sessions(env):
    c, B, _ = env
    configure(c, B)
    link(c, B)
    S = bearer(login(c, "ryan", "dir-pass-1"))
    c.cookies.clear()
    assert c.get("/api/status", headers=S).json()["authenticated"]
    # disabling directory sign-in ends its sessions
    configure(c, B, enabled=False)
    assert c.get("/api/status", headers=S).json()["authenticated"] is False
    configure(c, B, enabled=True)
    assert len(c.get("/api/sso/config", headers=B).json()["identities"]) == 1
    S = bearer(login(c, "ryan", "dir-pass-1"))
    c.cookies.clear()
    # pointing at a different directory drops the links and their sessions
    configure(c, B, url="ldaps://other.home.lan")
    assert c.get("/api/status", headers=S).json()["authenticated"] is False
    assert c.get("/api/sso/config", headers=B).json()["identities"] == []
    # unlinking ends sessions too
    link(c, B)
    S = bearer(login(c, "ryan", "dir-pass-1"))
    c.cookies.clear()
    iid = c.get("/api/sso/config", headers=B).json()["identities"][0]["id"]
    c.delete(f"/api/sso/identities/{iid}", headers=B)
    assert c.get("/api/status", headers=S).json()["authenticated"] is False


def test_failed_directory_logins_are_throttled(env):
    c, B, _ = env
    configure(c, B)
    link(c, B)
    codes = [login(c, "ryan", "nope").status_code for _ in range(8)]
    assert 429 in codes


def test_config_validation(env):
    c, B, _ = env
    for bad in ({"url": "http://dir"}, {"url": "ldap://"}, {"url": "ldaps://u:p@dir"}, {"pin_sha256": "abc"},
                {"base_dn": "not a dn"}, {"user_filter": "(uid=*)"}, {"verify": "ca", "ca_pem": "junk"}):
        r = c.put("/api/ldap/config", json={**CFG, **bad}, headers=B)
        assert r.status_code == 400, (bad, r.text)
    assert ldapauth.parse_url("ldap://dir.home.lan") == ("dir.home.lan", 389, False)  # StartTLS
    assert ldapauth.parse_url("ldaps://dir.home.lan:3269") == ("dir.home.lan", 3269, True)


# ---------------------------------------------------------------- real TLS

def _cert(names):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    san = [x509.IPAddress(ipaddress.ip_address(n)) if n[0].isdigit() else x509.DNSName(n) for n in names]
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


@pytest.fixture()
def tls_server(tmp_path):
    """A TLS listener that completes the handshake and then reads until closed:
    enough to test what happens before any LDAP message is sent."""
    def start(names):
        cert, key = _cert(names)
        cf, kf = tmp_path / "c.pem", tmp_path / "k.pem"
        cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cf, kf)
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        ls.listen(5)
        received = []

        def run():
            while True:
                try:
                    s, _ = ls.accept()
                except OSError:
                    return
                try:
                    with ctx.wrap_socket(s, server_side=True) as t:
                        t.settimeout(2)
                        while True:
                            b = t.recv(4096)
                            if not b:
                                break
                            received.append(b)
                except (ssl.SSLError, OSError):
                    pass

        threading.Thread(target=run, daemon=True).start()
        fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        return ls.getsockname()[1], cert.public_bytes(serialization.Encoding.PEM).decode(), fp, received
    return start


def test_tls_ca_hostname_and_pin(tls_server):
    port, pem, fp, received = tls_server(["localhost", "127.0.0.1"])
    url = f"ldaps://localhost:{port}"
    # self-signed and not trusted
    with pytest.raises(ldapauth.LdapError, match="not trusted|connect"):
        ldapauth._open({"url": url, "verify": "ca"}, "cn=x", "secret-pw")
    # trusted through a supplied CA certificate
    conn = ldapauth._open({"url": url, "verify": "ca", "ca_pem": pem}, None, None)
    assert conn.sv_fingerprint == fp
    conn.unbind()
    # pinned
    conn = ldapauth._open({"url": url, "verify": "pin", "pin_sha256": fp.upper()}, None, None)
    conn.unbind()
    with pytest.raises(ldapauth.LdapError, match="fingerprint changed"):
        ldapauth._open({"url": url, "verify": "pin", "pin_sha256": "0" * 64}, "cn=x", "secret-pw")
    assert ldapauth.fetch_fingerprint(url) == fp
    time.sleep(0.2)
    assert not any(b"secret-pw" in b for b in received), "no credential is sent before the certificate check"


def test_tls_hostname_mismatch(tls_server):
    port, pem, fp, received = tls_server(["dir.example.com"])
    with pytest.raises(ldapauth.LdapError, match="not valid for localhost"):
        ldapauth._open({"url": f"ldaps://localhost:{port}", "verify": "ca", "ca_pem": pem}, "cn=x", "secret-pw")
    time.sleep(0.2)
    assert not any(b"secret-pw" in b for b in received)


def test_hostname_matching():
    cert, _ = _cert(["*.home.lan", "dir.example.com", "10.0.0.5"])
    der = cert.public_bytes(serialization.Encoding.DER)
    assert ldapauth._hostname_ok(der, "dc.home.lan")
    assert ldapauth._hostname_ok(der, "DIR.example.com")
    assert ldapauth._hostname_ok(der, "10.0.0.5")
    assert not ldapauth._hostname_ok(der, "a.b.home.lan")
    assert not ldapauth._hostname_ok(der, "home.lan")
    assert not ldapauth._hostname_ok(der, "10.0.0.6")
    assert not ldapauth._hostname_ok(der, "evil.example.com")
