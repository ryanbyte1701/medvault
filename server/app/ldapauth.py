"""Directory sign-in over LDAPS or LDAP + StartTLS.

MedVault looks the person up with a service account (or anonymously), checks
an optional group allow list, then binds as that person with the password they
typed. Only encrypted connections are used, and the server certificate is
checked against trusted CAs and the host name, or against a pinned SHA-256
fingerprint, *before* any credential is sent.

Like OIDC, a directory account can only sign in after a MedVault user has
linked it, and it never unlocks the vault: the encryption key is still needed
after a restart.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import ssl
import uuid
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from ldap3 import BASE, NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import parse_dn

CONNECT_TIMEOUT = 5
RECEIVE_TIMEOUT = 10
AD_IN_CHAIN = "1.2.840.113556.1.4.1941"  # LDAP_MATCHING_RULE_IN_CHAIN (nested groups)

PRESETS: dict[str, dict] = {
    "active_directory": {
        "name": "Active Directory",
        "user_filter": "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={username})(userPrincipalName={username})))",
        "id_attr": "objectGUID",
        "nested_groups": True,
        "help": "Windows Active Directory or Synology Directory Server. Use ldaps://dc.example.com (port 636), a service account such as CN=medvault,CN=Users,DC=example,DC=com, and your domain as the base DN.",
    },
    "synology_ldap": {
        "name": "Synology LDAP Server",
        "user_filter": "(&(objectClass=posixAccount)(uid={username}))",
        "id_attr": "entryUUID",
        "nested_groups": False,
        "help": "The LDAP Server package. Turn on 'Enable LDAP over SSL/TLS', use ldaps://your-nas:636, the bind DN shown on the Settings tab (uid=root,cn=users,dc=...), and base DN dc=... . A self-signed NAS certificate needs the fingerprint option.",
    },
    "freeipa": {
        "name": "FreeIPA",
        "user_filter": "(&(objectClass=person)(uid={username}))",
        "id_attr": "ipaUniqueID",
        "nested_groups": False,
        "help": "Use ldaps://ipa.example.com, a system account under cn=sysaccounts,cn=etc, and cn=users,cn=accounts,dc=example,dc=com as the base DN.",
    },
    "openldap": {
        "name": "OpenLDAP",
        "user_filter": "(&(objectClass=inetOrgPerson)(uid={username}))",
        "id_attr": "entryUUID",
        "nested_groups": False,
        "help": "Any RFC 4511 directory. Group checks use memberOf when the server has it, otherwise the group's member, uniqueMember or memberUid values.",
    },
}


class LdapError(Exception):
    """The directory could not be used (configuration, network, TLS)."""


class BadCredentials(Exception):
    """Wrong username or password, or the account is not allowed."""


# ---------------------------------------------------------------- config checks

def parse_url(url: str) -> tuple[str, int, bool]:
    """Returns (host, port, use_ldaps). Plain LDAP is only accepted with StartTLS."""
    u = urlparse((url or "").strip())
    if u.scheme not in ("ldaps", "ldap") or not u.hostname or u.username or u.password or (u.path not in ("", "/")) or u.query:
        raise LdapError("Use a URL like ldaps://dc.example.com or ldap://dc.example.com (with StartTLS)")
    port = u.port or (636 if u.scheme == "ldaps" else 389)
    return u.hostname, port, u.scheme == "ldaps"


def normalize_pin(pin: str) -> str:
    """Accepts 'AB:CD:..' or plain hex SHA-256; returns lowercase hex."""
    h = re.sub(r"[^0-9a-fA-F]", "", (pin or "").replace("sha256", "").replace("SHA256", ""))
    if len(h) != 64:
        raise LdapError("The certificate fingerprint must be a SHA-256 hash (64 hex digits)")
    return h.lower()


def check_config(cfg: dict) -> None:
    parse_url(cfg.get("url", ""))
    if cfg.get("verify") == "pin":
        normalize_pin(cfg.get("pin_sha256", ""))
    elif cfg.get("ca_pem"):
        try:
            x509.load_pem_x509_certificates(cfg["ca_pem"].encode())
        except ValueError as exc:
            raise LdapError("The CA certificate is not valid PEM") from exc
    if not cfg.get("base_dn"):
        raise LdapError("Enter the base DN to search for users")
    for dn in [cfg["base_dn"], *(cfg.get("groups") or []), *([cfg["bind_dn"]] if cfg.get("bind_dn") else [])]:
        try:
            parse_dn(dn)
        except LDAPException as exc:
            raise LdapError(f"Not a valid DN: {dn}") from exc
    flt = cfg.get("user_filter") or ""
    if "{username}" not in flt or not flt.startswith("(") or flt.count("(") != flt.count(")"):
        raise LdapError("The user filter must be an LDAP filter containing {username}")
    if cfg.get("bind_dn") and not bind_password(cfg):
        raise LdapError("Enter the bind password for the service account")


def bind_password(cfg: dict) -> str:
    f = os.environ.get("MEDVAULT_LDAP_BIND_PASSWORD_FILE")
    if f and Path(f).exists():
        return Path(f).read_text().strip()
    return cfg.get("bind_password") or ""


def issuer(cfg: dict) -> str:
    """Identity namespace: links stay valid only for the same server and base DN."""
    host, port, _ = parse_url(cfg["url"])
    return f"ldap://{host.lower()}:{port}/{','.join(p.strip().lower() for p in cfg['base_dn'].split(','))}"


# ---------------------------------------------------------------- TLS

def _hostname_ok(der: bytes, host: str) -> bool:
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False  # CN fallback is obsolete (RFC 6125)
    try:
        ip = ipaddress.ip_address(host)
        return ip in san.get_values_for_type(x509.IPAddress)
    except ValueError:
        pass
    host = host.lower().rstrip(".")
    for name in san.get_values_for_type(x509.DNSName):
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:] and not host.startswith("."):
            return True
    return False


def _tls(cfg: dict, host: str) -> Tls:
    pin = cfg.get("verify") == "pin"
    return Tls(
        validate=ssl.CERT_NONE if pin else ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLS_CLIENT,  # TLS 1.2+ by default
        ca_certs_data=None if pin else (cfg.get("ca_pem") or None),
        sni=None if _is_ip(host) else host,
    )


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _verify_peer(cfg: dict, conn: Connection, host: str) -> str:
    """Checks the certificate of an established TLS session. Returns its SHA-256."""
    sock = conn.socket
    der = sock.getpeercert(binary_form=True) if isinstance(sock, ssl.SSLSocket) else None
    if not der:
        raise LdapError("The directory connection is not encrypted")
    fp = hashlib.sha256(der).hexdigest()
    if cfg.get("verify") == "pin":
        if fp != normalize_pin(cfg.get("pin_sha256", "")):
            raise LdapError(f"The directory's certificate fingerprint changed (now {fp}). If you replaced the certificate, update the pin.")
    elif not _hostname_ok(der, host):
        raise LdapError(f"The directory's certificate is not valid for {host}")
    return fp


def _open(cfg: dict, user: str | None, password: str | None) -> Connection:
    """Open an encrypted, verified connection. Nothing is sent in the clear and
    no credential is sent before the certificate has been checked."""
    host, port, use_ssl = parse_url(cfg["url"])
    server = Server(host, port=port, use_ssl=use_ssl, tls=_tls(cfg, host), get_info=NONE, connect_timeout=CONNECT_TIMEOUT)
    conn = Connection(server, user=user, password=password, auto_bind="NONE", receive_timeout=RECEIVE_TIMEOUT,
                      read_only=True, raise_exceptions=False, auto_referrals=False)
    try:
        conn.open()
        if not use_ssl and not conn.start_tls():
            raise LdapError("The directory refused StartTLS")
        conn.sv_fingerprint = _verify_peer(cfg, conn, host)
    except LdapError:
        conn.unbind()
        raise
    except (LDAPException, ssl.SSLError, OSError) as exc:
        conn.unbind()
        raise LdapError(f"Could not connect securely to {host}:{port}: {_why(exc, host)}") from exc
    return conn


def _why(exc: Exception, host: str = "") -> str:
    s = str(exc) or exc.__class__.__name__
    if "doesn't match any name" in s:
        return f"the certificate is not valid for {host}"
    if "CERTIFICATE_VERIFY_FAILED" in s:
        return "the certificate is not trusted (add your CA certificate, or pin its fingerprint)"
    return s[:200]


def fetch_fingerprint(url: str) -> str:
    """For the settings page: the SHA-256 of the certificate the server presents
    right now, so an owner with a self-signed NAS certificate can pin it."""
    cfg = {"url": url, "verify": "pin", "pin_sha256": "0" * 64}
    host, port, use_ssl = parse_url(url)
    server = Server(host, port=port, use_ssl=use_ssl, tls=_tls(cfg, host), get_info=NONE, connect_timeout=CONNECT_TIMEOUT)
    conn = Connection(server, auto_bind="NONE", receive_timeout=RECEIVE_TIMEOUT, raise_exceptions=False)
    try:
        conn.open()
        if not use_ssl and not conn.start_tls():
            raise LdapError("The directory refused StartTLS")
        der = conn.socket.getpeercert(binary_form=True)
        return hashlib.sha256(der).hexdigest()
    except (LDAPException, ssl.SSLError, OSError) as exc:
        raise LdapError(f"Could not connect to {host}:{port}: {_why(exc, host)}") from exc
    finally:
        conn.unbind()


# ---------------------------------------------------------------- authentication

def _service(cfg: dict) -> Connection:
    conn = _open(cfg, cfg.get("bind_dn") or None, bind_password(cfg) if cfg.get("bind_dn") else None)
    if not conn.bind():
        conn.unbind()
        raise LdapError("The directory rejected the service account (bind DN or password)")
    return conn


def _valid_username(username: str) -> bool:
    return 0 < len(username) <= 256 and not any(ord(c) < 32 or ord(c) == 127 for c in username)


def _first(entry: dict, attr: str):
    v = entry.get(attr)
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _stable_id(raw: dict, id_attr: str, dn: str) -> str:
    v = raw.get(id_attr) or []
    if v:
        b = v[0]
        if id_attr == "objectGUID" and isinstance(b, bytes) and len(b) == 16:
            return str(uuid.UUID(bytes_le=b))
        return (b.decode("utf-8", "replace") if isinstance(b, bytes) else str(b)).lower()
    return "dn:" + dn.lower()


def _norm_dn(dn: str) -> str:
    try:
        return ",".join(f"{a.lower()}={v.lower()}" for a, v, _ in parse_dn(dn, escape=False, strip=True))
    except LDAPException:
        return dn.lower()


def _in_group(cfg: dict, conn: Connection, user_dn: str, member_of: list[str], uid: str | None, group: str) -> bool:
    preset = PRESETS.get(cfg.get("preset") or "openldap", PRESETS["openldap"])
    g = _norm_dn(group)
    if any(_norm_dn(m) == g for m in member_of):
        return True
    if preset["nested_groups"]:
        conn.search(user_dn, f"(memberOf:{AD_IN_CHAIN}:={escape_filter_chars(group)})", BASE, attributes=["1.1"], size_limit=1)
        if conn.entries:
            return True
    flt = f"(|(member={escape_filter_chars(user_dn)})(uniqueMember={escape_filter_chars(user_dn)})"
    if uid:
        flt += f"(memberUid={escape_filter_chars(uid)})"
    flt += ")"
    conn.search(group, flt, BASE, attributes=["1.1"], size_limit=1)
    return bool(conn.entries)


def authenticate(cfg: dict, username: str, password: str) -> dict:
    """Returns {issuer, subject, dn, email, name} or raises BadCredentials/LdapError."""
    if not _valid_username(username) or not password:
        raise BadCredentials()  # an empty password would be an unauthenticated bind
    preset = PRESETS.get(cfg.get("preset") or "openldap", PRESETS["openldap"])
    id_attr = cfg.get("id_attr") or preset["id_attr"]
    flt = (cfg.get("user_filter") or preset["user_filter"]).replace("{username}", escape_filter_chars(username))
    conn = _service(cfg)
    try:
        ok = conn.search(cfg["base_dn"], flt, SUBTREE, attributes=[id_attr, "mail", "displayName", "cn", "uid", "memberOf"], size_limit=2)
        if not ok and conn.result.get("result") not in (0, 4):
            raise LdapError(f"Directory search failed: {conn.result.get('description')}")
        entries = [e for e in conn.response or [] if e.get("type") == "searchResEntry"]
        if len(entries) != 1:
            raise BadCredentials()  # unknown, or ambiguous: never guess
        e = entries[0]
        dn, attrs, raw = e["dn"], e.get("attributes") or {}, e.get("raw_attributes") or {}
        member_of = [str(m) for m in (attrs.get("memberOf") or [])]
        uid = _first(attrs, "uid")
        groups = cfg.get("groups") or []
        if groups and not any(_in_group(cfg, conn, dn, member_of, uid, g) for g in groups):
            raise BadCredentials()
        ident = {
            "issuer": issuer(cfg),
            "subject": _stable_id(raw, id_attr, dn),
            "dn": dn,
            "email": _first(attrs, "mail") or None,
            "name": _first(attrs, "displayName") or _first(attrs, "cn") or username,
        }
    finally:
        conn.unbind()
    user = _open(cfg, dn, password)
    try:
        if not user.bind():
            raise BadCredentials()
    finally:
        user.unbind()
    return ident


def test(cfg: dict) -> dict:
    """Connect, bind the service account and read the base DN."""
    conn = _service(cfg)
    try:
        fp = getattr(conn, "sv_fingerprint", None)
        if not conn.search(cfg["base_dn"], "(objectClass=*)", BASE, attributes=["1.1"]):
            raise LdapError(f"The base DN {cfg['base_dn']} was not found or is not readable")
    finally:
        conn.unbind()
    return {"ok": True, "fingerprint": fp}


def env_overrides(cfg: dict) -> dict:
    """MEDVAULT_LDAP_* variables, for setups that prefer env/Docker secrets."""
    out = dict(cfg)
    m = {"MEDVAULT_LDAP_URL": "url", "MEDVAULT_LDAP_BIND_DN": "bind_dn", "MEDVAULT_LDAP_BASE_DN": "base_dn",
         "MEDVAULT_LDAP_PRESET": "preset", "MEDVAULT_LDAP_PIN_SHA256": "pin_sha256", "MEDVAULT_LDAP_NAME": "name"}
    for env, key in m.items():
        if os.environ.get(env):
            out[key] = os.environ[env].strip()
    if os.environ.get("MEDVAULT_LDAP_PIN_SHA256"):
        out["verify"] = "pin"
    if os.environ.get("MEDVAULT_LDAP_GROUPS"):
        out["groups"] = [g.strip() for g in os.environ["MEDVAULT_LDAP_GROUPS"].split(";") if g.strip()]
    if os.environ.get("MEDVAULT_LDAP_URL"):
        out.setdefault("enabled", True)
        out["managed"] = "env"
    return out

