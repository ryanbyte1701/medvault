"""Single sign-on with OpenID Connect.

MedVault acts as an OIDC relying party (authorization code flow with PKCE).
One generic implementation covers Google, Microsoft Entra ID, Authentik,
Authelia, Keycloak, Synology SSO Server and any other standards-compliant
provider; the presets below only pre-fill the issuer and explain where to
register the app.

SSO replaces the *sign-in password* only. The vault encryption key is a
separate secret that never reaches the identity provider: after a restart the
vault stays locked until someone enters the encryption key (or the recovery
key file, or ``MEDVAULT_PASSPHRASE_FILE`` auto-unlocks it), exactly as with a
local sign-in.

Sign-in is only possible for identities that a signed-in user has linked to
their MedVault account first (Settings > Single sign-on). Nobody gets an
account just because the identity provider knows them.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode, urlparse

import jwt
import requests

HTTP_TIMEOUT = 15
DISCOVERY_TTL = 3600
ALLOWED_ALGS = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
DEFAULT_SCOPES = "openid email profile"

# Presets: issuer template + short help. "{x}" placeholders are filled from the
# provider's fields (e.g. tenant, base_url, realm, slug).
PRESETS: dict[str, dict] = {
    "google": {
        "name": "Google",
        "issuer": "https://accounts.google.com",
        "fields": [],
        "help": "Google Cloud console > APIs & Services > Credentials > Create OAuth client ID (Web application). Add the redirect URI below as an authorized redirect URI.",
    },
    "microsoft": {
        "name": "Microsoft",
        "issuer": "https://login.microsoftonline.com/{tenant}/v2.0",
        "fields": [{"key": "tenant", "label": "Tenant ID or domain", "placeholder": "common, consumers, or your tenant ID", "default": "common"}],
        "help": "Microsoft Entra admin center > App registrations > New registration. Platform: Web, with the redirect URI below. Then Certificates & secrets > New client secret. Use 'consumers' for personal Microsoft accounts, 'common' for any account, or your tenant ID for a work account.",
    },
    "authentik": {
        "name": "Authentik",
        "issuer": "{base_url}/application/o/{slug}/",
        "fields": [
            {"key": "base_url", "label": "Authentik URL", "placeholder": "https://auth.example.com"},
            {"key": "slug", "label": "Application slug", "placeholder": "medvault"},
        ],
        "help": "Applications > Providers > Create > OAuth2/OpenID Provider (confidential client), redirect URI below, then create an Application with the slug you enter here.",
    },
    "authelia": {
        "name": "Authelia",
        "issuer": "{base_url}",
        "fields": [{"key": "base_url", "label": "Authelia URL", "placeholder": "https://auth.example.com"}],
        "help": "Add a client under identity_providers.oidc.clients in Authelia's configuration with redirect_uris set to the URI below, scopes openid, email, profile and token_endpoint_auth_method client_secret_basic.",
    },
    "keycloak": {
        "name": "Keycloak",
        "issuer": "{base_url}/realms/{realm}",
        "fields": [
            {"key": "base_url", "label": "Keycloak URL", "placeholder": "https://kc.example.com"},
            {"key": "realm", "label": "Realm", "placeholder": "home", "default": "master"},
        ],
        "help": "Realm > Clients > Create client (OpenID Connect), turn on Client authentication, add the redirect URI below as a valid redirect URI, then copy the secret from the Credentials tab.",
    },
    "synology": {
        "name": "Synology SSO",
        "issuer": "{base_url}/webman/sso",
        "fields": [{"key": "base_url", "label": "NAS address", "placeholder": "https://nas.example.com:5001"}],
        "help": "Install SSO Server from Package Center, enable OIDC under Service, then Application > Add with the redirect URI below. Your NAS needs a certificate MedVault trusts (see README).",
    },
    "generic": {
        "name": "OpenID Connect",
        "issuer": "",
        "fields": [],
        "help": "Any OpenID Connect provider. Enter its issuer URL; MedVault reads /.well-known/openid-configuration from it.",
    },
}


class SSOError(Exception):
    pass


# ---------------------------------------------------------------- helpers

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def pkce_pair() -> tuple[str, str]:
    verifier = b64url(secrets.token_bytes(32))
    return verifier, pkce_challenge(verifier)


def pkce_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode()).digest())


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def resolve_issuer(p: dict) -> str:
    """Issuer for a provider: explicit issuer wins, else the preset template."""
    if p.get("issuer"):
        return p["issuer"].strip()
    tpl = PRESETS.get(p.get("preset") or "generic", PRESETS["generic"])["issuer"]
    fields = dict(p.get("fields") or {})
    for f in PRESETS.get(p.get("preset") or "generic", {}).get("fields", []):
        fields.setdefault(f["key"], f.get("default", ""))
    try:
        issuer = tpl.format(**{k: str(v).strip().rstrip("/") for k, v in fields.items()})
    except (KeyError, IndexError):
        issuer = ""
    return issuer


def validate_url(url: str, what: str = "The issuer") -> None:
    """Only https (or http on localhost / an explicitly trusted LAN) is accepted,
    for the issuer and for every endpoint its discovery document names."""
    u = urlparse(url if isinstance(url, str) else "")
    if u.scheme not in ("https", "http") or not u.hostname or u.username or u.password:
        raise SSOError(f"{what} must be an https:// URL")
    if u.scheme == "http" and u.hostname not in ("localhost", "127.0.0.1") and os.environ.get("MEDVAULT_OIDC_ALLOW_HTTP") != "1":
        raise SSOError(f"{what} must use https:// (set MEDVAULT_OIDC_ALLOW_HTTP=1 to allow http on a trusted LAN)")
    if "{" in url or any(c in url for c in "\r\n\t <>\"\\"):
        raise SSOError(f"{what} is not a valid URL" if what != "The issuer" else "Fill in every field of the provider")


def validate_issuer_url(issuer: str) -> None:
    validate_url(issuer, "The issuer")


# Microsoft's multi-tenant endpoints (common/organizations/consumers) publish a
# templated issuer; the real issuer contains the signing-in user's tenant id.
MS_HOST = "login.microsoftonline.com"
MS_TEMPLATE = f"https://{MS_HOST}/{{tenantid}}/v2.0"
_TENANT_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def ms_template_allowed(issuer: str, doc_issuer: str) -> bool:
    return urlparse(issuer).hostname == MS_HOST and issuer.startswith(f"https://{MS_HOST}/") and doc_issuer == MS_TEMPLATE


def _norm(u: str) -> str:
    return u.rstrip("/")


# ---------------------------------------------------------------- OIDC client

@dataclass
class _Cached:
    value: dict
    at: float


class OIDC:
    """Discovery, authorization URL, code exchange and ID token validation."""

    def __init__(self):
        self._disc: dict[str, _Cached] = {}
        self._jwks: dict[str, _Cached] = {}
        self._lock = threading.Lock()

    def clear(self) -> None:
        with self._lock:
            self._disc.clear()
            self._jwks.clear()

    def _get(self, url: str) -> dict:
        try:
            r = requests.get(url, timeout=HTTP_TIMEOUT, headers={"Accept": "application/json"})
        except requests.RequestException as exc:
            raise SSOError(f"Could not reach {urlparse(url).netloc}: {exc.__class__.__name__}") from exc
        if r.status_code != 200:
            raise SSOError(f"{url} returned HTTP {r.status_code}")
        try:
            return r.json()
        except ValueError as exc:
            raise SSOError(f"{url} did not return JSON") from exc

    def discover(self, issuer: str, force: bool = False) -> dict:
        validate_issuer_url(issuer)
        with self._lock:
            c = self._disc.get(issuer)
        if c and not force and time.time() - c.at < DISCOVERY_TTL:
            return c.value
        doc = self._get(_norm(issuer) + "/.well-known/openid-configuration")
        for k in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not doc.get(k):
                raise SSOError(f"Provider configuration is missing {k}")
        if _norm(doc["issuer"]) != _norm(issuer) and not ms_template_allowed(issuer, doc["issuer"]):
            raise SSOError(f"Issuer mismatch: the provider calls itself {doc['issuer']}")
        validate_url(doc["authorization_endpoint"], "The provider's authorization endpoint")
        validate_url(doc["token_endpoint"], "The provider's token endpoint")
        validate_url(doc["jwks_uri"], "The provider's key (JWKS) endpoint")
        with self._lock:
            self._disc[issuer] = _Cached(doc, time.time())
        return doc

    def authorization_url(self, p: dict, redirect_uri: str, state: str, nonce: str, challenge: str, prompt: str | None = None) -> str:
        doc = self.discover(resolve_issuer(p))
        q = {
            "response_type": "code",
            "client_id": p["client_id"],
            "redirect_uri": redirect_uri,
            "scope": p.get("scopes") or DEFAULT_SCOPES,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if prompt or p.get("prompt"):
            q["prompt"] = prompt or p["prompt"]
        sep = "&" if "?" in doc["authorization_endpoint"] else "?"
        return doc["authorization_endpoint"] + sep + urlencode(q)

    def exchange_code(self, p: dict, code: str, redirect_uri: str, verifier: str) -> dict:
        doc = self.discover(resolve_issuer(p))
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri, "code_verifier": verifier}
        auth = None
        secret = p.get("client_secret") or ""
        methods = doc.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
        if secret and "client_secret_basic" not in methods and "client_secret_post" in methods:
            data.update(client_id=p["client_id"], client_secret=secret)
        elif secret:
            auth = (p["client_id"], secret)
        else:
            data["client_id"] = p["client_id"]
        try:
            r = requests.post(doc["token_endpoint"], data=data, auth=auth, timeout=HTTP_TIMEOUT, headers={"Accept": "application/json"})
        except requests.RequestException as exc:
            raise SSOError(f"Token request failed: {exc.__class__.__name__}") from exc
        try:
            j = r.json()
        except ValueError:
            j = {}
        if r.status_code != 200 or not j.get("id_token"):
            raise SSOError("The provider rejected the sign-in: " + str(j.get("error_description") or j.get("error") or f"HTTP {r.status_code}"))
        return j

    def _jwk_set(self, uri: str, force: bool) -> jwt.PyJWKSet:
        with self._lock:
            c = self._jwks.get(uri)
        if c is None or force or time.time() - c.at > DISCOVERY_TTL:
            c = _Cached(self._get(uri), time.time())
            with self._lock:
                self._jwks[uri] = c
        return jwt.PyJWKSet.from_dict(c.value)

    def _key_for(self, uri: str, kid: str | None, alg: str):
        for force in (False, True):  # refetch once on an unknown kid (key rotation)
            try:
                keys = [k for k in self._jwk_set(uri, force).keys if k.public_key_use in (None, "sig")]
            except jwt.PyJWKSetError as exc:
                raise SSOError("The provider's signing keys could not be read") from exc
            if kid is not None:
                match = [k for k in keys if k.key_id == kid]
            else:
                match = [k for k in keys if k.algorithm_name == alg] or (keys if len(keys) == 1 else [])
            if match:
                return match[0].key
        raise SSOError("The ID token was signed with an unknown key")

    def validate_id_token(self, p: dict, id_token: str, nonce: str) -> dict:
        doc = self.discover(resolve_issuer(p))
        try:
            hdr = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise SSOError("Malformed ID token") from exc
        alg = hdr.get("alg")
        supported = set(doc.get("id_token_signing_alg_values_supported") or ["RS256"]) & ALLOWED_ALGS
        if alg not in supported:
            raise SSOError(f"ID token algorithm {alg} is not allowed")
        key = self._key_for(doc["jwks_uri"], hdr.get("kid"), alg)
        try:
            claims = jwt.decode(
                id_token,
                key=key,
                algorithms=[alg],
                audience=p["client_id"],
                leeway=120,
                options={"require": ["exp", "iat", "iss", "sub", "aud"], "verify_iss": False},
            )
        except jwt.PyJWTError as exc:
            raise SSOError(f"ID token rejected: {exc}") from exc
        expected_iss = doc["issuer"]
        if expected_iss == MS_TEMPLATE:
            # Only the Microsoft preset may use the template, and the tenant must be a real tenant id.
            tid = str(claims.get("tid", ""))
            if p.get("preset") != "microsoft" or not ms_template_allowed(resolve_issuer(p), expected_iss) or not _TENANT_RE.match(tid):
                raise SSOError("ID token issuer does not match the provider")
            expected_iss = MS_TEMPLATE.replace("{tenantid}", tid)
        if _norm(claims["iss"]) != _norm(expected_iss):
            raise SSOError("ID token issuer does not match the provider")
        aud = claims["aud"]
        if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != p["client_id"]:
            raise SSOError("ID token was issued to a different client")
        if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise SSOError("ID token nonce mismatch")
        return claims


# ---------------------------------------------------------------- pending flows

class PendingStore:
    """Short-lived in-memory records (auth requests and login tickets)."""

    def __init__(self, ttl: int, cap: int = 5000):
        self.ttl, self.cap = ttl, cap
        self._d: dict[str, tuple[dict, float]] = {}
        self._lock = threading.Lock()

    def put(self, value: dict) -> str:
        key = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            for k in [k for k, (_, t) in self._d.items() if now - t > self.ttl]:
                del self._d[k]
            while len(self._d) >= self.cap:
                del self._d[next(iter(self._d))]
            self._d[key] = (value, now)
        return key

    def pop(self, key: str) -> dict | None:
        with self._lock:
            v = self._d.pop(key or "", None)
        if not v or time.time() - v[1] > self.ttl:
            return None
        return v[0]

    def clear(self) -> None:
        with self._lock:
            self._d.clear()


# ---------------------------------------------------------------- config

def env_provider() -> dict | None:
    """A provider configured through environment variables (read-only in the UI)."""
    issuer = os.environ.get("MEDVAULT_OIDC_ISSUER", "").strip()
    client_id = os.environ.get("MEDVAULT_OIDC_CLIENT_ID", "").strip()
    if not issuer or not client_id:
        return None
    secret = os.environ.get("MEDVAULT_OIDC_CLIENT_SECRET", "")
    sf = os.environ.get("MEDVAULT_OIDC_CLIENT_SECRET_FILE")
    if sf and Path(sf).exists():
        secret = Path(sf).read_text().strip()
    preset = os.environ.get("MEDVAULT_OIDC_PRESET", "generic")
    return {
        "id": "env",
        "name": os.environ.get("MEDVAULT_OIDC_NAME") or PRESETS.get(preset, PRESETS["generic"])["name"],
        "preset": preset if preset in PRESETS else "generic",
        "issuer": issuer,
        "client_id": client_id,
        "client_secret": secret,
        "scopes": os.environ.get("MEDVAULT_OIDC_SCOPES") or DEFAULT_SCOPES,
        "enabled": True,
        "managed": "env",
    }


def app_redirect_allowed(uri: str) -> bool:
    """Mobile apps receive their one-time ticket on a custom-scheme URI, or on a
    verified https App Link if the operator lists one."""
    prefixes = [p.strip() for p in os.environ.get("MEDVAULT_SSO_APP_REDIRECTS", "medvault://,scanvault://").split(",") if p.strip()]
    if not uri or any(c in uri for c in "\r\n\t <>\"\\"):
        return False
    u = urlparse(uri)
    if u.scheme in ("javascript", "data", "file", "vbscript", "blob", "about", "intent", "content"):
        return False
    for p in prefixes:
        pu = urlparse(p)
        if pu.scheme != u.scheme:
            continue
        if u.scheme in ("http", "https"):
            # Exact scheme, host and port; the path must be the prefix's path or below it.
            if u.scheme == "https" and u.netloc.lower() == pu.netloc.lower() and not u.username and not u.password:
                base = pu.path.rstrip("/")
                if u.path == pu.path or u.path.startswith(base + "/"):
                    return True
        elif uri.startswith(p):
            return True
    return False
