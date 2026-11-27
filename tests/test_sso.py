"""OIDC single sign-on against a mocked identity provider."""
import base64
import hashlib
import json
import re
import secrets
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
import responses
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app import crypto, main, sso
from app.store import Store

H = {"X-ScanVault": "1"}
ISS = "https://idp.example.com"
PASS = "orbit-cedar-lantern-quill"
PW = "pw-1234567890"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwks():
    j = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
    j.update(kid="k1", use="sig", alg="RS256")
    return {"keys": [j]}


class IdP:
    """Records the last authorization request and mints ID tokens for it."""

    def __init__(self):
        self.sub = "user-123"
        self.email = "ryan@example.com"
        self.nonce = None
        self.override = {}
        self.sign_key = KEY
        self.token_requests = []

    def install(self, rsps):
        rsps.add(responses.GET, ISS + "/.well-known/openid-configuration", json={
            "issuer": ISS, "authorization_endpoint": ISS + "/authorize", "token_endpoint": ISS + "/token",
            "jwks_uri": ISS + "/jwks", "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        })
        rsps.add(responses.GET, ISS + "/jwks", json=jwks())
        rsps.add_callback(responses.POST, ISS + "/token", callback=self._token)

    def _token(self, req):
        self.token_requests.append(req)
        form = parse_qs(req.body)
        assert form["grant_type"] == ["authorization_code"] and form["code_verifier"][0]
        now = int(time.time())
        claims = {"iss": ISS, "sub": self.sub, "aud": "sv-client", "iat": now, "exp": now + 300, "nonce": self.nonce,
                  "email": self.email, "email_verified": True, **self.override}
        tok = jwt.encode(claims, self.sign_key, algorithm="RS256", headers={"kid": "k1"})
        return 200, {}, json.dumps({"access_token": "at", "token_type": "Bearer", "id_token": tok})


@pytest.fixture()
def env(monkeypatch):
    d = Path(tempfile.mkdtemp(prefix="sv-sso-"))
    monkeypatch.setattr(main, "store", Store(d))
    monkeypatch.setattr(main, "vault", crypto.Vault())
    monkeypatch.setattr(main, "oidc", sso.OIDC())
    main._sso_requests.clear()
    main._sso_tickets.clear()
    main._start_hits.clear()
    idp = IdP()
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        idp.install(rsps)
        with TestClient(main.app, base_url="https://sv.example.com") as c:
            r = c.post("/api/setup", json={"username": "ryan", "password": "pw-1234567890", "passphrase": PASS}, headers=H)
            assert r.status_code == 200, r.text
            c.cookies.clear()
            yield c, idp, {"Authorization": f"Bearer {r.json()['token']}"}


def add_provider(c, B, **kw):
    r = c.post("/api/sso/providers", json={"preset": "generic", "name": "Home IdP", "issuer": ISS, "client_id": "sv-client", "client_secret": "s3cret", "password": PW, **kw}, headers={**B, **H})
    assert r.status_code == 200, r.text
    return r.json()


def follow_to_idp(c, idp, resp):
    """Given the redirect to the IdP, return the callback URL the IdP would send the browser to."""
    assert resp.status_code in (302, 307), resp.text
    loc = urlparse(resp.headers["location"])
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == ISS + "/authorize"
    q = {k: v[0] for k, v in parse_qs(loc.query).items()}
    assert q["code_challenge_method"] == "S256" and q["redirect_uri"] == "https://sv.example.com/api/auth/sso/callback"
    idp.nonce = q["nonce"]
    return f"/api/auth/sso/callback?code=abc&state={q['state']}"


def confirm(c, page, action="allow"):
    """The app flow stops on a ScanVault confirmation page before any ticket is issued."""
    assert page.status_code == 200 and "Sign in to the ScanVault app?" in page.text, page.text
    assert "ticket" not in page.text
    cid = re.search(r'name="cid" value="([^"]+)"', page.text).group(1)
    r = c.post("/api/auth/sso/app-confirm", data={"cid": cid, "action": action}, follow_redirects=False)
    assert r.status_code == 303
    return r


def fragment_params(location):
    path, _, qs = location.partition("?")
    return path, {k: v[0] for k, v in parse_qs(qs).items()}


def link(c, idp, B, pid=None):
    pid = pid or c.get("/api/sso/config", headers=B).json()["providers"][0]["id"]
    r = c.post(f"/api/auth/sso/{pid}/link", json={"password": PW}, headers={**B, **H})
    assert r.status_code == 200, r.text
    # The browser goes to the IdP directly; emulate it by reading the URL we got back.
    loc = urlparse(r.json()["url"])
    q = {k: v[0] for k, v in parse_qs(loc.query).items()}
    idp.nonce = q["nonce"]
    r = c.get(f"/api/auth/sso/callback?code=abc&state={q['state']}", follow_redirects=False)
    assert r.headers["location"] == "/#/settings?sso=linked", r.headers["location"]
    return pid


def test_provider_admin_and_status(env):
    c, idp, B = env
    assert c.get("/api/status").json()["sso"] == []
    p = add_provider(c, B)
    assert "client_secret" not in p and p["has_secret"] and p["resolved_issuer"] == ISS
    assert c.get("/api/status").json()["sso"] == [{"id": p["id"], "name": "Home IdP", "preset": "generic"}]
    # secrets are write-only and kept on update
    p2 = c.put(f"/api/sso/providers/{p['id']}", json={"name": "Renamed", "client_secret": "", "password": PW}, headers={**B, **H}).json()
    assert p2["has_secret"] and p2["name"] == "Renamed"
    assert "s3cret" not in json.dumps(c.get("/api/sso/config", headers=B).json())
    # bad issuer is rejected before saving
    r = c.post("/api/sso/providers", json={"preset": "generic", "issuer": "http://evil.example.com", "client_id": "x", "password": PW}, headers={**B, **H})
    assert r.status_code == 400
    # presets fill the issuer from fields
    assert sso.resolve_issuer({"preset": "keycloak", "fields": {"base_url": "https://kc.example.com/", "realm": "home"}}) == "https://kc.example.com/realms/home"
    assert sso.resolve_issuer({"preset": "microsoft", "fields": {}}) == "https://login.microsoftonline.com/common/v2.0"
    assert sso.resolve_issuer({"preset": "synology", "fields": {"base_url": "https://nas:5001"}}) == "https://nas:5001/webman/sso"
    # admin endpoints need a session
    assert c.post("/api/sso/providers", json={}, headers=H).status_code == 401


def test_unlinked_identity_cannot_sign_in(env):
    c, idp, B = env
    p = add_provider(c, B)
    cb = follow_to_idp(c, idp, c.get(f"/api/auth/sso/{p['id']}/start", follow_redirects=False))
    r = c.get(cb, follow_redirects=False)
    path, q = fragment_params(r.headers["location"])
    assert path == "/#/" and "isn't linked" in q["sso_error"]


def test_link_then_sign_in_web(env):
    c, idp, B = env
    add_provider(c, B)
    pid = link(c, idp, B)
    ids = c.get("/api/sso/config", headers=B).json()["identities"]
    assert len(ids) == 1 and ids[0]["email"] == "ryan@example.com"
    # token request used HTTP basic client auth
    assert idp.token_requests[-1].headers["Authorization"].startswith("Basic ")

    # restart: vault locked, nobody signed in
    main.vault.lock()
    c.cookies.clear()
    cb = follow_to_idp(c, idp, c.get(f"/api/auth/sso/{pid}/start", follow_redirects=False))
    r = c.get(cb, follow_redirects=False)
    path, q = fragment_params(r.headers["location"])
    assert path == "/#/sso"
    r = c.post("/api/auth/sso/exchange", json={"ticket": q["ticket"]})
    assert r.status_code == 200, r.text
    assert r.json()["unlocked"] is False and "sv_session" in r.cookies
    st = c.get("/api/status").json()
    assert st["authenticated"] and st["username"] == "ryan" and not st["unlocked"]
    # SSO does not open the vault: the encryption key is still required
    assert c.get("/api/patients").status_code == 423
    assert c.post("/api/vault/unlock", json={"passphrase": PASS}, headers=H).json()["unlocked"]
    assert c.get("/api/patients").status_code == 200
    # tickets are single use
    assert c.post("/api/auth/sso/exchange", json={"ticket": q["ticket"]}).status_code == 400


def test_callback_binding_and_token_checks(env):
    c, idp, B = env
    add_provider(c, B)
    pid = link(c, idp, B)
    c.cookies.clear()

    # callback in a different browser (no binding cookie) is refused
    cb = follow_to_idp(c, idp, c.get(f"/api/auth/sso/{pid}/start", follow_redirects=False))
    c.cookies.clear()
    r = c.get(cb, follow_redirects=False)
    assert "different browser" in fragment_params(r.headers["location"])[1]["sso_error"]

    # replayed state
    cb = follow_to_idp(c, idp, c.get(f"/api/auth/sso/{pid}/start", follow_redirects=False))
    c.get(cb, follow_redirects=False)
    assert "expired" in fragment_params(c.get(cb, follow_redirects=False).headers["location"])[1]["sso_error"]

    for bad in ({"nonce": "wrong"}, {"aud": "someone-else"}, {"iss": "https://other.example.com"}, {"exp": int(time.time()) - 3600}):
        idp.override = bad
        cb = follow_to_idp(c, idp, c.get(f"/api/auth/sso/{pid}/start", follow_redirects=False))
        loc = c.get(cb, follow_redirects=False).headers["location"]
        assert "sso_error" in loc, (bad, loc)
    idp.override = {}

    # forged signature
    idp.sign_key = OTHER_KEY
    cb = follow_to_idp(c, idp, c.get(f"/api/auth/sso/{pid}/start", follow_redirects=False))
    assert "sso_error" in c.get(cb, follow_redirects=False).headers["location"]
    idp.sign_key = KEY

    # IdP-reported error
    cb = follow_to_idp(c, idp, c.get(f"/api/auth/sso/{pid}/start", follow_redirects=False))
    r = c.get(cb.replace("code=abc", "error=access_denied&error_description=User+cancelled"), follow_redirects=False)
    assert fragment_params(r.headers["location"])[1]["sso_error"] == "User cancelled"


def test_mobile_app_flow(env):
    c, idp, B = env
    add_provider(c, B)
    pid = link(c, idp, B)
    c.cookies.clear()
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

    assert c.get(f"/api/auth/sso/{pid}/start?app_redirect=https://evil.example.com/&code_challenge={challenge}", follow_redirects=False).status_code == 400
    assert c.get(f"/api/auth/sso/{pid}/start?app_redirect=scanvault://sso", follow_redirects=False).status_code == 400

    r = c.get(f"/api/auth/sso/{pid}/start?app_redirect=scanvault://sso&app_state=xyz&code_challenge={challenge}", follow_redirects=False)
    assert "sv_sso" not in r.cookies  # apps are bound by PKCE, not cookies
    cb = follow_to_idp(c, idp, r)
    r = confirm(c, c.get(cb, follow_redirects=False))
    loc = urlparse(r.headers["location"])
    assert loc.scheme == "scanvault" and loc.netloc == "sso"
    q = {k: v[0] for k, v in parse_qs(loc.query).items()}
    assert q["state"] == "xyz"
    assert c.post("/api/auth/sso/exchange", json={"ticket": q["ticket"], "code_verifier": "wrong" * 10}).status_code == 400
    # the failed attempt consumed the ticket; run again
    cb = follow_to_idp(c, idp, c.get(f"/api/auth/sso/{pid}/start?app_redirect=scanvault://sso&code_challenge={challenge}", follow_redirects=False))
    q = {k: v[0] for k, v in parse_qs(urlparse(confirm(c, c.get(cb, follow_redirects=False)).headers["location"]).query).items()}
    r = c.post("/api/auth/sso/exchange", json={"ticket": q["ticket"], "code_verifier": verifier})
    assert r.status_code == 200, r.text
    tok = r.json()["token"]
    c.cookies.clear()
    assert c.get("/api/status", headers={"Authorization": f"Bearer {tok}"}).json()["authenticated"]

    # app errors go back to the app too
    cb = follow_to_idp(c, idp, c.get(f"/api/auth/sso/{pid}/start?app_redirect=scanvault://sso&app_state=s1&code_challenge={challenge}", follow_redirects=False))
    r = c.get(cb.replace("code=abc", "error=access_denied"), follow_redirects=False)
    assert r.headers["location"].startswith("scanvault://sso?error=access_denied")


def test_password_login_can_be_turned_off_safely(env, monkeypatch):
    c, idp, B = env
    p = add_provider(c, B)
    # refused until this user has a linked identity
    assert c.put("/api/sso/settings", json={"local_login": False, "password": PW}, headers={**B, **H}).status_code == 400
    link(c, idp, B)
    assert c.put("/api/sso/settings", json={"local_login": False, "password": PW}, headers={**B, **H}).json()["local_login"] is False
    assert c.get("/api/status").json()["local_login"] is False
    r = c.post("/api/auth/login", json={"username": "ryan", "password": "pw-1234567890"})
    assert r.status_code == 403 and r.json()["code"] == "local_login_disabled"
    # break-glass environment variable
    monkeypatch.setattr(main, "FORCE_LOCAL_LOGIN", True)
    assert c.post("/api/auth/login", json={"username": "ryan", "password": "pw-1234567890"}).status_code == 200
    monkeypatch.setattr(main, "FORCE_LOCAL_LOGIN", False)
    # removing the last usable SSO link turns password sign-in back on
    iid = c.get("/api/sso/config", headers=B).json()["identities"][0]["id"]
    assert c.delete(f"/api/sso/identities/{iid}", headers={**B, **H}).json()["local_login"] is True
    link(c, idp, B)
    c.put("/api/sso/settings", json={"local_login": False, "password": PW}, headers={**B, **H})
    assert c.delete(f"/api/sso/providers/{p['id']}", headers={**B, **H}).json()["local_login"] is True


def test_identity_linked_to_one_account_only(env):
    c, idp, B = env
    add_provider(c, B)
    link(c, idp, B)
    # a second ScanVault user cannot claim the same IdP account
    uid = crypto.random_id()
    main.store.conn().execute("INSERT INTO users(id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)", (uid, "sam", crypto.hash_password("pw-0987654321"), "admin", time.time()))
    tok, _ = main.new_session(uid)
    B2 = {"Authorization": f"Bearer {tok}"}
    pid = c.get("/api/sso/config", headers=B2).json()["providers"][0]["id"]
    r = c.post(f"/api/auth/sso/{pid}/link", json={"password": "pw-0987654321"}, headers={**B2, **H})
    q = {k: v[0] for k, v in parse_qs(urlparse(r.json()["url"]).query).items()}
    idp.nonce = q["nonce"]
    loc = c.get(f"/api/auth/sso/callback?code=abc&state={q['state']}", follow_redirects=False).headers["location"]
    assert "already linked" in fragment_params(loc)[1]["sso_error"]


def test_env_provider(env, monkeypatch):
    c, idp, B = env
    monkeypatch.setenv("SCANVAULT_OIDC_ISSUER", ISS)
    monkeypatch.setenv("SCANVAULT_OIDC_CLIENT_ID", "sv-client")
    monkeypatch.setenv("SCANVAULT_OIDC_CLIENT_SECRET", "s3cret")
    monkeypatch.setenv("SCANVAULT_OIDC_PRESET", "authentik")
    st = c.get("/api/status").json()
    assert st["sso"] == [{"id": "env", "name": "Authentik", "preset": "authentik"}]
    assert c.put("/api/sso/providers/env", json={"name": "x", "password": PW}, headers={**B, **H}).status_code == 409
    link(c, idp, B)


def test_microsoft_multi_tenant_issuer(monkeypatch):
    o = sso.OIDC()
    tpl = "https://login.microsoftonline.com/{tenantid}/v2.0"
    base = "https://login.microsoftonline.com/common/v2.0"
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, base + "/.well-known/openid-configuration", json={
            "issuer": tpl, "authorization_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "token_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/token", "jwks_uri": "https://login.microsoftonline.com/common/discovery/v2.0/keys",
            "id_token_signing_alg_values_supported": ["RS256"]})
        rsps.add(responses.GET, "https://login.microsoftonline.com/common/discovery/v2.0/keys", json=jwks())
        p = {"preset": "microsoft", "fields": {"tenant": "common"}, "client_id": "app"}
        now = int(time.time())
        tid = "9188040d-6c67-4c5b-b112-36a304b66dad"
        good = jwt.encode({"iss": f"https://login.microsoftonline.com/{tid}/v2.0", "tid": tid, "sub": "s", "aud": "app", "iat": now, "exp": now + 60, "nonce": "n"}, KEY, "RS256", headers={"kid": "k1"})
        assert o.validate_id_token(p, good, "n")["tid"] == tid
        bad = jwt.encode({"iss": "https://login.microsoftonline.com/other/v2.0", "tid": tid, "sub": "s", "aud": "app", "iat": now, "exp": now + 60, "nonce": "n"}, KEY, "RS256", headers={"kid": "k1"})
        with pytest.raises(sso.SSOError):
            o.validate_id_token(p, bad, "n")


def test_app_confirmation_can_be_cancelled(env):
    c, idp, B = env
    add_provider(c, B)
    pid = link(c, idp, B)
    challenge = "a" * 43
    cb = follow_to_idp(c, idp, c.get(f"/api/auth/sso/{pid}/start?app_redirect=scanvault://sso&app_state=s&code_challenge={challenge}", follow_redirects=False))
    r = confirm(c, c.get(cb, follow_redirects=False), action="cancel")
    assert r.headers["location"] == "scanvault://sso?error=cancelled&state=s"
    # the confirmation id is single use
    assert c.post("/api/auth/sso/app-confirm", data={"cid": "nope", "action": "allow"}).status_code == 400


def test_reauth_required_and_sessions_revoked(env):
    c, idp, B = env
    BH = {**B, **H}
    # a session alone can't add a provider, link an account or turn password sign-in off
    assert c.post("/api/sso/providers", json={"preset": "generic", "issuer": ISS, "client_id": "sv-client"}, headers=BH).json()["code"] == "reauth_required"
    assert c.post("/api/sso/providers", json={"preset": "generic", "issuer": ISS, "client_id": "sv-client", "password": "wrong"}, headers=BH).status_code == 403
    p = add_provider(c, B)
    assert c.post(f"/api/auth/sso/{p['id']}/link", json={}, headers=BH).json()["code"] == "reauth_required"
    assert c.put(f"/api/sso/providers/{p['id']}", json={"name": "x"}, headers=BH).status_code == 403
    link(c, idp, B)
    assert c.put("/api/sso/settings", json={"local_login": False}, headers=BH).json()["code"] == "reauth_required"

    # sign in with SSO: that fresh session may make changes without the password
    c.cookies.clear()
    cb = follow_to_idp(c, idp, c.get(f"/api/auth/sso/{p['id']}/start", follow_redirects=False))
    ticket = fragment_params(c.get(cb, follow_redirects=False).headers["location"])[1]["ticket"]
    S = {"Authorization": "Bearer " + c.post("/api/auth/sso/exchange", json={"ticket": ticket}).json()["token"]}
    c.cookies.clear()
    assert c.get("/api/sso/config", headers=S).json()["reauth_fresh"] is True
    assert c.put(f"/api/sso/providers/{p['id']}", json={"name": "Fresh"}, headers={**S, **H}).status_code == 200
    # ...but not once it is older than 10 minutes
    main.store.conn().execute("UPDATE sessions SET created_at=created_at-3600 WHERE identity_id IS NOT NULL")
    assert c.put(f"/api/sso/providers/{p['id']}", json={"name": "Old"}, headers={**S, **H}).status_code == 403

    # unlinking ends sessions that the link created; the password session survives
    iid = c.get("/api/sso/config", headers=B).json()["identities"][0]["id"]
    assert c.delete(f"/api/sso/identities/{iid}", headers=BH).status_code == 200
    assert c.get("/api/status", headers=S).json()["authenticated"] is False
    assert c.get("/api/status", headers=B).json()["authenticated"] is True

    # removing a provider does too
    link(c, idp, B)
    cb = follow_to_idp(c, idp, c.get(f"/api/auth/sso/{p['id']}/start", follow_redirects=False))
    ticket = fragment_params(c.get(cb, follow_redirects=False).headers["location"])[1]["ticket"]
    S = {"Authorization": "Bearer " + c.post("/api/auth/sso/exchange", json={"ticket": ticket}).json()["token"]}
    c.cookies.clear()
    assert c.get("/api/status", headers=S).json()["authenticated"]
    c.delete(f"/api/sso/providers/{p['id']}", headers=BH)
    assert c.get("/api/status", headers=S).json()["authenticated"] is False


def test_identity_signs_in_only_through_its_provider(env):
    c, idp, B = env
    a = add_provider(c, B, name="A")
    b = add_provider(c, B, name="B", client_id="sv-client")  # same issuer, separate entry
    link(c, idp, B, a["id"])
    c.cookies.clear()
    cb = follow_to_idp(c, idp, c.get(f"/api/auth/sso/{b['id']}/start", follow_redirects=False))
    assert "isn't linked" in fragment_params(c.get(cb, follow_redirects=False).headers["location"])[1]["sso_error"]
    cb = follow_to_idp(c, idp, c.get(f"/api/auth/sso/{a['id']}/start", follow_redirects=False))
    assert fragment_params(c.get(cb, follow_redirects=False).headers["location"])[0] == "/#/sso"


def test_response_iss_must_match(env):
    c, idp, B = env
    p = add_provider(c, B)
    link(c, idp, B)
    c.cookies.clear()
    cb = follow_to_idp(c, idp, c.get(f"/api/auth/sso/{p['id']}/start", follow_redirects=False))
    loc = c.get(cb + "&iss=https%3A%2F%2Fevil.example.com", follow_redirects=False).headers["location"]
    assert "different provider" in fragment_params(loc)[1]["sso_error"]


@pytest.mark.parametrize("bad", [
    {"issuer": "https://login.microsoftonline.com/{tenantid}/v2.0"},   # template from a non-Microsoft host
    {"authorization_endpoint": "javascript:alert(document.cookie)"},
    {"token_endpoint": "http://10.0.0.5/token"},
    {"jwks_uri": "file:///etc/passwd"},
])
def test_discovery_document_is_validated(bad):
    o = sso.OIDC()
    iss = "https://bad.example.com"
    doc = {"issuer": iss, "authorization_endpoint": iss + "/a", "token_endpoint": iss + "/t", "jwks_uri": iss + "/k", **bad}
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, iss + "/.well-known/openid-configuration", json=doc)
        with pytest.raises(sso.SSOError):
            o.discover(iss)


def test_tenant_template_only_for_microsoft_preset():
    o = sso.OIDC()
    tpl = "https://login.microsoftonline.com/{tenantid}/v2.0"
    base = "https://login.microsoftonline.com/common/v2.0"
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, base + "/.well-known/openid-configuration", json={
            "issuer": tpl, "authorization_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "token_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/token", "jwks_uri": "https://login.microsoftonline.com/common/discovery/v2.0/keys"})
        rsps.add(responses.GET, "https://login.microsoftonline.com/common/discovery/v2.0/keys", json=jwks())
        now = int(time.time())
        tok = jwt.encode({"iss": "https://accounts.google.com", "tid": "x/../../accounts.google.com", "sub": "s", "aud": "app", "iat": now, "exp": now + 60, "nonce": "n"}, KEY, "RS256", headers={"kid": "k1"})
        with pytest.raises(sso.SSOError):
            o.validate_id_token({"preset": "microsoft", "fields": {"tenant": "common"}, "client_id": "app"}, tok, "n")
        tid = "9188040d-6c67-4c5b-b112-36a304b66dad"
        ok = jwt.encode({"iss": f"https://login.microsoftonline.com/{tid}/v2.0", "tid": tid, "sub": "s", "aud": "app", "iat": now, "exp": now + 60, "nonce": "n"}, KEY, "RS256", headers={"kid": "k1"})
        with pytest.raises(sso.SSOError):  # same issuer configured as a generic provider
            o.validate_id_token({"preset": "generic", "issuer": base, "client_id": "app"}, ok, "n")


def test_app_redirect_allow_list(monkeypatch):
    monkeypatch.setenv("SCANVAULT_SSO_APP_REDIRECTS", "scanvault://,https://app.example.com/sso")
    ok = ["scanvault://sso", "https://app.example.com/sso", "https://app.example.com/sso/done"]
    bad = ["https://app.example.com.evil.net/sso", "https://app.example.com/ssox", "http://app.example.com/sso",
           "https://user@app.example.com/sso", "javascript:alert(1)", "intent://x", ""]
    assert all(sso.app_redirect_allowed(u) for u in ok)
    assert not any(sso.app_redirect_allowed(u) for u in bad)
