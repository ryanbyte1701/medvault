"""ScanVault -> MedVault rename: old names keep working."""
from app import apply_legacy_env


def test_legacy_env_copied_when_new_unset():
    env = {"SCANVAULT_DATA": "/old", "SCANVAULT_PUBLIC_URL": "https://a", "MEDVAULT_PUBLIC_URL": "https://b", "OTHER": "x"}
    used = apply_legacy_env(env)
    assert env["MEDVAULT_DATA"] == "/old"
    assert env["MEDVAULT_PUBLIC_URL"] == "https://b"  # the new name wins
    assert used == ["SCANVAULT_DATA", "SCANVAULT_PUBLIC_URL"]


def test_legacy_env_fills_empty_new_value():
    # docker compose turns an unset ${MEDVAULT_X:-} into an empty string
    env = {"SCANVAULT_PUBLIC_URL": "https://a", "MEDVAULT_PUBLIC_URL": ""}
    apply_legacy_env(env)
    assert env["MEDVAULT_PUBLIC_URL"] == "https://a"


def test_old_scanvault_sso_redirect_still_allowed(monkeypatch):
    from app import sso
    monkeypatch.delenv("MEDVAULT_SSO_APP_REDIRECTS", raising=False)
    assert sso.app_redirect_allowed("medvault://sso")
    assert sso.app_redirect_allowed("scanvault://sso")


class _Req:
    def __init__(self, headers):
        self.headers = {k.lower(): v for k, v in headers.items()}


def test_old_and_new_browser_header_accepted():
    from app import main
    assert main._has_app_header(_Req({"X-MedVault": "1"}))
    assert main._has_app_header(_Req({"X-ScanVault": "1"}))
    assert not main._has_app_header(_Req({}))


def test_old_android_user_agent_still_counts_as_android():
    from app import main
    assert main._client_kind(_Req({"user-agent": "ScanVault-Android/0.5.0"}), None) == "android"
    assert main._client_kind(_Req({"user-agent": "MedVault-Android/0.5.0"}), None) == "android"
