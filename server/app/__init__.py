"""MedVault server package.

MedVault used to be called ScanVault. Settings read MEDVAULT_* environment
variables; the old SCANVAULT_* names still work as aliases so existing
installs keep running unchanged. A MEDVAULT_* variable wins if both are set.
This runs before any module reads the environment.
"""
import os

LEGACY_ENV_PREFIX = "SCANVAULT_"
ENV_PREFIX = "MEDVAULT_"


def apply_legacy_env(environ=os.environ) -> list[str]:
    """Copy each SCANVAULT_X to MEDVAULT_X unless MEDVAULT_X is set. Returns the
    legacy names that were used, for a one-time deprecation notice."""
    used = []
    for key in sorted(k for k in environ if k.startswith(LEGACY_ENV_PREFIX)):
        new = ENV_PREFIX + key[len(LEGACY_ENV_PREFIX):]
        if not environ.get(new):
            environ[new] = environ[key]
        used.append(key)
    return used


LEGACY_ENV_USED = apply_legacy_env()
