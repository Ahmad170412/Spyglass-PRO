"""Local configuration and API key management."""

import json
import os
import sys
from pathlib import Path

CONFIG_DIR = Path.home() / ".lens-extender"
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULTS = {
    "shodan_api_key": "",
    "nvd_api_key": "",
    "greynoise_api_key": "",
    "abuseipdb_api_key": "",
    "virustotal_api_key": "",
    "censys_api_id": "",
    "censys_api_key": "",
    "proxy": "",
    "socks_proxy": "",
}


def _tighten() -> None:
    if sys.platform == "win32":
        # Windows doesn't support POSIX chmod; FILE_ATTRIBUTE_NORMAL (0x80) is
        # a no-op for access control.  Full ACL lockdown would require ctypes
        # calls to SetNamedSecurityInfo, which needs admin privileges.
        return
    try:
        CONFIG_FILE.chmod(0o600)
    except OSError:
        pass


def load() -> dict:
    config = dict(DEFAULTS)
    if CONFIG_FILE.exists():
        try:
            stored = json.loads(CONFIG_FILE.read_text())
            config.update({k: v for k, v in stored.items() if k in DEFAULTS})
        except (json.JSONDecodeError, OSError):
            pass
    # Environment variable overrides — fill in values not already set via config file.
    env_map = {
        "SHODAN_API_KEY": "shodan_api_key",
        "NVD_API_KEY": "nvd_api_key",
        "GREYNOISE_API_KEY": "greynoise_api_key",
        "ABUSEIPDB_API_KEY": "abuseipdb_api_key",
        "VIRUSTOTAL_API_KEY": "virustotal_api_key",
        "CENSYS_API_ID": "censys_api_id",
        "CENSYS_API_KEY": "censys_api_key",
        "LENS_PROXY": "proxy",
        "LENS_SOCKS_PROXY": "socks_proxy",
        "ALL_PROXY": "socks_proxy",
    }
    for env_key, config_key in env_map.items():
        val = os.environ.get(env_key, "")
        if val and not config.get(config_key):
            config[config_key] = val
    _tighten()
    return config


def save(config: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    fd = os.open(CONFIG_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(config, indent=2))
    _tighten()


def update(key: str, value) -> None:
    config = load()
    config[key] = value
    save(config)
