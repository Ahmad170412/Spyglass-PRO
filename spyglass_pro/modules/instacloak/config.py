"""Config loading (config.toml + env overrides) and the burner-login writer."""

from __future__ import annotations

import os
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - py3.11+ has tomllib
    tomllib = None

from .ui import say

DEFAULT_CONFIG = {
    "output_dir": "output",
    "profiles_dir": "profiles",
    "headless": False,
    "geoip": True,
    "human_preset": "default",
    "min_delay": 1.2,
    "max_delay": 3.5,
    "max_posts": 12,
    "max_followers": 200,
    "max_following": 200,
    "download_media": True,
    "download_videos": False,
    "attempt_followers": True,
    "deep": False,
    "login_enabled": False,
    "login_username": "",
    "login_password": "",
    "proxy_enabled": False,
    "proxy_url": "",
}


def load_config(path: str | None) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    candidates = [path] if path else ["config.toml"]
    found = next((p for p in candidates if p and Path(p).is_file()), None)
    if found and tomllib is not None:
        try:
            with open(found, "rb") as fh:
                data = tomllib.load(fh)
            for k, v in (data.get("instacloak") or {}).items():
                if k in cfg:
                    cfg[k] = v
            proxy = data.get("proxy") or {}
            if proxy.get("enabled"):
                cfg["proxy_enabled"] = True
                cfg["proxy_url"] = proxy.get("url", "")
            login = data.get("login") or {}
            if login:
                cfg["login_enabled"] = bool(login.get("enabled", cfg["login_enabled"]))
                if login.get("username"):
                    cfg["login_username"] = login["username"]
                if login.get("password"):
                    cfg["login_password"] = login["password"]
        except Exception as exc:
            say(f"  warning: couldn't read config ({exc}); using defaults", "yellow")
        # OPSEC: config.toml can hold burner credentials / proxy user:pass --
        # warn if it is readable by other users on this machine.
        if os.name == "posix":
            file_has_creds = bool(cfg["login_password"]) or "@" in cfg["proxy_url"]
            if file_has_creds:
                try:
                    mode = os.stat(found).st_mode & 0o777
                    if mode & 0o077:
                        say(f"  warning: {found} holds credentials but is readable by "
                            f"others (mode {oct(mode)}). Run: chmod 600 {found}", "yellow")
                except OSError:
                    pass
    elif found:
        say("  warning: tomllib unavailable (need Python 3.11+); using defaults", "yellow")

    env = os.environ
    if env.get("INSTACLOAK_PROXY"):
        cfg["proxy_enabled"], cfg["proxy_url"] = True, env["INSTACLOAK_PROXY"]
    if env.get("INSTACLOAK_OUTPUT_DIR"):
        cfg["output_dir"] = env["INSTACLOAK_OUTPUT_DIR"]
    if env.get("INSTACLOAK_PROFILES_DIR"):
        cfg["profiles_dir"] = env["INSTACLOAK_PROFILES_DIR"]
    if env.get("INSTACLOAK_HEADLESS") in ("1", "true", "yes"):
        cfg["headless"] = True
    if env.get("INSTACLOAK_LOGIN") in ("1", "true", "yes"):
        cfg["login_enabled"] = True
    if env.get("INSTACLOAK_LOGIN_USERNAME"):
        cfg["login_username"] = env["INSTACLOAK_LOGIN_USERNAME"]
    if env.get("INSTACLOAK_LOGIN_PASSWORD"):
        cfg["login_password"] = env["INSTACLOAK_LOGIN_PASSWORD"]
    return cfg


def _toml_escape(s: str) -> str:
    return (s.replace("\\", "\\\\").replace('"', '\\"')
             .replace("\n", "\\n").replace("\t", "\\t"))


def save_login_config(path_str: str, user: str, pw: str, enabled: bool = True) -> str:
    """Write the [login] section into config.toml, preserving other sections."""
    path = Path(path_str)
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    block = (f"[login]\nenabled = {str(enabled).lower()}\n"
             f'username = "{_toml_escape(user)}"\n'
             f'password = "{_toml_escape(pw)}"\n')
    lines = text.splitlines(keepends=True)
    replaced = False
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.lstrip().startswith("[login]"):
            out.append(block)
            replaced = True
            i += 1
            while i < len(lines) and not lines[i].lstrip().startswith("["):
                i += 1
            continue
        out.append(line)
        i += 1
    if not replaced:
        if out and not out[-1].endswith("\n"):
            out.append("\n")
        out.append("\n" + block)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(out), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return str(path)
