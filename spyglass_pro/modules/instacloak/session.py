"""Stealth session launch: one persistent profile per target (or a shared burner)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from .ui import say, say_parts

try:
    from cloakbrowser import launch_persistent_context
except ImportError:
    launch_persistent_context = None


def safe_dir_name(name: str) -> str:
    """Turn a target username into a safe filesystem component.

    Usernames come from CLI args / prompts and flow into profile and output
    directories; a crafted value like `../x` must never escape the profiles/
    or output/ roots. Real Instagram usernames pass through unchanged.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip(".")
    return cleaned or "target"


def open_session(cfg: dict, username: str):
    """Launch a persistent (footprint-building) stealth browser context."""
    if launch_persistent_context is None:
        say("  error: cloakbrowser not installed. Run: pip install -r requirements.txt", "red")
        sys.exit(1)

    if (cfg.get("login_enabled") and cfg.get("login_username")
            and cfg.get("login_password")):
        # Burner sessions share one profile so the login persists across targets
        profile_dir = str(Path(cfg["profiles_dir"]) / "login")
        say("  burner profile (shared, logged-in mode)", "magenta")
    else:
        # Defense in depth: never let the username escape profiles_dir
        profile_dir = str(Path(cfg["profiles_dir"]) / safe_dir_name(username))
    Path(profile_dir).mkdir(parents=True, exist_ok=True)

    kwargs = dict(
        headless=bool(cfg["headless"]),
        humanize=True,
        proxy=cfg["proxy_url"] if cfg["proxy_enabled"] else None,
        geoip=bool(cfg["geoip"]),
    )
    if cfg.get("human_preset"):
        kwargs["human_preset"] = cfg["human_preset"]

    say_parts("  profile: ", (profile_dir, "dim"))
    if cfg["proxy_enabled"]:
        say_parts("  proxy:   ", (cfg["proxy_url"].split("@")[-1], "dim"))
    say("  launching stealth Chromium...", "dim")
    try:
        return launch_persistent_context(profile_dir, **kwargs)
    except ImportError as geoip_err:  # missing cloakbrowser[geoip] extra
        say("  geoip extra not installed -- skipping timezone/locale matching "
            f"({geoip_err}). Install 'cloakbrowser[geoip]' to enable it.", "yellow")
        kwargs.pop("geoip", None)
        kwargs.pop("human_preset", None)
        try:
            return launch_persistent_context(profile_dir, **kwargs)
        except Exception as retry_err:
            say(f"  error: could not launch CloakBrowser: {retry_err}", "red")
            sys.exit(1)
    except Exception as first_err:
        say(f"  launch failed ({first_err.__class__.__name__}); retrying with minimal options", "yellow")
        minimal = dict(headless=bool(cfg["headless"]), humanize=True)
        if cfg["proxy_enabled"]:
            minimal["proxy"] = cfg["proxy_url"]
        try:
            return launch_persistent_context(profile_dir, **minimal)
        except Exception as second_err:
            say(f"  error: could not launch CloakBrowser: {second_err}", "red")
            say("  hint: run `cloakbrowser login` or set CLOAKBROWSER_LICENSE_KEY, "
                "and ensure the ~200MB binary can download on first launch.", "yellow")
            sys.exit(1)
