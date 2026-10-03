"""Shared browser harness for social platforms.

The hard part of this tool is not parsing a profile — it is getting a
request out of a machine that looks like a person. InstaCloak already
solved that: a persistent stealth browser profile per target, humanized
delays and scrolls, and every fetch executed *inside* the page so the
request carries the browser's TLS fingerprint and cookies.

Rather than fork that per platform, the harness owns the session and the
pacing and hands a live `page` to a platform adapter, which fills in the
normalized schema. InstaCloak's own engine is registered as an adapter
too, so it goes through exactly the same lifecycle as the newer ones.
"""

from __future__ import annotations

import contextlib
import re
import sys
import threading
import time

from . import registry, schema

# One stealth browser run at a time. The InstaCloak modules this harness
# borrows write to process-wide UI hooks, so two concurrent collections
# would interleave their progress lines and corrupt each other's reports.
BROWSER_LOCK = threading.Lock()


class ProgressSink:
    """Collects the engines' progress lines for the dashboard."""

    def __init__(self):
        self.lines = []

    def add(self, message):
        line = re.sub(r"\s+", " ", str(message)).strip()
        if line:
            self.lines.append(line)


@contextlib.contextmanager
def bridge_progress(sink):
    """Route InstaCloak's terminal UI into ``sink`` for the duration.

    The modules bind ``say``/``say_parts``/``section`` into their own
    namespaces at import time (``from .ui import say``), so patching
    ``instacloak.ui`` alone would not reach the call sites — every loaded
    module's binding has to be redirected individually.
    """

    def say(msg, *styles, **kwargs):
        sink.add(re.sub(r"\[/?[^\]]+\]", "", str(msg)))

    def say_parts(*parts, **kwargs):
        text = "".join(str(p[0]) if isinstance(p, tuple) else str(p) for p in parts)
        sink.add(re.sub(r"\[/?[^\]]+\]", "", text))

    def section(n, total, msg, **kwargs):
        sink.add(f"[{n}/{total}] " + re.sub(r"\[/?[^\]]+\]", "", str(msg)))

    hooks = {"say": say, "say_parts": say_parts, "section": section}
    saved = []
    for name, module in list(sys.modules.items()):
        if name == "instacloak" or name.startswith("instacloak."):
            for attr, hook in hooks.items():
                if getattr(module, attr, None) is not None:
                    saved.append((module, attr, getattr(module, attr)))
                    setattr(module, attr, hook)
    try:
        yield
    finally:
        for module, attr, original in saved:
            setattr(module, attr, original)


def _cfg_for(options: dict) -> dict:
    """Build an InstaCloak-shaped config for the shared session.

    Reusing instacloak.config keeps one set of knobs (headless, proxy,
    geoip, delays, profiles_dir) instead of a second, drifting copy.
    """
    from instacloak import config as ic_config

    cfg = ic_config.load_config(None)
    cfg["headless"] = bool(options.get("headless"))
    cfg["deep"] = bool(options.get("deep"))
    cfg["download_media"] = bool(options.get("media"))
    if options.get("proxy_url"):
        cfg["proxy_enabled"] = True
        cfg["proxy_url"] = options["proxy_url"]
    if options.get("burner_username") and options.get("burner_password"):
        cfg["login_enabled"] = True
        cfg["login_username"] = options["burner_username"]
        cfg["login_password"] = options["burner_password"]
    return cfg


def collect(platform_key: str, handle: str, options: dict | None = None,
            progress: ProgressSink | None = None) -> dict:
    """Run one platform collection and return the normalized result.

    Never raises for an expected failure: a missing platform, a dead
    session or a login wall all come back as a result dict with notes, so
    the dashboard always has something to render. ``progress`` collects the
    engines' own step-by-step output for the dashboard's run log.
    """
    options = options or {}
    progress = progress if progress is not None else ProgressSink()
    handle = (handle or "").strip().lstrip("@")
    result = schema.new_result(platform_key, handle)

    platform = registry.get(platform_key)
    if platform is None:
        result["error"] = f"unknown platform: {platform_key}"
        return result
    if not handle:
        result["error"] = "handle required"
        return result

    result["url"] = platform.profile_url(handle)
    result["capabilities"] = list(platform.capabilities)

    from instacloak.session import open_session, safe_dir_name

    cfg = _cfg_for(options)
    started = time.time()
    ctx = None
    try:
        with BROWSER_LOCK, bridge_progress(progress):
            ctx = open_session(cfg, safe_dir_name(f"{platform.key}-{handle}"))
            page = ctx.new_page()

            wants_login = bool(cfg.get("login_enabled") and cfg.get("login_username"))
            if wants_login and platform.login != "none":
                result["logged_in"] = _login(page, cfg, platform, result)
            elif wants_login:
                schema.add_note(result, f"{platform.label} has no burner-login flow; "
                                        "collected logged-out only")

            platform.collect(page, cfg, handle, result)
    except SystemExit as exc:
        # open_session exits when cloakbrowser is missing.
        result["error"] = (f"stealth browser unavailable (exit {exc.code}). "
                           "Install cloakbrowser: pip install cloakbrowser")
    except Exception as exc:
        result["error"] = f"{platform.label} collection failed: {_clean(exc)}"
    finally:
        if ctx is not None:
            try:
                ctx.close()
            except Exception:
                pass

    result["elapsed"] = round(time.time() - started, 1)
    if not result.get("error") and not result["found"] and not result["notes"]:
        schema.add_note(result, "nothing retrieved and nothing reported why")
    return result


def _login(page, cfg, platform, result) -> bool:
    """Run a platform's burner login, reporting honestly when it cannot."""
    try:
        if platform.login == "instacloak":
            from instacloak.auth import ensure_login
            return bool(ensure_login(page, cfg, result["handle"]))
        if platform.login == "x":
            from .platforms.x import ensure_login as x_login
            return bool(x_login(page, cfg, result))
    except Exception as exc:
        schema.add_note(result, f"burner login failed: {_clean(exc)}")
    return False


def _clean(exc) -> str:
    """One-line exception text for a note — no tracebacks into the UI."""
    return " ".join(str(exc).split())[:200]