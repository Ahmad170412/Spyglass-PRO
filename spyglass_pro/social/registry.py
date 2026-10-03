"""Platform registry — the list the rest of the app iterates.

A platform declares its identity, what it can retrieve, and one `collect`
callable. Nothing else in Spyglass-Pro needs to know a platform exists:
the API, the dashboard panel and the report all read this registry, so
adding a platform is a new module plus a `@register` line and no edits to
the request plumbing or the renderer.

Adapters import from here; this module never imports them. Registration is
lazy (see :func:`load_all`) to keep the engines out of the import path
until a scan is actually requested.
"""

from __future__ import annotations

import importlib
import threading

# platform key -> Platform
_REGISTRY: dict[str, "Platform"] = {}
_LOADED = False
_LOCK = threading.Lock()


class Platform:
    """One social platform the harness knows how to collect.

    key      registry id used by the API and the dashboard ("x")
    label    human name ("X")
    url      template taking the handle -> canonical profile URL
    capabilities
             what this platform can actually return. The dashboard uses
             this to tell the operator what to expect instead of letting
             them assume a field is missing because collection failed.
    login    whether a burner login can unlock more than the logged-out
             path, and whether the harness should offer it
    collect  async-free callable(page, cfg, handle, result) -> None that
             fills `result` in place using the normalized schema
    """

    def __init__(self, key, label, url, capabilities=(), login="none",
                 collect=None, homepage=""):
        self.key = key
        self.label = label
        self.url_template = url
        self.capabilities = tuple(capabilities)
        self.login = login
        self.collect = collect
        self.homepage = homepage

    def profile_url(self, handle: str) -> str:
        try:
            return self.url_template.format(handle=handle)
        except Exception:
            return self.url_template

    def to_dict(self) -> dict:
        """Public description for /api/social/platforms."""
        return {
            "key": self.key,
            "label": self.label,
            "homepage": self.homepage,
            "login": self.login,
            "capabilities": list(self.capabilities),
        }


def register(platform: Platform) -> Platform:
    _REGISTRY[platform.key] = platform
    return platform


def load_all() -> dict:
    """Import every bundled adapter once. Import failures degrade to absent."""
    global _LOADED
    with _LOCK:
        if _LOADED:
            return _REGISTRY
        for module in ("instagram", "x"):
            try:
                importlib.import_module(f"{__package__}.platforms.{module}")
            except Exception:
                # A broken adapter must not take the others down with it.
                continue
        _LOADED = True
    return _REGISTRY


def get(key: str) -> Platform | None:
    load_all()
    return _REGISTRY.get((key or "").strip().lower())


def all_platforms() -> list[Platform]:
    load_all()
    return [_REGISTRY[key] for key in sorted(_REGISTRY)]


def describe() -> list[dict]:
    return [platform.to_dict() for platform in all_platforms()]