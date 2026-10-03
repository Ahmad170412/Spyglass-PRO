"""In-page HTTP for social adapters.

InstaCloak's ``fetch.fetch_text`` sends an implicit **GET** — it was only
ever used against Instagram's GET-only endpoints, and adding a method
parameter there would fork the vendored copy from upstream. This module
keeps the same principle (requests execute *inside* the stealth browser, so
they carry its TLS fingerprint and cookies) while supporting the verbs
other platforms need.

Anything that changes how a request leaves the machine belongs here, not in
``spyglass_pro/modules/``.
"""

from __future__ import annotations

import json as _json

# One in-page fetch implementation for every verb. `credentials: include`
# sends the session's cookies; the AbortController keeps a hung request
# from pinning a browser worker for the whole job timeout.
_JS = """async (arg) => {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), arg.timeout_ms);
    try {
        const r = await fetch(arg.url, {
            method: arg.method,
            headers: arg.headers || {},
            credentials: 'include',
            signal: ctl.signal
        });
        return {status: r.status, text: await r.text()};
    } catch (e) {
        return {status: 0, text: String(e)};
    } finally {
        clearTimeout(timer);
    }
}"""

DEFAULT_TIMEOUT_MS = 30000


def _request(page, url, headers=None, method="GET", timeout_ms=DEFAULT_TIMEOUT_MS):
    try:
        result = page.evaluate(_JS, {
            "url": url,
            "headers": headers or {},
            "method": method,
            "timeout_ms": timeout_ms,
        })
    except Exception:
        return None
    if not isinstance(result, dict):
        return None
    status = result.get("status") or 0
    if 200 <= status < 300:
        return result.get("text")
    return None


def get_text(page, url, headers=None, timeout_ms=DEFAULT_TIMEOUT_MS):
    return _request(page, url, headers, "GET", timeout_ms)


def get_json(page, url, headers=None, timeout_ms=DEFAULT_TIMEOUT_MS):
    return _to_json(get_text(page, url, headers, timeout_ms))


def post_json(page, url, headers=None, timeout_ms=DEFAULT_TIMEOUT_MS):
    """POST and parse JSON. X's guest-token endpoint is POST-only."""
    return _to_json(_request(page, url, headers, "POST", timeout_ms))


def _to_json(text):
    if not text:
        return None
    try:
        return _json.loads(text)
    except Exception:
        return None