"""In-page HTTP for social adapters.

Every request executes *inside* the stealth browser, so it carries that
browser's TLS fingerprint and cookies rather than looking like a scraper.

Two transports, tried in order:

1. in-page ``fetch`` — shares the session exactly, but is subject to CORS,
   so the page must already be on the target origin;
2. Playwright's ``page.request`` — not CORS-bound and shares cookies, used
   as the fallback when the in-page call fails.

InstaCloak's ``fetch.py`` only ever issued implicit **GET** requests.
Rather than fork that vendored copy, the method is a parameter here, so a
platform whose endpoint needs another verb does not need a fork.

Anything that changes how a request leaves the machine belongs in this
module, not in ``spyglass_pro/modules/``.
"""

from __future__ import annotations

import json as _json

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
# Playwright's timeout is in seconds.
_FALLBACK_TIMEOUT_S = DEFAULT_TIMEOUT_MS / 1000


def _in_page(page, url, headers, method, timeout_ms):
    try:
        result = page.evaluate(_JS, {
            "url": url,
            "headers": headers or {},
            "method": method,
            "timeout_ms": timeout_ms,
        })
    except Exception:
        return None
    if isinstance(result, dict):
        status = result.get("status") or 0
        if 200 <= status < 300:
            return result.get("text")
    return None


def _via_request_api(page, url, headers, method, timeout_ms):
    """Fallback transport: same cookies, no CORS, but not same-origin TLS."""
    try:
        request = getattr(page, "request", None)
        if request is None:
            return None
        response = request.fetch(
            url, method=method, headers=headers or {},
            timeout=_FALLBACK_TIMEOUT_S,
        )
        if response.ok:
            return response.text()
    except Exception:
        return None
    return None


def request_text(page, url, headers=None, method="GET", timeout_ms=DEFAULT_TIMEOUT_MS):
    """Fetch a URL over whichever transport works. Returns text or None."""
    return (_in_page(page, url, headers, method, timeout_ms)
            or _via_request_api(page, url, headers, method, timeout_ms))


def request_json(page, url, headers=None, method="GET", timeout_ms=DEFAULT_TIMEOUT_MS):
    return _to_json(request_text(page, url, headers, method, timeout_ms))


def get_json(page, url, headers=None, timeout_ms=DEFAULT_TIMEOUT_MS):
    return request_json(page, url, headers, "GET", timeout_ms)


def _to_json(text):
    if not text:
        return None
    try:
        return _json.loads(text)
    except Exception:
        return None
