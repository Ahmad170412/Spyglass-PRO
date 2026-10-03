"""Network helpers — every request goes through the real browser.

Nothing here uses raw HTTP libraries: fetches happen via `fetch` executed
inside the page (real browser TLS + cookies + fingerprint), with Playwright's
`page.request` as a fallback. Media downloads use the browser's request API
too, so the CDN sees the stealth browser's TLS, not a scraper's.
"""

from __future__ import annotations

import json
from pathlib import Path

INSTAGRAM_APP_ID = "936619743392459"

EXT_MAP = {
    "image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp",
    "image/avif": ".avif", "image/gif": ".gif",
    "video/mp4": ".mp4", "video/webm": ".webm",
}


def fetch_text(page, url: str, headers: dict | None = None,
               timeout_ms: int = 30000) -> str | None:
    """Fetch a URL from inside the page (real browser TLS + cookies + fingerprint)."""
    js = """async (arg) => {
        const ctl = new AbortController();
        const t = setTimeout(() => ctl.abort(), arg.timeout_ms);
        try {
            const r = await fetch(arg.url, {headers: arg.headers || {}, credentials: 'include', signal: ctl.signal});
            const text = await r.text();
            return {status: r.status, text: text};
        } catch (e) {
            return {status: 0, text: String(e)};
        } finally { clearTimeout(t); }
    }"""
    try:
        res = page.evaluate(js, {"url": url, "headers": headers or {}, "timeout_ms": timeout_ms})
        if res and res.get("status") and 200 <= res["status"] < 300:
            return res["text"]
    except Exception:
        pass
    # Fallback: Playwright's request API (shares cookies; CDN/API usually fine)
    try:
        resp = page.request.get(url, headers=headers or {}, timeout=timeout_ms)
        if resp.ok:
            return resp.text()
    except Exception:
        pass
    return None


def fetch_json(page, url: str, headers: dict | None = None) -> dict | None:
    text = fetch_text(page, url, headers)
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def download_media(page, url: str, dest: Path, stem: str) -> str | None:
    try:
        resp = page.request.get(url, timeout=60000)
        if not resp.ok:
            return None
        ctype = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
        ext = EXT_MAP.get(ctype)
        if not ext:
            ext = Path(url.split("?")[0]).suffix or ".bin"
        out = dest / f"{stem}{ext}"
        dest.mkdir(parents=True, exist_ok=True)
        out.write_bytes(resp.body())
        return str(out)
    except Exception:
        return None
