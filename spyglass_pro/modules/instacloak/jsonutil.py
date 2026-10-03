"""Low-level digging into Instagram's embedded JSON.

Instagram serves page data as `<script>` blobs of JSON (sometimes wrapped in
`window._sharedData = ...` / `require(...)` module calls). These helpers find
and parse those blobs, then walk the parsed trees. They are pure functions —
no browser, no network — so they are easy to unit test offline.

Instagram rotates its JSON shapes every few weeks; keep the *generic* digging
here and the shape-specific field mapping in `profile.py` / `post.py`.
"""

from __future__ import annotations

import json
import re


def _match_braces(s: str, idx: int) -> str | None:
    """Return the brace-balanced substring starting at s[idx] ('{' or '[')."""
    if idx >= len(s) or s[idx] not in "{[":
        return None
    open_ch, close_ch = (s[idx], "}" if s[idx] == "{" else "]")
    depth = 0
    in_str = False
    esc = False
    for i in range(idx, len(s)):
        ch = s[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return s[idx:i + 1]
    return None


def extract_json_blobs(html: str) -> list:
    """Pull every plausible JSON object out of Instagram's script tags."""
    blobs: list = []
    for m in re.finditer(r"<script\b[^>]*>(.*?)</script>", html, re.S | re.I):
        content = m.group(1).strip()
        if not content:
            continue
        candidates: list[str] = []
        if content[:1] in "{[":
            candidates.append(content)
        for pat in (r"window\.__additionalDataLoaded\([^,]+,\s*",
                    r"window\._sharedData\s*=\s*",
                    r"window\.__initialData\s*=\s*"):
            mm = re.search(pat + r"([{[])", content)
            if mm:
                blob = _match_braces(content, mm.start(1))
                if blob:
                    candidates.append(blob)
        for cand in candidates:
            try:
                parsed = json.loads(cand)
                if isinstance(parsed, (dict, list)):
                    blobs.append(parsed)
            except Exception:
                pass
    return blobs


def deep_find(root, *keys) -> dict | None:
    """Return the first dict in the tree that has ALL of `keys` as direct keys."""
    stack = [root]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if all(k in node for k in keys):
                return node
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return None


def iter_dicts(node, depth: int = 0, max_depth: int = 60):
    """Yield every dict in a JSON tree (bounded, so huge blobs stay cheap)."""
    if depth > max_depth:
        return
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from iter_dicts(v, depth + 1, max_depth)
    elif isinstance(node, list):
        for v in node[:500]:
            yield from iter_dicts(v, depth + 1, max_depth)


def first(*vals):
    """First non-empty value (handles old- vs new-shape key names).

    Treats None/""/False as missing — use for strings/ids/URLs. Do NOT use
    for numeric counts: a legit 0 would be discarded.
    """
    return next((v for v in vals if v not in (None, "", False)), None)


def first_present(*vals):
    """First value that is not None (preserves legit 0s and False)."""
    return next((v for v in vals if v is not None), None)
