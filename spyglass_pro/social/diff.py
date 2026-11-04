"""Pure check-to-check diff — the engine behind CHECK AGAIN.

Two normalized payloads go in, one honest description of what changed
comes out. Nothing here touches the network, the database or the clock,
so every rule is testable by construction (``tests/test_diff.py``).

The semantics are ported from GREENWICH's hard-won landmines:

* **Additions only for posts.** Posts are keyed by their native id
  (status id, shortcode, AT-uri rkey, numeric repo id) — never the URL
  every item on a profile shares as a fallback when the id is missing.
  A post absent from the newest 40-item window may simply have scrolled
  out or been deleted; asserting "removed" from a bounded window
  manufactures findings, so removals are never claimed.
* **Completeness flags gate list claims.** Each follower/following list
  carries ``complete`` — the collector proved enumeration finished
  (pagination exhausted), *not* the profile counter, which lags the
  list. A handle present in ``new`` but missing from ``old`` proves
  "added" only when ``old`` was complete; "removed" needs ``new``
  complete. Each side is refused independently, with the reason
  rendered instead of a fabricated zero.
* **Counts are compared, never derived.** ``follower_count`` et al.
  produce a delta only when both checks actually measured a value;
  schema.py's ``None`` means "could not see", which stays unread — it
  never becomes a delta of 0.
* **Walls are first-class changes.** A list that became login-walled
  between checks is a finding in itself: surfaced as a new wall, never
  silently dropped.
* **Fields only compare when both sides saw them**, and list-valued
  fields compare order-insensitively so a reordering is not a "profile
  change".

Refusals come back as ``{"ok": False, "error": ...}``: no baseline yet,
a failed payload on either side, or an identity mismatch. Callers render
the error instead of an empty diff — "nothing changed" and "could not
compare" must never look the same.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from .schema import PROFILE_FIELDS

# The canonical counters, labelled from the shared field schema.
_COUNT_KEYS = ("follower_count", "following_count", "post_count")
_LABELS = {field["key"]: field["label"] for field in PROFILE_FIELDS}

# Non-counter profile fields worth diffing. Lists are handled by the
# list diff (followers/following lists arrive as handles, not fields).
_FIELD_KEYS = (
    "display_name",
    "bio",
    "url",
    "verified",
    "private",
    "joined",
    "location",
    "website",
    "avatar_url",
    "contact_email",
    "external_links",
)


def _refuse(error: str) -> dict[str, Any]:
    return {"ok": False, "error": error[:300], "changed": False}


def _keyed_posts(payload: dict[str, Any]) -> dict[str, dict]:
    """Post items keyed by native id (URL fallback). Unkeyable items skipped."""
    out: dict[str, dict] = {}
    for item in payload.get("posts") or []:
        if not isinstance(item, dict):
            continue
        key = item.get("id") or item.get("url")
        if key is None or key == "":
            continue
        out[str(key)] = item
    return out


def _diff_counts(old: dict, new: dict) -> list[dict[str, Any]]:
    out = []
    for key in _COUNT_KEYS:
        before, after = old.get(key), new.get(key)
        if isinstance(before, bool) or isinstance(after, bool):
            continue
        if not isinstance(before, (int, float)) or not isinstance(after, (int, float)):
            continue  # unread on either side is not a delta
        out.append({
            "key": key,
            "label": _LABELS.get(key, key),
            "old": before,
            "new": after,
            "delta": after - before,
        })
    return out


def _diff_posts(old: dict, new: dict) -> dict[str, Any]:
    """New posts only — a bounded window can go missing without a deletion.

    The previous side's window is the only proof that a post is *new*.
    An empty window beside a nonzero ``post_count`` means the feed fetch
    failed (the adapter notes it), not that the account had no posts —
    and ``post_count`` unread is "could not see", which also proves
    nothing. Claiming additions against either manufactures findings
    from a transient error, so the comparison is refused with the reason.
    """
    previous, current = _keyed_posts(old), _keyed_posts(new)
    added = [current[key] for key in current if key not in previous]
    out = {"added": added, "added_count": len(added), "compared": len(current)}
    if not previous and current:
        old_post_count = old.get("post_count")
        unread = old_post_count is None or isinstance(old_post_count, bool)
        nonzero = isinstance(old_post_count, (int, float)) and old_post_count > 0
        if unread or nonzero:
            seen = ("no post count was reported" if unread
                    else f"it reported {old_post_count:,} posts")
            out.update(
                added=[],
                added_count=0,
                refused=("the previous check retrieved no posts and " + seen +
                         " — additions cannot be claimed"),
            )
    return out


def _same_value(before, after) -> bool:
    if isinstance(before, list) and isinstance(after, list):
        try:
            return sorted(before) == sorted(after)
        except TypeError:
            return before == after
    return before == after


# Fields whose value is a signed CDN URL: the query string is re-signed on
# every fetch (Instagram hands out fresh ``oh=``/``oe=``/``_nc_sid=`` tokens
# per request), so comparing the full string flags a fake "changed" on every
# check even though it is the same resource. Identity is scheme + host +
# path; the photo id lives in the path, so a real avatar swap still shows.
_QUERY_VOLATILE_FIELDS = frozenset({"avatar_url"})


def _url_identity(value: str):
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    return parts.scheme, parts.netloc, parts.path


def _same_field(key: str, before, after) -> bool:
    if key in _QUERY_VOLATILE_FIELDS and isinstance(before, str) and isinstance(after, str):
        id_before, id_after = _url_identity(before), _url_identity(after)
        if id_before is not None and id_after is not None:
            return id_before == id_after
    return _same_value(before, after)


def _diff_fields(old: dict, new: dict) -> list[dict[str, Any]]:
    out = []
    for key in _FIELD_KEYS:
        before, after = old.get(key), new.get(key)
        if before is None or after is None:
            continue  # unread on either side is not a change
        if _same_field(key, before, after):
            continue
        out.append({"key": key, "label": _LABELS.get(key, key), "old": before, "new": after})
    return out


def _diff_walls(old: dict, new: dict) -> dict[str, list]:
    old_walls, new_walls = old.get("walls") or {}, new.get("walls") or {}
    appeared = [{"kind": kind, **new_walls[kind]} for kind in new_walls if kind not in old_walls]
    resolved = sorted(kind for kind in old_walls if kind not in new_walls)
    return {"new": appeared, "resolved": resolved}


def _diff_lists(old: dict, new: dict) -> dict[str, dict[str, Any]]:
    """Handle-level list diffs, each side gated on its own completeness."""
    old_lists = old.get("lists") or {}
    new_lists = new.get("lists") or {}
    out: dict[str, dict[str, Any]] = {}
    for kind in sorted(set(old_lists) | set(new_lists)):
        before, after = old_lists.get(kind), new_lists.get(kind)
        if not isinstance(before, dict) or not isinstance(after, dict):
            missing = "current" if not isinstance(after, dict) else "previous"
            out[kind] = {
                "refused": f"no {kind} list in the {missing} check",
                "added": [],
                "removed": [],
                "old_size": len((before or {}).get("handles") or []),
                "new_size": len((after or {}).get("handles") or []),
            }
            continue
        old_handles = {str(h).strip().lower() for h in before.get("handles") or []}
        new_handles = {str(h).strip().lower() for h in after.get("handles") or []}
        old_complete = bool(before.get("complete"))
        new_complete = bool(after.get("complete"))
        entry: dict[str, Any] = {
            "old_size": len(old_handles),
            "new_size": len(new_handles),
            "delta": len(new_handles) - len(old_handles),
            "old_complete": old_complete,
            "new_complete": new_complete,
            "added": [],
            "removed": [],
            "added_refused": None,
            "removed_refused": None,
        }
        if old_complete:
            entry["added"] = sorted(new_handles - old_handles)
        else:
            entry["added_refused"] = (
                f"baseline {kind} list was not fully enumerated — additions cannot be claimed"
            )
        if new_complete:
            entry["removed"] = sorted(old_handles - new_handles)
        else:
            entry["removed_refused"] = (
                f"this check's {kind} list was not fully enumerated — removals cannot be claimed"
            )
        out[kind] = entry
    return out


def diff(old: dict[str, Any] | None, new: dict[str, Any] | None) -> dict[str, Any]:
    """Diff two normalized payloads. Pure; see the module docstring.

    Returns ``{"ok": False, "error": ...}`` when the comparison itself is
    untrustworthy, and ``{"ok": True, "changed": bool, ...}`` otherwise.
    """
    if not isinstance(old, dict) or not isinstance(new, dict):
        return _refuse("no previous check to compare against — this run is the baseline")
    for side, payload in (("previous", old), ("current", new)):
        if payload.get("error"):
            return _refuse(f"{side} check failed: {payload['error']}")
        if not payload.get("found"):
            return _refuse(f"{side} check did not find the profile")
    if old.get("platform") != new.get("platform"):
        return _refuse("cannot compare different platforms")
    if (old.get("handle") or "").lower() != (new.get("handle") or "").lower():
        return _refuse("cannot compare different handles")

    counts = _diff_counts(old, new)
    posts = _diff_posts(old, new)
    fields = _diff_fields(old, new)
    walls = _diff_walls(old, new)
    lists = _diff_lists(old, new)

    changed = (
        any(entry["delta"] for entry in counts)
        or posts["added_count"] > 0
        or bool(fields)
        or bool(walls["new"])
        or bool(walls["resolved"])
        or any(entry["added"] or entry["removed"] for entry in lists.values())
    )
    return {
        "ok": True,
        "changed": changed,
        "partial": new.get("status") == "partial",
        "counts": counts,
        "posts": posts,
        "fields": fields,
        "walls": walls,
        "lists": lists,
    }
