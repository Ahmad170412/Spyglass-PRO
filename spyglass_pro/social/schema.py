"""One normalized profile shape for every social platform.

Instagram hands back `edge_owner_to_timeline_media`, X hands back
`legacy`/`core` user results, and the next platform will hand back
something else again. Adapters translate into the fields below, so the
report writer and the dashboard renderer never learn a platform's private
vocabulary — and adding a platform cannot mean touching either of them.

Every field is optional: a platform that cannot see a field leaves it
None and records a note instead of inventing a value. "We could not see
this" and "this is zero" must never look the same in a report.
"""

from __future__ import annotations

# Field metadata drives both the markdown report and the dashboard's
# generic renderer, which is why it lives here rather than in either.
# type: text | count | bool | date | link | image | list
#
# Note the counts are named *_count where a list of the same name would
# also exist (``post_count`` vs ``posts``). Platforms report counts and
# items under colliding keys, and one field cannot be both.
PROFILE_FIELDS = (
    {"key": "display_name", "label": "Name", "type": "text"},
    {"key": "bio", "label": "Bio", "type": "text"},
    {"key": "url", "label": "Profile URL", "type": "link"},
    {"key": "follower_count", "label": "Followers", "type": "count"},
    {"key": "following_count", "label": "Following", "type": "count"},
    {"key": "post_count", "label": "Posts", "type": "count"},
    {"key": "verified", "label": "Verified", "type": "bool"},
    {"key": "private", "label": "Private", "type": "bool"},
    {"key": "joined", "label": "Joined", "type": "date"},
    {"key": "location", "label": "Location", "type": "text"},
    {"key": "website", "label": "Website", "type": "link"},
    {"key": "avatar_url", "label": "Avatar", "type": "image"},
    {"key": "contact_email", "label": "Contact Email", "type": "text"},
    {"key": "external_links", "label": "External Links", "type": "list"},
)


def new_result(platform: str, handle: str) -> dict:
    """A result skeleton with every field present and empty.

    ``posts`` is a list of retrieved items and is distinct from the
    ``post_count`` field above; both start out empty rather than missing so
    a renderer never has to guess whether a key was absent or unread.
    """
    result = {
        "platform": platform,
        "handle": handle,
        "found": False,
        "logged_in": False,
        "source": None,
        "notes": [],
        "walls": {},
        "posts": [],
        "media_files": [],
        "entities": {},
    }
    for field in PROFILE_FIELDS:
        result[field["key"]] = [] if field["type"] == "list" else None
    return result


def add_note(result: dict, note: str) -> None:
    """Record something the operator should know that is not a failure."""
    note = " ".join(str(note).split())
    if note and note not in result["notes"]:
        result["notes"].append(note)


def add_wall(result: dict, kind: str, label: str, why: str) -> None:
    """Record a list we could not retrieve, and why.

    Mirrors InstaCloak's walled-list reporting: a follower list that needs
    a login is reported as walled, never as an empty list, because "no
    followers" and "could not see followers" are very different findings.
    """
    result["walls"][kind] = {"label": label, "why": why}


def set_fields(result: dict, **values) -> None:
    """Assign known profile fields, ignoring anything not in the schema."""
    known = {field["key"] for field in PROFILE_FIELDS}
    for key, value in values.items():
        if key not in known:
            raise KeyError(f"unknown profile field: {key}")
        if value is None or value == "" or value == []:
            continue
        result[key] = value


def visible_fields(result: dict) -> list[dict]:
    """Schema fields this run actually retrieved, in display order."""
    out = []
    for field in PROFILE_FIELDS:
        value = result.get(field["key"])
        if value is None or value == "" or value == []:
            continue
        if field["type"] == "bool" and value is False:
            continue
        out.append(field)
    return out


def format_value(field: dict, value) -> str:
    """Render one field for the markdown report."""
    kind = field["type"]
    if kind == "bool":
        return "yes" if value else "no"
    if kind == "count":
        return f"{value:,}" if isinstance(value, int) else str(value)
    if kind == "list":
        return ", ".join(str(item) for item in value)
    return str(value)