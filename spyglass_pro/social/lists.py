"""Follower/following list windows — one cap, one honesty rule.

Every collector that can enumerate a social graph walks pages up to
``RECORD_CAP`` handles and hands the result to :func:`record`, which
decides in one place whether the walk may call itself complete:

* **complete = pagination exhausted OR the walk reached the profile
  counter, and the whole list fits the window.** Exhaustion (the server
  sent no next page) is direct proof. Reaching the counter is
  GREENWICH's counter-lag rule: the profile counter *lags* the list, so
  listing ``expected`` or more records proves the list ended even when a
  next-page link still existed — while listing *fewer* proves only a
  window. Pages overshoot the cap by up to one page (~100 records on a
  400 window), so an over-cap list is trimmed to ``RECORD_CAP`` and
  marked **incomplete**: completeness claims only what was kept, or the
  diff engine would one day call a trimmed tail "removed". The counter
  is never a source of truth, only a ceiling to reach.
* **A failed walk with nothing collected becomes a wall**, never an
  empty list: "could not see followers" and "no followers" must never
  look the same (schema.py's wall contract).
* **A failed walk that got somewhere keeps its partial block**
  (``complete`` false, so the diff engine refuses handle-level claims
  from it) *and* walls the gap — both facts are true at once.
* Handles are deduplicated case-insensitively, kept in walk order.

``social/diff.py`` consumes the flags: a side with ``complete`` false
gets no added/removed claims from that side, only sizes.
"""

from __future__ import annotations

from .schema import add_wall

# Window per list per check. 400 ≈ five pages on every keyless API here
# (Mastodon 80/page, Bluesky ~90/page, GitHub/GitLab 100/page) — deep
# enough to catch real churn, shallow enough that one check stays cheap.
RECORD_CAP = 400


def _count(value) -> int | None:
    """A usable non-negative int count (bools are not counts)."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def block(handles, expected, exhausted, order: str = "recent") -> dict:
    """Build one list block with the completeness verdict."""
    seen: set[str] = set()
    ordered: list[str] = []
    for handle in handles or []:
        if not isinstance(handle, str):
            handle = str(handle)
        handle = handle.strip().lower()
        if not handle or handle in seen:
            continue
        seen.add(handle)
        ordered.append(handle)
    expected = _count(expected)
    reached_counter = expected is not None and expected > 0 and len(ordered) >= expected
    # Page granularity overshoots the cap by up to one page; trim to the
    # promised window and refuse completeness for anything cut — a claim
    # about kept records only, or tails become phantom removals later.
    capped = len(ordered) > RECORD_CAP
    if capped:
        ordered = ordered[:RECORD_CAP]
    return {
        "handles": ordered,
        "complete": (bool(exhausted) or reached_counter) and not capped,
        "expected": expected,
        "order": order,
        "limit": RECORD_CAP,
    }


def record(result: dict, kind: str, handles, expected, exhausted, error: str | None = None) -> None:
    """Attach a collected list to the result and reconcile its wall.

    ``kind`` is ``"followers"`` or ``"following"`` — the same keys
    :func:`schema.add_wall` uses, so a wall and a list block can never
    disagree about which graph they describe.
    """
    if handles:
        result.setdefault("lists", {})[kind] = block(handles, expected, exhausted)
        # A successful walk clears normalize's placeholder wall…
        result["walls"].pop(kind, None)
        if error:
            # …but a *partial* walk still walls the part it could not see.
            add_wall(result, kind, f"{kind} list", error)
    elif error:
        # Nothing collected: wall only. An empty block here would read as
        # "the account has no followers".
        add_wall(result, kind, f"{kind} list", error)
    else:
        # Clean empty walk: the server really did end the list at zero.
        result.setdefault("lists", {})[kind] = block([], expected, True)
        result["walls"].pop(kind, None)
