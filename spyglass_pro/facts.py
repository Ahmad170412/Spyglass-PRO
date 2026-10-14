"""Normalized fact layer — one response contract for every engine.

The three engines answer in payload shapes of their own, and every
consumer on top (the dashboard renderers, exports, and the graph /
timeline / search views to come) should not have to learn each shape.
This module derives a stable ``normalized`` block from a finished run::

    {
      "schema": "spyglass.facts/1",
      "qtype": "email",
      "target": "user@example.com",
      "engine": "spyglass_osint",
      "entities": [{"kind": "email", "value": "user@example.com",
                    "source": "target"}],
      "facts": [{"key": "accounts_agreed", "label": "Accounts (2+ engines agree)",
                 "value": 3, "source": "spyglass_osint",
                 "confidence": "high"}],
      "provenance": {"summary": "...", "progress_lines": 4,
                     "artifacts": 1, "stored_run_id": 5},
    }

Rules this layer keeps, matching the rest of the project:

* The raw payload stays authoritative. ``normalized`` is derived *from*
  it and may be omitted; the reverse must never happen.
* A run that failed yields **no** normalized block. Absence — not a
  null-valued or empty block dressed up as data — is what "nothing was
  known" must look like.
* Nothing is invented: a field the engines did not return stays absent
  from the block. Confidence reflects evidence the engines themselves
  compute (multi-engine agreement, direct third-party values), never a
  guess about how true a value is.
"""

from __future__ import annotations

SCHEMA = "spyglass.facts/1"

# Which engine family produced a query type. Everything without an entry
# came from the vendored Spyglass-OSINT modules.
_ENGINE = {
    "lens": "lens_extender",
    "social": "social_harness",
    "investigation": "correlated",
}

# Target string → entity kind, where the query type makes it unambiguous.
# darkweb and lens targets are heterogeneous (email / phone / domain / IP),
# so they go through _guess_kind instead.
_TARGET_KIND = {
    "email": "email",
    "username": "username",
    "phone": "phone",
    "website": "domain",
    "ip": "ip",
}

# Response-level keys that describe the *run*, not the findings. They must
# never leak into the generic fact extractor.
_SKIP_KEYS = {
    "error", "progress", "summary", "artifacts", "stored_run_id",
    "normalized", "report_dir", "artifact_error", "facts_error",
}


# ─── entry point ──────────────────────────────────────────────


def normalize(result, qtype="", target=""):
    """Derive the normalized block for a finished run.

    Returns ``None`` for anything that is not a plain result payload —
    most importantly an errored run, which has no facts to report.
    """
    if not isinstance(result, dict) or "error" in result:
        return None
    qtype = (qtype or "").strip()
    target = (target or "").strip()
    facts = []
    _EXTRACTORS.get(qtype, _extract_generic)(result, facts)
    provenance = {
        "summary": result.get("summary"),
        "progress_lines": len(result.get("progress") or []),
        "artifacts": len(result.get("artifacts") or []),
        "stored_run_id": result.get("stored_run_id"),
    }
    return {
        "schema": SCHEMA,
        "qtype": qtype,
        "target": target,
        "engine": _ENGINE.get(qtype, "spyglass_osint"),
        "entities": _entities(result, qtype, target),
        "facts": facts,
        "provenance": {key: value for key, value in provenance.items()
                       if value is not None},
    }


# ─── entities ─────────────────────────────────────────────────


def _entities(result, qtype, target):
    out = []
    seen = set()

    def add(kind, value, source):
        if value is None:
            return
        value = str(value).strip()
        if not value:
            return
        key = (str(kind), value.lower())
        if key in seen:
            return
        seen.add(key)
        out.append({"kind": str(kind), "value": value, "source": source})

    # The input itself is always an entity — it is what the run was about.
    if target:
        if qtype in _TARGET_KIND:
            kind = _TARGET_KIND[qtype]
        elif qtype in ("darkweb", "lens"):
            kind = _guess_kind(target)
        else:
            kind = None  # opsec 'self', metadata paths, social handles …
        if kind:
            add(kind, target, "target")

    if qtype == "investigation":
        # The investigation already correlates entities across legs; its
        # own index is the source of truth, not the per-type extractor.
        for plural, values in (result.get("entities") or {}).items():
            if not isinstance(values, list):
                continue
            singular = plural.rstrip("s") or plural
            for value in values:
                add(singular, value, "correlated")
    else:
        engine = _ENGINE.get(qtype, "spyglass_osint")
        for kind, value in _store_entities(result, qtype):
            add(kind, value, engine)
        _extra_entities(result, qtype, add, engine)
    return out


def _store_entities(result, qtype):
    """The case store's per-type entity extraction, when it is importable.

    Reusing it keeps the graph, the entity index and the case store
    agreeing on what counts as an entity — one extractor, one set of bugs.
    """
    try:
        from spyglass_osint import store
        return store._entities(result, qtype or "")
    except Exception:
        return []


def _extra_entities(result, qtype, add, engine):
    """Entities the case store's extractor does not cover for this type."""
    if qtype == "lens":
        add("ip", result.get("resolved_ip"), engine)
        guessed = _guess_kind(str(result.get("target") or ""))
        if guessed:
            add(guessed, result.get("target"), "target")
        for name in (result.get("hostnames") or [])[:20]:
            add("domain", name, engine)
    elif qtype == "social":
        add("username", result.get("handle"), "target")
    elif qtype == "ip":
        add("domain", result.get("hostname"), engine)
    elif qtype == "phone":
        pn = result.get("phonenumbers")
        if isinstance(pn, dict) and pn.get("e164"):
            add("phone", pn.get("e164"), engine)


def _guess_kind(value):
    value = (value or "").strip()
    if not value:
        return None
    if "@" in value and " " not in value:
        return "email"
    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() and int(p) <= 255 for p in parts):
        return "ip"
    if ":" in value and not any(ch in value for ch in "/ "):
        return "ip"  # IPv6
    digits = value.lstrip("+").replace(" ", "").replace("-", "")
    if digits.isdigit() and 5 <= len(digits) <= 15 and "." not in value:
        return "phone"
    if "." in value and " " not in value:
        return "domain"
    return "username"


# ─── facts ────────────────────────────────────────────────────


def _fact(out, key, label, value, source, confidence="high"):
    """Append one scalar fact.

    Absent values (None / '') are omitted — a fact that was not reported
    must not appear as an empty or zero result. A *reported* 0 is kept:
    "zero findings" after a real run is itself a finding. Containers are
    omitted too; facts are scalar so the block stays skimmable — lists
    live in ``entities`` and the raw payload.
    """
    if value is None or value == "":
        return
    if isinstance(value, (dict, list, tuple, set)):
        return
    out.append({"key": str(key), "label": str(label), "value": value,
                "source": str(source), "confidence": confidence})


def _count(value):
    return len(value) if isinstance(value, list) else 0


def _first(obj, keys):
    if not isinstance(obj, dict):
        return None
    for key in keys:
        value = obj.get(key)
        if value not in (None, "") and not isinstance(value, (dict, list)):
            return value
    return None


def _human(key):
    return str(key).replace("_", " ").strip().capitalize()


def _flat(out, obj, prefix, source, cap=8, confidence="high"):
    """Flat scalar entries of a nested dict, capped so one verbose third
    party cannot bury the block."""
    if not isinstance(obj, dict):
        return
    added = 0
    for key, value in obj.items():
        if added >= cap:
            break
        if key in _SKIP_KEYS:
            continue
        _fact(out, f"{prefix}.{key}", _human(key), value, source, confidence)
        added += 1


def _breach_facts(d, out, source):
    breach = d.get("breach")
    if isinstance(breach, dict):
        _fact(out, "breach_records", "Exposed records",
              breach.get("found"), "leakcheck+scylla")
        _fact(out, "breach_sources", "Breach sources",
              _count(breach.get("sources")), "leakcheck+scylla")
        _fact(out, "breach_fields", "Exposed field types",
              _count(breach.get("fields")), "leakcheck+scylla", "medium")
    if d.get("pwned") is not None and d.get("count") is not None:
        _fact(out, "hibp_breaches", "Breaches (HIBP)",
              d.get("count") or 0, "hibp")


_EMAIL_AGREE = ("both",)
_EMAIL_SINGLE = ("user_scanner_only", "holehe_only", "blackbird_only")

_USERNAME_AGREE = (
    "all_4", "all_3_no_bb", "all_3_no_mg", "all_3_no_sh", "all_3_no_us",
    "us+sherlock", "us+maigret", "us+blackbird",
    "sherlock+maigret", "sherlock+blackbird", "maigret+blackbird",
)
_USERNAME_SINGLE = ("us_only", "sherlock_only", "maigret_only",
                    "blackbird_only")


def _extract_email(d, out):
    src = "spyglass_osint"
    # Only claim counts for groups the engine actually reported; a
    # degraded run that returned no group keys reports no account facts.
    if any(key in d for key in _EMAIL_AGREE + _EMAIL_SINGLE):
        agreed = sum(_count(d.get(key)) for key in _EMAIL_AGREE)
        single = sum(_count(d.get(key)) for key in _EMAIL_SINGLE)
        _fact(out, "accounts_total", "Accounts found", agreed + single, src)
        _fact(out, "accounts_agreed", "Accounts (2+ engines agree)", agreed,
              src)
        _fact(out, "accounts_single", "Accounts (single engine)", single,
              src, "medium")
    _breach_facts(d, out, src)


def _extract_username(d, out):
    src = "spyglass_osint"
    if any(key in d for key in _USERNAME_AGREE + _USERNAME_SINGLE):
        agreed = sum(_count(d.get(key)) for key in _USERNAME_AGREE)
        single = sum(_count(d.get(key)) for key in _USERNAME_SINGLE)
        _fact(out, "accounts_total", "Accounts found", agreed + single, src)
        _fact(out, "accounts_agreed", "Accounts (2+ engines agree)", agreed,
              src)
        _fact(out, "accounts_single", "Accounts (single engine)", single,
              src, "medium")
        _fact(out, "accounts_4_of_4", "Accounts (all 4 engines agree)",
              _count(d.get("all_4")), src)
    _breach_facts(d, out, src)


def _extract_phone(d, out):
    src = "spyglass_osint"
    pn = d.get("phonenumbers")
    if isinstance(pn, dict):
        for key, label in (("valid", "Valid"), ("country_code", "Country code"),
                           ("region", "Region"), ("location", "Location"),
                           ("carrier", "Carrier"), ("type", "Line type"),
                           ("e164", "E.164")):
            _fact(out, f"phone_{key}", label, pn.get(key), src)
    if isinstance(d.get("ignorant"), list):
        _fact(out, "web_mentions", "Web mentions", len(d["ignorant"]), src,
              "medium")
    _breach_facts(d, out, src)


def _extract_website(d, out):
    src = "spyglass_osint"
    _fact(out, "page_title", "Page title", d.get("title"), src)
    _fact(out, "http_status", "HTTP status", d.get("status_code"), src)
    if "subdomains" in d:
        _fact(out, "subdomains", "Subdomains found",
              _count(d.get("subdomains")), src)
    records = d.get("dns_records")
    if isinstance(records, dict) and records.get("A"):
        a_count = len([p for p in str(records["A"]).replace(", ", ",").split(",")
                       if p.strip()])
        _fact(out, "a_records", "DNS A records", a_count, src)
    whois = d.get("whois")
    _fact(out, "whois_org", "Registrant org",
          _first(whois, ("Organization", "OrgName", "org", "Org")), "whois")
    _fact(out, "whois_registrar", "Registrar",
          _first(whois, ("Registar", "Registrar", "registrar")), "whois")
    _fact(out, "whois_created", "Registered",
          _first(whois, ("Creation Date", "Created", "created",
                        "Registration Date")), "whois")
    _flat(out, d.get("dns"), "dns", "dns", cap=8)


def _extract_ip(d, out):
    src = "spyglass_osint"
    _flat(out, d.get("geo"), "geo", "geoip", cap=8)
    _fact(out, "hostname", "Reverse DNS", d.get("hostname"), src)
    if "a_records" in d:
        _fact(out, "a_records", "A records", _count(d.get("a_records")), src)
    shodan = d.get("shodan")
    if isinstance(shodan, dict):
        _fact(out, "shodan_ports", "Open ports (Shodan)",
              _count(shodan.get("ports")), "shodan")
    _fact(out, "whois_org", "Registrant org",
          _first(d.get("whois"), ("Organization", "OrgName", "org", "Org")),
          "whois")


def _extract_lens(d, out):
    src = "lens_extender"
    _fact(out, "resolved_ip", "Resolved IP", d.get("resolved_ip"), src)
    _fact(out, "reverse_dns", "Reverse DNS", d.get("reverse_dns"), src)
    _fact(out, "shodan_org", "Shodan org", d.get("shodan_org"), "shodan")
    _fact(out, "shodan_isp", "Shodan ISP", d.get("shodan_isp"), "shodan")
    if "ports" in d:
        _fact(out, "ports", "Open ports", _count(d.get("ports")),
              "shodan+internetdb")
    if "vulns" in d:
        _fact(out, "vulns", "Vulnerabilities", _count(d.get("vulns")), src)
    if "software" in d:
        _fact(out, "software", "Software products",
              _count(d.get("software")), src)


def _extract_darkweb(d, out):
    _fact(out, "ahmia_hits", "Ahmia index hits", _count(d.get("ahmia")),
          "ahmia", "medium")
    _breach_facts(d, out, "spyglass_osint")


def _extract_opsec(d, out):
    src = "self-check"
    _fact(out, "proxy_configured", "Proxy configured",
          d.get("proxy_configured"), src)
    _fact(out, "dns_leak", "DNS leak", d.get("dns_leak"), src)
    if "recommendations" in d:
        _fact(out, "recommendations", "Recommendations",
              _count(d.get("recommendations")), src)
    _flat(out, d.get("direct"), "direct", src, cap=8)


def _extract_metadata(d, out):
    # An EXIF payload is a flat field dump: every scalar becomes a fact,
    # capped so one file with 400 MakerNotes cannot bury the block.
    added = 0
    for key, value in d.items():
        if added >= 40:
            break
        if key in _SKIP_KEYS:
            continue
        _fact(out, key, _human(key), value, "metadata")
        added += 1


def _extract_investigate(d, out):
    src = "correlated"
    entities = d.get("entities")
    if isinstance(entities, dict):
        for plural, values in entities.items():
            if isinstance(values, list):
                _fact(out, f"entities_{plural.rstrip('s')}",
                      f"{plural.capitalize()} correlated", len(values), src)
    correlations = d.get("correlations")
    if isinstance(correlations, list):
        matches = sum(1 for c in correlations
                      if isinstance(c, dict) and c.get("type") == "match")
        _fact(out, "correlations", "Correlations", len(correlations), src)
        _fact(out, "correlations_match", "Correlated matches", matches, src)
    legs = 0
    results = d.get("results")
    if isinstance(results, dict):
        legs += sum(1 for sub in results.values()
                    if isinstance(sub, dict) and "error" not in sub)
    for leg in ("ip_recon", "social"):
        value = d.get(leg)
        if isinstance(value, dict) and "error" not in value:
            legs += 1
    if any(key in d for key in ("results", "ip_recon", "social")):
        _fact(out, "legs", "Recon legs run", legs, src)


def _extract_social(d, out):
    src = "social_harness"
    _fact(out, "platform", "Platform", d.get("platform"), src)
    # Same convention as the report layer: found=False can mean "walled",
    # not "no such profile", so only a positive answer becomes a fact and
    # the walls list carries the honest explanation.
    if d.get("found"):
        _fact(out, "found", "Profile found", True, src)
    _fact(out, "followers", "Followers", d.get("follower_count"), src)
    _fact(out, "following", "Following", d.get("following_count"), src)
    _fact(out, "posts_count", "Posts", d.get("post_count"), src)
    # Match the report layer's convention: a False bool in a profile
    # means "the platform would not say", not a negative answer.
    if d.get("private"):
        _fact(out, "private", "Private", True, src)
    if d.get("verified"):
        _fact(out, "verified", "Verified", True, src)
    walls = d.get("walls")
    if isinstance(walls, dict):
        _fact(out, "walled", "Fields walled by the platform", len(walls), src,
              "medium")


def _extract_generic(d, out):
    added = 0
    for key, value in d.items():
        if added >= 20:
            break
        if key in _SKIP_KEYS:
            continue
        _fact(out, key, _human(key), value, "spyglass_osint")
        added += 1


_EXTRACTORS = {
    "email": _extract_email,
    "username": _extract_username,
    "phone": _extract_phone,
    "website": _extract_website,
    "ip": _extract_ip,
    "darkweb": _extract_darkweb,
    "opsec": _extract_opsec,
    "metadata": _extract_metadata,
    "lens": _extract_lens,
    "investigation": _extract_investigate,
    "social": _extract_social,
}
