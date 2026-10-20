"""Person resolution layer — one evidence-backed identity from an investigation.

``investigation.py`` gathers four legs and correlates a few pairwise facts.
This module sits on top of a finished investigation and answers a different
question: *what does the combined evidence say about one person?*

The contract is deliberately conservative. Everything is tagged with where it
came from, and nothing is merged on a hunch:

``anchors``
    Values the analyst supplied (email, username, phone, website). A website
    is a *context* anchor: WHOIS describes the domain, not necessarily the
    person who runs it.

``names`` / ``handles`` / ``emails`` / ``phones`` / ``locations`` /
``organizations`` / ``domains`` / ``websites``
    Identity attributes, each ``{value, source, confidence}``. Input anchors
    start the lists; profile fields and matched WHOIS values extend them.

``accounts``
    Platform observations, one row per platform, with the anchors that reached
    it (``via``) and the exact engines that found it (``tools``). Two engines
    agreeing makes the *account* high confidence; it does not make two people
    the same person.

``links``
    Evidence joining two observations, each with a confidence of ``high``,
    ``medium`` or ``possible``. A shared handle is always ``possible`` — it is
    a lead, never a proof.

``conflicts``
    Places where linked sources disagree (a profile location against the
    registrant country, for example). Conflicts are surfaced, not resolved by
    silent majority vote.

``context``
    WHOIS values that no anchor matched. They stay visibly separate from the
    identity instead of being folded into it.

The block is additive: old stored investigations have no ``person`` key and
render exactly as they did before.
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlsplit

SCHEMA = "spyglass.person/1"

_EMAIL_BUCKETS = ("both", "holehe_only", "user_scanner_only", "blackbird_only")
_EMAIL_BUCKET_TOOLS = {
    "both": ("2+ engines",),
    "holehe_only": ("holehe",),
    "user_scanner_only": ("user-scanner",),
    "blackbird_only": ("blackbird",),
}
_USERNAME_BUCKETS = {
    "all_4": ("user-scanner", "sherlock", "maigret", "blackbird"),
    "all_3_no_bb": ("user-scanner", "sherlock", "maigret"),
    "all_3_no_mg": ("user-scanner", "sherlock", "blackbird"),
    "all_3_no_sh": ("user-scanner", "maigret", "blackbird"),
    "all_3_no_us": ("sherlock", "maigret", "blackbird"),
    "us+sherlock": ("user-scanner", "sherlock"),
    "us+maigret": ("user-scanner", "maigret"),
    "us+blackbird": ("user-scanner", "blackbird"),
    "sherlock+maigret": ("sherlock", "maigret"),
    "sherlock+blackbird": ("sherlock", "blackbird"),
    "maigret+blackbird": ("maigret", "blackbird"),
    "us_only": ("user-scanner",),
    "sherlock_only": ("sherlock",),
    "maigret_only": ("maigret",),
    "blackbird_only": ("blackbird",),
}

# Registrars publish these instead of a person. They are not names, and
# treating them as identity attributes is how a privacy proxy becomes a lead.
_PRIVACY = re.compile(
    r"\b(redact\w*|privacy|withheld|not disclosed|data protected|gdpr|"
    r"whoisguard|domains by proxy|domain administrator|statutory masking)\b",
    re.IGNORECASE,
)
_PLACEHOLDERS = {"n/a", "na", "none", "null", "unknown", "-", "--", ""}

# Correlations already explained by a generated link, or too weak to read as
# an identity link at all.
_SKIP_CORRELATIONS = (
    "email + username overlap",
    "input email found in website whois",
)

# Social adapters name platforms by key; account engines name them by domain.
# Mapping the key to the domain is what lets "Instagram" and "instagram.com"
# become one row instead of two. A profile URL wins when present.
_SOCIAL_DOMAINS = {
    "instagram": "instagram.com",
    "github": "github.com",
    "gitlab": "gitlab.com",
    "keybase": "keybase.io",
    "bluesky": "bsky.app",
}

_RANK = {"unconfirmed": 0, "possible": 1, "medium": 2, "high": 3}


def _rank(confidence) -> int:
    return _RANK.get(str(confidence or "").lower(), 0)


def _clean(value) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def _dict(value) -> dict:
    """Narrow an arbitrary payload value to a dict without trusting it."""
    return value if isinstance(value, dict) else {}


def _public(value) -> str:
    """A value we are willing to show as a name or organization."""
    value = _clean(value)
    if not value or value.lower() in _PLACEHOLDERS or _PRIVACY.search(value):
        return ""
    return value


def _as_values(value) -> list[str]:
    """Input values, list-ready even though 1.3 accepts one per field."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    return [text] if text else []


def _split_values(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [_clean(item) for item in value if _clean(item)]
    return [_clean(part) for part in re.split(r"[,;]", str(value)) if _clean(part)]


def _norm(value) -> str:
    text = unicodedata.normalize("NFKD", str(value or ""))
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = re.sub(r"[^A-Za-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip().lower()


def _email_key(value) -> str:
    return _clean(value).lower()


def _handle_key(value) -> str:
    return _clean(value).lstrip("@").lower()


def _domain_key(value) -> str:
    text = _clean(value).lower().rstrip(".")
    return text[4:] if text.startswith("www.") else text


def _url_key(value) -> str:
    return _clean(value).lower().rstrip("/")


def _digits(value) -> str:
    return re.sub(r"\D", "", str(value or ""))


def _phone_key(value) -> str:
    digits = _digits(value)
    return digits[-10:] if len(digits) >= 10 else digits


def _phones_match(left, right) -> bool:
    a, b = _digits(left), _digits(right)
    size = min(len(a), len(b))
    return size >= 7 and a[-size:] == b[-size:]


def _url_host(value) -> str:
    text = _clean(value)
    if not text:
        return ""
    try:
        parsed = urlsplit(text if "://" in text else "//" + text)
    except ValueError:
        return ""
    return (parsed.hostname or "").strip(".").lower()


def _platform(value) -> str:
    text = _clean(value)
    if not text:
        return ""
    host = _url_host(text) if "://" in text or "/" in text else text
    host = (host or text).lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def _location_matches(location, country) -> bool:
    """Does a free-text profile location contain a whole country name?"""
    loc, ctry = _norm(location), _norm(country)
    if not loc or not ctry:
        return False
    if loc == ctry:
        return True
    if len(ctry) >= 3 and re.search(rf"\b{re.escape(ctry)}\b", loc):
        return True
    return bool(len(loc) >= 3 and re.search(rf"\b{re.escape(loc)}\b", ctry))


def _name_matches(left, right) -> bool:
    a, b = _norm(left), _norm(right)
    if not a or not b:
        return False
    if a == b:
        return True
    return len(a) >= 4 and len(b) >= 4 and (
        re.search(rf"\b{re.escape(a)}\b", b) is not None
        or re.search(rf"\b{re.escape(b)}\b", a) is not None
    )


def _phone_region_matches(region, country) -> bool:
    try:
        from spyglass_osint.investigation import _country_matches
        return _country_matches(region, country)
    except Exception:
        return _location_matches(country, region)


class _Bucket:
    """Ordered, de-duplicated identity attributes with merged provenance."""

    def __init__(self, key=None, prefer=None) -> None:
        self._key = key or _norm
        self._prefer = prefer
        self._items: dict[str, dict] = {}

    def add(self, value, source: str, confidence: str = "high", **extra) -> None:
        value = _clean(value)
        if not value:
            return
        key = self._key(value)
        if not key:
            return
        current = self._items.get(key)
        if current is None:
            item = {"value": value, "source": source, "confidence": confidence}
            item.update({k: v for k, v in extra.items() if v})
            self._items[key] = item
            return
        sources = [part.strip() for part in str(current.get("source", "")).split(",")]
        if source and source not in sources:
            current["source"] = ", ".join([*sources, source])
        if _rank(confidence) > _rank(current.get("confidence")):
            current["confidence"] = confidence
        for name, value_extra in extra.items():
            if value_extra and not current.get(name):
                current[name] = value_extra
        if self._prefer and self._prefer(value, current.get("value", "")):
            current["value"] = value

    def values(self) -> list[str]:
        return [item["value"] for item in self._items.values()]

    def items(self) -> list[dict]:
        return list(self._items.values())


def _prefer_phone(new, old) -> bool:
    return str(new).startswith("+") and not str(old).startswith("+")


def _add_anchor(anchors, seen, kind, value, source="input", context=False) -> None:
    value = _clean(value)
    if not value:
        return
    if kind == "email":
        key = (kind, _email_key(value))
    elif kind == "username":
        key = (kind, _handle_key(value))
    elif kind == "phone":
        key = (kind, _phone_key(value))
    else:
        key = (kind, _url_host(value) or _domain_key(value))
    if key in seen:
        return
    item = {"kind": kind, "value": value, "source": source, "confidence": "high"}
    if context:
        item["context"] = True
    anchors.append(item)
    seen.add(key)


def _add_link(links, seen, kind, desc, detail="", confidence="medium") -> None:
    desc = _clean(desc)
    if not desc:
        return
    key = (kind, desc.lower())
    current = seen.get(key)
    if current is not None:
        if _rank(confidence) > _rank(current.get("confidence")):
            current["confidence"] = confidence
        if detail and not current.get("detail"):
            current["detail"] = _clean(detail)
        return
    item = {"kind": kind, "desc": desc, "confidence": confidence}
    if detail:
        item["detail"] = _clean(detail)
    links.append(item)
    seen[key] = item


def _add_account(accounts, platform, url, via, tools) -> None:
    platform = _platform(platform)
    if not platform:
        return
    current = accounts.get(platform)
    if current is None:
        accounts[platform] = {
            "platform": platform,
            "url": _clean(url),
            "via": [via],
            "tools": list(tools),
        }
        return
    if via not in current["via"]:
        current["via"].append(via)
    for tool in tools:
        if tool and tool not in current["tools"]:
            current["tools"].append(tool)
    if url and (not current["url"] or via in ("username", "social")):
        current["url"] = _clean(url)


def _corr_confidence(desc: str) -> str:
    text = desc.lower()
    if "email domain matches website target" in text:
        return "high"
    if "email domain found in website whois" in text:
        return "medium"
    if "registered on" in text and "matches website" in text:
        return "medium"
    if "phone region matches" in text:
        return "medium"
    return ""


def resolve(inputs, result=None) -> dict:
    """Derive a person block from investigation inputs and results.

    Pure function: it reads ``inputs`` and ``result`` and returns a new dict.
    A malformed result degrades to anchors-only rather than raising.
    """
    inputs = inputs if isinstance(inputs, dict) else {}
    result = result if isinstance(result, dict) else {}
    results = result.get("results") if isinstance(result.get("results"), dict) else {}

    names = _Bucket()
    handles = _Bucket(_handle_key)
    emails = _Bucket(_email_key)
    phones = _Bucket(_phone_key, _prefer_phone)
    locations = _Bucket()
    organizations = _Bucket()
    domains = _Bucket(_domain_key)
    websites = _Bucket(_url_key)
    accounts: dict[str, dict] = {}
    anchors: list[dict] = []
    anchor_seen: set = set()
    links: list[dict] = []
    link_seen: dict = {}
    conflicts: list[dict] = []

    # ── analyst assertions ────────────────────────────────────
    for value in _as_values(inputs.get("email")):
        if "@" not in value:
            continue
        _add_anchor(anchors, anchor_seen, "email", value)
        emails.add(value, "input", "high")
        host = value.rsplit("@", 1)[-1].strip().lower()
        if host:
            domains.add(host, "input email", "medium")

    for value in _as_values(inputs.get("username")):
        _add_anchor(anchors, anchor_seen, "username", value)
        handles.add(value, "input", "high")

    for value in _as_values(inputs.get("phone")):
        _add_anchor(anchors, anchor_seen, "phone", value)
        phones.add(value, "input", "high")

    website_hosts: set[str] = set()
    for value in _as_values(inputs.get("website")):
        host = _url_host(value) or _platform(value)
        if not host:
            continue
        _add_anchor(anchors, anchor_seen, "website", host, context=True)
        website_hosts.add(host)
        websites.add(value if "://" in value else host, "input", "high")
        domains.add(host, "input website", "medium", context=True)

    # ── phone leg: a canonical E.164 is worth showing ─────────
    phone_result = _dict(results.get("phone"))
    number_info = _dict(phone_result.get("phonenumbers"))
    if number_info and not number_info.get("error") and number_info.get("e164"):
        phones.add(number_info["e164"], "phonenumbers", "high")

    # ── account registrations from the email and username legs ─
    email_result = _dict(results.get("email"))
    if _as_values(inputs.get("email")) and email_result and not email_result.get("error"):
        for bucket in _EMAIL_BUCKETS:
            for item in email_result.get(bucket) or []:
                if not isinstance(item, dict):
                    continue
                tools = item.get("engines") or _EMAIL_BUCKET_TOOLS[bucket]
                _add_account(accounts, item.get("domain"), item.get("url"),
                             "email", tools)

    username_result = _dict(results.get("username"))
    if _as_values(inputs.get("username")) and username_result and not username_result.get("error"):
        for bucket, tools in _USERNAME_BUCKETS.items():
            for item in username_result.get(bucket) or []:
                if not isinstance(item, dict):
                    continue
                _add_account(accounts, item.get("domain"), item.get("url"),
                             "username", tools)

    # ── social leg: profile fields are direct observations ────
    social = _dict(result.get("social"))
    social_platform = ""
    social_handle = ""
    social_name = ""
    social_location = ""
    social_emails: list[str] = []
    social_domains: set[str] = set()
    social_found = False

    if social and not social.get("error"):
        social_label = _platform(social.get("platform") or "social")
        social_platform = (
            _url_host(social.get("url"))
            or _SOCIAL_DOMAINS.get(social_label, social_label)
        )
        social_handle = _clean(social.get("handle")).lstrip("@")
        social_found = bool(social.get("found")) or bool(social.get("url"))
        if social_handle:
            _add_anchor(anchors, anchor_seen, "username", social_handle,
                        source=f"input ({social_label})")
            handles.add(social_handle, social_label, "high")
        if social_found:
            _add_account(accounts, social_platform, social.get("url"), "social",
                         [social_label])

        social_name = _public(social.get("display_name"))
        if social_name:
            names.add(social_name, social_label, "high")

        social_location = _clean(social.get("location"))
        if social_location:
            locations.add(social_location, social_label, "medium")

        profile_site = _clean(social.get("website"))
        if profile_site:
            websites.add(profile_site, social_label, "high")
            host = _url_host(profile_site)
            if host:
                domains.add(host, social_label, "high")
                social_domains.add(host)

        contact = _clean(social.get("contact_email"))
        if "@" in contact:
            emails.add(contact, social_label, "high")
            social_emails.append(contact)
            host = contact.rsplit("@", 1)[-1].strip().lower()
            if host:
                domains.add(host, social_label, "medium")

        external = social.get("external_links") or []
        if isinstance(external, str):
            external = [external]
        for link in external:
            link = _clean(link)
            if not link:
                continue
            websites.add(link, social_label, "high")
            host = _url_host(link)
            if host:
                domains.add(host, social_label, "high")
                social_domains.add(host)

        bio = _clean(social.get("bio"))
        if bio:
            mentioned: list[tuple[str, str]] = []
            for kind, values in (("email", _as_values(inputs.get("email"))),
                                 ("handle", _as_values(inputs.get("username")))):
                mentioned.extend((kind, item) for item in values)
            if social_handle:
                mentioned.append(("handle", social_handle))
            # One bio mention is enough: email first, then the handle. Listing
            # every occurrence turns one proof into three rows and inflates
            # the link count without adding evidence.
            for kind, value in mentioned:
                needle = value.lstrip("@")
                if len(needle) < 3:
                    continue
                if re.search(rf"(?<![\w@]){re.escape(needle)}(?![\w])", bio, re.IGNORECASE):
                    _add_link(
                        links, link_seen, "profile-bio",
                        f"Profile bio mentions {kind} {value}", value, "high")
                    break

    # ── website leg: WHOIS is domain context until it matches ─
    website_result = _dict(results.get("website"))
    whois = _dict(website_result.get("whois"))

    who_emails: list[str] = []
    who_phones: list[str] = []
    who_names: list[str] = []
    who_orgs: list[str] = []
    who_country = ""

    if whois and not website_result.get("error"):
        for key in ("Email", "Registrant Email", "Admin Email", "Tech Email",
                    "Extra Emails"):
            who_emails.extend(value for value in _split_values(whois.get(key))
                              if "@" in value)
        for key in ("Phone", "Extra Phones"):
            who_phones.extend(value for value in _split_values(whois.get(key))
                              if len(_digits(value)) >= 7)
        for key in ("Registrant Name", "Admin Name", "Tech Name", "Name"):
            value = _public(whois.get(key))
            if value:
                who_names.append(value)
        for key in ("Organization", "Registrant Organization", "Admin Organization",
                    "Tech Organization", "Organisation", "OrgName", "Org", "org"):
            value = _public(whois.get(key))
            if value and value not in who_orgs:
                who_orgs.append(value)
        who_country = _public(whois.get("Country"))

    def _unique(items):
        seen = set()
        out = []
        for item in items:
            key = _email_key(item) if "@" in item else _phone_key(item) if _digits(item) else _norm(item)
            if key and key not in seen:
                seen.add(key)
                out.append(item)
        return out

    who_emails = _unique(who_emails)
    who_phones = _unique(who_phones)

    input_emails = _as_values(inputs.get("email"))
    known_emails = {_email_key(value) for value in input_emails}
    known_emails |= {_email_key(value) for value in social_emails}
    input_phones = _as_values(inputs.get("phone"))
    if number_info.get("e164"):
        input_phones.append(number_info["e164"])

    context_emails: list[str] = []
    context_phones: list[str] = []
    context_names: list[str] = []
    context_orgs: list[str] = []

    who_email_match = False
    for value in who_emails:
        if _email_key(value) in known_emails:
            emails.add(value, "WHOIS", "high")
            _add_link(links, link_seen, "whois-email",
                      "Known email found in website WHOIS", value, "high")
            who_email_match = True
        else:
            context_emails.append(value)

    who_phone_match = False
    for value in who_phones:
        if any(_phones_match(value, known) for known in input_phones):
            phones.add(value, "WHOIS", "high")
            _add_link(links, link_seen, "whois-phone",
                      "Input phone found in website WHOIS", value, "high")
            who_phone_match = True
        else:
            context_phones.append(value)

    profile_names = names.values()
    who_name_match = False
    for value in who_names:
        if any(_name_matches(value, profile) for profile in profile_names):
            names.add(value, "WHOIS", "high")
            _add_link(links, link_seen, "whois-name",
                      "Profile name found in website WHOIS", value, "high")
            who_name_match = True
        else:
            context_names.append(value)

    whois_linked = who_email_match or who_phone_match or who_name_match
    for value in who_orgs:
        if whois_linked:
            organizations.add(value, "WHOIS", "medium")
        else:
            context_orgs.append(value)
    if (who_country and whois_linked
            and not (social_location and _location_matches(social_location, who_country))):
        locations.add(who_country, "WHOIS", "medium")

    # ── links that come from combining two legs ───────────────
    overlap = sorted(
        account["platform"] for account in accounts.values()
        if "email" in account["via"] and "username" in account["via"])
    if overlap and input_emails:
        _add_link(
            links, link_seen, "email-username-overlap",
            f"Email and username both registered on {len(overlap)} platform(s)",
            ", ".join(overlap[:8]), "high")

    usernames = _as_values(inputs.get("username"))
    primary_username = usernames[0] if usernames else ""
    if primary_username:
        platforms = {account["platform"] for account in accounts.values()
                     if "username" in account["via"]}
        if social_found and social_handle and _handle_key(social_handle) == _handle_key(primary_username):
            platforms.add(social_platform)
        if len(platforms) >= 2:
            _add_link(
                links, link_seen, "handle-reuse",
                f"Handle @{primary_username.lstrip('@')} appears on {len(platforms)} "
                "platforms — same handle, not proof of one person",
                ", ".join(sorted(platforms)[:8]), "possible")

    if input_emails and primary_username:
        local = input_emails[0].split("@", 1)[0]
        if len(_handle_key(local)) >= 3 and _handle_key(local) == _handle_key(primary_username):
            _add_link(
                links, link_seen, "email-localpart",
                f"Email local-part matches username @{primary_username.lstrip('@')}",
                input_emails[0], "possible")

    for value in social_emails:
        if _email_key(value) in {_email_key(item) for item in input_emails}:
            _add_link(links, link_seen, "profile-email",
                      "Profile contact email matches input email", value, "high")

    email_domains = {value.rsplit("@", 1)[-1].strip().lower()
                     for value in input_emails if "@" in value}
    matched_sites = social_domains & (website_hosts | email_domains)
    if matched_sites:
        _add_link(links, link_seen, "profile-website",
                  "Profile links to a known domain",
                  ", ".join(sorted(matched_sites)[:8]), "high")

    # ── correlation rows, with a confidence that is not all "match" ─
    for correlation in result.get("correlations") or []:
        if not isinstance(correlation, dict) or correlation.get("type") != "match":
            continue
        desc = _clean(correlation.get("desc"))
        if not desc or any(skip in desc.lower() for skip in _SKIP_CORRELATIONS):
            continue
        confidence = _corr_confidence(desc)
        if confidence:
            _add_link(links, link_seen, "correlation", desc,
                      _clean(correlation.get("detail")), confidence)

    # ── conflicts: only where WHOIS is actually linked to the person ─
    if whois_linked:
        if social_location and who_country and not _location_matches(social_location, who_country):
            conflicts.append({
                "kind": "location",
                "desc": f"Profile location \"{social_location}\" differs from WHOIS country \"{who_country}\"",
                "values": [social_location, who_country],
            })
        region = _clean(number_info.get("region"))
        if region and who_country and not _phone_region_matches(region, who_country):
            conflicts.append({
                "kind": "phone-region",
                "desc": f"Phone region {region} differs from WHOIS country \"{who_country}\"",
                "values": [region, who_country],
            })
        if social_name and who_names and not any(
                _name_matches(social_name, value) for value in who_names):
            conflicts.append({
                "kind": "name",
                "desc": f"Profile name \"{social_name}\" differs from WHOIS name \"{who_names[0]}\"",
                "values": [social_name, who_names[0]],
            })

    # ── breaches: one row per source, merged across legs ───────
    breach_rows: dict[tuple[str, str], dict] = {}
    exposed_fields: set[str] = set()
    for leg in ("email", "username", "phone"):
        sub = results.get(leg)
        if not isinstance(sub, dict) or sub.get("error"):
            continue
        breach = sub.get("breach")
        if not isinstance(breach, dict):
            continue
        for field in breach.get("fields") or []:
            exposed_fields.add(_clean(field))
        found = breach.get("found")
        if isinstance(found, bool):
            found = int(found)
        sources = breach.get("sources") or []
        if sources:
            for source in sources:
                if isinstance(source, dict):
                    name = _clean(source.get("name") or source.get("title") or "unknown")
                    date = _clean(source.get("date") or source.get("breach_date") or "")
                else:
                    name, date = _clean(source), ""
                if not name:
                    continue
                breach_key = (name.lower(), date)
                row = breach_rows.setdefault(
                    breach_key, {"name": name, "date": date, "via": []})
                if leg not in row["via"]:
                    row["via"].append(leg)
        elif found:
            row = breach_rows.setdefault(
                ("breach check", ""),
                {"name": "Breach check", "date": "", "via": [], "count": 0})
            row["count"] = max(row.get("count", 0), int(found))
            if leg not in row["via"]:
                row["via"].append(leg)

    # ── finalize accounts ─────────────────────────────────────
    account_items = list(accounts.values())
    for account in account_items:
        account["via"] = sorted(
            account["via"], key=lambda value: {"email": 0, "username": 1, "social": 2}.get(value, 3))
        account["tools"] = sorted(account["tools"], key=str.lower)
        if ("social" in account["via"] or len(account["via"]) >= 2
                or len(account["tools"]) >= 2):
            account["confidence"] = "high"
        else:
            account["confidence"] = "medium"
    account_items.sort(key=lambda item: (-_rank(item["confidence"]), item["platform"]))

    links.sort(key=lambda item: (-_rank(item["confidence"]), item["desc"].lower()))
    breaches = sorted(breach_rows.values(),
                      key=lambda item: (item["name"].lower(), item["date"]))

    confirmed = sum(1 for item in links if item["confidence"] == "high")
    possible = sum(1 for item in links if item["confidence"] == "possible")

    resolved = bool(account_items or social_name or social_location or links)
    if confirmed:
        confidence = "high"
    elif resolved:
        confidence = "medium"
    else:
        confidence = "unconfirmed"

    context: dict[str, object] = {}
    if website_hosts:
        context["website"] = sorted(website_hosts)[0]
    if context_orgs:
        context["organizations"] = sorted(set(context_orgs))
    if context_names:
        context["names"] = sorted(set(context_names))
    if context_emails:
        context["emails"] = sorted(set(context_emails))
    if context_phones:
        context["phones"] = sorted(set(context_phones))
    if who_country and not whois_linked:
        context["locations"] = [who_country]

    notes: list[str] = []
    if context:
        notes.append("WHOIS values describe the domain, not necessarily the person; "
                     "only values that matched an anchor were attached to the identity.")
    if social and social.get("error"):
        notes.append(f"Social leg failed: {_clean(social.get('error'))}")
    elif social and not social_found:
        notes.append("The social profile was not found, so no profile fields were attached.")

    counts = {
        "anchors": len(anchors),
        "accounts": len(account_items),
        "names": len(names.items()),
        "emails": len(emails.items()),
        "phones": len(phones.items()),
        "links": len(links),
        "confirmed_links": confirmed,
        "possible_links": possible,
        "conflicts": len(conflicts),
        "breaches": len(breaches),
    }

    return {
        "schema": SCHEMA,
        "confidence": confidence,
        "anchors": anchors,
        "names": names.items(),
        "handles": handles.items(),
        "emails": emails.items(),
        "phones": phones.items(),
        "locations": locations.items(),
        "organizations": organizations.items(),
        "domains": domains.items(),
        "websites": websites.items(),
        "accounts": account_items,
        "breaches": breaches,
        "exposed_fields": sorted(field for field in exposed_fields if field),
        "links": links,
        "conflicts": conflicts,
        "context": context,
        "notes": notes,
        "counts": counts,
    }
