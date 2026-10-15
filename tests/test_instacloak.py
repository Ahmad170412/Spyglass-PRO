#!/usr/bin/env python3
"""Offline tests for InstaCloak's parsing/extraction logic.

No network, no browser: exercises JSON-blob extraction, profile/post
normalization (modern 2026 + legacy shapes), contacts, report assembly,
config round-trips, login decisions and story parsing.

Run:  .venv/bin/python tests/test_instacloak.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "spyglass_pro" / "modules"))

from instacloak import auth, contacts, jsonutil, profile, report, social, stories
from instacloak import config as configmod
from instacloak import post as postmod


def html_with_blobs(*payloads) -> str:
    """Wrap JSON payloads in Instagram-style script tags."""
    out = ["<html><head>"]
    for p in payloads:
        out.append(f'<script type="application/json" data-sjs="" data-processed="1">'
                   f'{json.dumps(p)}</script>')
    out.append("</head></html>")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Modern (2026+) fixtures -- what instagram.com actually serves logged-out
# ---------------------------------------------------------------------------

MODERN_USER = {
    "pk": "25025320",
    "username": "modern_user",
    "full_name": "Modern User",
    "biography": "Testing bio. Mail hello@modern.io or +1 555 111 2222 #recon",
    "bio_links": [{"link_type": "external", "url": "https://l.instagram.com/?u=https%3A%2F%2Fexample.com",
                   "title": "My Site", "is_pinned": True}],
    "pronouns": ["he/him"],
    "account_badges": [{"badge": "new"}],
    "is_joined_recently": True,
    "is_memorialized": False,
    "is_coppa_enforced": False,
    "is_unpublished": False,
    "has_any_clips": True,
    "show_text_post_app_badge": False,
    "text_post_app_badge_label": "modern_user",
    "latest_reel_media": 1788364739,
    "lox_highlights_connection": {"edges": [
        {"node": {"id": "hl1", "title": "Travel",
                  "cover_media_cropped_thumbnail_url": "https://cdn/hl1.jpg"}},
    ]},
    "is_private": False,
    "is_verified": True,
    "is_business": False,
    "follower_count": 686_000_000,
    "following_count": 285,
    "all_media_count": 1234,
    "profile_pic_url": "https://scontent.cdninstagram.com/v/...pic.jpg",
}

MODERN_REEL = {
    "id": "987654",
    "pk": "987654",
    "code": "ReelCode123",
    "media_type": 2,
    "taken_at": 1788364739,
    "caption": {"pk": "1811", "text": "A reel #cool @friend1"},
    "like_count": 420156,
    "comment_count": 9084,
    "location": {"name": "Paris, France", "city": "Paris", "country": "FR"},
    "user": {"pk": "1", "username": "modern_user", "is_verified": True},
    "image_versions2": {"candidates": [
        {"width": 1080, "height": 1350, "url": "https://cdn/cover_big.jpg"},
        {"width": 150, "height": 150, "url": "https://cdn/cover_small.jpg"}]},
    "video_versions": [{"height": 1350, "url": "https://cdn/video.mp4"}],
    "usertags": {"in": [{"position": [0, 0], "user": {"username": "tagged_reel"}}]},
}

MODERN_CAROUSEL = {
    "code": "Carousel123",
    "media_type": 8,
    "taken_at": 1700000000,
    "caption": None,
    "like_count": 5,
    "comment_count": 1,
    "user": {"username": "modern_user"},
    "carousel_media": [
        {"media_type": 1, "image_versions2": {"candidates": [
            {"width": 1080, "height": 1080, "url": "https://cdn/one.jpg"}]}},
        {"media_type": 2, "image_versions2": {"candidates": [
            {"width": 1080, "height": 1080, "url": "https://cdn/two_cover.jpg"}]},
         "video_versions": [{"url": "https://cdn/two.mp4"}]},
    ],
}

# ---------------------------------------------------------------------------
# Legacy fixtures -- old GraphQL shapes (still seen via web_profile_info API)
# ---------------------------------------------------------------------------

LEGACY_USER = {
    "id": "12345",
    "username": "legacy_user",
    "full_name": "Legacy User",
    "biography": "Legacy bio biz@legacy.io",
    "external_url": "https://legacy.io",
    "is_private": False,
    "is_verified": False,
    "is_business_account": True,
    "business_category_name": "Agency",
    "business_email": "biz@legacy.io",
    "business_phone_number": "+1 555 987 6543",
    "profile_pic_url_hd": "https://cdn.example/pic_hd.jpg",
    "edge_followed_by": {"count": 1111},
    "edge_follow": {"count": 222},
    "edge_owner_to_timeline_media": {"count": 333, "page_info": {}, "edges": [
        {"node": {
            "id": "a1", "shortcode": "ABC123",
            "display_url": "https://cdn.example/a.jpg", "is_video": False,
            "taken_at_timestamp": 1700000000,
            "edge_media_to_caption": {"edges": [{"node": {"text": "First #hello @friend"}}]},
            "edge_media_preview_like": {"count": 42},
            "edge_media_to_comment": {"count": 3},
            "location": {"name": "Rome"},
            "edge_media_to_tagged_user": {"edges": [{"node": {"user": {"username": "tagged1"}}}]},
            "edge_media_to_parent_comment": {"edges": [
                {"node": {"owner": {"username": "commenter1"}, "text": "nice"}}]},
        }},
    ]},
}

LEGACY_POST = LEGACY_USER["edge_owner_to_timeline_media"]["edges"][0]["node"]

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_modern_profile_extraction():
    html = html_with_blobs({"result": {"data": {
        "xig_user_by_username": MODERN_USER,
        "other": [1, 2, 3]}}})
    blobs = jsonutil.extract_json_blobs(html)
    assert len(blobs) == 1
    found = profile.find_user_in_blobs(blobs, "modern_user")
    assert found is not None and found["username"] == "modern_user"
    prof = profile.norm_profile(found)
    assert prof["counts"] == {"followers": 686_000_000, "following": 285, "posts": 1234}
    assert prof["id"] == "25025320"
    assert prof["is_verified"] is True
    assert prof["external_url"].startswith("https://l.instagram.com")
    assert prof["is_business"] is False
    assert prof["business_contact_exposed"] is False


def test_modern_reel_normalization():
    post = postmod.norm_post(MODERN_REEL)
    assert post["shortcode"] == "ReelCode123"
    assert post["caption"] == "A reel #cool @friend1"
    assert post["likes"] == 420156 and post["comments_count"] == 9084
    assert post["timestamp"] == 1788364739
    assert post["is_video"] is True
    assert post["owner_username"] == "modern_user"
    assert post["media"] == [{"type": "video", "url": "https://cdn/video.mp4"}]
    assert post["tagged_users"] == ["tagged_reel"]
    assert post["location"]["name"] == "Paris, France"
    assert post["comments"] == []


def test_modern_carousel_normalization():
    post = postmod.norm_post(MODERN_CAROUSEL)
    assert post["is_video"] is False
    assert post["caption"] == ""
    assert post["media"] == [
        {"type": "image", "url": "https://cdn/one.jpg"},
        {"type": "video", "url": "https://cdn/two.mp4"},
    ]


def test_modern_post_found_in_blobs():
    html = html_with_blobs({"page": {"data": {"xdt_media": MODERN_REEL}},
                            "other": {"code": "OtherCode123", "like_count": 1}})
    found = postmod.find_post_in_blobs(jsonutil.extract_json_blobs(html), "ReelCode123")
    assert found and found["caption"] == "A reel #cool @friend1"
    assert postmod.find_post_in_blobs(jsonutil.extract_json_blobs(html), "Missing") is None


def test_legacy_profile_and_post():
    prof = profile.norm_profile(LEGACY_USER)
    assert prof["counts"] == {"followers": 1111, "following": 222, "posts": 333}
    assert prof["business_email"] == "biz@legacy.io"
    assert prof["business_phone_number"] == "+1 555 987 6543"
    assert prof["business_contact_exposed"] is True
    assert prof["business_category"] == "Agency"
    assert prof["profile_pic_url"].endswith("pic_hd.jpg")
    assert prof["recent_posts"][0]["shortcode"] == "ABC123"

    post = postmod.norm_post(LEGACY_POST)
    assert post["shortcode"] == "ABC123"
    assert post["caption"] == "First #hello @friend"
    assert post["likes"] == 42 and post["comments_count"] == 3
    assert post["location"]["name"] == "Rome"
    assert post["tagged_users"] == ["tagged1"]
    assert post["comments"] == [{"username": "commenter1", "text": "nice"}]
    assert post["media"] == [{"type": "image", "url": "https://cdn.example/a.jpg"}]


def test_legacy_blob_and_deep_find():
    html = """
    <html><head>
    <script>window.__additionalDataLoaded('profile',{"data":{"user":LEGACY}});</script>
    <script>window._sharedData = {"entry_data":{"ProfilePage":[
        {"graphql":{"user":{"username":"shared1","biography":"yo",
         "edge_followed_by":{"count":6},
         "edge_owner_to_timeline_media":{"count":2}}}}]}};</script>
    </head></html>""".replace("LEGACY", json.dumps(LEGACY_USER))
    blobs = jsonutil.extract_json_blobs(html)
    assert len(blobs) >= 2
    found = profile.find_user_in_blobs(blobs, "legacy_user")
    assert found and found["username"] == "legacy_user"
    found2 = profile.find_user_in_blobs(blobs, "shared1")
    assert found2 and found2["biography"] == "yo"


def test_brace_matching_edge_cases():
    s = '{"a": {"b": "}x{"}, "c": [1,2,{"d":3}]}'
    assert json.loads(jsonutil._match_braces(s, 0))["c"][2]["d"] == 3
    assert jsonutil._match_braces('not json', 0) is None
    arr = '[{"x": 1}, {"y": "]"}]'
    assert json.loads(jsonutil._match_braces(arr, 0))[1]["y"] == "]"


def test_contacts():
    prof = profile.norm_profile(LEGACY_USER)
    post = postmod.norm_post(LEGACY_POST)
    cts = contacts.collect_contacts(prof, [post])
    assert "biz@legacy.io" in cts["emails"]
    assert "+1 555 987 6543" in cts["phones"]
    modern = profile.norm_profile(MODERN_USER)
    m_contacts = contacts.collect_contacts(modern, [postmod.norm_post(MODERN_REEL)])
    assert "hello@modern.io" in m_contacts["emails"]
    assert any("555" in p for p in m_contacts["phones"])
    assert "bio" in m_contacts["sources"]


def test_aggregations_and_wall_regex():
    prof = profile.norm_profile(MODERN_USER)
    post = postmod.norm_post(MODERN_REEL)
    texts = [prof["biography"], post["caption"]]
    assert contacts.count_matches(texts, contacts.HASHTAG_RE).get("recon") == 1
    assert contacts.count_matches(texts, contacts.HASHTAG_RE).get("cool") == 1
    assert contacts.count_matches(texts, contacts.MENTION_RE).get("friend1") == 1
    assert social.detect_login_wall("instagram\n686M followers\nLog in to see who follows")
    assert social.detect_login_wall("Sign up to see more posts from @modern_user")
    assert not social.detect_login_wall("Log in\nSign up\ninstagram\n686M followers\n285 following")
    assert not social.detect_login_wall("No log in here, just posts and captions")


def test_deep_metadata_extraction():
    """Extra logged-out metadata: badges, pronouns, highlights, bio link titles."""
    prof = profile.norm_profile(MODERN_USER)
    assert prof["pronouns"] == ["he/him"]
    assert "new" in prof["account_badges"]
    assert prof["is_joined_recently"] is True
    assert prof["is_memorialized"] is False
    assert prof["has_any_clips"] is True
    assert prof["last_reel_at"] and prof["last_reel_at"].startswith("2026-")
    assert prof["highlights"][0]["title"] == "Travel"
    assert prof["highlights"][0]["cover_url"].startswith("https://cdn/")
    assert prof["bio_links"][0]["title"] == "My Site"
    assert prof["bio_links"][0]["is_pinned"] is True
    assert prof["bio_links"][0]["url"].startswith("https://l.instagram.com/")


def test_login_config_roundtrip():
    """save_login_config writes/replaces [login], preserving other sections."""
    import tempfile

    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10: tomli backport (requirements.txt)
        import tomli as tomllib

    with tempfile.TemporaryDirectory() as tmp:
        cfg = Path(tmp) / "config.toml"
        cfg.write_text("[instacloak]\nheadless = true\n", encoding="utf-8")
        p = configmod.save_login_config(str(cfg), "burner_1", 'p@ss"word\\x')
        assert str(cfg) == p
        data = tomllib.loads(cfg.read_text(encoding="utf-8"))
        assert data["login"]["enabled"] is True
        assert data["login"]["username"] == "burner_1"
        assert data["login"]["password"] == 'p@ss"word\\x'
        assert data["instacloak"]["headless"] is True  # other section preserved
        # replacing updates values, doesn't duplicate the section
        configmod.save_login_config(str(cfg), "burner_2", "newpass", enabled=False)
        data = tomllib.loads(cfg.read_text(encoding="utf-8"))
        assert data["login"]["username"] == "burner_2"
        assert data["login"]["enabled"] is False
        assert cfg.read_text(encoding="utf-8").count("[login]") == 1


def test_login_needed_decision():
    """login_needed: logged-out pages need the flow; logged-in ones don't."""
    assert auth.login_needed({}) is True
    assert auth.login_needed({"loginCtas": 1, "home": False}) is True
    assert auth.login_needed({"loginCtas": 0, "home": True}) is False
    assert auth.login_needed({"loginCtas": 0, "avatar": True}) is False
    assert auth.login_needed({"loginCtas": 0, "inbox": True}) is False


def test_stories_parse():
    """parse_stories flattens the story tray API shape."""
    items = [{
        "pk": "story_1", "taken_at": 1788364739, "expiring_at": 1788451139,
        "media_type": 2,
        "image_versions2": {"candidates": [{"width": 1080, "url": "https://cdn/story.jpg"}]},
        "video_versions": [{"height": 1920, "url": "https://cdn/story.mp4"}],
    }, {"pk": "story_2", "taken_at": 1788364740, "expiring_at": 1788451140}]
    out = stories.parse_stories(items)
    assert len(out) == 2
    # media_type 2 (video): the mp4 must come first so downloads grab the
    # real file, not the poster frame
    assert out[0]["urls"] == ["https://cdn/story.mp4", "https://cdn/story.jpg"]
    assert out[1]["urls"] == []
    assert out[0]["expiring_at"] == 1788451139


def test_list_wall_verification():
    """The login wall's suggested-account pool must never pass as a real list."""
    # Genuine list dialog: has a Followers/Following header, no login CTA
    assert social._list_looks_real({"hasDialog": True, "loginCta": False, "listHeader": True})
    # Login wall: dialog with login/signup CTAs and no list header
    assert not social._list_looks_real({"hasDialog": True, "loginCta": True, "listHeader": False})
    # Login wall: suggestion dialog with no list header
    assert not social._list_looks_real({"hasDialog": True, "loginCta": False, "listHeader": False})
    # No dialog rendered at all (full-page wall / nothing)
    assert not social._list_looks_real({"hasDialog": False})
    assert not social._list_looks_real(None)
    assert not social._list_looks_real({})


def test_dom_profile_fallback():
    """Page-text scraping rescues counts/name when the API is throttled."""
    private_text = ("teamleaderistrue\nThe Team Leader\n3 posts\n61 followers\n"
                    "801 following\nFollow\nThis profile is private\n"
                    "Follow to see their photos and videos.\nSuggested for you")
    prof = profile.profile_from_dom_text(private_text, False, "teamleaderistrue")
    assert prof["counts"] == {"posts": 3, "followers": 61, "following": 801}
    assert prof["is_private"] is True
    assert prof["full_name"] == "The Team Leader"
    assert prof["id"] is None and prof["biography"] is None

    public_text = ("natgeo\nNational Geographic\n268.6M followers\n194 "
                   "following\n12 posts\nStep into wonder")
    prof = profile.profile_from_dom_text(public_text, True, "natgeo")
    assert prof["counts"]["followers"] == 268_600_000
    assert prof["counts"]["following"] == 194
    assert prof["counts"]["posts"] == 12
    assert prof["is_private"] is False and prof["is_verified"] is True
    assert prof["full_name"] == "National Geographic"

    # nothing recognizable -> no profile (never fabricate)
    assert profile.profile_from_dom_text("just some text", False, "x")["counts"] \
        == {"posts": None, "followers": None, "following": None}


def test_stripped_node_business_unknown():
    """A logged-out node stripped of professional fields must say unknown,
    never a fabricated False."""
    stripped = {k: v for k, v in MODERN_USER.items() if k != "is_business"}
    prof = profile.norm_profile(stripped)
    assert prof["is_business"] is None
    assert prof["business_contact_exposed"] is None
    assert prof["business_category"] is None


def test_professional_contact_flags():
    """Contact-button tri-state across node shapes."""
    n = dict(LEGACY_USER)
    n.pop("business_email")
    n.pop("business_phone_number")
    prof = profile.norm_profile(n)
    assert prof["is_business"] is True
    assert prof["business_contact_exposed"] is None  # professional but no payload
    n["should_show_public_contacts"] = False
    assert profile.norm_profile(n)["business_contact_exposed"] is False
    n["public_email"] = "hi@shop.io"
    prof = profile.norm_profile(n)
    assert prof["business_contact_exposed"] is True
    assert prof["business_email"] == "hi@shop.io"


def test_markdown_render():
    """render_markdown covers profile, posts, social graph, media, notes."""
    prof = profile.norm_profile(LEGACY_USER)
    post = postmod.norm_post(LEGACY_POST)
    rep = report.build_report({}, "legacy_user", prof, "ok", [post],
                              ([], True), ([], True),
                              ["media/ABC123.jpg"], ["followers list login-walled"], 0.0)
    md = report.render_markdown(rep)
    assert md.startswith("# InstaCloak report — @legacy_user")
    assert "Legacy bio biz@legacy.io" in md
    assert "| business | True |" in md
    assert "| category | Agency |" in md
    assert "| contact button | yes (email, phone) |" in md
    assert "| hello | 1 |" in md              # hashtag table row
    assert "https://www.instagram.com/p/ABC123/" in md
    assert "login-walled" in md
    assert "media/ABC123.jpg" in md
    assert "@commenter1" in md
    assert md.endswith("*Public data only. Use responsibly.*\n")


def test_markdown_escapes_and_write():
    """Cell text is escaped; controls stripped; write_markdown lands report.md."""
    import tempfile

    fake = {"username": "x", "full_name": None,
            "biography": "a | b \x1b[31mred\x1b[0m\nsecond line",
            "counts": {"followers": 1, "following": 0, "posts": 0},
            "is_private": False, "is_verified": False, "is_business": False,
            "bio_links": [], "highlights": [], "pronouns": [],
            "account_badges": [], "related_profiles": []}
    rep = report.build_report({}, "x", fake, "ok", [], ([], True), ([], True),
                              [], [], 0.0)
    md = report.render_markdown(rep)
    assert "\\|" in md                     # pipe escaped inside the table
    assert "\x1b" not in md                # ANSI stripped
    # newlines collapsed to one line and the pipe escaped in the bio cell
    assert "> a \\| b [31mred[0m second line" in md
    with tempfile.TemporaryDirectory() as tmp:
        p = report.write_markdown(rep, Path(tmp))
        assert p.name == "report.md"
        assert p.read_text(encoding="utf-8").startswith("# InstaCloak report")


def test_zero_counts_preserved():
    """A post with 0 likes/comments/views must report 0, not None."""
    zero = {"code": "Zero123", "like_count": 0, "comment_count": 0,
            "video_view_count": 0, "media_type": 1, "caption": "no engagement",
            "user": {"username": "modern_user"}}
    post = postmod.norm_post(zero)
    assert post["likes"] == 0
    assert post["comments_count"] == 0
    assert post["video_views"] == 0


def test_terminal_output_sanitized():
    """Attacker-controlled text (bios/captions) can't inject ANSI/control chars."""
    from instacloak.ui import c
    nasty = "bio \x1b[31mRED\x1b[0m \x07 bell \x1b]0;title\x07"
    cleaned = c(nasty, "bold")
    assert "\x1b" not in cleaned
    assert "\x07" not in cleaned
    assert "RED" in cleaned and "bell" in cleaned


def test_safe_dir_name_blocks_traversal():
    """Usernames used as filesystem components can never escape the base dir."""
    from instacloak.session import safe_dir_name
    assert safe_dir_name("mrbeast") == "mrbeast"
    assert safe_dir_name("a/b\\c") == "a_b_c"
    assert safe_dir_name("..") == "target"
    for evil in ("../evil", "../../etc/passwd", "..\\..\\windows", "....////etc"):
        out = safe_dir_name(evil)
        assert "/" not in out and "\\" not in out, out
        assert Path(out).name == out, out  # single component, never ".."


def test_report_assembly():
    prof = profile.norm_profile(LEGACY_USER)
    post = postmod.norm_post(LEGACY_POST)
    rep = report.build_report({}, "legacy_user", prof, "ok", [post],
                              (["f1", "f2"], True), ([], True),
                              ["media/ABC123.jpg"], [], 0.0)
    assert rep["profile_status"] == "ok"
    assert rep["followers"]["collected"] == 2 and rep["followers"]["walled"] is True
    assert rep["hashtags"]["hello"] == 1
    assert rep["posts_count"] == 1
    assert rep["contacts"]["emails"][0] == "biz@legacy.io"


def test_login_mode_parsing():
    """Run-mode answers map correctly; empty defaults to logged out."""
    from instacloak import cli
    assert cli.parse_run_mode("2") is True
    assert cli.parse_run_mode("burner") is True
    assert cli.parse_run_mode("logged in") is True
    assert cli.parse_run_mode("1") is False
    assert cli.parse_run_mode("") is False       # Enter -> logged out
    assert cli.parse_run_mode("logged out") is False
    assert cli.parse_run_mode("x") is None       # unrecognized
    assert cli.login_creds_configured({"login_username": "", "login_password": ""}) is False
    assert cli.login_creds_configured({"login_username": "b", "login_password": "p"}) is True


def test_ask_run_mode_io():
    """ask_run_mode reads the choice and aborts cleanly on EOF."""
    import contextlib
    import io

    from instacloak import cli

    class NonTty(io.StringIO):
        def isatty(self):
            return False

    cfg = {"login_username": "burner_1", "login_password": "pw"}
    old_stdin = sys.stdin
    try:
        sys.stdin = NonTty("2\n")
        assert cli.ask_run_mode(cfg) is True
        sys.stdin = NonTty("\n")
        assert cli.ask_run_mode(cfg) is False        # Enter defaults logged out
        sys.stdin = NonTty("")
        assert cli.ask_run_mode(cfg) is None         # EOF aborts
        sys.stdin = NonTty("zzz\nzzz\n")
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.ask_run_mode(cfg) is False    # garbage twice -> default
    finally:
        sys.stdin = old_stdin


def test_mode_flag_parses():
    """--mode login|logout is honored; other values are rejected."""
    from instacloak import cli
    old_argv = sys.argv
    try:
        sys.argv = ["instacloak", "-u", "natgeo", "--mode", "login"]
        assert cli.cli_args().mode == "login"
        sys.argv = ["instacloak", "--mode", "logout"]
        assert cli.cli_args().mode == "logout"
        sys.argv = ["instacloak", "-u", "natgeo"]
        assert cli.cli_args().mode is None
    finally:
        sys.argv = old_argv


def test_mode_asked_before_target():
    """With creds configured, the mode question precedes the target prompt."""
    import argparse
    import contextlib
    import io

    from instacloak import cli

    class NonTty(io.StringIO):
        def isatty(self):
            return False

    cfg = {"login_username": "burner_1", "login_password": "pw"}
    old_stdin = sys.stdin
    buf = io.StringIO()
    try:
        sys.stdin = NonTty("2\nnatgeo\nn\n")   # mode=login, target, decline proceed
        args = argparse.Namespace(username=None, yes=False, mode=None)
        with contextlib.redirect_stdout(buf):
            cli.run_osint(cfg, args)
    finally:
        sys.stdin = old_stdin
    out = buf.getvalue()
    assert out.index("mode [1/2]") < out.index("target username")
    assert out.index("target username") < out.index("Proceed?")
    assert "mode: logged in as @burner_1" in out


def test_non_tty_without_username_aborts_with_hint():
    """A piped/CI run with no -u must exit gracefully with a usage hint,
    never spin the menu or EOF-traceback."""
    import contextlib
    import io

    from instacloak import cli

    class NonTty(io.StringIO):
        def isatty(self):
            return False

    old_stdin, old_argv = sys.stdin, sys.argv
    buf = io.StringIO()
    try:
        sys.stdin = NonTty("")
        sys.argv = ["instacloak", "--headless"]
        with contextlib.redirect_stdout(buf):
            cli.main()
    finally:
        sys.stdin, sys.argv = old_stdin, old_argv
    out = buf.getvalue()
    assert "non-interactive input detected" in out
    assert "-u <username>" in out
    assert "InstaCloak report" not in out        # never reached the menu


def test_run_osint_eof_at_username_prompt():
    """EOF mid-flow (e.g. Ctrl-D or a short pipe) aborts cleanly, not a traceback."""
    import argparse
    import contextlib
    import io

    from instacloak import cli

    class NonTty(io.StringIO):
        def isatty(self):
            return False

    old_stdin = sys.stdin
    buf = io.StringIO()
    try:
        sys.stdin = NonTty("")
        args = argparse.Namespace(username=None, yes=False, mode=None)
        with contextlib.redirect_stdout(buf):
            cli.run_osint({}, args)               # must not raise EOFError
    finally:
        sys.stdin = old_stdin
    assert "no target given" in buf.getvalue()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\nALL {len(fns)} OFFLINE TESTS PASSED")
