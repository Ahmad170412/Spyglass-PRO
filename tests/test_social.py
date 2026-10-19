"""Tests for the multi-platform social harness.

The adapters' `normalize` functions and the report writer are pure — no
browser, no network — so the mapping from each platform's private JSON
shape onto the normalized schema is verified offline against recorded
fixtures. That is where a silent field-mapping bug would hide: a renamed
key produces a blank cell, not an exception.
"""

import os
import re
import unittest
from pathlib import Path

import helpers  # puts spyglass_pro/modules on sys.path; also gives us the repo root

from spyglass_pro.social import registry, report, schema
from spyglass_pro.social.platforms import instagram

_APP_JS = Path(helpers._ROOT) / "spyglass_pro" / "static" / "js" / "app.js"
_FIELD_ENTRY = re.compile(
    r"key:\s*'(?P<key>[^']+)',\s*label:\s*'(?P<label>[^']+)',\s*type:\s*'(?P<type>[^']+)'"
)


class SchemaTest(unittest.TestCase):
    def test_every_field_starts_empty_not_missing(self):
        result = schema.new_result("instagram", "someone")
        for field in schema.PROFILE_FIELDS:
            self.assertIn(field["key"], result)
            self.assertIsNone(result[field["key"]] if field["type"] != "list" else None)
        self.assertFalse(result["found"])

    def test_unset_fields_are_never_zero(self):
        """"Could not see this" must not become 0 or False."""
        result = schema.new_result("instagram", "someone")
        set_result = result
        schema.set_fields(set_result, follower_count=None, verified=False)
        self.assertIsNone(set_result["follower_count"])
        self.assertIs(set_result["verified"], False)
        # A False bool is hidden from the report; a 0 count is not.
        self.assertNotIn("verified", [f["key"] for f in schema.visible_fields(set_result)])

    def test_set_fields_rejects_unknown_keys(self):
        with self.assertRaises(KeyError):
            schema.set_fields(schema.new_result("instagram", "y"), followers_typo=5)

    def test_notes_are_deduplicated_and_flattened(self):
        result = schema.new_result("instagram", "y")
        schema.add_note(result, "a  note\nwith   spaces")
        schema.add_note(result, "a note with spaces")
        self.assertEqual(result["notes"], ["a note with spaces"])

    def test_walls_record_a_reason(self):
        result = schema.new_result("instagram", "y")
        schema.add_wall(result, "posts", "posts", "needs a login")
        self.assertEqual(result["walls"]["posts"]["why"], "needs a login")

    def test_formatting(self):
        self.assertEqual(schema.format_value({"type": "count"}, 12345), "12,345")
        self.assertEqual(schema.format_value({"type": "bool"}, True), "yes")
        self.assertEqual(schema.format_value({"type": "list"}, ["a", "b"]), "a, b")


class FrontendSchemaMirrorTest(unittest.TestCase):
    """The dashboard renders the profile table from its own copy of the field
    metadata, so the copy has to match ``schema.PROFILE_FIELDS`` exactly.

    Drift here is invisible at runtime: a field missing from the JS table
    renders as a blank row, and a mistyped ``type`` renders a date as
    plain text. Both are silent, which is why they are pinned here.
    """

    def _js_fields(self):
        source = _APP_JS.read_text(encoding="utf-8")
        block = re.search(r"var SOCIAL_FIELDS = \[(?P<body>.*?)\];", source, re.S)
        self.assertIsNotNone(block, "SOCIAL_FIELDS not found in app.js — renamed?")
        return [(m.group("key"), m.group("label"), m.group("type"))
                for m in _FIELD_ENTRY.finditer(block.group("body"))]

    def test_js_field_list_matches_python_schema(self):
        expected = [(f["key"], f["label"], f["type"]) for f in schema.PROFILE_FIELDS]
        self.assertEqual(self._js_fields(), expected)

    def test_every_python_field_is_rendered(self):
        """Guards the specific regression: contact_email was absent from app.js."""
        js_keys = {key for key, _label, _type in self._js_fields()}
        missing = [f["key"] for f in schema.PROFILE_FIELDS if f["key"] not in js_keys]
        self.assertEqual(missing, [], f"fields the dashboard never renders: {missing}")


class RegistryTest(unittest.TestCase):
    def test_bundled_platforms_register(self):
        keys = [platform["key"] for platform in registry.describe()]
        for expected in ("instagram", "mastodon", "bluesky", "github",
                         "gitlab", "keybase"):
            self.assertIn(expected, keys)

    def test_keyless_platforms_need_no_browser_or_login(self):
        for key in ("mastodon", "bluesky", "github", "gitlab", "keybase"):
            platform = registry.get(key)
            self.assertEqual(platform.login, "none")
            self.assertFalse(platform.browser)
        self.assertTrue(registry.get("instagram").browser)

    def test_unknown_platform_is_none(self):
        self.assertIsNone(registry.get("myspace"))
        self.assertIsNone(registry.get(""))

    def test_removed_platforms_are_not_registered(self):
        """X support was removed; the key must not come back through a stale import."""
        self.assertIsNone(registry.get("x"))
        self.assertNotIn("x", [platform["key"] for platform in registry.describe()])

    def test_profile_url_substitution(self):
        platform = registry.get("instagram")
        self.assertEqual(platform.profile_url("example"),
                         "https://www.instagram.com/example/")

    def test_burner_login_forces_a_visible_browser(self):
        """Headless + burner = guaranteed login failure.

        instacloak.auth's challenge hand-off polls a *visible* window for
        120s waiting for a human to clear the verification prompt. With no
        window it burns the timeout and continues logged-out, silently
        losing the feature the operator enabled. So headless loses.
        """
        from spyglass_pro.social import harness

        cfg = harness._cfg_for({
            "headless": True,
            "burner_username": "burner_one",
            "burner_password": "hunter2hunter2",
        })
        self.assertTrue(cfg["login_enabled"])
        self.assertFalse(cfg["headless"], "burner login must not run headless")

    def test_headless_is_honoured_without_a_burner(self):
        from spyglass_pro.social import harness

        cfg = harness._cfg_for({"headless": True})
        self.assertTrue(cfg["headless"])

    def test_partial_burner_credentials_do_not_enable_a_login(self):
        """A username with no password is not a login — it must not force headed."""
        from spyglass_pro.social import harness

        cfg = harness._cfg_for({"headless": True, "burner_username": "only_a_name"})
        self.assertFalse(cfg.get("login_enabled"))
        self.assertTrue(cfg["headless"])


class BurnerProfileTest(unittest.TestCase):
    """The burner profile directory decides how much a rotated account
    inherits from the previous one."""

    def setUp(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _cfg(self, burner="burner_one", **over):
        cfg = {"login_enabled": True, "login_username": burner,
               "login_password": "pw", "profiles_dir": self._tmp.name,
               "headless": False, "proxy_enabled": False, "proxy_url": "",
               "geoip": False, "minimal": False, "output_dir": self._tmp.name,
               "user_data_dir": self._tmp.name, "download_media": False, "deep": False}
        cfg.update(over)
        return cfg

    def _open(self, cfg):
        """Call open_session with the browser stubbed; return the launch kwargs."""
        from unittest import mock

        from instacloak import session

        captured = {}

        def fake_launch(persistent_context=None, **kwargs):
            captured.update(kwargs)
            captured["_persistent_context"] = persistent_context
            return mock.MagicMock()

        with mock.patch.object(session, "launch_persistent_context", fake_launch), \
             mock.patch.object(session, "say", lambda *a, **k: None), \
             mock.patch.object(session, "say_parts", lambda *a, **k: None):
            session.open_session(cfg, "someone")
        return captured

    def test_burner_profile_is_keyed_by_the_burner_username(self):
        captured = self._open(self._cfg("burner_one"))
        self.assertIn("login-burner_one", str(captured["_persistent_context"]))

    def test_rotating_burners_does_not_reuse_the_old_profile(self):
        """A fresh burner must not inherit the previous one's cookies and flags."""
        one = self._open(self._cfg("burner_one"))["_persistent_context"]
        two = self._open(self._cfg("burner_two"))["_persistent_context"]
        self.assertNotEqual(str(one), str(two))

    def test_no_burner_uses_a_per_target_profile(self):
        captured = self._open(self._cfg(burner=None, login_enabled=False,
                                        login_username=None, login_password=None))
        self.assertIn("someone", str(captured["_persistent_context"]))

    def test_profile_name_stays_one_path_component(self):
        """Traversal guard: the result must be a single component, so a
        username can never escape profiles_dir."""
        from instacloak.session import safe_dir_name

        for hostile in ("../../etc/passwd", "a/b", "..", "/abs/path", "x\\y"):
            out = safe_dir_name(hostile)
            self.assertNotIn("/", out, hostile)
            self.assertNotIn("\\", out, hostile)
            self.assertNotIn(os.sep, out, hostile)
            self.assertTrue(out, hostile)

    def test_describe_exposes_capabilities(self):
        for entry in registry.describe():
            self.assertTrue(entry["capabilities"], entry["key"])
            self.assertIn(entry["login"], ("none", "instacloak"))

    def test_a_broken_adapter_does_not_hide_the_others(self):
        """One adapter failing to import must not empty the registry."""
        from unittest import mock

        import spyglass_pro.social.registry as reg

        saved_registry, saved_loaded = dict(reg._REGISTRY), reg._LOADED

        def fake_import(name):
            if name.endswith(".instagram"):
                raise ImportError("boom")
            return reg  # anything non-None; the real module is already imported

        try:
            reg._REGISTRY.clear()
            reg._LOADED = False
            with mock.patch.object(reg.importlib, "import_module", side_effect=fake_import):
                reg.load_all()
            self.assertNotIn("instagram", reg._REGISTRY)
        finally:
            reg._REGISTRY.clear()
            reg._REGISTRY.update(saved_registry)
            reg._LOADED = saved_loaded


MASTODON_ACCOUNT = {
    "id": "1",
    "username": "example",
    "acct": "example",
    "display_name": "Example <b>Person</b>",
    "note": "<p>hello &amp; welcome</p>",
    "url": "https://mastodon.social/@example",
    "avatar": "https://files.masto/a.png",
    "followers_count": 120,
    "following_count": 30,
    "statuses_count": 7,
    "locked": False,
    "bot": False,
    "created_at": "2020-01-02T00:00:00.000Z",
    "fields": [
        {"name": "Web", "value": "<a href=\"https://example.com\">example.com</a>",
         "verified_at": "2021-05-05T00:00:00.000Z"},
        {"name": "Unverified", "value": "nope", "verified_at": None},
    ],
}

MASTODON_STATUSES = [
    {"id": "9", "url": "https://mastodon.social/@example/9",
     "content": "<p>first <a href=\"https://x\">post</a></p>",
     "favourites_count": 4, "replies_count": 1,
     "created_at": "2024-01-01T00:00:00.000Z",
     "media_attachments": [{"type": "image"}]},
]

BLUESKY_PROFILE = {
    "did": "did:plc:abc",
    "handle": "example.bsky.social",
    "displayName": "Example Person",
    "description": "hello  world",
    "avatar": "https://cdn.bsky/avatar",
    "followersCount": 500,
    "followsCount": 60,
    "postsCount": 42,
    "indexedAt": "2023-06-01T00:00:00.000Z",
}

BLUESKY_FEED = [
    {"post": {"uri": "at://did:plc:abc/app.bsky.feed.post/rkey1",
              "likeCount": 8, "replyCount": 2,
              "indexedAt": "2024-02-01T00:00:00.000Z",
              "record": {"text": "hi there", "createdAt": "2024-02-01T00:00:00.000Z"}}},
]


class MastodonNormalizeTest(unittest.TestCase):
    def _result(self, account=None):
        from spyglass_pro.social.platforms import mastodon

        result = schema.new_result("mastodon", "example")
        mastodon.normalize(account if account is not None else MASTODON_ACCOUNT, result)
        return result

    def test_maps_profile_fields_and_strips_html(self):
        result = self._result()
        self.assertTrue(result["found"])
        self.assertEqual(result["display_name"], "Example Person")
        self.assertEqual(result["bio"], "hello & welcome")
        self.assertEqual(result["follower_count"], 120)
        self.assertEqual(result["post_count"], 7)

    def test_only_verified_links_survive(self):
        self.assertEqual(self._result()["external_links"], ["https://example.com"])

    def test_rich_link_markup_yields_the_href(self):
        """Mastodon wraps display hosts in invisible scheme spans, which
        tag-stripping turned into 'https:// example.com' (note the space).
        The href is the verified URL — parse it."""
        from spyglass_pro.social.platforms import mastodon

        result = schema.new_result("mastodon", "example")
        account = dict(MASTODON_ACCOUNT, fields=[
            {"name": "Web",
             "value": '<a href="https://example.com" rel="me"><span class="invisible">https://</span><span>example.com</span></a>',
             "verified_at": "2021-05-05T00:00:00.000Z"},
        ])
        mastodon.normalize(account, result)
        self.assertEqual(result["external_links"], ["https://example.com"])

    def test_non_http_href_is_dropped(self):
        from spyglass_pro.social.platforms import mastodon

        self.assertEqual(mastodon._link_href('<a href="javascript:alert(1)">x</a>'), "")
        self.assertEqual(mastodon._link_href("no anchor here"), "")

    def test_lists_are_walls_not_empty_lists(self):
        result = self._result()
        self.assertIn("followers", result["walls"])
        self.assertIn("following", result["walls"])

    def test_private_and_bot_are_reported(self):
        from spyglass_pro.social.platforms import mastodon

        locked = dict(MASTODON_ACCOUNT, locked=True, bot=True)
        result = schema.new_result("mastodon", "example")
        mastodon.normalize(locked, result)
        self.assertTrue(result["private"])
        self.assertIn("bot", " ".join(result["notes"]))

    def test_missing_account_is_not_found(self):
        self.assertFalse(self._result({})["found"])

    def test_posts_map_counts(self):
        from spyglass_pro.social.platforms import mastodon

        result = self._result()
        mastodon.normalize_posts(MASTODON_STATUSES, result)
        (post,) = result["posts"]
        self.assertEqual(post["caption"], "first post")
        self.assertEqual(post["likes"], 4)
        self.assertEqual(post["comments"], 1)


class BlueskyNormalizeTest(unittest.TestCase):
    def _result(self, profile=None):
        from spyglass_pro.social.platforms import bluesky

        result = schema.new_result("bluesky", "example.bsky.social")
        bluesky.normalize(profile if profile is not None else BLUESKY_PROFILE, result)
        return result

    def test_maps_profile_fields(self):
        result = self._result()
        self.assertTrue(result["found"])
        self.assertEqual(result["display_name"], "Example Person")
        self.assertEqual(result["url"], "https://bsky.app/profile/example.bsky.social")
        self.assertEqual(result["follower_count"], 500)
        self.assertEqual(result["joined"], "2023-06-01T00:00:00.000Z")

    def test_lists_are_walls_not_empty_lists(self):
        result = self._result()
        self.assertIn("followers", result["walls"])
        self.assertIn("following", result["walls"])

    def test_missing_profile_is_not_found(self):
        self.assertFalse(self._result({})["found"])

    def test_feed_maps_to_post_urls(self):
        from spyglass_pro.social.platforms import bluesky

        result = self._result()
        bluesky.normalize_feed(BLUESKY_FEED, "example.bsky.social", result)
        (post,) = result["posts"]
        self.assertEqual(post["url"],
                         "https://bsky.app/profile/example.bsky.social/post/rkey1")
        self.assertEqual(post["caption"], "hi there")
        self.assertEqual(post["likes"], 8)


GITHUB_PROFILE = {
    "login": "octocat",
    "name": "The Octocat",
    "bio": "GitHub mascot",
    "html_url": "https://github.com/octocat",
    "blog": "octocat.github.io",
    "location": "San Francisco",
    "email": "octocat@example.com",
    "twitter_username": "octocat",
    "followers": 9000,
    "following": 9,
    "public_repos": 8,
    "created_at": "2011-01-25T18:44:36Z",
    "avatar_url": "https://avatars.githubusercontent.com/u/583231",
    "type": "User",
}

GITHUB_REPOS = [
    {"id": 1296269, "name": "Hello-World", "full_name": "octocat/Hello-World",
     "description": "My first repository",
     "html_url": "https://github.com/octocat/Hello-World",
     "stargazers_count": 1801, "forks_count": 1500,
     "pushed_at": "2013-01-23T14:27:08Z"},
    {"id": 1296270, "name": "Spoon-Knife", "full_name": "octocat/Spoon-Knife",
     "description": None,
     "html_url": "https://github.com/octocat/Spoon-Knife",
     "stargazers_count": 11150, "forks_count": 126731,
     "pushed_at": "2022-10-07T08:15:01Z"},
]


class GitHubLoginValidationTest(unittest.TestCase):
    """Logins validated locally *before* any request: a malformed target
    fails cheaply and unambiguously instead of generating a 404 that reads
    as a real "no such user" — and without spending any of the sixty
    requests an hour the keyless API allows."""

    def _collect(self, handle):
        from unittest import mock

        from spyglass_pro.social.platforms import github

        result = schema.new_result("github", handle)
        with mock.patch.object(github.httpx, "Client") as client:
            github.collect(None, {}, handle, result)
        client.assert_not_called()  # validation must predate every request
        return result

    def test_valid_logins_pass_the_regex(self):
        from spyglass_pro.social.platforms import github
        for login in ("a", "octocat", "The-Octocat-2", "a" * 39):
            self.assertTrue(github._LOGIN_RE.fullmatch(login), login)

    def test_invalid_logins_never_reach_the_network(self):
        for login in ("-octocat", "octocat-", "octo--cat", "octo cat",
                      "user@example.com", "", "a" * 40, "octo+c/evil"):
            self.assertFalse(self._collect(login)["found"])
        error = self._collect("user@example.com")["error"]
        self.assertIn("not a valid GitHub login", error)


class GitHubNormalizeTest(unittest.TestCase):
    def _result(self, profile=None):
        from spyglass_pro.social.platforms import github

        result = schema.new_result("github", "octocat")
        github.normalize(profile if profile is not None else GITHUB_PROFILE, result)
        return result

    def test_maps_profile_fields(self):
        result = self._result()
        self.assertTrue(result["found"])
        self.assertEqual(result["display_name"], "The Octocat")
        self.assertEqual(result["url"], "https://github.com/octocat")
        self.assertEqual(result["follower_count"], 9000)
        self.assertEqual(result["following_count"], 9)
        self.assertEqual(result["post_count"], 8)
        self.assertEqual(result["joined"], "2011-01-25T18:44:36Z")
        self.assertEqual(result["contact_email"], "octocat@example.com")

    def test_bare_blog_domain_gets_a_scheme(self):
        """The blog field accepts anything; the renderer's link fields are
        scheme-allowlisted, so a bare domain is greedily https'd rather
        than silently dropped from the table at render time."""
        result = self._result()
        self.assertEqual(result["website"], "https://octocat.github.io")

    def test_external_links_cover_blog_and_twitter(self):
        result = self._result()
        self.assertEqual(result["external_links"],
                         ["https://octocat.github.io", "https://x.com/octocat"])

    def test_lists_are_walls_not_empty_lists(self):
        result = self._result()
        self.assertIn("followers", result["walls"])
        self.assertIn("following", result["walls"])

    def test_organization_is_noted_not_fabricated(self):
        profile = dict(GITHUB_PROFILE, type="Organization")
        notes = self._result(profile)["notes"]
        self.assertTrue(any("organization account" in n for n in notes))

    def test_missing_profile_is_not_found(self):
        self.assertFalse(self._result({})["found"])

    def test_repos_map_to_posts(self):
        from spyglass_pro.social.platforms import github

        result = self._result()
        github.normalize_repos(GITHUB_REPOS, result)
        (first, second) = result["posts"]
        self.assertEqual(first["url"], "https://github.com/octocat/Hello-World")
        self.assertEqual(first["caption"], "My first repository")
        self.assertEqual(first["likes"], 1801)      # stars
        self.assertEqual(first["comments"], 1500)   # forks
        self.assertEqual(first["timestamp"], "2013-01-23T14:27:08Z")
        # No description falls back to the repo name — never an empty caption.
        self.assertEqual(second["caption"], "Spoon-Knife")


class GitHubCollectTest(unittest.TestCase):
    """The networked paths, driven offline through mocked _get calls."""

    def _run(self, side_effects, handle="octocat"):
        from unittest import mock

        from spyglass_pro.social.platforms import github

        result = schema.new_result("github", handle)
        with mock.patch.object(github, "_get", side_effect=side_effects):
            github.collect(None, {}, handle, result)
        return result

    def test_success_maps_profile_and_repos(self):
        result = self._run([
            (200, dict(GITHUB_PROFILE), {"x-ratelimit-remaining": "58"}),
            (200, GITHUB_REPOS, {"x-ratelimit-remaining": "57"}),
        ])
        self.assertTrue(result["found"])
        self.assertEqual(result["source"], "api.github.com (keyless)")
        self.assertEqual(len(result["posts"]), 2)

    def test_budget_note_is_on_the_result(self):
        """Sixty an hour per IP is a real limit — the remaining budget must
        be readable from the result, not witnessed by surprise 403s."""
        result = self._run([
            (200, dict(GITHUB_PROFILE), {"x-ratelimit-remaining": "58"}),
            (200, GITHUB_REPOS, {"x-ratelimit-remaining": "57"}),
        ])
        self.assertTrue(any("58/60" in note for note in result["notes"]))

    def test_missing_account_is_a_clear_error(self):
        result = self._run([(404, None, {"x-ratelimit-remaining": "59"})])
        self.assertFalse(result["found"])
        self.assertEqual(result["error"], "no GitHub account found for @octocat")

    def test_exhausted_budget_is_named_not_dropped(self):
        """A 403 on a dry budget must not read as 'no such user'."""
        result = self._run([
            (403, None, {"x-ratelimit-remaining": "0"}),
        ])
        self.assertFalse(result["found"])
        self.assertIn("budget exhausted", result["error"])
        self.assertIn("GITHUB_TOKEN", result["error"])

    def test_403_with_budget_left_names_the_secondary_limit(self):
        """A 403 while the headers still show requests left is NOT the hourly
        budget — without its own message it would tell the operator to mint
        a token they do not need."""
        result = self._run([
            (403, None, {"x-ratelimit-remaining": "59"}),
        ])
        self.assertFalse(result["found"])
        self.assertIn("secondary rate limit", result["error"])
        self.assertNotIn("GITHUB_TOKEN", result["error"])

    def test_token_lets_the_note_name_its_tier(self):
        """With GITHUB_TOKEN in the environment the note says what was
        actually sent — even if GitHub ever reported a keyless-sized
        limit, the wording stays honest about the request's provenance."""
        from unittest import mock

        with mock.patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_zzz"}):
            result = self._run([
                (200, dict(GITHUB_PROFILE),
                 {"x-ratelimit-remaining": "4998",
                  "x-ratelimit-limit": "5000"}),
                (200, GITHUB_REPOS, {}),
            ])
        self.assertTrue(any(
            "GitHub budget (GITHUB_TOKEN authenticated): 4998/5000" in n
            for n in result["notes"]))
        self.assertFalse(any(
            "keyless" in n for n in result["notes"]))

    def test_renamed_account_is_reported_not_swapped(self):
        renamed = dict(GITHUB_PROFILE, login="octocat2")
        result = self._run([
            (200, renamed, {}),
            (200, [], {}),
        ])
        self.assertTrue(result["found"])
        self.assertTrue(any("renamed" in n for n in result["notes"]))

    def test_failing_repos_leg_never_hides_the_profile(self):
        """A partial result is honest: profile data stands, the missing
        repos leg is named."""
        result = self._run([
            (200, dict(GITHUB_PROFILE), {"x-ratelimit-remaining": "58"}),
            (500, None, {}),
        ])
        self.assertTrue(result["found"])
        self.assertTrue(any("repos endpoint failed" in n for n in result["notes"]))


GITLAB_PROFILE = {
    # The short unauthenticated user object, byte-for-byte the fields
    # gitlab.com/api/v4 serves: no bio, no location, no created_at —
    # those are admin-only, so the adapter can never return them.
    "id": 1,
    "username": "sytses",
    "public_email": "sid@example.com",
    "name": "Sid Sijbrandij",
    "state": "active",
    "locked": False,
    "avatar_url": "https://gitlab.com/uploads/-/system/user/avatar/1/a.png",
    "web_url": "https://gitlab.com/sytses",
}

GITLAB_PROJECTS = [
    {"id": 2230440, "name": "dotfiles", "description": "My dotfiles.",
     "web_url": "https://gitlab.com/sytses/dotfiles", "star_count": 17,
     "forks_count": 4, "last_activity_at": "2025-10-27T10:47:39.506Z",
     "visibility": "public"},
    {"id": 72353001, "name": "GitLab", "description": None,
     "web_url": "https://gitlab.com/sytses/gitlab", "star_count": 0,
     "forks_count": 0, "last_activity_at": "2025-08-06T17:01:49.329Z"},
]


class GitLabLoginValidationTest(unittest.TestCase):
    """Handles are validated locally so a typo never burns budget."""

    def _collect(self, handle, result=None):
        from unittest import mock

        from spyglass_pro.social.platforms import gitlab

        result = result or schema.new_result("gitlab", handle)
        with mock.patch.object(gitlab.httpx, "Client") as client:
            gitlab.collect(None, {}, handle, result)
        client.assert_not_called()  # validation must predate every request
        return result

    def test_valid_handles_pass_the_regex(self):
        from spyglass_pro.social.platforms import gitlab
        # dots, hyphens and underscores are legal *inside* a namespace
        for handle in ("a", "sytses", "a-b_c.d", "0x-user.name", "A" * 255):
            self.assertTrue(gitlab._LOGIN_RE.fullmatch(handle), handle)

    def test_invalid_handles_never_reach_the_network(self):
        for handle in ("-octo", ".octo", "_octo", "octo cat", "user@example.com",
                       "", "a" * 256, "octo+evil"):
            self.assertFalse(self._collect(handle)["found"])
        error = self._collect("user@example.com")["error"]
        self.assertIn("not a valid GitLab handle", error)


class GitLabNormalizeTest(unittest.TestCase):
    def _result(self, profile=None):
        from spyglass_pro.social.platforms import gitlab

        result = schema.new_result("gitlab", "sytses")
        gitlab.normalize(profile if profile is not None else GITLAB_PROFILE,
                         result)
        return result

    def test_maps_the_fields_the_short_object_actually_has(self):
        result = self._result()
        self.assertTrue(result["found"])
        self.assertEqual(result["display_name"], "Sid Sijbrandij")
        self.assertEqual(result["url"], "https://gitlab.com/sytses")
        self.assertEqual(result["contact_email"], "sid@example.com")
        self.assertEqual(result["avatar_url"],
                         GITLAB_PROFILE["avatar_url"])

    def test_admin_only_fields_stay_unset_not_zero_or_made_up(self):
        """Bio/location/website/joined simply do not exist in the keyless
        object — the schema's unset-empty rule covers the rest, and the
        capability list never promises them. A silent-looking zero here
        would read as '0 followers', which is not an answer the API gave."""
        result = self._result()
        self.assertIsNone(result["bio"])
        self.assertIsNone(result["location"])
        self.assertIsNone(result["joined"])
        self.assertIsNone(result["follower_count"])

    def test_published_public_email_only_when_nonempty(self):
        result = self._result(dict(GITLAB_PROFILE, public_email=""))
        self.assertIsNone(result["contact_email"])
        result = self._result(dict(GITLAB_PROFILE, public_email=None))
        self.assertIsNone(result["contact_email"])

    def test_state_and_locked_are_notes_not_silent(self):
        notes = self._result(
            dict(GITLAB_PROFILE, state="banned"))["notes"]
        self.assertTrue(any("'banned'" in n for n in notes))
        notes = self._result(dict(GITLAB_PROFILE, locked=True))["notes"]
        self.assertTrue(any("locked" in n for n in notes))
        # An ordinary active account generates no state noise.
        self.assertFalse(any("state" in n
                             for n in self._result()["notes"]))

    def test_missing_profile_is_not_found(self):
        self.assertFalse(self._result({})["found"])

    def test_projects_map_to_posts(self):
        from spyglass_pro.social.platforms import gitlab

        result = self._result()
        gitlab.normalize_projects(GITLAB_PROJECTS, result)
        (first, second) = result["posts"]
        self.assertEqual(first["url"], "https://gitlab.com/sytses/dotfiles")
        self.assertEqual(first["caption"], "My dotfiles.")
        self.assertEqual(first["likes"], 17)    # stars
        self.assertEqual(first["comments"], 4)  # forks
        self.assertEqual(first["timestamp"], "2025-10-27T10:47:39.506Z")
        # No description falls back to the project name, like the repos
        # leg of the GitHub adapter — never an empty caption.
        self.assertEqual(second["caption"], "GitLab")


class GitlabCollectTest(unittest.TestCase):
    """The networked paths, driven offline through mocked _get calls."""

    def _run(self, side_effects, handle="sytses"):
        from unittest import mock

        from spyglass_pro.social.platforms import gitlab

        result = schema.new_result("gitlab", handle)
        with mock.patch.object(gitlab, "_get", side_effect=side_effects):
            gitlab.collect(None, {}, handle, result)
        return result

    def test_success_maps_profile_and_projects(self):
        headers = {"ratelimit-limit": "500", "ratelimit-remaining": "497"}
        result = self._run([
            (200, [dict(GITLAB_PROFILE)], headers),
            (200, GITLAB_PROJECTS,
             {**headers, "x-total": "22"}),
        ])
        self.assertTrue(result["found"])
        self.assertEqual(result["source"], "gitlab.com/api/v4 (keyless)")
        self.assertEqual(len(result["posts"]), 2)
        # GitLab's own X-Total is the real public-project count.
        self.assertEqual(result["post_count"], 22)
        self.assertTrue(any("X-Total" in n for n in result["notes"]))
        self.assertTrue(any("of 22 public projects" in n
                            for n in result["notes"]))

    def test_budget_note_reads_the_headers(self):
        headers = {"ratelimit-limit": "500", "ratelimit-remaining": "494"}
        result = self._run([
            (200, [dict(GITLAB_PROFILE)], headers),
            (200, GITLAB_PROJECTS, headers),
        ])
        self.assertTrue(any("494/500" in n for n in result["notes"]))

    def test_token_changes_the_wording_not_the_math(self):
        """Scope follows the request (GITLAB_TOKEN sent), never a guess
        from the limit — GitLab serves some lookups with limit buckets
        smaller than 500, and calling those 'authenticated' would be a
        lie exactly where an operator is debugging throttles."""
        from unittest import mock

        with mock.patch.dict("os.environ", {"GITLAB_TOKEN": "glpat-zzz"}):
            result = self._run([
                (200, [dict(GITLAB_PROFILE)],
                 {"ratelimit-limit": "1", "ratelimit-remaining": "0"}),
                (200, GITLAB_PROJECTS, {}),
            ])
        self.assertTrue(any(
            "GitLab budget (GITLAB_TOKEN authenticated): 0/1" in n
            for n in result["notes"]))
        self.assertFalse(any(
            "keyless" in n for n in result["notes"]))

    def test_missing_account_is_exact_because_the_miss_is_cheap(self):
        """GET /users?username=X answers with an empty list — so 'no such
        user' is exact here, not silence behind a throttled request."""
        result = self._run([
            (200, [], {"ratelimit-limit": "500",
                       "ratelimit-remaining": "499"}),
        ])
        self.assertFalse(result["found"])
        self.assertEqual(result["error"],
                         "no GitLab account found for @sytses")

    def test_exhausted_budget_is_named_with_its_reset(self):
        """A 429 on a dry per-minute window must not read as 'no such user'."""
        result = self._run([
            (429, None, {"ratelimit-limit": "500",
                         "ratelimit-remaining": "0"}),
        ])
        self.assertFalse(result["found"])
        self.assertIn("budget exhausted", result["error"])
        self.assertIn("500 requests/minute", result["error"])

    def test_403_with_budget_left_names_the_secondary_limit(self):
        result = self._run([
            (403, None, {"ratelimit-limit": "500",
                         "ratelimit-remaining": "500"}),
        ])
        self.assertFalse(result["found"])
        self.assertIn("secondary rate limit", result["error"])
        self.assertNotIn("budget exhausted", result["error"])

    def test_failing_projects_leg_never_hides_the_profile(self):
        """A partial result is honest: the profile stands, the missing
        projects leg is named, and no count is invented without X-Total."""
        headers = {"ratelimit-limit": "500", "ratelimit-remaining": "497"}
        result = self._run([
            (200, [dict(GITLAB_PROFILE)], headers),
            (500, None, {}),
        ])
        self.assertTrue(result["found"])
        self.assertIsNone(result["post_count"])   # unset, never a fake zero
        self.assertTrue(any("recent projects unavailable" in n
                            for n in result["notes"]))

    def test_total_without_recent_list_stays_totalled(self):
        """X-Total arrives even when the *first* page is empty; a zero
        public-project account must not be denoted by a missing count."""
        headers = {"ratelimit-limit": "500", "ratelimit-remaining": "494"}
        result = self._run([
            (200, [dict(GITLAB_PROFILE)], headers),
            (200, [], {"x-total": "0"}),
        ])
        self.assertTrue(result["found"])
        self.assertIsNone(result["post_count"])   # 0 is a count; None isn't
        self.assertFalse(any("X-Total" in n for n in result["notes"]))


# The public lookup object, trimmed to the fields the adapter asks for. The
# proofs carry a canonical ``service_url`` and a ``state`` (1 = proven), and
# the response nests the profile under ``basics``/``profile``/``pictures``.
KEYBASE_USER = {
    "id": "23260c2ce19420f97b58d7d95b68ca00",
    "basics": {"username": "chris", "ctime": 1391653108, "id_version": 1285},
    "profile": {
        "full_name": "Chris Coyne",
        "location": "Maine",
        "bio": "Previously worked on Keybase, OkCupid.",
    },
    "proofs_summary": {
        "all": [
            {"proof_type": "twitter", "nametag": "malgorithms", "state": 1,
             "service_url": "https://twitter.com/malgorithms"},
            {"proof_type": "github", "nametag": "malgorithms", "state": 1,
             "service_url": "https://github.com/malgorithms"},
            {"proof_type": "reddit", "nametag": "malgorithms", "state": 1,
             "service_url": "https://reddit.com/user/malgorithms"},
            {"proof_type": "hackernews", "nametag": "malgorithms", "state": 1,
             "service_url": "https://news.ycombinator.com/user?id=malgorithms"},
            {"proof_type": "generic_web_site", "nametag": "chriscoyne.com",
             "state": 1, "service_url": "https://chriscoyne.com"},
        ],
        "cryptocurrency": [{"type": "bitcoin", "address": "3LKaAcHgUjaB3Zw"}],
    },
    "pictures": {"primary": {"url": "https://s3.example/chris_360.jpg"}},
}


class KeybaseLoginValidationTest(unittest.TestCase):
    """Handles are validated locally so a typo never spends a request."""

    def _collect(self, handle):
        from unittest import mock

        from spyglass_pro.social.platforms import keybase

        result = schema.new_result("keybase", handle)
        with mock.patch.object(keybase.httpx, "Client") as client:
            keybase.collect(None, {}, handle, result)
        client.assert_not_called()
        return result

    def test_valid_handles_pass_the_regex(self):
        from spyglass_pro.social.platforms import keybase
        # 2-16 chars, letters/digits/underscore, first char alphanumeric.
        for handle in ("a1", "chris", "a_b", "x_y", "A" * 16):
            self.assertTrue(keybase._LOGIN_RE.fullmatch(handle), handle)

    def test_invalid_handles_never_reach_the_network(self):
        for handle in ("", "a", "-chris", "_chris", "chris-x", "chris x",
                       "user@example.com", "A" * 17):
            self.assertFalse(self._collect(handle)["found"])
        self.assertIn("not a valid Keybase username",
                      self._collect("user@example.com")["error"])


class KeybaseNormalizeTest(unittest.TestCase):
    def _result(self, profile=None):
        from spyglass_pro.social.platforms import keybase

        result = schema.new_result("keybase", "chris")
        keybase.normalize(profile if profile is not None else KEYBASE_USER,
                          result)
        return result

    def test_maps_profile_fields(self):
        result = self._result()
        self.assertTrue(result["found"])
        self.assertEqual(result["display_name"], "Chris Coyne")
        self.assertEqual(result["location"], "Maine")
        self.assertEqual(result["url"], "https://keybase.io/chris")
        self.assertEqual(result["avatar_url"], "https://s3.example/chris_360.jpg")

    def test_joined_is_derived_from_ctime_epoch(self):
        self.assertEqual(self._result()["joined"], "2014-02-06T02:18:28Z")

    def test_proven_proofs_become_external_links(self):
        """The proof graph is the reason this adapter exists: verified
        identities, taken from Keybase's own canonical service_url."""
        links = self._result()["external_links"]
        self.assertIn("https://github.com/malgorithms", links)
        self.assertIn("https://news.ycombinator.com/user?id=malgorithms", links)
        self.assertIn("https://chriscoyne.com", links)
        self.assertEqual(len(links), 5)
        self.assertTrue(any("5 proven identity proof" in n
                            for n in self._result()["notes"]))

    def test_unverified_proofs_are_not_counted_as_identities(self):
        profile = dict(KEYBASE_USER)
        profile["proofs_summary"] = dict(KEYBASE_USER["proofs_summary"])
        profile["proofs_summary"]["all"] = KEYBASE_USER["proofs_summary"]["all"] + [
            {"proof_type": "twitter", "nametag": "ghost", "state": 0,
             "service_url": "https://twitter.com/ghost"},
        ]
        result = self._result(profile)
        self.assertNotIn("https://twitter.com/ghost", result["external_links"])
        self.assertTrue(any("not counted" in n for n in result["notes"]))

    def test_crypto_addresses_are_surfaced(self):
        notes = " ".join(self._result()["notes"])
        self.assertIn("cryptocurrency address", notes)
        self.assertIn("bitcoin", notes)

    def test_followers_are_a_wall_not_an_empty_list(self):
        self.assertIn("followers", self._result()["walls"])

    def test_missing_profile_is_not_found(self):
        self.assertFalse(self._result({})["found"])

    def test_no_proofs_says_so(self):
        profile = dict(KEYBASE_USER, proofs_summary={})
        notes = " ".join(self._result(profile)["notes"])
        self.assertIn("no proven identity proofs", notes)


class KeybaseCollectTest(unittest.TestCase):
    """The networked paths, driven offline through mocked _get calls."""

    def _run(self, side_effects, handle="chris"):
        from unittest import mock

        from spyglass_pro.social.platforms import keybase

        result = schema.new_result("keybase", handle)
        with mock.patch.object(keybase, "_get", side_effect=side_effects):
            keybase.collect(None, {}, handle, result)
        return result

    def test_success_maps_profile_and_proofs(self):
        result = self._run([
            (200, {"status": {"code": 0}, "them": [dict(KEYBASE_USER)]}),
        ])
        self.assertTrue(result["found"])
        self.assertEqual(result["source"], "keybase.io public lookup (keyless)")
        self.assertIn("https://github.com/malgorithms", result["external_links"])

    def test_null_in_them_is_an_exact_miss(self):
        result = self._run([(200, {"status": {"code": 0}, "them": [None]})])
        self.assertFalse(result["found"])
        self.assertEqual(result["error"], "no Keybase account found for @chris")

    def test_api_input_error_is_surfaced_not_hidden(self):
        result = self._run([
            (200, {"status": {"code": 100, "name": "INPUT_ERROR",
                              "desc": "bad list value"}}),
        ])
        self.assertFalse(result["found"])
        self.assertIn("bad list value", result["error"])

    def test_http_failure_is_named(self):
        result = self._run([(500, None)])
        self.assertFalse(result["found"])
        self.assertIn("HTTP 500", result["error"])

    def test_different_returned_username_is_noted(self):
        """Keybase usernames are immutable, so a differing return is a sign
        the API resolved something else — surfaced, not swallowed."""
        profile = dict(KEYBASE_USER)
        profile["basics"] = dict(KEYBASE_USER["basics"], username="chris")
        result = self._run([(200, {"status": {"code": 0},
                                   "them": [profile]})], handle="chriscoyne")
        self.assertTrue(any("resolves to" in n for n in result["notes"]))


INSTAGRAM_REPORT = {
    "profile": {
        "full_name": "Example Person",
        "biography": "hello",
        "is_verified": True,
        "is_private": False,
        "profile_pic_url": "https://cdn/p.jpg",
        "external_url": "https://example.com",
        "business_email": "hello@example.com",
        # norm_profile nests the counters here — reading them from the top
        # level silently produced a blank follower count.
        "counts": {"followers": 12345, "following": 50, "posts": 10},
    },
    "posts": [{"shortcode": "abc", "url": "https://instagram.com/p/abc",
               "caption": "hi", "likes": 3, "comment_count": 1}],
    "media_files": ["output/example/media/abc.jpg"],
    "followers": [{"username": "a"}],
    "following": [],
    "notes": ["rate limited on stories"],
    "contacts": {"emails": ["a@example.com"]},
}


class InstagramNormalizeTest(unittest.TestCase):
    def _result(self, source=None):
        result = schema.new_result("instagram", "example")
        instagram.normalize(source if source is not None else INSTAGRAM_REPORT, result)
        return result

    def test_maps_profile_fields(self):
        result = self._result()
        self.assertTrue(result["found"])
        self.assertEqual(result["display_name"], "Example Person")
        self.assertEqual(result["external_links"], ["https://example.com"])
        self.assertEqual(result["metrics"]["followers"], 12345)

    def test_counts_come_from_the_nested_counts_block(self):
        """norm_profile nests them; reading the top level gave blank cells."""
        result = self._result()
        self.assertEqual(result["follower_count"], 12345)
        self.assertEqual(result["following_count"], 50)
        self.assertEqual(result["post_count"], 10)

    def test_falls_back_to_top_level_counts(self):
        result = self._result({"profile": {"counts": {}, "followers": 7}})
        self.assertEqual(result["follower_count"], 7)

    def test_maps_business_email_as_contact(self):
        self.assertEqual(self._result()["contact_email"], "hello@example.com")

    def test_partial_list_is_labelled_partial(self):
        """5 of 686M is not 686M followers."""
        result = self._result(dict(INSTAGRAM_REPORT, lists_skipped=True))
        self.assertEqual(result["metrics"]["followers_retrieved"], 1)
        self.assertIn("partial", " ".join(result["notes"]))
        self.assertNotIn("followers", result["walls"])

    def test_maps_posts_and_media(self):
        result = self._result()
        self.assertEqual(len(result["posts"]), 1)
        self.assertEqual(result["posts"][0]["url"], "https://instagram.com/p/abc")
        self.assertEqual(result["media_files"], ["output/example/media/abc.jpg"])

    def test_missing_follower_list_is_a_wall_not_an_empty_list(self):
        result = self._result()
        self.assertIn("following", result["walls"])
        self.assertEqual(result["walls"]["following"]["why"],
                         "not retrievable for this account")
        # The *count* from the profile is separate from the list, and survives.
        self.assertEqual(result["following_count"], 50)

    def test_retrieved_lists_are_summarised_not_dropped(self):
        result = self._result()
        self.assertNotIn("followers", result["walls"])
        self.assertEqual(result["metrics"]["followers_retrieved"], 1)
        self.assertIn("1 followers retrieved", result["notes"])

    def test_login_walled_list_with_nothing_retrieved_is_a_wall(self):
        result = self._result(dict(INSTAGRAM_REPORT, followers=[], lists_skipped=True))
        self.assertIn("followers", result["walls"])
        self.assertIn("login-walled", result["walls"]["followers"]["why"])

    def test_carries_engine_notes_through(self):
        self.assertIn("rate limited on stories", self._result()["notes"])

    def test_no_profile_is_not_found(self):
        result = self._result({})
        self.assertFalse(result["found"])


class MastodonSecurityTest(unittest.TestCase):
    """Instance hostnames are untrusted input on both sides.

    The handle's instance half comes from the operator (or any token
    holder), and the home host for the statuses fetch comes from a
    server-returned account URL — either could aim httpx at loopback,
    link-local, or intranet addresses (SSRF) without a hostname guard.
    """

    def test_ip_literals_are_rejected(self):
        from spyglass_pro.social.platforms import mastodon

        for host in ("127.0.0.1", "169.254.169.254", "10.0.0.5",
                     "::1", "0.0.0.0"):
            self.assertFalse(mastodon._valid_host(host), host)

    def test_bare_labels_and_junk_are_rejected(self):
        from spyglass_pro.social.platforms import mastodon

        for host in ("", "localhost", "intranet", "no-dot-here",
                     "a" * 64 + ".example.com", "example.com:80/x"):
            self.assertFalse(mastodon._valid_host(host), host)

    def test_real_instances_are_accepted(self):
        from spyglass_pro.social.platforms import mastodon

        for host in ("mastodon.social", "fosstodon.org",
                     "Mastodon.Social.", "chaos.social"):
            self.assertTrue(mastodon._valid_host(host), host)

    def test_evil_instance_errors_without_network(self):
        """No HTTP leaves the machine: validation runs before lookup."""
        from unittest import mock

        from spyglass_pro.social.platforms import mastodon

        result = schema.new_result("mastodon", "user@127.0.0.1")
        with mock.patch.object(mastodon, "_lookup") as lookup:
            mastodon.collect(None, {}, "user@127.0.0.1", result)
        lookup.assert_not_called()
        self.assertIn("invalid instance hostname", result.get("error", ""))

    def test_evil_home_host_keeps_profile_but_skips_posts(self):
        """A hostile lookup answer cannot redirect the statuses fetch."""
        from unittest import mock

        from spyglass_pro.social.platforms import mastodon

        account = dict(MASTODON_ACCOUNT, url="http://169.254.169.254/@example")
        result = schema.new_result("mastodon", "example")
        with mock.patch.object(mastodon, "_lookup", return_value=account), \
             mock.patch.object(mastodon, "_statuses") as statuses:
            mastodon.collect(None, {}, "example", result)
        statuses.assert_not_called()
        self.assertTrue(result["found"])
        self.assertIn("skipped", " ".join(result["notes"]))


class ReportTest(unittest.TestCase):
    def _result(self):
        result = schema.new_result("instagram", "example")
        instagram.normalize(INSTAGRAM_REPORT, result)
        return result

    def test_report_names_the_platform_and_session(self):
        text = report.render(self._result())
        self.assertIn("Instagram Recon — @example", text)
        self.assertIn("logged out", text)

    def test_report_states_counts(self):
        text = report.render(self._result())
        self.assertIn("12,345", text)
        self.assertIn("hello", text)

    def test_walls_are_reported_with_reasons(self):
        text = report.render(self._result())
        self.assertIn("Not retrieved", text)
        self.assertIn("not retrievable for this account", text)

    def test_error_is_surfaced(self):
        result = self._result()
        result["error"] = "instagram.com unreachable"
        self.assertIn("instagram.com unreachable", report.render(result))

    def test_write_creates_the_file(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = report.write(self._result(), tmp, "example.md")
            self.assertTrue(Path(path).is_file())
            self.assertIn("Instagram Recon", Path(path).read_text(encoding="utf-8"))

    def test_summary_is_one_line(self):
        line = report.summary(self._result())
        self.assertNotIn("\n", line)
        self.assertIn("@example", line)

    def test_summary_reports_errors_and_misses(self):
        result = schema.new_result("instagram", "nobody")
        self.assertIn("nothing retrieved", report.summary(result))
        result["error"] = "boom"
        self.assertIn("error", report.summary(result))


if __name__ == "__main__":
    unittest.main()
