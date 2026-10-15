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
        source = _APP_JS.read_text()
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
        for expected in ("instagram", "mastodon", "bluesky"):
            self.assertIn(expected, keys)

    def test_keyless_platforms_need_no_browser_or_login(self):
        for key in ("mastodon", "bluesky"):
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
        self.assertEqual(self._result()["external_links"], ["example.com"])

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
            self.assertIn("Instagram Recon", Path(path).read_text())

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
