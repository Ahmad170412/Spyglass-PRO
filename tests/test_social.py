"""Tests for the multi-platform social harness.

The adapters' `normalize` functions and the report writer are pure — no
browser, no network — so the mapping from each platform's private JSON
shape onto the normalized schema is verified offline against recorded
fixtures. That is where a silent field-mapping bug would hide: a renamed
key produces a blank cell, not an exception.
"""

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
        self.assertIn("instagram", keys)

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
