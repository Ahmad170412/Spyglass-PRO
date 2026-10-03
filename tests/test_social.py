"""Tests for the multi-platform social harness.

The adapters' `normalize` functions and the report writer are pure — no
browser, no network — so the mapping from each platform's private JSON
shape onto the normalized schema is verified offline against recorded
fixtures. That is where a silent field-mapping bug would hide: a renamed
X key produces a blank cell, not an exception.
"""

import unittest

import helpers  # noqa: F401  — puts spyglass_pro/modules on sys.path

from spyglass_pro.social import registry, report, schema
from spyglass_pro.social.platforms import instagram, x


class SchemaTest(unittest.TestCase):
    def test_every_field_starts_empty_not_missing(self):
        result = schema.new_result("x", "someone")
        for field in schema.PROFILE_FIELDS:
            self.assertIn(field["key"], result)
            self.assertIsNone(result[field["key"]] if field["type"] != "list" else None)
        self.assertFalse(result["found"])

    def test_unset_fields_are_never_zero(self):
        """"Could not see this" must not become 0 or False."""
        result = schema.new_result("x", "someone")
        set_result = result
        schema.set_fields(set_result, follower_count=None, verified=False)
        self.assertIsNone(set_result["follower_count"])
        self.assertIs(set_result["verified"], False)
        # A False bool is hidden from the report; a 0 count is not.
        self.assertNotIn("verified", [f["key"] for f in schema.visible_fields(set_result)])

    def test_set_fields_rejects_unknown_keys(self):
        with self.assertRaises(KeyError):
            schema.set_fields(schema.new_result("x", "y"), followers_typo=5)

    def test_notes_are_deduplicated_and_flattened(self):
        result = schema.new_result("x", "y")
        schema.add_note(result, "a  note\nwith   spaces")
        schema.add_note(result, "a note with spaces")
        self.assertEqual(result["notes"], ["a note with spaces"])

    def test_walls_record_a_reason(self):
        result = schema.new_result("x", "y")
        schema.add_wall(result, "posts", "posts", "needs a login")
        self.assertEqual(result["walls"]["posts"]["why"], "needs a login")

    def test_formatting(self):
        self.assertEqual(schema.format_value({"type": "count"}, 12345), "12,345")
        self.assertEqual(schema.format_value({"type": "bool"}, True), "yes")
        self.assertEqual(schema.format_value({"type": "list"}, ["a", "b"]), "a, b")


class RegistryTest(unittest.TestCase):
    def test_bundled_platforms_register(self):
        keys = [platform["key"] for platform in registry.describe()]
        self.assertIn("x", keys)
        self.assertIn("instagram", keys)

    def test_unknown_platform_is_none(self):
        self.assertIsNone(registry.get("myspace"))
        self.assertIsNone(registry.get(""))

    def test_profile_url_substitution(self):
        platform = registry.get("x")
        self.assertEqual(platform.profile_url("jack"), "https://x.com/jack")

    def test_describe_exposes_capabilities(self):
        for entry in registry.describe():
            self.assertTrue(entry["capabilities"], entry["key"])
            self.assertIn(entry["login"], ("none", "x", "instacloak"))

    def test_a_broken_adapter_does_not_hide_the_others(self):
        """One adapter failing to import must not empty the registry."""
        from unittest import mock
        import spyglass_pro.social.registry as reg

        saved_registry, saved_loaded = dict(reg._REGISTRY), reg._LOADED

        def fake_import(name):
            if name.endswith(".x"):
                raise ImportError("boom")
            return reg  # anything non-None; the real module is already imported

        try:
            reg._REGISTRY.clear()
            reg._LOADED = False
            with mock.patch.object(reg.importlib, "import_module", side_effect=fake_import):
                reg.load_all()
            self.assertNotIn("x", reg._REGISTRY)
        finally:
            reg._REGISTRY.clear()
            reg._REGISTRY.update(saved_registry)
            reg._LOADED = saved_loaded


# Recorded shape of X's UserByScreenName result (trimmed).
X_USER = {
    "result": {
        "data": {
            "user": {
                "result": {
                    "legacy": {
                        "name": "Example Person",
                        "screen_name": "example",
                        "description": "building things",
                        "followers_count": 12345,
                        "friends_count": 678,
                        "statuses_count": 4321,
                        "verified": True,
                        "protected": False,
                        "created_at": "Tue Mar 05 12:00:00 +0000 2013",
                        "profile_image_url_https": "https://pbs.twimg.com/a.jpg",
                        "url": "https://t.co/example",
                    },
                    "core": {"name": "Example Person", "location": "Berlin"},
                    "entities": {"description": {"urls": [
                        {"expanded_url": "https://example.com", "url": "https://t.co/ex"},
                    ]}},
                }
            }
        }
    }
}


class XNormalizeTest(unittest.TestCase):
    def _result(self, user=None):
        result = schema.new_result("x", "example")
        x.normalize(user if user is not None else X_USER["result"]["data"]["user"]["result"],
                    result)
        return result

    def test_maps_every_available_field(self):
        result = self._result()
        self.assertTrue(result["found"])
        self.assertEqual(result["display_name"], "Example Person")
        self.assertEqual(result["bio"], "building things")
        self.assertEqual(result["follower_count"], 12345)
        self.assertEqual(result["following_count"], 678)
        self.assertEqual(result["post_count"], 4321)
        self.assertIs(result["verified"], True)
        self.assertIs(result["private"], False)
        self.assertEqual(result["location"], "Berlin")
        self.assertEqual(result["avatar_url"], "https://pbs.twimg.com/a.jpg")
        self.assertIn("Tue Mar 05", result["joined"])

    def test_extracts_external_links_from_bio_entities(self):
        links = self._result()["external_links"]
        self.assertIn("https://example.com", links)
        self.assertIn("https://t.co/example", links)
        self.assertEqual(len(links), len(set(links)), "links must be deduplicated")

    def test_missing_legacy_block_does_not_raise(self):
        result = self._result({"core": {"name": "No Legacy"}})
        self.assertTrue(result["found"])
        self.assertEqual(result["display_name"], "No Legacy")
        self.assertIsNone(result["follower_count"])

    def test_empty_user_reports_found_but_sparse(self):
        result = self._result({})
        self.assertTrue(result["found"])
        self.assertEqual(schema.visible_fields(result), [])

    def test_zero_counts_survive_as_real_values(self):
        result = self._result({"legacy": {"followers_count": 0, "friends_count": 0}})
        self.assertEqual(result["follower_count"], 0)
        keys = [f["key"] for f in schema.visible_fields(result)]
        self.assertIn("follower_count", keys)


INSTAGRAM_REPORT = {
    "profile": {
        "full_name": "Example Person",
        "biography": "hello",
        "is_verified": True,
        "is_private": False,
        "profile_pic_url": "https://x/p.jpg",
        "external_url": "https://example.com",
        "business_email": "hello@example.com",
        # norm_profile nests the counters here — reading them from the top
        # level silently produced a blank follower count.
        "counts": {"followers": 100, "following": 50, "posts": 10},
    },
    "posts": [{"shortcode": "abc", "url": "https://instagram.com/p/abc",
               "caption": "hi", "likes": 3, "comment_count": 1}],
    "media_files": ["output/example/media/abc.jpg"],
    "followers": [{"username": "a"}],
    "following": [],
    "notes": ["rate limited on stories"],
    "contacts": {"emails": ["a@example.com"]},
}


class XApiV2NormalizeTest(unittest.TestCase):
    """The official-API path is the maintainable one, so it is pinned here."""

    API_USER = {
        "data": {
            "id": "12", "name": "Example Person", "username": "example",
            "description": "building things", "location": "Berlin",
            "created_at": "2013-03-05T12:00:00.000Z", "verified": True,
            "protected": False,
            "profile_image_url": "https://pbs.twimg.com/a.jpg",
            "public_metrics": {"followers_count": 10, "following_count": 4,
                               "tweet_count": 99, "listed_count": 1},
        }
    }

    def _result(self):
        from spyglass_pro.social.platforms import x as xmod
        result = schema.new_result("x", "example")
        user = self.API_USER["data"]
        xmod._normalize_api_user(user, result)
        return result

    def test_maps_every_available_field(self):
        result = self._result()
        self.assertTrue(result["found"])
        self.assertEqual(result["display_name"], "Example Person")
        self.assertEqual(result["follower_count"], 10)
        self.assertEqual(result["following_count"], 4)
        self.assertEqual(result["post_count"], 99)
        self.assertEqual(result["url"], "https://x.com/example")
        self.assertIs(result["verified"], True)

    def test_walled_lists_stay_walled_on_the_api_path(self):
        """Follower *lists* need a different scope than follower counts."""
        from spyglass_pro.social.platforms import x as xmod
        result = schema.new_result("x", "example")
        xmod._normalize_api_user(self.API_USER["data"], result)
        xmod._apply_walls(result, False)
        self.assertIn("followers", result["walls"])
        self.assertEqual(result["follower_count"], 10)

    def test_no_token_means_the_official_path_is_skipped(self):
        import os
        from unittest import mock
        from spyglass_pro.social.platforms import x as xmod
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SPYGLASS_X_TOKEN", None)
            result = schema.new_result("x", "example")
            self.assertFalse(xmod.collect_official(None, "example", result))
        self.assertFalse(result["found"])


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
        self.assertEqual(result["metrics"]["followers"], 100)

    def test_counts_come_from_the_nested_counts_block(self):
        """norm_profile nests them; reading the top level gave blank cells."""
        result = self._result()
        self.assertEqual(result["follower_count"], 100)
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
    def _x_result(self):
        result = schema.new_result("x", "example")
        x.normalize(X_USER["result"]["data"]["user"]["result"], result)
        return result

    def test_report_names_the_platform_and_session(self):
        text = report.render(self._x_result())
        self.assertIn("X Recon — @example", text)
        self.assertIn("logged out", text)

    def test_report_states_counts(self):
        text = report.render(self._x_result())
        self.assertIn("12,345", text)
        self.assertIn("Berlin", text)

    def test_walls_are_reported_with_reasons(self):
        result = self._x_result()
        x._apply_walls(result, False)
        text = report.render(result)
        self.assertIn("Not retrieved", text)
        self.assertIn("unauthenticated", text)

    def test_error_is_surfaced(self):
        result = self._x_result()
        result["error"] = "X bearer rotated"
        self.assertIn("X bearer rotated", report.render(result))

    def test_write_creates_the_file(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = report.write(self._x_result(), tmp, "example.md")
            self.assertTrue(Path(path).is_file())
            self.assertIn("X Recon", Path(path).read_text())

    def test_summary_is_one_line(self):
        line = report.summary(self._x_result())
        self.assertNotIn("\n", line)
        self.assertIn("@example", line)

    def test_summary_reports_errors_and_misses(self):
        result = schema.new_result("x", "nobody")
        self.assertIn("nothing retrieved", report.summary(result))
        result["error"] = "boom"
        self.assertIn("error", report.summary(result))


if __name__ == "__main__":
    unittest.main()