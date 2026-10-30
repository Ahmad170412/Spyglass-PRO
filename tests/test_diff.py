"""Tests for social/diff.py — the pure CHECK AGAIN diff engine.

The rules under test, one per GREENWICH landmine the engine ports:

* additions only, keyed by native id (a shrinking window is not a deletion);
* per-side refusal when a follower list was not fully enumerated;
* no delta without two measured values (None is unread, not zero);
* walls and profile fields are first-class changes;
* refusals (no baseline / failed payload / identity mismatch) never
  render as "nothing changed".
"""

import unittest

import helpers  # noqa: F401  — puts the repo root and modules/ on sys.path

from spyglass_pro.social.diff import diff


def payload(**over):
    """A successful normalized result (schema.new_result's real shape)."""
    base = {
        "platform": "mastodon",
        "handle": "dawn@social.example",
        "found": True,
        "logged_in": False,
        "source": "api",
        "status": "ok",
        "notes": [],
        "walls": {"followers": {"label": "followers list", "why": "counts only"}},
        "posts": [],
        "media_files": [],
        "follower_count": 100,
        "following_count": 50,
        "post_count": 10,
        "display_name": "Dawn",
        "bio": "first bio",
        "url": "https://social.example/@dawn",
        "verified": False,
        "private": False,
        "external_links": ["https://example.test"],
    }
    base.update(over)
    return base


def post(key, caption="hello"):
    return {"id": key, "url": f"https://social.example/p/{key}",
            "caption": caption, "timestamp": "2026-10-28T08:00:00Z"}


class RefusalTest(unittest.TestCase):
    def test_no_baseline_refuses(self):
        out = diff(None, payload())
        self.assertFalse(out["ok"])
        self.assertFalse(out["changed"])
        self.assertIn("baseline", out["error"])

    def test_failed_previous_refuses(self):
        out = diff(payload(error="instance refused the list"), payload())
        self.assertFalse(out["ok"])
        self.assertIn("previous check failed", out["error"])

    def test_failed_current_refuses(self):
        out = diff(payload(), payload(error="timeout"))
        self.assertFalse(out["ok"])
        self.assertIn("current check failed", out["error"])

    def test_not_found_refuses(self):
        out = diff(payload(found=False), payload())
        self.assertFalse(out["ok"])
        self.assertIn("did not find", out["error"])

    def test_identity_mismatch_refuses(self):
        self.assertFalse(diff(payload(), payload(platform="bluesky"))["ok"])
        self.assertFalse(diff(payload(), payload(handle="someone.else"))["ok"])
        # Handles compare case-insensitively (all six platforms resolve so).
        self.assertTrue(diff(payload(), payload(handle="Dawn@Social.example"))["ok"])

    def test_non_dict_refuses(self):
        self.assertFalse(diff([], payload())["ok"])


class CountsTest(unittest.TestCase):
    def test_identical_payloads_are_unchanged(self):
        out = diff(payload(), payload())
        self.assertTrue(out["ok"])
        self.assertFalse(out["changed"])
        self.assertEqual(len(out["counts"]), 3)
        self.assertTrue(all(c["delta"] == 0 for c in out["counts"]))
        self.assertEqual(out["posts"]["added_count"], 0)
        self.assertEqual(out["fields"], [])
        self.assertFalse(out["partial"])

    def test_delta_only_when_both_measured(self):
        out = diff(payload(follower_count=100), payload(follower_count=None))
        keys = [c["key"] for c in out["counts"]]
        self.assertNotIn("follower_count", keys)  # unread, not zero
        self.assertIn("following_count", keys)
        self.assertFalse(out["changed"])

    def test_delta_and_labels(self):
        out = diff(payload(follower_count=100), payload(follower_count=130))
        entry = next(c for c in out["counts"] if c["key"] == "follower_count")
        self.assertEqual((entry["old"], entry["new"], entry["delta"]), (100, 130, 30))
        self.assertEqual(entry["label"], "Followers")
        self.assertTrue(out["changed"])


class PostsTest(unittest.TestCase):
    def test_new_post_detected_by_native_id(self):
        old = payload(posts=[post("a"), post("b")])
        new = payload(posts=[post("b"), post("c"), post("a")])
        out = diff(old, new)
        self.assertEqual(out["posts"]["added_count"], 1)
        self.assertEqual(out["posts"]["added"][0]["id"], "c")
        self.assertTrue(out["changed"])

    def test_shrinking_window_never_claims_removal(self):
        """40-item window: posts that fell off the end are NOT deletions."""
        old = payload(posts=[post("a"), post("b"), post("c")], post_count=3)
        new = payload(posts=[post("a")], post_count=3)
        out = diff(old, new)
        self.assertEqual(out["posts"]["added_count"], 0)
        self.assertFalse(out["changed"])

    def test_post_key_falls_back_to_url(self):
        a1 = {"id": None, "url": "https://social.example/p/x", "caption": "x"}
        a2 = {"id": None, "url": "https://social.example/p/x", "caption": "x edited"}
        out = diff(payload(posts=[a1]), payload(posts=[a2]))
        self.assertEqual(out["posts"]["added_count"], 0)

    def test_unkeyable_posts_are_skipped_silently(self):
        out = diff(payload(posts=[{"caption": "orphan"}]), payload(posts=[]))
        self.assertEqual(out["posts"], {"added": [], "added_count": 0, "compared": 0})

    def test_failed_previous_collection_refuses_additions(self):
        """An empty window beside a nonzero count is a fetch failure, not
        an account with no posts — claiming additions manufactures findings
        from a transient error (the Bluesky feed-failure landmine)."""
        old = payload(posts=[], post_count=4185)
        new = payload(posts=[post("a"), post("b")], post_count=4185)
        out = diff(old, new)
        self.assertEqual(out["posts"]["added_count"], 0)
        self.assertIn("additions cannot be claimed", out["posts"]["refused"])
        self.assertFalse(out["changed"])

    def test_unread_previous_count_refuses_additions(self):
        out = diff(payload(posts=[], post_count=None),
                   payload(posts=[post("a")], post_count=1))
        self.assertEqual(out["posts"]["added_count"], 0)
        self.assertIn("no post count was reported", out["posts"]["refused"])

    def test_genuinely_empty_account_still_claims_additions(self):
        """A baseline that truly saw zero posts (count == 0) can prove newness."""
        out = diff(payload(posts=[], post_count=0),
                   payload(posts=[post("a"), post("b")], post_count=2))
        self.assertEqual(out["posts"]["added_count"], 2)
        self.assertNotIn("refused", out["posts"])
        self.assertTrue(out["changed"])

    def test_refusal_does_not_hide_real_changes(self):
        """The posts phase can refuse while counts still move."""
        out = diff(payload(posts=[], post_count=10, follower_count=100),
                   payload(posts=[post("a")], post_count=11, follower_count=101))
        self.assertIn("refused", out["posts"])
        self.assertTrue(out["changed"])
        self.assertEqual([c["delta"] for c in out["counts"] if c["key"] == "follower_count"], [1])


class FieldsTest(unittest.TestCase):
    def test_changed_field_reported_with_label(self):
        out = diff(payload(), payload(bio="second bio"))
        self.assertEqual(len(out["fields"]), 1)
        self.assertEqual(out["fields"][0]["key"], "bio")
        self.assertEqual(out["fields"][0]["label"], "Bio")
        self.assertEqual(out["fields"][0]["old"], "first bio")
        self.assertEqual(out["fields"][0]["new"], "second bio")
        self.assertTrue(out["changed"])

    def test_bool_flip_is_a_change(self):
        out = diff(payload(verified=False), payload(verified=True))
        self.assertEqual([f["key"] for f in out["fields"]], ["verified"])

    def test_unread_field_is_not_a_change(self):
        out = diff(payload(website=None), payload(website="https://me.example"))
        self.assertEqual(out["fields"], [])
        self.assertFalse(out["changed"])

    def test_link_reorder_is_not_a_change(self):
        out = diff(payload(external_links=["a", "b"]), payload(external_links=["b", "a"]))
        self.assertEqual(out["fields"], [])
        self.assertFalse(out["changed"])

    def test_re_signed_avatar_url_is_not_a_change(self):
        """Instagram re-signs CDN queries per fetch — same path, same image."""
        old = payload(avatar_url=(
            "https://scontent.cdninstagram.com/v/t51.82787-19/723240529_x_n.jpg"
            "?stp=dst-jpg_s150x150_tt6&oh=aaa&oe=111"))
        new = payload(avatar_url=(
            "https://scontent.cdninstagram.com/v/t51.82787-19/723240529_x_n.jpg"
            "?stp=dst-jpg_s150x150_tt6&oh=bbb&oe=222"))
        out = diff(old, new)
        self.assertEqual(out["fields"], [])
        self.assertFalse(out["changed"])

    def test_real_avatar_swap_is_a_change(self):
        out = diff(
            payload(avatar_url="https://cdn.example/u/1/a.jpg?oh=aaa&oe=111"),
            payload(avatar_url="https://cdn.example/u/1/b.jpg?oh=bbb&oe=222"),
        )
        self.assertEqual([f["key"] for f in out["fields"]], ["avatar_url"])
        self.assertTrue(out["changed"])

    def test_volatile_query_rule_is_scoped_to_avatar(self):
        """Only avatar_url ignores the query; a website's query is content."""
        out = diff(
            payload(website="https://me.example/?ref=old"),
            payload(website="https://me.example/?ref=new"),
        )
        self.assertEqual([f["key"] for f in out["fields"]], ["website"])


class WallsTest(unittest.TestCase):
    def test_new_wall_is_a_change(self):
        new = payload(walls={
            "followers": {"label": "followers list", "why": "counts only"},
            "following": {"label": "following list", "why": "login-walled — a burner unlocks it"},
        })
        out = diff(payload(), new)
        self.assertEqual([w["kind"] for w in out["walls"]["new"]], ["following"])
        self.assertEqual(out["walls"]["resolved"], [])
        self.assertTrue(out["changed"])

    def test_resolved_wall_is_a_change(self):
        old = payload(walls={
            "followers": {"label": "followers list", "why": "counts only"},
            "stories": {"label": "stories", "why": "login-walled"},
        })
        out = diff(old, payload())
        self.assertEqual(out["walls"]["new"], [])
        self.assertEqual(out["walls"]["resolved"], ["stories"])
        self.assertTrue(out["changed"])


class ListsTest(unittest.TestCase):
    @staticmethod
    def _with_list(result, handles, complete, **extra):
        block = {"handles": list(handles), "complete": complete}
        block.update(extra)
        return result | {"lists": {"followers": block}}

    def test_complete_both_sides_full_diff(self):
        old = self._with_list(payload(), ["alice", "bob", "carol"], True, expected=3)
        new = self._with_list(payload(), ["Bob", "carol", "dave"], True, expected=4)
        entry = diff(old, new)["lists"]["followers"]
        self.assertEqual(entry["added"], ["dave"])
        self.assertEqual(entry["removed"], ["alice"])
        self.assertIsNone(entry["added_refused"])
        self.assertIsNone(entry["removed_refused"])

    def test_incomplete_baseline_refuses_additions_only(self):
        old = self._with_list(payload(), ["alice", "bob"], False)
        new = self._with_list(payload(), ["alice", "bob", "carol"], True)
        entry = diff(old, new)["lists"]["followers"]
        # Additions unclaimable: carol might predate an unenumerated baseline.
        self.assertEqual(entry["added"], [])
        self.assertIn("not fully enumerated", entry["added_refused"])
        # Removals claimable: the new list is complete and shows both still here.
        self.assertEqual(entry["removed"], [])
        self.assertIsNone(entry["removed_refused"])

    def test_incomplete_current_refuses_removals_only(self):
        old = self._with_list(payload(), ["alice", "bob", "carol"], True)
        new = self._with_list(payload(), ["carol", "dave"], False)
        entry = diff(old, new)["lists"]["followers"]
        self.assertEqual(entry["added"], ["dave"])   # old complete → claimable
        self.assertEqual(entry["removed"], [])
        self.assertIn("not fully enumerated", entry["removed_refused"])

    def test_both_incomplete_refuse_both_but_report_sizes(self):
        old = self._with_list(payload(), ["alice"], False)
        new = self._with_list(payload(), ["alice", "bob"], False)
        entry = diff(old, new)["lists"]["followers"]
        self.assertEqual(entry["old_size"], 1)
        self.assertEqual(entry["new_size"], 2)
        self.assertIsNotNone(entry["added_refused"])
        self.assertIsNotNone(entry["removed_refused"])
        self.assertEqual(entry["added"], [])
        self.assertEqual(entry["removed"], [])

    def test_list_present_on_one_side_only_refused(self):
        old = self._with_list(payload(), ["alice"], True)
        out = diff(old, payload())
        entry = out["lists"]["followers"]
        self.assertIn("current check", entry["refused"])
        self.assertEqual(entry["added"], [])
        self.assertFalse(out["changed"])

    def test_partial_status_surfaces(self):
        new = payload(status="partial")
        self.assertTrue(diff(payload(), new)["partial"])
        self.assertFalse(diff(payload(), payload())["partial"])


if __name__ == "__main__":
    unittest.main()
