"""Tests for social/lists.py and the collectors' list walks.

The honesty rules under test:

* ``complete`` comes from pagination exhaustion or reaching the profile
  counter — never from a short page or an unproven sample;
* a failed walk with nothing collected walls with the reason and never
  writes an empty list (which would read as "no followers");
* a partial walk keeps its block (incomplete, so the diff engine
  refuses claims) *and* walls the gap;
* the size gate and the GitLab token gate cost zero requests — walls,
  not probes;
* every adapter's walk reconciles the normalize-time placeholder wall.
"""

import unittest
from unittest import mock

import helpers  # noqa: F401  — puts the repo root and modules/ on sys.path

from spyglass_pro.social import lists, schema


def _result(platform="mastodon"):
    return schema.new_result(platform, "example")


def _resp(status, body=None, headers=None):
    r = mock.Mock()
    r.status_code = status
    r.json.return_value = body
    r.headers = headers or {}
    return r


class BlockTest(unittest.TestCase):
    def test_handles_deduped_lowercased_in_walk_order(self):
        block = lists.block(["Alice", "alice ", "bob", "  BOB", "carol"], None, False)
        self.assertEqual(block["handles"], ["alice", "bob", "carol"])

    def test_exhausted_walk_is_complete(self):
        self.assertTrue(lists.block(["a", "b"], 500, True)["complete"])

    def test_reaching_the_counter_proves_the_list_ended(self):
        """Counter lags the list — listing >= expected means the walk finished."""
        block = lists.block(["a", "b", "c"], 3, False)
        self.assertTrue(block["complete"])
        self.assertEqual(block["expected"], 3)

    def test_short_unexhausted_walk_is_only_a_window(self):
        block = lists.block(["a", "b"], 500, False)
        self.assertFalse(block["complete"])
        self.assertEqual(block["limit"], lists.RECORD_CAP)
        self.assertEqual(block["order"], "recent")

    def test_zero_counter_never_completes_an_unexhausted_walk(self):
        self.assertFalse(lists.block([], 0, False)["complete"])
        self.assertTrue(lists.block([], 0, True)["complete"])

    def test_over_cap_list_is_trimmed_and_refused_completeness(self):
        """Pages overshoot the window; a trimmed tail must never read as
        "removed" on the next check, so completeness refuses the cut."""
        handles = [f"u{i}" for i in range(lists.RECORD_CAP + 150)]
        block = lists.block(handles, lists.RECORD_CAP + 150, True)  # even exhausted
        self.assertEqual(len(block["handles"]), lists.RECORD_CAP)
        self.assertFalse(block["complete"])
        # …and the counter-lag rule cannot rescue a cut list either.
        block2 = lists.block(handles, 450, False)
        self.assertFalse(block2["complete"])
        # A full fit keeps both routes open.
        fit = lists.block(handles[: lists.RECORD_CAP], lists.RECORD_CAP, False)
        self.assertTrue(fit["complete"])

    def test_missing_counter_rests_on_exhaustion_alone(self):
        self.assertFalse(lists.block(["a"], None, False)["complete"])
        self.assertTrue(lists.block(["a"], None, True)["complete"])
        # A bool is not a count: ignored, but exhaustion still counts.
        block = lists.block(["a"], True, True)
        self.assertTrue(block["complete"])
        self.assertIsNone(block["expected"])


class RecordTest(unittest.TestCase):
    def test_success_stores_block_and_clears_the_wall(self):
        result = _result()
        result["follower_count"] = 50
        lists.record(result, "followers", ["Alice", "bob"], 50, True)
        self.assertEqual(result["lists"]["followers"]["handles"], ["alice", "bob"])
        self.assertTrue(result["lists"]["followers"]["complete"])
        self.assertNotIn("followers", result["walls"])

    def test_failure_with_nothing_collected_walls_only(self):
        result = _result()
        lists.record(result, "followers", [], None, False, error="HTTP 401")
        self.assertNotIn("followers", result["lists"])
        self.assertEqual(result["walls"]["followers"]["why"], "HTTP 401")
        self.assertEqual(result["walls"]["followers"]["label"], "followers list")

    def test_partial_walk_keeps_block_and_walls_the_gap(self):
        result = _result()
        lists.record(result, "followers", ["alice"], 400, False,
                     error="list walk interrupted (network error mid-walk)")
        block = result["lists"]["followers"]
        self.assertEqual(block["handles"], ["alice"])
        self.assertFalse(block["complete"])          # claims refused downstream
        self.assertIn("interrupted", result["walls"]["followers"]["why"])

    def test_clean_empty_walk_is_a_true_empty_list(self):
        result = _result()
        lists.record(result, "following", [], 0, True)
        self.assertEqual(result["lists"]["following"]["handles"], [])
        self.assertTrue(result["lists"]["following"]["complete"])
        self.assertNotIn("following", result["walls"])


class MastodonWalkTest(unittest.TestCase):
    def _walk_result(self, kind, placeholder=True):
        result = _result("mastodon")
        if placeholder:
            result["walls"].update({kind: {"label": f"{kind} list",
                                          "why": "counts only"}})
        return result

    def _walk(self, kind, responses, result=None):
        from spyglass_pro.social.platforms import mastodon

        result = result or self._walk_result(kind)
        client = mock.Mock()
        client.get.side_effect = responses
        mastodon._walk_list(client, "social.example", "42", kind, result)
        return result, client

    def test_link_pagination_to_exhaustion_clears_the_wall(self):
        result = self._walk_result("followers")
        result["follower_count"] = 3
        page1 = _resp(200, [{"acct": "alice"}, {"acct": "Bob"}],
                      {"Link": '<https://social.example/api/v1/accounts/42/followers?max_id=1>; rel="next"'})
        page2 = _resp(200, [{"acct": "carol"}])
        result, client = self._walk("followers", [page1, page2], result)
        block = result["lists"]["followers"]
        self.assertEqual(block["handles"], ["alice", "bob", "carol"])
        self.assertTrue(block["complete"])           # no next link = end
        self.assertNotIn("followers", result["walls"])
        self.assertEqual(client.get.call_args_list[1][0][0],
                         "https://social.example/api/v1/accounts/42/followers?max_id=1")

    def test_auth_wall_is_reported_not_empty(self):
        result, _ = self._walk("followers", [_resp(401, {})])
        self.assertNotIn("followers", result["lists"])
        self.assertIn("login", result["walls"]["followers"]["why"])

    def test_network_error_mid_walk_walls_and_keeps_the_partial(self):
        page1 = _resp(200, [{"acct": "alice"}],
                      {"Link": '<https://social.example/next>; rel="next"'})
        result, _ = self._walk("followers", [page1, TimeoutError("boom")])
        self.assertEqual(result["lists"]["followers"]["handles"], ["alice"])
        self.assertFalse(result["lists"]["followers"]["complete"])
        self.assertIn("interrupted", result["walls"]["followers"]["why"])

    def test_cap_stops_the_walk_incomplete(self):
        from spyglass_pro.social.platforms import mastodon

        def page(a, b):
            return _resp(200, [{"acct": a}, {"acct": b}],
                         {"Link": '<https://social.example/next>; rel="next"'})

        with mock.patch.object(mastodon, "RECORD_CAP", 4):
            result, client = self._walk("followers", [page("a", "b"), page("c", "d")])
        self.assertEqual(result["lists"]["followers"]["handles"],
                         ["a", "b", "c", "d"])
        self.assertFalse(result["lists"]["followers"]["complete"])  # cap, not end
        self.assertEqual(client.get.call_count, 2)


class BlueskyWalkTest(unittest.TestCase):
    def _walk(self, responses, kind="followers", key="followers", expected=500):
        from spyglass_pro.social.platforms import bluesky

        result = schema.new_result("bluesky", "example.bsky.social")
        result["walls"].update({kind: {"label": f"{kind} list", "why": "counts only"}})
        with mock.patch.object(bluesky, "_get", side_effect=responses) as get:
            bluesky._walk_list(mock.Mock(), "did:plc:x", kind,
                               "app.bsky.graph.getFollowers", key, expected, result)
        return result, get

    def test_cursor_pagination_to_no_cursor_is_complete(self):
        page1 = {"followers": [{"handle": "alice.bsky.social"},
                               {"handle": "bob.bsky.social"}], "cursor": "c1"}
        page2 = {"followers": [{"handle": "carol.bsky.social"}]}
        result, _ = self._walk([page1, page2])
        block = result["lists"]["followers"]
        self.assertEqual(block["handles"], ["alice.bsky.social", "bob.bsky.social",
                                            "carol.bsky.social"])
        self.assertTrue(block["complete"])
        self.assertNotIn("followers", result["walls"])

    def test_appview_failure_walls_without_an_empty_list(self):
        result, _ = self._walk([None])
        self.assertNotIn("followers", result["lists"])
        self.assertIn("interrupted", result["walls"]["followers"]["why"])

    def test_following_uses_the_follows_response_key(self):
        page = {"follows": [{"handle": "dawn.bsky.social"}]}
        result, _ = self._walk([page], kind="following", key="follows", expected=1)
        self.assertEqual(result["lists"]["following"]["handles"], ["dawn.bsky.social"])
        self.assertTrue(result["lists"]["following"]["complete"])  # reached counter


class GithubWalkTest(unittest.TestCase):
    def _walk(self, responses, expected=9):
        from spyglass_pro.social.platforms import github

        result = schema.new_result("github", "octocat")
        result["walls"].update({"followers": {"label": "followers list",
                                              "why": "counts only"}})
        with mock.patch.object(github, "_get", side_effect=responses) as get:
            github._walk_list(mock.Mock(), "/users/octocat/followers",
                              "followers", expected, result)
        return result, get

    def test_short_page_ends_the_walk_and_clears_the_wall(self):
        result, _ = self._walk([(200, [{"login": "hubot"}, {"login": "defunkt"}], {})])
        block = result["lists"]["followers"]
        self.assertEqual(block["handles"], ["hubot", "defunkt"])
        self.assertTrue(block["complete"])
        self.assertNotIn("followers", result["walls"])

    def test_oversized_account_is_walled_without_a_request(self):
        result, get = self._walk([], expected=9000)
        get.assert_not_called()
        self.assertNotIn("followers", result["lists"])
        self.assertIn("exceeds", result["walls"]["followers"]["why"])
        self.assertIn("400", result["walls"]["followers"]["why"])

    def test_budget_exhaustion_mid_walk_is_named(self):
        result, _ = self._walk([
            (200, [{"login": "a"}] * 100, {"x-ratelimit-remaining": "1"}),
            (403, None, {"x-ratelimit-remaining": "0"}),
        ], expected=300)
        self.assertFalse(result["lists"]["followers"]["complete"])
        self.assertIn("budget exhausted", result["walls"]["followers"]["why"])


class GitlabWalkTest(unittest.TestCase):
    def _walk(self, has_token, responses=()):
        from spyglass_pro.social.platforms import gitlab

        result = schema.new_result("gitlab", "sytses")
        with mock.patch.object(gitlab, "_get", side_effect=list(responses)) as get:
            gitlab._walk_list(mock.Mock(), 7, "followers", has_token, result)
        return result, get

    def test_keyless_walls_with_the_reason_and_spends_nothing(self):
        result, get = self._walk(has_token=False)
        get.assert_not_called()
        self.assertNotIn("followers", result["lists"])
        why = result["walls"]["followers"]["why"]
        self.assertIn("auth-gated", why)
        self.assertIn("GITLAB_TOKEN", why)

    def test_token_walks_and_clears_the_wall(self):
        result, _ = self._walk(has_token=True, responses=[
            (200, [{"username": "sid"}, {"username": "others"}], {}),
        ])
        block = result["lists"]["followers"]
        self.assertEqual(block["handles"], ["sid", "others"])
        self.assertTrue(block["complete"])
        self.assertNotIn("followers", result["walls"])


class InstagramNormalizeShapeTest(unittest.TestCase):
    """build_report's dict shape must not read as a four-key list."""

    def _report(self, **over):
        base = {
            "profile": {"full_name": "Example", "counts": {"followers": 5, "following": 2}},
            "posts": [], "media_files": [], "notes": [], "contacts": {},
            "followers": {"count": 5, "collected": 3, "walled": False,
                          "usernames": ["a", "b", "c"]},
            "following": {"count": 2, "collected": 0, "walled": True, "usernames": []},
        }
        base.update(over)
        return base

    def test_dict_shape_counts_usernames_not_keys(self):
        from spyglass_pro.social.platforms import instagram

        result = schema.new_result("instagram", "example")
        instagram.normalize(self._report(), result)
        self.assertEqual(result["metrics"]["followers_retrieved"], 3)
        self.assertIn("3 followers retrieved", result["notes"])
        # Retrieved list lands as a diffable (incomplete) block…
        self.assertEqual(result["lists"]["followers"]["handles"], ["a", "b", "c"])
        self.assertFalse(result["lists"]["followers"]["complete"])
        # …while the walled one stays a wall, never an empty list.
        self.assertNotIn("following", result["lists"])
        self.assertIn("login-walled", result["walls"]["following"]["why"])

    def test_bare_list_shape_still_works(self):
        from spyglass_pro.social.platforms import instagram

        report = dict(self._report(), followers=[{"username": "x"}], following=[],
                      lists_skipped=False)
        result = schema.new_result("instagram", "example")
        instagram.normalize(report, result)
        self.assertEqual(result["metrics"]["followers_retrieved"], 1)
        self.assertIn("not retrievable", result["walls"]["following"]["why"])


if __name__ == "__main__":
    unittest.main()
