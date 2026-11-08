"""Tests for the tracked-target API and the CHECK AGAIN runner.

The contract under test:

* targets are managed entities — add/list/get/delete over
  ``/api/social/targets``, with normalization and duplicate refusal
  enforced server-side;
* ``POST /targets/<id>/check`` is the *only* social run route left: the
  old free-form ``/api/social/run`` is gone (404), checks only exist
  against tracked targets;
* a check collects → diffs against the previous successful check →
  records; the first success pins the baseline, failures never write a
  snapshot or move it;
* transport matches every other run route: blocking by default, 202 +
  job_id when async is requested.
"""

import os
import tempfile
import unittest
from unittest import mock

import helpers  # noqa: F401  — puts the repo root and modules/ on sys.path

import spyglass_pro.app as app_module
import spyglass_pro.runner as runner
from spyglass_pro.app import app
from spyglass_pro.social import tracking


def _payload(n=1, followers=100):
    """A normalized result payload — schema.new_result's real shape."""
    return {
        "platform": "bluesky",
        "handle": "dawn.example.bsky.social",
        "found": True,
        "logged_in": False,
        "source": "appview",
        "status": "ok",
        "notes": [],
        "walls": {},
        "posts": [{"id": f"at://post/{n}", "url": f"https://bsky.app/p/{n}",
                   "caption": "hello", "timestamp": "2026-10-28T08:00:00Z"}],
        "media_files": [],
        "follower_count": followers,
        "following_count": 10,
        "post_count": 50,
        "display_name": "Dawn",
        "bio": "hello",
        "external_links": [],
    }


class IsolatedHomeTest(unittest.TestCase):
    """Every case runs against its own SPYGLASS_HOME store."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch.dict(
            os.environ,
            {"SPYGLASS_HOME": self.tmp.name, "SPYGLASS_STORE_KEY": "",
             "SPYGLASS_STORE_PASS": "", "SPYGLASS_PRO_TOKEN": ""},
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        self.client = app.test_client()


class TargetsRouteTest(IsolatedHomeTest):
    def test_empty_store_lists_nothing(self):
        self.assertEqual(self.client.get("/api/social/targets").get_json(), [])

    def test_add_normalizes_and_returns_201(self):
        resp = self.client.post("/api/social/targets",
                                json={"platform": "Bluesky",
                                      "handle": "@Dawn.Example.bsky.social"})
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data["platform"], "bluesky")
        self.assertEqual(data["handle"], "dawn.example.bsky.social")
        self.assertEqual(data["checks"], 0)
        self.assertIsNone(data["baseline"])
        listed = self.client.get("/api/social/targets").get_json()
        self.assertEqual(len(listed), 1)

    def test_duplicate_after_normalization_is_400(self):
        self.client.post("/api/social/targets",
                         json={"platform": "bluesky", "handle": "dawn"})
        resp = self.client.post("/api/social/targets",
                                json={"platform": "BLUESKY", "handle": "@Dawn"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("already tracked", resp.get_json()["error"])

    def test_unknown_platform_is_refused(self):
        respos = [
            self.client.post("/api/social/targets",
                             json={"platform": "myspace", "handle": "dawn"}),
            self.client.post("/api/social/targets",
                             json={"platform": "bluesky", "handle": ""}),
        ]
        self.assertEqual([r.status_code for r in respos], [400, 400])
        self.assertIn("unknown platform", respos[0].get_json()["error"])

    def test_get_one_target_carries_history(self):
        added = self.client.post("/api/social/targets",
                                 json={"platform": "mastodon",
                                       "handle": "dawn@social.example"}).get_json()
        resp = self.client.get(f"/api/social/targets/{added['id']}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["history"], [])

    def test_detail_carries_the_recomputed_diff(self):
        """The dashboard reads the check's verdict on every load.

        Recomputed with the shared diff engine, not a second
        implementation: no checks → None, one check → the baseline
        refusal, two checks → a real comparison of the two newest
        snapshots.
        """
        tid = self.client.post("/api/social/targets",
                               json={"platform": "bluesky",
                                     "handle": "dawn"}).get_json()["id"]

        first = self.client.get(f"/api/social/targets/{tid}").get_json()
        self.assertIsNone(first["last_diff"])

        tracking.record_check(tid, _payload(followers=100), status="ok")
        second = self.client.get(f"/api/social/targets/{tid}").get_json()
        self.assertFalse(second["last_diff"]["ok"])
        self.assertIn("this run is the baseline", second["last_diff"]["error"])

        tracking.record_check(tid, _payload(n=2, followers=107), status="ok")
        third = self.client.get(f"/api/social/targets/{tid}").get_json()
        diff = third["last_diff"]
        self.assertTrue(diff["ok"])
        deltas = {c["key"]: c["delta"] for c in diff["counts"]}
        self.assertEqual(deltas["follower_count"], 7)
        self.assertEqual(diff["posts"]["added_count"], 1)
        # Each snapshot carries its own verdict so the timeline can rewind:
        # newest diffs against the check before it, the oldest is the baseline.
        self.assertTrue(third["history"][0]["diff"]["ok"])
        self.assertIn("this run is the baseline",
                      third["history"][-1]["diff"]["error"])

    def test_media_is_served_only_when_a_snapshot_references_it(self):
        """A path is not enough: it must belong to this target's checks and
        sit under a media root. Otherwise the media route would be a
        filesystem read primitive."""
        tid = self.client.post("/api/social/targets",
                               json={"platform": "instagram",
                                     "handle": "dawn"}).get_json()["id"]
        with tempfile.TemporaryDirectory() as root, \
             tempfile.TemporaryDirectory() as outside:
            root = os.path.realpath(root)
            file_path = os.path.join(root, "media", "ok.jpg")
            os.makedirs(os.path.dirname(file_path))
            with open(file_path, "wb") as fh:
                fh.write(b"jpeg-bytes")
            unreferenced = os.path.join(root, "media", "other.jpg")
            with open(unreferenced, "wb") as fh:
                fh.write(b"other")
            outside_path = os.path.join(os.path.realpath(outside), "secret.jpg")
            with open(outside_path, "wb") as fh:
                fh.write(b"secret")

            payload = _payload()
            payload["media_files"] = [file_path, outside_path]
            tracking.record_check(tid, payload, status="ok")

            with mock.patch.object(app_module, "_media_roots",
                                   return_value=[root]):
                served = self.client.get("/api/social/media/%d" % tid,
                                         query_string={"path": file_path})
                self.assertEqual(served.status_code, 200)
                self.assertEqual(served.data, b"jpeg-bytes")
                # Windows keeps send_file's handle open until the response is
                # closed; without this the TemporaryDirectory cleanup below
                # dies with WinError 32 even though every assertion passed.
                served.close()

                missing = self.client.get("/api/social/media/%d" % tid)
                self.assertEqual(missing.status_code, 400)

                # In the root but never referenced by a snapshot.
                denied = self.client.get("/api/social/media/%d" % tid,
                                         query_string={"path": unreferenced})
                self.assertEqual(denied.status_code, 404)

                # Referenced, but outside every media root.
                escaped = self.client.get("/api/social/media/%d" % tid,
                                          query_string={"path": outside_path})
                self.assertEqual(escaped.status_code, 404)

        self.assertEqual(
            self.client.get("/api/social/media/99?path=x").status_code, 404)

    def test_unknown_ids_are_404(self):
        self.assertEqual(self.client.get("/api/social/targets/99").status_code, 404)
        self.assertEqual(self.client.delete("/api/social/targets/99").status_code, 404)

    def test_delete_forgets_the_target_and_its_snapshots(self):
        added = self.client.post("/api/social/targets",
                                 json={"platform": "bluesky",
                                       "handle": "dawn"}).get_json()
        tracking.record_check(added["id"], _payload(), status="ok")
        resp = self.client.delete(f"/api/social/targets/{added['id']}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.client.get("/api/social/targets").get_json(), [])
        self.assertEqual(self.client.get(f"/api/social/targets/{added['id']}").status_code, 404)

    def test_old_freeform_run_route_is_gone(self):
        """Phase 4 replaced it: checks exist only against tracked targets."""
        resp = self.client.post("/api/social/run",
                                json={"platform": "bluesky", "handle": "x"})
        self.assertEqual(resp.status_code, 404)

    def test_check_unknown_target_is_404_without_touching_the_pool(self):
        with mock.patch.object(runner, "check_social_target") as check:
            resp = self.client.post("/api/social/targets/7/check", json={})
        self.assertEqual(resp.status_code, 404)
        check.assert_not_called()

    def test_check_is_blocking_by_default_and_202_when_async(self):
        added = self.client.post("/api/social/targets",
                                 json={"platform": "bluesky",
                                       "handle": "dawn"}).get_json()
        fake = {"target": added, "diff": {"ok": True}, "first": True}
        with mock.patch.object(runner, "check_social_target",
                               return_value=dict(fake)) as check:
            resp = self.client.post(f"/api/social/targets/{added['id']}/check",
                                    json={"deep": False})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["diff"], {"ok": True})
        # target_id, engine-clean payload (no transport flag)
        self.assertEqual(check.call_args[0][0], added["id"])
        self.assertEqual(check.call_args[0][1], {"deep": False})

        with mock.patch.object(runner, "submit_job",
                               return_value={"job_id": "j1", "status": "running"}) as submit:
            resp = self.client.post(f"/api/social/targets/{added['id']}/check?async=1")
        self.assertEqual(resp.status_code, 202)
        self.assertEqual(resp.get_json()["job_id"], "j1")
        self.assertEqual(submit.call_args[0][0], runner.check_social_target)
        self.assertEqual(submit.call_args[0][1], added["id"])


class CheckRunnerTest(IsolatedHomeTest):
    """check_social_target's collect → diff → record pipeline, offline."""

    def _add(self):
        return tracking.add_target("bluesky", "dawn.example.bsky.social")

    def test_first_success_pins_the_baseline(self):
        target = self._add()
        with mock.patch.object(runner, "run_social",
                               return_value=_payload()) as run:
            out = runner.check_social_target(target["id"])
        self.assertEqual(run.call_args[0][:2], ("bluesky", "dawn.example.bsky.social"))
        self.assertTrue(out["first"])
        self.assertFalse(out["diff"]["ok"])              # refusal, not a fake empty diff
        self.assertIn("baseline", out["diff"]["error"])
        self.assertEqual(out["target"]["checks"], 1)
        self.assertEqual(out["target"]["baseline"]["follower_count"], 100)
        self.assertTrue(any("baseline" in line or "checking" in line
                            for line in out["progress"]))

    def test_second_success_diffs_against_the_previous_check(self):
        target = self._add()
        with mock.patch.object(runner, "run_social", return_value=_payload(followers=100)):
            runner.check_social_target(target["id"])
        with mock.patch.object(runner, "run_social",
                               return_value=_payload(n=2, followers=140)):
            out = runner.check_social_target(target["id"])
        self.assertFalse(out["first"])
        diff = out["diff"]
        self.assertTrue(diff["ok"])
        self.assertTrue(diff["changed"])
        follower_delta = next(c for c in diff["counts"] if c["key"] == "follower_count")
        self.assertEqual(follower_delta["delta"], 40)
        self.assertEqual(diff["posts"]["added_count"], 1)
        self.assertEqual(out["target"]["checks"], 2)
        self.assertEqual(len(tracking.history(target["id"])), 2)

    def test_failed_check_records_bookkeeping_only(self):
        target = self._add()
        with mock.patch.object(runner, "run_social", return_value=_payload(followers=100)):
            runner.check_social_target(target["id"])
        with mock.patch.object(
                runner, "run_social",
                return_value={"error": "mastodon instance timed out — retry later"}):
            out = runner.check_social_target(target["id"])
        self.assertFalse(out["diff"]["ok"])
        self.assertIn("check failed", out["diff"]["error"])
        stored = tracking.get_target(target["id"])
        self.assertEqual(stored["checks"], 1)                     # not a check
        self.assertIn("timed out", stored["last_status"])         # attempt visible
        self.assertEqual(stored["baseline"]["follower_count"], 100)  # baseline intact
        self.assertEqual(len(tracking.history(target["id"])), 1)   # chain unpolluted

    def test_unfound_profile_counts_as_failure(self):
        target = self._add()
        with mock.patch.object(runner, "run_social",
                               return_value={"found": False, "notes": []}):
            out = runner.check_social_target(target["id"])
        self.assertFalse(out["diff"]["ok"])
        self.assertIn("no bluesky profile found", out["diff"]["error"])
        self.assertEqual(tracking.get_target(target["id"])["checks"], 0)

    def test_unknown_target_is_an_error_dict(self):
        out = runner.check_social_target(4242)
        self.assertIn("unknown target #4242", out["error"])


if __name__ == "__main__":
    unittest.main()
