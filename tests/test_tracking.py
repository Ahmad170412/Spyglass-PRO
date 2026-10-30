"""Tests for social/tracking.py — targets, snapshots, retention (isolated via SPYGLASS_HOME).

The invariants under test are the ones CHECK AGAIN depends on:

* a target is one normalized (platform, handle) identity — duplicates
  after normalization are rejected, not silently merged later;
* only a successful check (ok/partial) appends a snapshot and pins the
  baseline; a failed run updates bookkeeping and nothing else;
* retention keeps exactly HISTORY_LIMIT snapshots per target while the
  baseline on the target row survives pruning;
* reads come back newest-first, the one order history cards, stat deltas
  and the diff engine all share;
* payloads are encrypted at rest when a key is configured, and still
  readable through the public API.
"""

import os
import sqlite3
import tempfile
import unittest
from unittest import mock

import helpers  # noqa: F401  — puts the repo root and modules/ on sys.path

from spyglass_pro.social import tracking


def _payload(n=1, followers=100):
    """A normalized result payload — schema.new_result's real shape."""
    return {
        "platform": "bluesky",
        "handle": "dawn.example.bsky.social",
        "found": True,
        "logged_in": False,
        "source": "appview",
        "notes": [],
        "walls": {"followers": {"label": "followers list", "why": "counts only"}},
        "posts": [
            {"id": f"at://post/{n}", "url": f"https://bsky.app/profile/x/post/{n}",
             "caption": "hello", "timestamp": "2026-10-28T08:00:00Z"}
        ],
        "media_files": [],
        "follower_count": followers,
        "following_count": 10,
        "post_count": 50,
        "display_name": "Dawn",
        "bio": "hello",
        "external_links": [],
        "status": "ok",
    }


class TrackingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch.dict(
            os.environ,
            {"SPYGLASS_HOME": self.tmp.name, "SPYGLASS_STORE_KEY": "", "SPYGLASS_STORE_PASS": ""},
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    # ─── targets ────────────────────────────────────────

    def test_add_normalizes_and_starts_unchecked(self):
        t = tracking.add_target("Bluesky", "@Dawn.Example.bsky.social")
        self.assertEqual(t["platform"], "bluesky")
        self.assertEqual(t["handle"], "dawn.example.bsky.social")
        self.assertEqual(t["checks"], 0)
        self.assertIsNone(t["baseline"])
        self.assertIsNone(t["last_check_at"])

    def test_add_rejects_duplicates_after_normalization(self):
        tracking.add_target("Bluesky", "@Dawn.Example")
        with self.assertRaises(ValueError):
            tracking.add_target("bluesky", "dawn.example")

    def test_add_rejects_unusable_input(self):
        for platform, handle in (("", "x"), ("bluesky", ""), ("bluesky", "  @ "),
                                 ("bluesky", "has space")):
            with self.assertRaises(ValueError, msg=repr((platform, handle))):
                tracking.add_target(platform, handle)

    def test_list_find_remove(self):
        t = tracking.add_target("mastodon", "dawn@social.example")
        rows = tracking.list_targets()
        self.assertEqual(len(rows), 1)
        self.assertEqual(tracking.find_target("mastodon", "Dawn@social.example")["id"], t["id"])
        self.assertIsNone(tracking.find_target("mastodon", "nobody"))
        self.assertIsNone(tracking.find_target("", ""))

        tracking.record_check(t["id"], _payload(), status="ok")
        self.assertTrue(tracking.remove_target(t["id"]))
        self.assertFalse(tracking.remove_target(t["id"]))
        self.assertEqual(tracking.list_targets(), [])
        # Snapshots go with the target — removal forgets, it does not orphan.
        raw = sqlite3.connect(os.path.join(self.tmp.name, "spyglass.db"))
        orphans = raw.execute("SELECT count(*) FROM social_snapshots").fetchone()[0]
        raw.close()
        self.assertEqual(orphans, 0)

    # ─── checks and the baseline ────────────────────────

    def test_first_check_pins_baseline(self):
        t = tracking.add_target("github", "ahmad-dev")
        out = tracking.record_check(t["id"], _payload(followers=500), status="ok")
        self.assertEqual(out["checks"], 1)
        self.assertIsNotNone(out["baseline_at"])
        self.assertEqual(out["baseline"]["follower_count"], 500)
        self.assertEqual(out["last_status"], "ok")
        snap = tracking.latest_snapshot(t["id"])
        self.assertEqual(snap["follower_count"], 500)
        self.assertEqual(snap["status"], "ok")

    def test_failed_run_is_not_a_check_and_keeps_baseline(self):
        t = tracking.add_target("mastodon", "dawn@social.example")
        tracking.record_check(t["id"], _payload(followers=500), status="ok")
        out = tracking.record_check(
            t["id"], None, status="error", error="instance refused the list (auth required)"
        )
        self.assertEqual(out["checks"], 1)          # counters unchanged
        self.assertEqual(out["baseline"]["follower_count"], 500)
        self.assertIn("auth required", out["last_status"])
        self.assertEqual(len(tracking.history(t["id"])), 1)  # chain unpolluted
        self.assertIsNotNone(out["last_check_at"])  # but the attempt is visible

    def test_partial_check_records_status_in_payload(self):
        t = tracking.add_target("instagram", "dawn.shoots")
        tracking.record_check(t["id"], _payload(), status="partial")
        snap = tracking.latest_snapshot(t["id"])
        self.assertEqual(snap["status"], "partial")
        self.assertEqual(tracking.get_target(t["id"])["last_status"], "partial")

    def test_check_unknown_target_raises(self):
        with self.assertRaises(ValueError):
            tracking.record_check(9999, _payload(), status="ok")

    # ─── history and retention ──────────────────────────

    def test_history_is_newest_first(self):
        t = tracking.add_target("bluesky", "dawn.example.bsky.social")
        for n in (1, 2, 3):
            tracking.record_check(t["id"], _payload(n=n), status="ok")
        hist = tracking.history(t["id"])
        self.assertEqual(
            [h["payload"]["posts"][0]["id"] for h in hist],
            ["at://post/3", "at://post/2", "at://post/1"],
        )

    def test_retention_keeps_20_and_baseline_survives(self):
        self.assertEqual(tracking.HISTORY_LIMIT, 20)
        t = tracking.add_target("gitlab", "ahmad-dev")
        for i in range(25):  # followers 100..124, first is baseline
            tracking.record_check(t["id"], _payload(n=i, followers=100 + i), status="ok")

        hist = tracking.history(t["id"])
        self.assertEqual(len(hist), 20)
        self.assertEqual(hist[0]["payload"]["follower_count"], 124)   # newest first
        self.assertEqual(hist[-1]["payload"]["follower_count"], 105)  # oldest kept = check 6
        self.assertEqual(tracking.latest_snapshot(t["id"])["follower_count"], 124)

        out = tracking.get_target(t["id"])
        self.assertEqual(out["checks"], 25)
        # The baseline rides on the target row, not in the pruned chain.
        self.assertEqual(out["baseline"]["follower_count"], 100)

    def test_history_limit_argument(self):
        t = tracking.add_target("mastodon", "dawn@social.example")
        for n in (1, 2, 3):
            tracking.record_check(t["id"], _payload(n=n), status="ok")
        self.assertEqual(len(tracking.history(t["id"], limit=2)), 2)
        self.assertIsNone(tracking.latest_snapshot(tracking.add_target("bluesky", "fresh")["id"]))

    # ─── encryption at rest ─────────────────────────────

    def test_payload_encrypted_when_key_configured(self):
        from cryptography.fernet import Fernet

        key = Fernet.generate_key().decode()
        with mock.patch.dict(os.environ, {"SPYGLASS_STORE_KEY": key}):
            t = tracking.add_target("instagram", "dawn.shoots")
            tracking.record_check(t["id"], _payload(followers=777), status="ok")

            raw = sqlite3.connect(os.path.join(self.tmp.name, "spyglass.db"))
            blob = raw.execute("SELECT payload FROM social_snapshots").fetchone()[0]
            baseline_blob = raw.execute(
                "SELECT baseline_json FROM social_targets"
            ).fetchone()[0]
            raw.close()
            self.assertNotIn("followers", blob)
            self.assertNotIn("followers", baseline_blob)
            self.assertTrue(blob.startswith("gAAAA"))

            # Public API still decrypts transparently.
            out = tracking.get_target(t["id"])
            self.assertEqual(out["baseline"]["follower_count"], 777)
            self.assertEqual(tracking.latest_snapshot(t["id"])["follower_count"], 777)

    def test_isolated_per_spyglass_home(self):
        t = tracking.add_target("bluesky", "only.here")
        with tempfile.TemporaryDirectory() as other:
            with mock.patch.dict(os.environ, {"SPYGLASS_HOME": other}):
                self.assertEqual(tracking.list_targets(), [])
        self.assertEqual(len(tracking.list_targets()), 1)
        self.assertIsNotNone(tracking.get_target(t["id"]))


if __name__ == "__main__":
    unittest.main()
