"""Tests for store.py — the SQLite case store (isolated via SPYGLASS_HOME)."""

import os
import tempfile
import unittest
from unittest import mock

from helpers import imp

store = imp("store")


def _website_result(ips, subs):
    return {
        "dns_records": {"A": ", ".join(ips)},
        "subdomains": subs,
        "whois": {"Organization": "Acme Inc", "Registrant Email": "a@acme.com"},
    }


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch.dict(os.environ, {"SPYGLASS_HOME": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_store_and_list(self):
        store.store_result(_website_result(["1.2.3.4"], ["www.x.com"]), "website", "x.com")
        cases = store.list_cases()
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["target"], "x.com")
        self.assertEqual(cases[0]["qtype"], "website")
        self.assertEqual(cases[0]["count"], 1)

    def test_diff_added_and_removed(self):
        store.store_result(_website_result(["1.2.3.4"], ["www.x.com", "a.x.com"]), "website", "x.com")
        store.store_result(_website_result(["1.2.3.4", "5.6.7.8"], ["www.x.com", "b.x.com"]), "website", "x.com")
        d = store.diff("x.com", "website")
        self.assertNotIn("error", d)
        self.assertIn("domain:b.x.com", d["added"])
        self.assertIn("ip:5.6.7.8", d["added"])
        self.assertIn("domain:a.x.com", d["removed"])
        self.assertNotIn("domain:www.x.com", d["added"] + d["removed"])

    def test_diff_needs_two_runs(self):
        store.store_result(_website_result(["1.2.3.4"], ["www.x.com"]), "website", "x.com")
        self.assertIn("error", store.diff("x.com", "website"))

    def test_timeline(self):
        store.store_result(_website_result(["1.2.3.4"], ["www.x.com"]), "website", "x.com")
        rows = store.timeline("x.com", "website")
        self.assertEqual(len(rows), 1)
        self.assertIn("ip:1.2.3.4", rows[0]["entities"])

    def test_export_profile_merges_qtypes(self):
        store.store_result(_website_result(["1.2.3.4"], ["www.x.com"]), "website", "x.com")
        store.store_result({"query": "x.com", "type": "domain", "ahmia": []}, "darkweb", "x.com")
        profile = store.export_profile("x.com")
        self.assertEqual(profile["target"], "x.com")
        self.assertEqual(profile["schema_version"], 1)
        self.assertIn("website", profile["results"])
        self.assertIn("darkweb", profile["results"])
        self.assertIn("www.x.com", profile["entities"]["domain"])

    def test_entities_website(self):
        ents = store._entities(_website_result(["1.2.3.4"], ["www.x.com"]), "website")
        kv = {f"{k}:{v}" for k, v in ents}
        self.assertIn("ip:1.2.3.4", kv)
        self.assertIn("domain:www.x.com", kv)
        self.assertIn("org:acme inc", kv)
        self.assertIn("email:a@acme.com", kv)

    def test_entities_social_indexes_the_handle(self):
        """Social runs store as social_<platform>; the handle is the node."""
        for qtype in ("social", "social_mastodon", "social_bluesky", "social_instagram"):
            ents = store._entities({"handle": "Gargron", "platform": "mastodon"}, qtype)
            self.assertIn(("username", "gargron"), ents, qtype)

    def test_entities_social_ignores_missing_handle(self):
        self.assertEqual(store._entities({"platform": "mastodon"}, "social_mastodon"), [])


@unittest.skipUnless(store._CRYPTO_AVAILABLE, "cryptography not installed")
class EntityEncryptionTest(unittest.TestCase):
    """The entity index must be encrypted at rest, like the result blob.

    The index holds the same identifiers (domains, IPs, emails) as the
    result JSON; storing it in cleartext next to a Fernet ciphertext blob
    defeated the encryption the store advertises. This pins the raw bytes.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        from cryptography.fernet import Fernet
        patcher = mock.patch.dict(os.environ, {
            "SPYGLASS_HOME": self.tmp.name,
            "SPYGLASS_STORE_KEY": Fernet.generate_key().decode(),
        })
        patcher.start()
        self.addCleanup(patcher.stop)

    def _raw_db_bytes(self):
        # WAL may still hold the rows until the connection closes; read the
        # main file and any -wal/-shm so the assertion cannot pass by accident.
        blob = b""
        for name in os.listdir(self.tmp.name):
            if name.startswith("spyglass.db"):
                with open(os.path.join(self.tmp.name, name), "rb") as fh:
                    blob += fh.read()
        return blob

    def test_entity_values_are_not_written_in_cleartext(self):
        store.store_result(_website_result(["1.2.3.4"], ["secret.x.com"]), "website", "x.com")
        raw = self._raw_db_bytes()
        for needle in (b"secret.x.com", b"1.2.3.4", b"a@acme.com"):
            self.assertNotIn(needle, raw, needle)

    def test_diff_and_timeline_still_read_decrypted(self):
        store.store_result(_website_result(["1.2.3.4"], ["www.x.com"]), "website", "x.com")
        store.store_result(_website_result(["1.2.3.4", "5.6.7.8"], ["www.x.com"]), "website", "x.com")
        d = store.diff("x.com", "website")
        self.assertIn("ip:5.6.7.8", d["added"])
        rows = store.timeline("x.com", "website")
        self.assertIn("domain:www.x.com", rows[0]["entities"])

    def test_legacy_cleartext_rows_still_read(self):
        """A store written before this change (plaintext entities) must not
        turn into ciphertext-looking blobs once a key is configured."""
        store.store_result(_website_result(["1.2.3.4"], ["www.x.com"]), "website", "x.com")
        db = store._connect()
        try:
            # Simulate a legacy row: overwrite one entity with its cleartext.
            db.execute("UPDATE entities SET value=? WHERE kind='domain'", ("www.x.com",))
            db.commit()
            ents = store._entity_set(db, db.execute(
                "SELECT id FROM runs LIMIT 1").fetchone()["id"])
        finally:
            db.close()
        self.assertIn("domain:www.x.com", ents)


if __name__ == "__main__":
    unittest.main()
