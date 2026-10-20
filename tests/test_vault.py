"""Tests for the API-key vault.

The vault owns its own file (``~/.spyglass/vault.json``) so that cutting
the vendored Lens engine out of this tree cannot take the dashboard's
Settings storage with it. These tests pin the three properties that make
that safe:

* a value written through the vault comes back;
* the keys the old Lens config file held are carried over once, and the
  old file is left exactly as it was;
* an unreadable or corrupt vault degrades to "nothing stored" instead of
  taking the server down.
"""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spyglass_pro import vault


class VaultTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.vault_dir = root / "spyglass"
        self.vault_file = self.vault_dir / "vault.json"
        self.legacy_file = root / "lens-extender" / "config.json"
        patch_dir = mock.patch.object(vault, "VAULT_DIR", self.vault_dir)
        patch_file = mock.patch.object(vault, "VAULT_FILE", self.vault_file)
        patch_legacy = mock.patch.object(vault, "LEGACY_FILE", self.legacy_file)
        for patch in (patch_dir, patch_file, patch_legacy):
            patch.start()
            self.addCleanup(patch.stop)

    def _write_legacy(self, payload):
        self.legacy_file.parent.mkdir(parents=True, exist_ok=True)
        self.legacy_file.write_text(json.dumps(payload), encoding="utf-8")

    def test_save_then_load_round_trip(self):
        vault.save({"intelx_api_key": "secret", "hibp_api_key": "other"})
        loaded = vault.load()
        self.assertEqual(loaded["intelx_api_key"], "secret")
        self.assertEqual(loaded["hibp_api_key"], "other")

    def test_only_known_keys_are_stored(self):
        vault.save({"intelx_api_key": "secret", "shodan_api_key": "infra"})
        raw = json.loads(self.vault_file.read_text(encoding="utf-8"))
        self.assertNotIn("shodan_api_key", raw)
        self.assertEqual(set(raw), set(vault.KEYS))

    def test_legacy_config_is_carried_over_once(self):
        self._write_legacy({"intelx_api_key": "legacy-intelx",
                            "hibp_api_key": "legacy-hibp",
                            "shodan_api_key": "infra",
                            "proxy": "socks5://127.0.0.1:9050"})
        loaded = vault.load()
        self.assertEqual(loaded["intelx_api_key"], "legacy-intelx")
        self.assertEqual(loaded["hibp_api_key"], "legacy-hibp")
        self.assertEqual(loaded["proxy"], "socks5://127.0.0.1:9050")
        # The migrated values landed in the new file...
        raw = json.loads(self.vault_file.read_text(encoding="utf-8"))
        self.assertEqual(raw["intelx_api_key"], "legacy-intelx")
        # ...and the old file is untouched: the sibling tool still owns it.
        legacy_raw = json.loads(self.legacy_file.read_text(encoding="utf-8"))
        self.assertEqual(legacy_raw["shodan_api_key"], "infra")
        self.assertEqual(legacy_raw["intelx_api_key"], "legacy-intelx")

    def test_migration_does_not_overwrite_a_later_value(self):
        vault.save({"intelx_api_key": "newer"})
        self._write_legacy({"intelx_api_key": "legacy"})
        self.assertEqual(vault.load()["intelx_api_key"], "newer")

    def test_corrupt_vault_degrades_to_empty(self):
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.vault_file.write_text("{not json", encoding="utf-8")
        self.assertEqual(vault.load()["intelx_api_key"], "")

    @unittest.skipIf(os.name == "nt", "POSIX file modes only")
    def test_vault_file_is_owner_only(self):
        vault.save({"intelx_api_key": "secret"})
        mode = stat.S_IMODE(self.vault_file.stat().st_mode)
        self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()
