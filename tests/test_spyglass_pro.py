"""Tests for the Spyglass-Pro layer itself — the merge glue.

The engine suites under this directory cover the vendored packages; this
one covers what the merge added on top: the Flask API surface, the auth
gate, proxy validation, the job pool's bounds, and the case-history
queries wired to the store's entity index.

Everything here is hermetic — a temporary ``SPYGLASS_HOME`` for the case
store, no network, no browser.
"""

import contextlib
import os
import pathlib
import tempfile
import time
import unittest
from unittest import mock

import helpers  # noqa: F401  — puts spyglass_pro/modules on sys.path

from spyglass_pro import runner
from spyglass_pro.app import _validate_proxy, app, bind_config


class ProxyValidationTest(unittest.TestCase):
    """A proxy URL reaches the environment every subprocess inherits."""

    def test_accepts_supported_schemes(self):
        for url in ("http://127.0.0.1:8080", "https://proxy:443",
                    "socks5://127.0.0.1:9050", "socks5h://h:1080",
                    "socks4://h:1080", "socks4a://h:1080"):
            self.assertEqual(_validate_proxy(url), url, url)

    def test_empty_clears(self):
        self.assertEqual(_validate_proxy(""), "")
        self.assertEqual(_validate_proxy(None), "")

    def test_rejects_non_proxy_schemes(self):
        for url in ("file:///etc/passwd", "gopher://h:70", "ftp://h:21",
                    "javascript:alert(1)", "data:text/html,x"):
            self.assertIsNone(_validate_proxy(url), url)

    def test_rejects_control_characters_and_whitespace(self):
        for url in ("socks5://h:9050\x00evil", "socks5://h:9050\nX: 1",
                    "socks5://h:9050 ;rm -rf"):
            self.assertIsNone(_validate_proxy(url), repr(url))

    def test_requires_hostname(self):
        self.assertIsNone(_validate_proxy("http://"))
        self.assertIsNone(_validate_proxy("socks5://:9050"))


class TokenGateTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_open_when_no_token_configured(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SPYGLASS_PRO_TOKEN", None)
            self.assertEqual(self.client.get("/api/status").status_code, 200)

    def test_api_requires_token_when_configured(self):
        with mock.patch.dict(os.environ, {"SPYGLASS_PRO_TOKEN": "s3cret"}):
            self.assertEqual(self.client.get("/api/status").status_code, 401)
            self.assertEqual(self.client.get("/api/cases").status_code, 401)

    def test_token_accepted_through_each_channel(self):
        with mock.patch.dict(os.environ, {"SPYGLASS_PRO_TOKEN": "s3cret"}):
            for headers, path in (
                ({"Authorization": "Bearer s3cret"}, "/api/status"),
                ({"X-Spyglass-Token": "s3cret"}, "/api/status"),
                ({}, "/api/status?token=s3cret"),
            ):
                self.assertEqual(
                    self.client.get(path, headers=headers).status_code, 200, path)

    def test_wrong_token_rejected(self):
        with mock.patch.dict(os.environ, {"SPYGLASS_PRO_TOKEN": "s3cret"}):
            self.assertEqual(
                self.client.get("/api/status?token=wrong").status_code, 401)

    def test_html_shell_stays_ungated(self):
        """The shell must load so the JS can prompt for the token."""
        with mock.patch.dict(os.environ, {"SPYGLASS_PRO_TOKEN": "s3cret"}):
            self.assertEqual(self.client.get("/").status_code, 200)


class BindConfigTest(unittest.TestCase):
    def test_safe_defaults(self):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("SPYGLASS_PRO_")}
        with mock.patch.dict(os.environ, env, clear=True):
            host, port, debug = bind_config()
        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, 5000)
        self.assertFalse(debug, "debug mode must be off by default")

    def test_debug_is_opt_in(self):
        with mock.patch.dict(os.environ, {"SPYGLASS_PRO_DEBUG": "1"}):
            self.assertTrue(bind_config()[2])


class JobPoolTest(unittest.TestCase):
    def test_errors_are_flattened_and_capped(self):
        exc = ValueError("line one\nline two " + "x" * 500)
        msg = runner._safe_error(exc)
        self.assertNotIn("\n", msg)
        self.assertLessEqual(len(msg), 300)

    def test_unknown_module_reports_clean_error(self):
        result = runner.run_spyglass("evil", "target", {})
        self.assertEqual(result, {"error": "unknown module: evil"})

    def test_timeout_releases_the_caller(self):
        with mock.patch.object(runner, "JOB_TIMEOUT", 0.2):
            result = runner.run_job(time.sleep, 5)
        self.assertIn("timed out", result["error"])

    def test_queue_cap_rejects(self):
        with mock.patch.object(runner, "MAX_QUEUE", 1), \
             mock.patch.object(runner, "_PENDING", 1):
            result = runner.run_job(lambda: {"ok": True})
        self.assertIn("queue full", result["error"])

    def test_successful_job_returns_result(self):
        self.assertEqual(runner.run_job(lambda: {"ok": 1}), {"ok": 1})


class StoredRunFeedbackTest(unittest.TestCase):
    """A scan that stored a run must say so.

    ``stored_run_id`` is what the frontend uses to refresh the Cases table
    and to confirm the store happened — every store path has to set it.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(
            os.environ, {"SPYGLASS_HOME": self._tmp.name})
        self._env.start()
        import pathlib as _pathlib
        import lens_extender.store as le_store
        self._lens = mock.patch.multiple(
            le_store,
            STORE_DIR=_pathlib.Path(self._tmp.name) / "lens",
            STORE_FILE=_pathlib.Path(self._tmp.name) / "lens" / "cases.db",
        )
        self._lens.start()

    def tearDown(self):
        self._lens.stop()
        self._env.stop()
        self._tmp.cleanup()

    def test_spyglass_run_reports_stored_run_id(self):
        result = runner.run_spyglass(
            "opsec", "self", {"store": "1"})
        self.assertIn("stored_run_id", result)
        self.assertEqual(result["stored_run_id"], 1)

    def test_lens_run_reports_stored_run_id(self):
        from lens_extender import analyzer, osint as le_osint

        class FakeResult:
            resolved_ip = "1.1.1.1"
            domain = "example.com"
            reverse_dns = "host.example.com"
            errors = []

        with mock.patch.object(le_osint, "gather", return_value=FakeResult()), \
             mock.patch.object(analyzer, "build_report",
                               return_value={"resolved_ip": "1.1.1.1"}) as build:
            result = runner.run_lens("1.1.1.1", {"store": "1"})
        self.assertTrue(build.called)
        self.assertEqual(result.get("stored_run_id"), 1, result)

    def test_investigation_reports_stored_run_id(self):
        from spyglass_osint import investigation
        with mock.patch.object(investigation, "investigate",
                               return_value={"entities": {}, "correlations": []}):
            result = runner.run_investigate({"email": "a@x.com", "store": "1"})
        self.assertEqual(result.get("stored_run_id"), 1)

    def test_investigation_without_store_says_nothing(self):
        from spyglass_osint import investigation
        with mock.patch.object(investigation, "investigate",
                               return_value={"entities": {}, "correlations": []}):
            result = runner.run_investigate({"email": "a@x.com"})
        self.assertNotIn("stored_run_id", result)

    def test_investigation_honours_export_flags(self):
        from spyglass_osint import investigation
        # export.* writes into the working directory — keep that out of the repo.
        with tempfile.TemporaryDirectory() as workdir, \
             mock.patch.dict(os.environ, {"SPYGLASS_HOME": self._tmp.name}), \
             mock.patch("os.getcwd", return_value=workdir), \
             _chdir(workdir), \
             mock.patch.object(investigation, "investigate",
                               return_value={"entities": {}, "correlations": []}):
            result = runner.run_investigate({"email": "a@x.com", "json": "1"})
            kinds = [a["kind"] for a in result.get("artifacts", [])]
            self.assertIn("json", kinds)


@contextlib.contextmanager
def _chdir(path):
    """export.py writes relative to the process CWD, not SPYGLASS_HOME."""
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


class CaseQueryTest(unittest.TestCase):
    """The entity index behind the Cases panel's diff/timeline/dossier."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(
            os.environ, {"SPYGLASS_HOME": self._tmp.name})
        self._env.start()
        from spyglass_osint import store
        self.store = store

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()

    def _website(self, subs):
        return {
            "dns_records": {"A": "93.184.216.34"},
            "subdomains": subs,
            "whois": {"Organization": "Acme Inc", "Registrant Email": "a@acme.com"},
        }

    def test_target_is_required(self):
        for fn in (runner.case_diff, runner.case_timeline, runner.case_profile):
            self.assertIn("error", fn(""))
            self.assertIn("error", fn("   "))

    def test_diff_needs_two_runs(self):
        self.store.store_result(self._website(["a.example.com"]), "website", "example.com")
        result = runner.case_diff("example.com", "website")
        self.assertIn("error", result)
        self.assertEqual(result["added"], [])

    def test_diff_reports_added_and_removed_entities(self):
        self.store.store_result(
            self._website(["www.example.com", "old.example.com"]), "website", "example.com")
        self.store.store_result(
            self._website(["www.example.com", "new.example.com"]), "website", "example.com")
        result = runner.case_diff("example.com", "website")
        self.assertEqual(result["added"], ["domain:new.example.com"])
        self.assertEqual(result["removed"], ["domain:old.example.com"])

    def test_diff_can_be_scoped_to_one_query_type(self):
        self.store.store_result({"ip": "1.1.1.1"}, "ip", "example.com")
        self.store.store_result({"ip": "2.2.2.2"}, "ip", "example.com")
        self.assertEqual(runner.case_diff("example.com", "ip")["added"], ["ip:2.2.2.2"])
        self.assertEqual(runner.case_diff("example.com", "website")["error"],
                         "need at least two stored runs to diff")

    def test_timeline_is_oldest_first(self):
        self.store.store_result(self._website(["one.example.com"]), "website", "example.com")
        self.store.store_result(self._website(["one.example.com",
                                               "two.example.com"]), "website", "example.com")
        runs = runner.case_timeline("example.com", "website")["runs"]
        self.assertEqual(len(runs), 2)
        self.assertIn("domain:one.example.com", runs[0]["entities"])
        self.assertNotIn("domain:two.example.com", runs[0]["entities"])
        self.assertIn("domain:two.example.com", runs[1]["entities"])

    def test_timeline_empty_for_unknown_target(self):
        self.assertEqual(runner.case_timeline("nobody.example")["runs"], [])

    def test_profile_merges_latest_run_per_type(self):
        self.store.store_result(self._website(["one.example.com"]), "website", "example.com")
        self.store.store_result({"ip": "1.1.1.1"}, "ip", "example.com")
        profile = runner.case_profile("example.com")
        self.assertEqual(sorted(profile["results"]), ["ip", "website"])
        self.assertEqual(profile["schema_version"], 1)
        self.assertEqual(profile["entities"]["domain"], ["one.example.com"])
        # Both the resolved A record and the ip scan land under "ip".
        self.assertEqual(profile["entities"]["ip"], ["1.1.1.1", "93.184.216.34"])

    def test_profile_decrypts_stored_results(self):
        """export_profile must read back what store_result encrypted."""
        self.store.store_result(self._website(["one.example.com"]), "website", "example.com")
        with mock.patch.dict(os.environ, {"SPYGLASS_STORE_KEY": _fernet_key()}):
            profile = runner.case_profile("example.com")
        self.assertEqual(profile["results"]["website"]["subdomains"], ["one.example.com"])

    def test_encrypted_store_round_trip(self):
        with mock.patch.dict(os.environ, {"SPYGLASS_STORE_KEY": _fernet_key()}):
            self.store.store_result({"ip": "9.9.9.9"}, "ip", "secret.example")
            db = self.store._connect()
            try:
                run_id = db.execute("SELECT MAX(id) FROM runs").fetchone()[0]
                row = db.execute(
                    "SELECT result_json FROM runs WHERE id=?", (run_id,)).fetchone()[0]
            finally:
                db.close()
            self.assertNotIn("9.9.9.9", row, "ciphertext must not contain plaintext")
            self.assertEqual(self.store._decrypt(row), '{"ip": "9.9.9.9"}')


def _fernet_key():
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode()


class ListCasesTest(unittest.TestCase):
    """The merged case list spans both engines' stores.

    The Lens store path is hardcoded to ``~/.lens-extender`` upstream, so
    it is repointed at a temp directory here — the suite must never read
    or create the operator's real case databases.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(
            os.environ, {"SPYGLASS_HOME": self._tmp.name})
        self._env.start()
        import lens_extender.store as le_store
        self._lens = mock.patch.multiple(
            le_store,
            STORE_DIR=pathlib.Path(self._tmp.name) / "lens",
            STORE_FILE=pathlib.Path(self._tmp.name) / "lens" / "cases.db",
        )
        self._lens.start()

    def tearDown(self):
        self._lens.stop()
        self._env.stop()
        self._tmp.cleanup()

    def test_merges_both_stores_newest_first(self):
        from spyglass_osint import store
        store.store_result({"ip": "1.1.1.1"}, "ip", "example.com")
        cases = runner.list_cases()
        self.assertTrue(any(c["target"] == "example.com" for c in cases))
        stamps = [c["run_at"] for c in cases]
        self.assertEqual(stamps, sorted(stamps, reverse=True))

    def test_empty_when_no_store_exists(self):
        self.assertEqual(runner.list_cases(), [])

    def test_shape_matches_the_cases_table(self):
        from spyglass_osint import store
        store.store_result({"ip": "1.1.1.1"}, "ip", "example.com")
        for case in runner.list_cases():
            self.assertEqual(sorted(case), ["id", "qtype", "run_at", "target"])


if __name__ == "__main__":
    unittest.main()