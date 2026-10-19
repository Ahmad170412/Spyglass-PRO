"""Tests for the Spyglass-Pro layer itself — the merge glue.

The engine suites under this directory cover the vendored packages; this
one covers what the merge added on top: the Flask API surface, the auth
gate, proxy validation, the job pool's bounds, and the case-history
queries wired to the store's entity index.

Everything here is hermetic — a temporary ``SPYGLASS_HOME`` for the case
store, no network, no browser.
"""

import contextlib
import json
import os
import pathlib
import tempfile
import time
import unittest
from unittest import mock

import helpers  # noqa: F401  — puts spyglass_pro/modules on sys.path

from spyglass_pro import runner
from spyglass_pro.app import _mask_proxy, _validate_proxy, app, bind_config


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

    def test_queue_rejection_is_marked_for_http_429(self):
        """A refusal must be distinguishable from a scan that ran and failed.

        Both arrive as {"error": ...}; without the sentinel an API client
        cannot tell back-pressure from a real error and would treat a busy
        server as a successful request with a broken payload.
        """
        with mock.patch.object(runner, "MAX_QUEUE", 1), \
             mock.patch.object(runner, "_PENDING", 1):
            result = runner.run_job(lambda: {"ok": True})
        self.assertTrue(result[runner.REJECTED_KEY])

    def test_successful_job_is_not_marked_rejected(self):
        self.assertNotIn(runner.REJECTED_KEY, runner.run_job(lambda: {"ok": 1}))


class TargetValidationTest(unittest.TestCase):
    """Junk targets must be refused before they reach a subprocess.

    Without this, a 2KB garbage string was accepted by the opsec panel and
    came back with confident geo/ISP data for the operator's own IP, and a
    700-character string was handed to sherlock, holding a worker for minutes.
    """

    def test_overlong_targets_are_rejected(self):
        for module in ("website", "email", "phone", "username", "darkweb", "ip"):
            err = runner._validate_target(module, "a" * 700)
            self.assertIsNotNone(err, f"{module} accepted a 700-character target")
            self.assertIn("too long", err)

    def test_shell_metacharacters_are_rejected(self):
        for junk in ("'; DROP TABLE users;--", "a.com; rm -rf /", "$(whoami)",
                     "`id`", "a.com|cat /etc/passwd", "<script>alert(1)</script>"):
            self.assertIsNotNone(runner._validate_target("website", junk),
                                 f"accepted {junk!r}")

    def test_empty_target_rejected_where_it_would_query_nothing(self):
        for module in ("website", "email", "phone", "username", "darkweb", "ip"):
            err = runner._validate_target(module, "")
            self.assertIsNotNone(err)
            self.assertIn("required", err)

    def test_self_check_modules_still_accept_empty_target(self):
        """opsec health-checks the local machine and metadata takes a path —
        an empty target is meaningful for both, so validation must allow it."""
        self.assertIsNone(runner._validate_target("opsec", ""))
        self.assertIsNone(runner._validate_target("metadata", ""))

    def test_opsec_rejects_an_absurd_target_it_would_ignore(self):
        """opsec never reads its target, but a long one still produced
        confident geo/ISP output about the operator's own IP. Empty stays
        valid (the self-check), junk does not."""
        err = runner._validate_target("opsec", "a" * 700)
        self.assertIsNotNone(err)
        self.assertIn("too long", err)

    def test_ip_module_requires_an_ip(self):
        for junk in ("not-an-ip", "999.999.999.999", "example.com"):
            self.assertIsNotNone(runner._validate_target("ip", junk))
        self.assertIsNone(runner._validate_target("ip", "8.8.8.8"))
        self.assertIsNone(runner._validate_target("ip", "2001:4860:4860::8888"))

    def test_ip_module_accepts_ipv6_literals(self):
        for good in ("::1", "2001:4860:4860::8888", "fe80::abcd"):
            self.assertIsNone(runner._validate_target("ip", good), good)

    def test_ip_module_rejects_malformed_ipv6(self):
        # A colon used to be sufficient ("gggg::1" was accepted and then
        # always failed at resolve time); only a real address passes now.
        for junk in (":", "2001:db8:::1", "12345::", "gggg::1", "::gggg"):
            self.assertIsNotNone(runner._validate_target("ip", junk), junk)

    def test_legitimate_targets_are_accepted(self):
        """The gate must not break real recon input."""
        valid = [
            ("website", "example.com"),
            ("website", "sub.domain.co.uk"),
            ("email", "user@example.com"),
            ("email", "a.b+tag@sub.example.org"),
            ("phone", "+14155552671"),
            ("phone", "555-123-4567"),
            ("username", "torproject"),
            ("username", "some_user.name-1"),
            ("ip", "8.8.8.8"),
            ("darkweb", "example.com"),
        ]
        for module, target in valid:
            self.assertIsNone(runner._validate_target(module, target),
                              f"{module} wrongly rejected {target!r}")

    def test_run_spyglass_rejects_before_dispatch(self):
        """The rejection happens before a handler runs, so no subprocess starts."""
        with mock.patch.dict(runner._SPYGLASS_HANDLERS,
                             {"website": mock.Mock(return_value={"ok": True})}):
            result = runner.run_spyglass("website", "a" * 700, {})
        self.assertIn("error", result)
        self.assertNotIn(runner.REJECTED_KEY, result)


class IdentifierValidationTest(unittest.TestCase):
    """Real phone formats reach the engine; leading-dash input never does."""

    def test_phone_formats_with_separators_are_accepted(self):
        for target in ("+1 415 555 0100", "(415) 555-0100",
                       "415.555.0100", "555-123-4567"):
            self.assertIsNone(runner._validate_target("phone", target), target)

    def test_leading_dash_is_rejected_for_phone_and_email(self):
        # A leading '-' could read as an option flag once it lands in argv.
        for module, target in (("phone", "-1234567"), ("email", "-a@b.com")):
            self.assertIsNotNone(runner._validate_target(module, target), target)

    def test_letters_are_not_a_phone_number(self):
        for junk in ("1-800-FLOWERS", "call-me", "12345x"):
            self.assertIsNotNone(runner._validate_target("phone", junk), junk)


class QueueRejectionHttpTest(unittest.TestCase):
    """A full queue must surface as 429, not 200."""

    def setUp(self):
        self.client = app.test_client()

    def test_queue_full_returns_429(self):
        with mock.patch.object(runner, "MAX_QUEUE", 1), \
             mock.patch.object(runner, "_PENDING", 1):
            resp = self.client.get("/api/spyglass/run?module=website&target=example.com")
        self.assertEqual(resp.status_code, 429)
        self.assertIn("queue full", resp.get_json()["error"])

    def test_sentinel_is_not_leaked_to_clients(self):
        with mock.patch.object(runner, "MAX_QUEUE", 1), \
             mock.patch.object(runner, "_PENDING", 1):
            resp = self.client.get("/api/spyglass/run?module=website&target=example.com")
        self.assertNotIn(runner.REJECTED_KEY, resp.get_json())

    def test_invalid_target_returns_200_with_error(self):
        """Validation failure is a client mistake, not server back-pressure,
        so it stays a 200 with an error body like every other scan error."""
        resp = self.client.get("/api/spyglass/run?module=website&target=" + "a" * 700)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("error", resp.get_json())


class DeleteCaseTest(unittest.TestCase):
    """Stored runs must be deletable, or the case table only grows."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._env = mock.patch.dict(
            os.environ, {"SPYGLASS_HOME": self._tmp.name})
        self._env.start()
        self.addCleanup(self._env.stop)
        import pathlib as _pathlib

        import lens_extender.store as le_store
        self._lens = mock.patch.multiple(
            le_store,
            STORE_DIR=_pathlib.Path(self._tmp.name) / "lens",
            STORE_FILE=_pathlib.Path(self._tmp.name) / "lens" / "cases.db",
        )
        self._lens.start()
        self.addCleanup(self._lens.stop)

    def test_delete_removes_run_and_entities(self):
        from spyglass_osint import store
        run_id = store.store_result({"subdomains": ["a.example.com"]},
                                    "website", "del-me.example.com")
        self.assertTrue(runner.list_cases())
        result = runner.delete_case(run_id, "website")
        self.assertEqual(result.get("deleted"), run_id)
        self.assertEqual(runner.list_cases(), [])
        self.assertEqual(store.timeline("del-me.example.com", "website"), [])

    def test_delete_missing_run_is_404_shaped(self):
        result = runner.delete_case(999999, "website")
        self.assertIn("no stored run", result.get("error", ""))

    def test_delete_rejects_junk_ids(self):
        for junk in ("", "abc", "-3", "0", None):
            self.assertIn("error", runner.delete_case(junk, "website"))

    def test_delete_endpoint_round_trip(self):
        from spyglass_osint import store
        run_id = store.store_result({"subdomains": ["b.example.com"]},
                                    "website", "round-trip.example.com")
        client = app.test_client()
        resp = client.delete(f"/api/cases/run?id={run_id}&qtype=website")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json().get("deleted"), run_id)
        resp = client.delete(f"/api/cases/run?id={run_id}&qtype=website")
        self.assertEqual(resp.status_code, 404)


class AsyncJobPollTest(unittest.TestCase):
    """Polling a finished job must never 500.

    A successful job stores ``error: None`` in its record; the poll route
    used to call ``.startswith`` on that None and crash the exact request
    the live dashboard makes after every async scan.
    """

    def setUp(self):
        self.client = app.test_client()

    def test_poll_finished_successful_job_returns_200(self):
        done = {"job_id": "abc123", "name": "run_spyglass", "status": "done",
                "created_at": 0, "result": {"summary": "ok"}, "error": None,
                "progress": ["starting opsec recon for self"]}
        with mock.patch.object(runner, "get_job", return_value=dict(done)):
            resp = self.client.get("/api/job/abc123")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "done")

    def test_poll_unknown_job_returns_404(self):
        with mock.patch.object(runner, "get_job",
                               return_value={"error": "unknown job: nope"}):
            resp = self.client.get("/api/job/nope")
        self.assertEqual(resp.status_code, 404)

    def test_stream_response_has_no_hop_by_hop_headers(self):
        """waitress (the default server) 500s any response carrying a
        ``Connection`` header, which used to make every SSE stream fail.
        Uses a real finished job: meta + done arrive with no waiting."""
        def job():
            return {"summary": "ok"}

        job_id = runner.submit_job(job)["job_id"]
        deadline = time.time() + 20
        while runner.get_job(job_id).get("status") != "done" and time.time() < deadline:
            time.sleep(0.05)
        self.assertEqual(runner.get_job(job_id).get("status"), "done")
        resp = self.client.get(f"/api/stream/{job_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("Connection", resp.headers)
        body = resp.get_data(as_text=True)
        self.assertIn("event: done", body)


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
        from lens_extender import analyzer
        from lens_extender import osint as le_osint

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


class SettingsSaveTest(unittest.TestCase):
    """The vault must round-trip: save sets, empty clears, junk proxy 400s.

    A fake store keeps the suite off the operator's real
    ~/.lens-extender/config.json; env vars the save writes are removed on
    teardown so one test cannot leak a key into the next.
    """

    def setUp(self):
        self.client = app.test_client()
        self.saved = {}

        class FakeStore:
            def load(inner_self):
                return dict(self.saved)

            def save(inner_self, cfg):
                self.saved.clear()
                self.saved.update(cfg)

        self._store = mock.patch("spyglass_pro.app._settings_store",
                                 return_value=FakeStore())
        self._store.start()
        self.addCleanup(self._store.stop)
        for env in ("SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY",
                    "CENSYS_API_ID", "CENSYS_API_KEY", "GREYNOISE_API_KEY",
                    "NVD_API_KEY", "INTELX_API_KEY", "HIBP_API_KEY"):
            os.environ.pop(env, None)
        self.addCleanup(os.environ.pop, "SHODAN_API_KEY", None)

    def test_save_then_clear_round_trip(self):
        resp = self.client.post("/api/settings", json={"shodan_api_key": "abc123"})
        self.assertEqual(resp.status_code, 200)
        snap = self.client.get("/api/settings").get_json()
        key = next(k for k in snap["keys"] if k["key"] == "shodan_api_key")
        self.assertTrue(key["configured"])
        self.assertTrue(key["hint"].endswith("c123"))

        resp = self.client.post("/api/settings", json={"shodan_api_key": ""})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("shodan_api_key", resp.get_json()["cleared"])
        snap = self.client.get("/api/settings").get_json()
        key = next(k for k in snap["keys"] if k["key"] == "shodan_api_key")
        self.assertFalse(key["configured"])

    def test_invalid_proxy_is_rejected(self):
        resp = self.client.post("/api/settings", json={"proxy": "file:///etc/passwd"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("proxy", resp.get_json()["error"].lower())


class AsyncSubmitTest(unittest.TestCase):
    """Async submit answers 202 with a job id, or 429 when the queue is full."""

    def setUp(self):
        self.client = app.test_client()

    def test_async_submit_returns_202_with_job_id(self):
        with mock.patch.object(runner, "submit_job",
                               return_value={"job_id": "job-1", "status": "running"}):
            resp = self.client.get("/api/spyglass/run?module=website&target=example.com&async=1")
        self.assertEqual(resp.status_code, 202)
        self.assertEqual(resp.get_json()["job_id"], "job-1")

    def test_async_submit_queue_full_returns_429_without_leaking_sentinel(self):
        refused = {"error": "run_spyglass rejected: job queue full (16 pending)"}
        refused[runner.REJECTED_KEY] = True
        with mock.patch.object(runner, "submit_job", return_value=dict(refused)):
            resp = self.client.get("/api/spyglass/run?module=website&target=example.com&async=1")
        self.assertEqual(resp.status_code, 429)
        self.assertNotIn(runner.REJECTED_KEY, resp.get_json())


class BlackbirdProbeAgreementTest(unittest.TestCase):
    """The status probe must agree with the engine's own resolution.

    The engine falls back to fixed clone layouts when blackbird is not
    on PATH; a probe using which() alone once reported the tool missing
    on a machine where scans would have used it.
    """

    def test_fallback_file_counts_as_present(self):
        import tempfile

        from spyglass_pro.app import _blackbird_present
        with tempfile.TemporaryDirectory() as tmp:
            script = os.path.join(tmp, "blackbird.py")
            pathlib.Path(script).write_text("# fake blackbird\n")
            with mock.patch("shutil.which", return_value=None), \
                 mock.patch("spyglass_osint.utils._BLACKBIRD_PATHS", [script]):
                self.assertTrue(_blackbird_present())

    def test_nothing_anywhere_counts_as_missing(self):
        from spyglass_pro.app import _blackbird_present
        with mock.patch("shutil.which", return_value=None), \
             mock.patch("spyglass_osint.utils._BLACKBIRD_PATHS", []):
            self.assertFalse(_blackbird_present())


class AuditFixTest(unittest.TestCase):
    """October audit fixes: validation must cover every dispatch path."""

    def test_investigation_rejects_junk_before_dispatch(self):
        from spyglass_osint import investigation
        with mock.patch.object(investigation, "investigate") as inv:
            result = runner.run_investigate({"website": "a" * 700})
        inv.assert_not_called()
        self.assertIn("too long", result["error"])

    def test_investigation_rejects_shell_metachars(self):
        from spyglass_osint import investigation
        with mock.patch.object(investigation, "investigate") as inv:
            result = runner.run_investigate({"username": "$(whoami)"})
        inv.assert_not_called()
        self.assertIn("error", result)

    def test_investigation_accepts_legitimate_inputs(self):
        from spyglass_osint import investigation
        with mock.patch.object(investigation, "investigate",
                               return_value={"entities": {}, "correlations": []}):
            result = runner.run_investigate({"email": "a@x.com"})
        self.assertNotIn("error", result)

    def test_social_handle_length_capped(self):
        from spyglass_pro.social import harness
        with mock.patch.object(harness, "collect") as collect:
            result = runner.run_social("mastodon", "x" * 300, {})
        collect.assert_not_called()
        self.assertIn("too long", result["error"])


class SocialStoreTest(unittest.TestCase):
    """The social form's Store checkbox must actually store.

    run_social used to accept the flag and silently drop it — the run
    completed with no stored_run_id and the case table never changed.
    Runs store as social_<platform> so one handle on two platforms lands
    in two timelines and never diffs against itself.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._env = mock.patch.dict(
            os.environ, {"SPYGLASS_HOME": self._tmp.name})
        self._env.start()
        self.addCleanup(self._env.stop)
        import pathlib as _pathlib

        import lens_extender.store as le_store
        self._lens = mock.patch.multiple(
            le_store,
            STORE_DIR=_pathlib.Path(self._tmp.name) / "lens",
            STORE_FILE=_pathlib.Path(self._tmp.name) / "lens" / "cases.db",
        )
        self._lens.start()
        self.addCleanup(self._lens.stop)

    def test_store_flag_stores_as_social_platform(self):
        from spyglass_osint import store

        from spyglass_pro.social import harness

        fake = {"platform": "mastodon", "handle": "Gargron",                "found": True, "display_name": "Eugen",
                "follower_count": 1}
        with mock.patch.object(harness, "collect", return_value=dict(fake)):
            result = runner.run_social("mastodon", "Gargron", {"store": "1"})
        self.assertIn("stored_run_id", result)
        cases = [c for c in runner.list_cases()
                 if c["qtype"] == "social_mastodon"]
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["target"], "Gargron")
        self.assertIn("username:gargron",
                      store.timeline("Gargron", "social_mastodon")[0]["entities"])

    def test_without_store_nothing_is_stored(self):
        from spyglass_pro.social import harness

        fake = {"platform": "bluesky", "handle": "x.bsky.social",
                "found": True}
        with mock.patch.object(harness, "collect", return_value=dict(fake)):
            result = runner.run_social("bluesky", "x.bsky.social", {})
        self.assertNotIn("stored_run_id", result)
        self.assertEqual(runner.list_cases(), [])

    def test_errored_run_is_not_stored(self):
        from spyglass_pro.social import harness

        with mock.patch.object(harness, "collect",
                               return_value={"error": "boom", "platform": "mastodon",
                                             "handle": "nobody"}):
            result = runner.run_social("mastodon", "nobody", {"store": "1"})
        self.assertNotIn("stored_run_id", result)
        self.assertEqual(runner.list_cases(), [])


class RequestOriginGateTest(unittest.TestCase):
    """The default install has no token, so request origin must be pinned.

    DNS rebinding points an attacker domain at 127.0.0.1: the rebound request
    carries that domain as Host and reads as same-origin to the attacker's
    page. Without a Host allowlist it read the whole API. Cross-site requests
    are refused separately (Origin / Sec-Fetch-Site); a non-browser client
    sends neither header and is unaffected.
    """

    def setUp(self):
        self.client = app.test_client()

    def test_loopback_hosts_are_allowed(self):
        with mock.patch.dict(os.environ, {"SPYGLASS_PRO_TOKEN": ""}):
            for host in ("127.0.0.1", "localhost", "127.0.0.1:5000", "[::1]:5000"):
                self.assertEqual(
                    self.client.get("/api/status", headers={"Host": host}).status_code,
                    200, host)

    def test_foreign_host_is_rejected_without_a_token(self):
        with mock.patch.dict(os.environ, {"SPYGLASS_PRO_TOKEN": ""}):
            resp = self.client.get("/api/status", headers={"Host": "attacker.example"})
        self.assertEqual(resp.status_code, 400)

    def test_allowlist_permits_a_real_hostname(self):
        with mock.patch.dict(os.environ, {
                "SPYGLASS_PRO_TOKEN": "",
                "SPYGLASS_PRO_ALLOWED_HOSTS": "recon.internal,10.0.0.5:5000"}):
            for host in ("recon.internal", "10.0.0.5:5000"):
                self.assertEqual(
                    self.client.get("/api/status", headers={"Host": host}).status_code,
                    200, host)

    def test_token_makes_the_host_check_unnecessary(self):
        with mock.patch.dict(os.environ, {"SPYGLASS_PRO_TOKEN": "s3cret"}):
            resp = self.client.get("/api/status",
                                   headers={"Host": "proxied.example",
                                            "Authorization": "Bearer s3cret"})
        self.assertEqual(resp.status_code, 200)

    def test_cross_site_request_is_refused(self):
        resp = self.client.get("/api/status", headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(resp.status_code, 403)

    def test_cross_origin_request_is_refused(self):
        resp = self.client.get("/api/status", headers={"Origin": "https://evil.example"})
        self.assertEqual(resp.status_code, 403)

    def test_null_origin_is_refused(self):
        resp = self.client.get("/api/status", headers={"Origin": "null"})
        self.assertEqual(resp.status_code, 403)

    def test_same_origin_request_is_allowed(self):
        resp = self.client.get("/api/status", headers={
            "Origin": "http://localhost", "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(resp.status_code, 200)

    def test_scripted_client_without_browser_headers_is_unaffected(self):
        with mock.patch.dict(os.environ, {"SPYGLASS_PRO_TOKEN": ""}):
            self.assertEqual(self.client.get("/api/status").status_code, 200)


class ProxyMaskingTest(unittest.TestCase):
    """A proxy credential must never be echoed back by any endpoint."""

    CREDS = "http://alice:s3cr3t@127.0.0.1:8080"

    def setUp(self):
        self.client = app.test_client()
        self._store = mock.patch("spyglass_pro.app._settings_store", return_value=None)
        self._store.start()
        self.addCleanup(self._store.stop)

    def test_mask_hides_only_the_credentials(self):
        self.assertEqual(_mask_proxy(self.CREDS), "http://••••@127.0.0.1:8080")
        self.assertEqual(_mask_proxy("socks5://127.0.0.1:9050"),
                         "socks5://127.0.0.1:9050")
        self.assertEqual(_mask_proxy(""), "")

    def test_status_never_echoes_the_credential(self):
        with mock.patch.dict(os.environ, {"SPYGLASS_PROXY": self.CREDS}):
            body = self.client.get("/api/status").get_json()
        self.assertNotIn("s3cr3t", json.dumps(body, default=str))
        self.assertEqual(body["proxy"], "http://••••@127.0.0.1:8080")

    def test_settings_snapshot_masks_the_proxy(self):
        with mock.patch.dict(os.environ, {"SPYGLASS_PROXY": self.CREDS}):
            body = self.client.get("/api/settings").get_json()
        self.assertNotIn("s3cr3t", json.dumps(body, default=str))

    def test_proxy_get_masks_the_credential(self):
        with mock.patch.dict(os.environ, {"SPYGLASS_PROXY": self.CREDS}):
            body = self.client.get("/api/proxy").get_json()
        self.assertNotIn("s3cr3t", json.dumps(body, default=str))

    def test_untouched_masked_field_keeps_the_proxy(self):
        with mock.patch.dict(os.environ, {"SPYGLASS_PROXY": self.CREDS}):
            resp = self.client.post("/api/settings",
                                    json={"proxy": _mask_proxy(self.CREDS)})
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(os.environ["SPYGLASS_PROXY"], self.CREDS)

    def test_editing_a_masked_value_is_rejected(self):
        with mock.patch.dict(os.environ, {"SPYGLASS_PROXY": self.CREDS}):
            resp = self.client.post("/api/settings",
                                    json={"proxy": "http://••••@newhost:8080"})
        self.assertEqual(resp.status_code, 400)


class SecurityHeaderTest(unittest.TestCase):
    """The dashboard ships baseline browser hardening on every response."""

    def setUp(self):
        self.client = app.test_client()

    def test_shell_carries_the_hardening_headers(self):
        resp = self.client.get("/")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "no-referrer")
        csp = resp.headers.get("Content-Security-Policy") or ""
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("'unsafe-eval'", csp)

    def test_api_responses_carry_them_too(self):
        resp = self.client.get("/api/status")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")


if __name__ == "__main__":
    unittest.main()
