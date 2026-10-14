"""Tests for live progress streaming: the runner's push plumbing and the
/api/stream SSE endpoint that feeds the dashboard's run console.

Everything here is offline: a job is a couple of threads and a gate, and
the stream endpoint is driven through Flask's test client. The two
properties the live console depends on are pinned here — a progress
line reaches the job record *while the job is still running*, and the
stream replays lines in order before announcing completion.
"""

import json
import threading
import time
import unittest
from unittest import mock

import helpers  # noqa: F401  — puts spyglass_pro/modules on sys.path

import spyglass_pro.app as app_module
from spyglass_pro import runner
from spyglass_pro.app import app


def _parse_frames(raw):
    """[(event, data), ...] from an SSE body; comments are dropped."""
    frames = []
    for chunk in raw.split("\n\n"):
        if not chunk.strip() or chunk.startswith(":"):
            continue
        event, data = None, None
        for line in chunk.split("\n"):
            if line.startswith("event: "):
                event = line[len("event: "):]
            elif line.startswith("data: "):
                data = json.loads(line[len("data: "):])
        if event is not None:
            frames.append((event, data))
    return frames


def _wait_for(predicate, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def _drain_stream(client, url, deadline=25.0):
    """Consume a streaming response on a background thread so a broken
    done-detection fails the assertion instead of hanging the suite."""
    holder = {}

    def _work():
        resp = client.get(url)
        holder["status"] = resp.status_code
        if resp.status_code != 200:
            return
        body = resp.response
        if isinstance(body, (bytes, bytearray)):
            holder["body"] = bytes(body)
            return
        chunks = []
        for chunk in body:
            chunks.append(chunk)
        holder["body"] = b"".join(chunks)

    worker = threading.Thread(target=_work, daemon=True)
    worker.start()
    worker.join(deadline)
    if worker.is_alive():
        raise AssertionError(f"stream did not finish within {deadline}s")
    return holder


class LiveProgressTest(unittest.TestCase):
    def test_lines_reach_the_job_record_while_running(self):
        """The live console's whole premise: the first line must be in the
        job record before the job finishes."""
        gate = threading.Event()

        def job():
            progress = runner.Progress()
            progress.add("leg one dispatched")
            gate.wait(timeout=10)
            progress.add("leg two dispatched")
            return {"ok": True, "progress": progress.lines}

        job_id = runner.submit_job(job)["job_id"]
        try:
            self.assertTrue(_wait_for(
                lambda: runner.get_job(job_id).get("progress") == [
                    "leg one dispatched"]),
                "first progress line never reached the job record")
            self.assertEqual(runner.get_job(job_id)["status"], "running")
        finally:
            gate.set()
        self.assertTrue(_wait_for(
            lambda: runner.get_job(job_id).get("status") == "done"))
        job = runner.get_job(job_id)
        self.assertEqual(job["progress"],
                         ["leg one dispatched", "leg two dispatched"])
        self.assertEqual(job["result"], {
            "ok": True,
            "progress": ["leg one dispatched", "leg two dispatched"],
        })

    def test_get_job_snapshots_progress(self):
        """A stream iterating a job's progress must not see the list
        mutate underneath it."""
        gate = threading.Event()

        def job():
            progress = runner.Progress()
            progress.add("one")
            gate.wait(timeout=10)
            progress.add("two")
            return {"ok": True}

        job_id = runner.submit_job(job)["job_id"]
        try:
            self.assertTrue(_wait_for(
                lambda: runner.get_job(job_id).get("progress") == ["one"]))
            snapshot = runner.get_job(job_id)
            snapshot["progress"].append("injected")
            self.assertEqual(runner.get_job(job_id)["progress"], ["one"])
        finally:
            gate.set()
        self.assertTrue(_wait_for(
            lambda: runner.get_job(job_id).get("status") == "done"))

    def test_wait_progress_reports_unknown_jobs(self):
        self.assertFalse(runner.wait_progress("no-such-job", timeout=0.05))


class StreamEndpointTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    @staticmethod
    def _finished_job(lines=("alpha", "beta")):
        """A job that has pushed its lines and completed."""
        def job():
            progress = runner.Progress()
            for line in lines:
                progress.add(line)
            return {"ok": True}

        job_id = runner.submit_job(job)["job_id"]
        assert _wait_for(lambda: runner.get_job(job_id).get("status") == "done")
        return job_id

    def test_replay_then_done_for_a_finished_job(self):
        job_id = self._finished_job()
        drained = _drain_stream(self.client, f"/api/stream/{job_id}")
        self.assertEqual(drained["status"], 200)
        frames = _parse_frames(drained["body"].decode("utf-8"))
        self.assertEqual([event for event, _ in frames],
                         ["meta", "log", "log", "done"])
        self.assertEqual([data["line"] for event, data in frames
                          if event == "log"], ["alpha", "beta"])
        events = dict(frames)
        self.assertEqual(events["meta"]["job_id"], job_id)
        self.assertTrue(events["done"]["ok"])

    def test_live_stream_reaches_done(self):
        """Stream while the job is still running: lines are replayed,
        then the final result arrives as the done event."""
        gate = threading.Event()

        def job():
            progress = runner.Progress()
            progress.add("first line")
            gate.wait(timeout=10)
            progress.add("second line")
            return {"ok": True, "summary": "all legs finished"}

        job_id = runner.submit_job(job)["job_id"]
        # Open the gate only after the stream request is under way, so
        # the second line is genuinely pushed mid-stream.
        threading.Timer(0.3, gate.set).start()
        drained = _drain_stream(self.client, f"/api/stream/{job_id}")
        self.assertEqual(drained["status"], 200)
        frames = _parse_frames(drained["body"].decode("utf-8"))
        names = [event for event, _ in frames]
        self.assertEqual(names[0], "meta")
        self.assertEqual(names[-1], "done")
        lines = [data["line"] for event, data in frames if event == "log"]
        self.assertEqual(lines, ["first line", "second line"])
        self.assertEqual(dict(frames)["done"]["summary"],
                         "all legs finished")

    def test_stream_content_type_is_event_stream(self):
        job_id = self._finished_job(lines=())
        resp = self.client.get(f"/api/stream/{job_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.mimetype.startswith("text/event-stream"))

    def test_unknown_job_is_404(self):
        resp = self.client.get("/api/stream/" + "deadbeef" * 8)
        self.assertEqual(resp.status_code, 404)
        self.assertIn("unknown job", resp.get_json()["error"])

    def test_stream_limit_back_pressures_with_429(self):
        """Open streams hold WSGI threads, so past the cap the client is
        told to poll — the same back-pressure story as the job queue."""
        job_id = self._finished_job(lines=())
        with mock.patch.object(app_module, "_ACTIVE_STREAMS",
                               app_module._MAX_STREAMS):
            resp = self.client.get(f"/api/stream/{job_id}")
        self.assertEqual(resp.status_code, 429)
        self.assertIn("stream limit reached", resp.get_json()["error"])

    def test_token_gate_covers_the_stream(self):
        with mock.patch.dict("os.environ", {"SPYGLASS_PRO_TOKEN": "s3cret"}):
            self.assertEqual(self.client.get("/api/stream/x").status_code, 401)
            resp = self.client.get("/api/stream/x?token=s3cret")
            # Auth passes the gate; the job itself does not exist.
            self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
