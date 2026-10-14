"""Tests for file-type detection in spyglass_osint.metadata.

ExifTool content-sniffs anything outside its format list as TXT and labels
every ``.ts`` file MPEG-TS, so ``_reconcile_file_type`` corrects both —
and that correction is exactly where a silent mislabel hides: the scan
succeeds, the type line just lies. These tests pin the contract without
needing exiftool itself, plus one end-to-end ``extract()`` that adapts to
whatever the machine has.
"""

import os
import tempfile
import unittest

import helpers  # noqa: F401 — puts spyglass_pro/modules on sys.path
from spyglass_osint import metadata
from spyglass_osint.utils import _EXIFTOOL


def _tmp_file(suffix, content):
    mode = "wb" if isinstance(content, bytes) else "w"
    with tempfile.NamedTemporaryFile(
            suffix=suffix, delete=False, mode=mode) as tmp:
        tmp.write(content)
        return tmp.name


class ReconcileTest(unittest.TestCase):
    def test_txt_fallback_yields_to_known_extension(self):
        path = _tmp_file(".py", "import os\n")
        self.addCleanup(os.unlink, path)
        result = {"FileType": "TXT", "MIMEType": "text/plain"}
        metadata._reconcile_file_type(path, result)
        self.assertEqual(result["FileType"], "Python")
        self.assertEqual(result["FileTypeExtension"], "py")
        self.assertEqual(result["MIMEType"], "text/x-python")

    def test_genuine_detection_is_kept(self):
        """A zip disguised as .txt must still report as ZIP."""
        path = _tmp_file(".txt", "import os\n")
        self.addCleanup(os.unlink, path)
        result = {"FileType": "ZIP", "MIMEType": "application/zip"}
        metadata._reconcile_file_type(path, result)
        self.assertEqual(result["FileType"], "ZIP")

    def test_typescript_source_is_not_video(self):
        path = _tmp_file(".ts", "const x: number = 1;\n")
        self.addCleanup(os.unlink, path)
        result = {"FileType": "MPEG-TS", "MIMEType": "video/mp2t"}
        metadata._reconcile_file_type(path, result)
        self.assertEqual(result["FileType"], "TypeScript")
        self.assertEqual(result["MIMEType"], "text/x-typescript")

    def test_real_transport_stream_keeps_its_label(self):
        payload = b"\x47" + bytes(187) + b"\x47" + bytes(187)
        path = _tmp_file(".ts", payload)
        self.addCleanup(os.unlink, path)
        result = {"FileType": "MPEG-TS", "MIMEType": "video/mp2t"}
        metadata._reconcile_file_type(path, result)
        self.assertEqual(result["FileType"], "MPEG-TS")

    def test_empty_file_falls_back_to_extension(self):
        path = _tmp_file(".py", "")
        self.addCleanup(os.unlink, path)
        result = {}
        metadata._reconcile_file_type(path, result)
        self.assertEqual(result["FileType"], "Python")

    def test_unknown_extension_is_untouched(self):
        path = _tmp_file(".zzz", "hello\n")
        self.addCleanup(os.unlink, path)
        result = {"FileType": "TXT", "MIMEType": "text/plain"}
        metadata._reconcile_file_type(path, result)
        self.assertEqual(result["FileType"], "TXT")


class ExtractTest(unittest.TestCase):
    def test_py_file_never_reports_txt(self):
        """The exact report: a .py file whose type line said TXT."""
        path = _tmp_file(".py", "import os\nprint('hello')\n")
        self.addCleanup(os.unlink, path)
        result = metadata.extract(path)
        self.assertNotIn("error", result)
        self.assertNotEqual(result.get("FileType"), "TXT")
        if _EXIFTOOL:
            self.assertEqual(result.get("FileType"), "Python")
        else:
            # No exiftool: the extension table is the only signal, and it
            # still must not say TXT.
            self.assertEqual(result.get("file_type"), "text/x-python")

    def test_typescript_source_end_to_end(self):
        path = _tmp_file(".ts", "const x: number = 1;\n")
        self.addCleanup(os.unlink, path)
        result = metadata.extract(path)
        self.assertNotIn("error", result)
        if _EXIFTOOL:
            self.assertEqual(result.get("FileType"), "TypeScript")
        else:
            # Extension-table fallback still maps .ts to the stream entry.
            self.assertEqual(result.get("file_type"), "video/mp2t")

    def test_missing_file_is_an_error_not_a_crash(self):
        result = metadata.extract("/nonexistent/file.py")
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
