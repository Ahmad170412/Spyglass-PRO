"""Pins the dashboard's JS tables to the server's Python vocabulary.

The merge layer and the frontend both describe the recon world:
``app.py::_TOOLS_LEGS`` / ``_TOOL_PROBES`` / ``_SETTINGS_SPEC`` on the
server, ``app.js`` ``TOOL_ROWS`` in the UI. These are the hand-synced
duplicates that have drifted before (see AUDIT-2026-10.md) — the tool
grid has no runtime failure mode when it disagrees with the server, it
just quietly shows the wrong dots. Each test below fails loudly if an
edit to one side is not mirrored in the other.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]

# Labels in the UI mapped to the query types the server uses.
_LABEL_TO_QTYPE = {
    "Email": "email",
    "Username": "username",
    "Phone": "phone",
    "Website": "website",
    "Metadata": "metadata",
}


class ToolGridContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (_ROOT / "spyglass_pro" / "static" / "js" / "app.js").read_text(
            encoding="utf-8")

    def test_tool_rows_cover_every_server_leg(self):
        """Every query type the server can degrade has a UI row with the
        exact same tool set — the grid's "which legs are off" display is
        only truthful if the leg lists agree element for element."""
        from spyglass_pro.app import _TOOLS_LEGS

        rows = dict(re.findall(r"label: '([^']+)', tools: \[([^\]]*)\]", self.js))
        self.assertEqual(set(rows), set(_LABEL_TO_QTYPE),
                         f"UI labels are not the expected five: {sorted(rows)}")
        for label, blob in rows.items():
            qtype = _LABEL_TO_QTYPE[label]
            js_tools = set(re.findall(r"'([^']+)'", blob))
            self.assertEqual(js_tools, set(_TOOLS_LEGS[qtype]),
                             f"{qtype}: UI grid vs deployed server legs differ")

    def test_grid_tools_are_all_real_probes(self):
        """A tool named in the grid but absent from ``_TOOL_PROBES`` renders
        as permanently missing; a probe absent from the grid is checked but
        never shown. Both directions must hold."""
        from spyglass_pro.app import _TOOL_PROBES
        tools_blobs = re.findall(r"tools: \[([^\]]*)\]", self.js)
        named = set()
        for blob in tools_blobs:
            named.update(re.findall(r"'([^']+)'", blob))
        self.assertTrue(named)
        self.assertEqual(named, set(_TOOL_PROBES))

    def test_key_rows_reference_known_vault_specs(self):
        """The Dark web row keys its dots off vault spec ids; one typo'd id
        silently renders as 'open Settings' forever. Every referenced id
        must be a real spec, and the row must track that module's keyed
        sources exactly — never invent one."""
        from spyglass_pro.app import _SETTINGS_SPEC
        spec_ids = {spec["key"] for spec in _SETTINGS_SPEC}
        key_blobs = re.findall(r"keys: \[\[(.*?)\]\]", self.js)
        self.assertEqual(len(key_blobs), 1, "expected the Dark web row")
        referenced = set()
        for blob in key_blobs:
            referenced.update(re.findall(r"([a-z0-9_]+)', '[^']+'", blob))
        self.assertTrue(referenced)
        unknown = referenced - spec_ids
        self.assertEqual(unknown, set(),
                         f"UI vault ids with no server spec: {sorted(unknown)}")
        darkweb_blob = key_blobs[0]
        darkweb_ids = set(re.findall(r"([a-z0-9_]+)', '[^']+'", darkweb_blob))
        self.assertEqual(darkweb_ids, {"intelx_api_key", "hibp_api_key"})


if __name__ == "__main__":
    unittest.main()
