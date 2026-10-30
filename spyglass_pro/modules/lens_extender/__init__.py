# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TeamLeader. Vendored from Lens-Extender @ 06d451a;
# see NOTICE and AUDIT-2026-10.md before syncing.
"""Lens-Extender — case store only; the recon engine was deleted.

The upstream package shipped the full engine (osint, analyzer, report,
cli). Those modules are gone from this tree; ``store`` survives so runs
written by an older build remain listable and deletable. See NOTICE.
"""

# Vendored from upstream @ 06d451a as a dev snapshot; the -dev suffix is
# dropped here so installed packages never report a pre-release version.
__version__ = "1.0.0"
