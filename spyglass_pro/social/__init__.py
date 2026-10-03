"""Multi-platform social collection.

One harness, one normalized profile shape, one registry. Platforms are
adapters under :mod:`spyglass_pro.social.platforms`; everything else in
Spyglass-Pro iterates the registry rather than branching per platform.

This lives in the merge layer, not in ``spyglass_pro/modules/``: the
vendored engine tree is kept in step with its upstreams, and feature work
there would collide with every future sync.
"""

from . import registry, schema
from .harness import collect
from .registry import Platform, all_platforms, describe, get

__all__ = [
    "Platform",
    "all_platforms",
    "collect",
    "describe",
    "get",
    "registry",
    "schema",
]
