"""Detect a labelled USB stick for the auto-dump plugin.

The dump itself (mount + copy) is a root action; this is the small, testable
bit the plugin uses to notice a stick with the configured label is present. A
stick shows up as a ``/dev/disk/by-label/<LABEL>`` symlink the moment the kernel
reads its filesystem label, so presence is just that path existing.

Pure/stdlib, Python 3.11.
"""
from __future__ import annotations

import os
import re

_LABEL_RE = re.compile(r"\A[A-Za-z0-9_-]{1,32}\Z")


def valid_label(label: str) -> bool:
    """A safe filesystem label for a by-label device path (1..32 of
    ``A-Z a-z 0-9 _ -``)."""
    return bool(_LABEL_RE.match(label or ""))


def device_for(label: str, exists=os.path.exists):
    """The ``/dev/disk/by-label/<label>`` path when a stick with that label is
    present, else ``None``. ``exists`` is injectable for tests."""
    if not valid_label(label):
        return None
    path = "/dev/disk/by-label/" + label
    return path if exists(path) else None
