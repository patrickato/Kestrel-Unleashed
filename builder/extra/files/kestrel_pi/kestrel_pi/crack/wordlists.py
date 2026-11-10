"""Discover and order the wordlists on the device.

Every readable file in ``wordlists_dir`` is a candidate. Each carries a
*signature* -- ``name:size:mtime`` -- so replacing a list with a bigger one of
the same name changes its signature and the cracker gives every target a fresh
pass against it (the ``recrack_on_new_wordlist`` behaviour). Pure stdlib.
"""

from __future__ import annotations

import hashlib
import os

# hashcat ships a set of rule files (best64, rockyou-30000, dive, ...). A bare
# rule name in [crack] rules resolves from the operator's wordlists dir first,
# then from here, so e.g. rules = ["best64.rule"] works with nothing to download.
HASHCAT_RULES_DIR = "/usr/share/hashcat/rules"


def _signature(path, st):
    """A change-detecting id for a wordlist: ``basename:size:mtime``. A different
    file (even same name) sorts to a different signature, which re-arms targets
    that already tried the old one."""
    return "%s:%d:%d" % (os.path.basename(path), st.st_size, int(st.st_mtime))


def discover(wordlists_dir, order="size"):
    """Return the ordered list of wordlists as dicts
    ``{"path", "name", "size", "sig"}``.

    ``order``:
      - ``"size"``  - smallest first (fastest to a common password; the default)
      - ``"name"``  - case-insensitive by filename
      - an explicit comma-separated list of filenames -- those first, in the
        given order, then any remaining files by size.

    Symlinks and non-files are skipped; an unreadable dir yields ``[]``. A rule
    file the operator also dropped here (``*.rule``) is NOT a wordlist and is
    excluded, so pointing ``rules`` at it does not also run it as a dictionary.
    """
    out = []
    try:
        names = os.listdir(wordlists_dir)
    except OSError:
        return []
    for name in names:
        if name.endswith(".rule"):
            continue
        path = os.path.join(wordlists_dir, name)
        try:
            if not os.path.isfile(path):
                continue
            st = os.stat(path)
        except OSError:
            continue
        if st.st_size <= 0:
            continue
        out.append({"path": path, "name": name, "size": st.st_size,
                    "sig": _signature(path, st)})
    return _order(out, order)


def _order(lists, order):
    by_size = sorted(lists, key=lambda w: (w["size"], w["name"].lower()))
    spec = (order or "size").strip()
    if spec == "size" or not spec:
        return by_size
    if spec == "name":
        return sorted(lists, key=lambda w: w["name"].lower())
    # An explicit comma-separated filename list: those first (in order), then the
    # rest by size. Unknown names in the spec are ignored.
    wanted = [n.strip() for n in spec.split(",") if n.strip()]
    if not wanted:
        return by_size
    by_name = {w["name"]: w for w in lists}
    head, seen = [], set()
    for name in wanted:
        w = by_name.get(name)
        if w is not None and w["name"] not in seen:
            head.append(w)
            seen.add(w["name"])
    tail = [w for w in by_size if w["name"] not in seen]
    return head + tail


def optimize(sources, out_path, wpa=True, min_len=8, max_len=63):
    """Merge ``sources`` (wordlist paths, in priority order) into one list at
    ``out_path``: de-duplicated and, with ``wpa``, limited to WPA-valid passphrase
    length (``min_len``..``max_len`` characters -- WPA2 keys are 8-63, so shorter
    or longer lines can never be the key and are dropped).

    First-seen order is kept, so a frequency-ranked source stays ranked and the
    best candidates lead the merged list -- the "one good list" without losing the
    smallest-first effectiveness. De-duplication keys on an 8-byte hash of each
    candidate, not the candidate itself, so even a 14M-line list like rockyou de-
    dupes in well under 200 MB of RAM on any Pi. Written atomically via a temp
    file. Returns ``{sources, read, written, too_short, too_long, duplicates}``."""
    seen = set()
    stats = {"sources": 0, "read": 0, "written": 0,
             "too_short": 0, "too_long": 0, "duplicates": 0}
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", errors="replace") as out:
        for src in sources:
            try:
                fh = open(src, "r", encoding="utf-8", errors="replace")
            except OSError:
                continue
            stats["sources"] += 1
            with fh:
                for line in fh:
                    cand = line.rstrip("\r\n")
                    if not cand:
                        continue
                    stats["read"] += 1
                    if wpa:
                        n = len(cand)
                        if n < min_len:
                            stats["too_short"] += 1
                            continue
                        if n > max_len:
                            stats["too_long"] += 1
                            continue
                    digest = hashlib.blake2b(cand.encode("utf-8", "replace"),
                                             digest_size=8).digest()
                    if digest in seen:
                        stats["duplicates"] += 1
                        continue
                    seen.add(digest)
                    out.write(cand + "\n")
                    stats["written"] += 1
    os.replace(tmp, out_path)
    return stats


def resolve_rules(rules, wordlists_dir, extra_dirs=(HASHCAT_RULES_DIR,)):
    """Resolve the configured rule files to absolute paths that exist. A bare
    name is looked up in ``wordlists_dir`` first, then each of ``extra_dirs``
    (hashcat's own rules dir by default, so ``best64.rule`` resolves with nothing
    to download); an absolute path is used as given. Missing files are dropped (a
    typo'd rule never aborts a run)."""
    out = []
    for rule in rules or ():
        rule = str(rule).strip()
        if not rule:
            continue
        if os.path.isabs(rule):
            if os.path.isfile(rule):
                out.append(rule)
            continue
        for directory in (wordlists_dir, *extra_dirs):
            path = os.path.join(directory, rule)
            if os.path.isfile(path):
                out.append(path)
                break
    return out
