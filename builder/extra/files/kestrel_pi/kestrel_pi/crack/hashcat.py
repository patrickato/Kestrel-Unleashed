"""Build the ``hashcat`` command line and parse its ``--show`` output.

The only module that knows hashcat's CLI, and still subprocess-free: it returns
argv lists and parses text the caller captured, so the worker owns the one place
that actually spawns a process and tests drive this with canned output.

Kestrel stores ``.hc22000`` lines, so cracking is always ``-m 22000`` (hashcat's
mode for both the EAPOL 4-way handshake and PMKID). The Pi has no usable GPU for
hashcat, so pocl's CPU device is used; ``-w`` (workload) and ``nice`` keep it a
background sipper. A shared potfile accumulates every crack across runs, and a
second ``--show`` pass reads back which hashlines it holds for a given hashfile.
"""

from __future__ import annotations

import shutil

HASHCAT = "hashcat"
MODE = "22000"


def have_hashcat():
    """True if the hashcat binary is on PATH (it is, on a built image)."""
    return shutil.which(HASHCAT) is not None


def build_crack_cmd(hashfile, wordlist, potfile, rules=(), nice=15, workload=1):
    """argv for a straight-dictionary crack of ``hashfile`` with ``wordlist``.

    ``nice`` prepends ``nice -n N`` so the hashcat child yields to capture; a
    rule file (``-r``) is applied per entry in ``rules``; ``-w`` is the workload
    profile. ``--quiet`` silences the banner; results are read back with
    :func:`build_show_cmd`, never scraped from stdout, so a crack and the
    accounting never disagree."""
    cmd = []
    try:
        nice = int(nice)
    except (TypeError, ValueError):
        nice = 15
    nice = max(0, min(19, nice))
    if nice:
        cmd += ["nice", "-n", str(nice)]
    try:
        workload = int(workload)
    except (TypeError, ValueError):
        workload = 1
    workload = max(1, min(4, workload))
    cmd += [HASHCAT, "-m", MODE, "-a", "0", "--quiet",
            "--potfile-path", str(potfile), "-w", str(workload)]
    for rule in rules or ():
        cmd += ["-r", str(rule)]
    cmd += [str(hashfile), str(wordlist)]
    return cmd


def build_show_cmd(hashfile, potfile):
    """argv to list which lines of ``hashfile`` are cracked in ``potfile``.

    Output is ``<hashline>:<password>`` per cracked line. Cheap: it only reads
    the potfile, runs no attack."""
    return [HASHCAT, "-m", MODE, "--show", "--potfile-path", str(potfile),
            str(hashfile)]


def parse_show(output):
    """Parse ``--show`` output into ``[(hashline, password), ...]``.

    Each line is ``<hashline>:<password>``. The hc22000 hashline uses ``*`` as
    its field separator and carries no ``:``, so the FIRST ``:`` is the separator
    and everything after it is the password -- splitting on the first colon
    recovers a password that itself contains ``:``. Blank lines are skipped."""
    pairs = []
    for line in (output or "").splitlines():
        line = line.rstrip("\n")
        if not line or ":" not in line:
            continue
        hashline, password = line.split(":", 1)
        if hashline:
            pairs.append((hashline, password))
    return pairs
