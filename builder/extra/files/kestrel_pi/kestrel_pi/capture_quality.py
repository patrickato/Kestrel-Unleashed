"""Grade the crack-worthiness of an access point's captured material.

Not every capture is equal. A PMKID is a single clientless frame that cracks on
its own; a full 4-way handshake is just as crackable; and a handshake where the
AP itself replied (an M2+M3 / M3+M4 message pair) is better evidence than an
M1+M2 the AP never completed. Kestrel already writes only hashcat-crackable
lines, so this doesn't decide *whether* something can be cracked -- it tells the
operator (and the cracker's ordering, and the agent) *how good* each AP's
material is, so a target with a solid PMKID isn't treated the same as one with a
single partial handshake.

The signal comes straight from the ``.hc22000`` line: field 1 is the type
(``01`` PMKID, ``02`` EAPOL) and, for EAPOL, field 8 is the message-pair byte
whose low three bits say which pair was seen. Pure/stdlib, Python 3.11, no I/O --
the caller hands it the lines (the capture store producer groups them by BSSID).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, Tuple

# hc22000 message-pair (field 8, low 3 bits): 2/3 = M2+M3, 4/5 = M3+M4 -- the AP
# took part in the exchange. 0 = M1+M2 (from M2), 1 = M1+M4; those can be a
# client talking to an AP that never replied, so they are weaker evidence.
_AP_CONFIRMED_PAIRS = frozenset({2, 3, 4, 5})

# Grades, best first, with a numeric score the cracker/agent can order by
# (higher = try sooner / better material). PMKID edges a bare handshake because
# it is clientless and deduplicated; having both is best.
GRADE_SCORE = {
    "pmkid+handshake": 3,
    "pmkid": 2,
    "handshake": 1,
    "none": 0,
}


@dataclass(frozen=True)
class Signal:
    """What one hashline says: ``kind`` is ``"pmkid"``, ``"eapol"`` or ``""``
    (unparseable), and ``ap_confirmed`` is True for an EAPOL whose message pair
    shows the AP replied (M2+M3 / M3+M4)."""
    kind: str
    ap_confirmed: bool = False


@dataclass(frozen=True)
class Quality:
    """An AP's best available material. ``grade`` drives the badge; ``score``
    (see :data:`GRADE_SCORE`) drives ordering; ``label`` is the short UI badge;
    ``note`` is a one-line human hint; the counts and ``ap_confirmed`` are the
    evidence behind the grade."""
    grade: str
    label: str
    score: int
    pmkid: int
    handshake: int
    ap_confirmed: bool
    note: str


def signal(line: str) -> Signal:
    """The :class:`Signal` for one raw ``.hc22000`` line (``kind=""`` for a blank
    or non-WPA line)."""
    fields = (line or "").strip().split("*")
    if len(fields) < 6 or fields[0] != "WPA":
        return Signal("")
    if fields[1] == "01":
        return Signal("pmkid")
    if fields[1] == "02":
        pair = None
        if len(fields) > 8:
            try:
                pair = int(fields[8], 16) & 0x07
            except ValueError:
                pair = None
        return Signal("eapol", ap_confirmed=pair in _AP_CONFIRMED_PAIRS)
    return Signal("")


def from_signals(pmkid: int, handshake: int, ap_confirmed: bool) -> Quality:
    """Finalize an AP's :class:`Quality` from its tallied signals, so a producer
    can accumulate counts in a single pass and call this once per AP."""
    if pmkid and handshake:
        grade, label = "pmkid+handshake", "PMKID + 4-way"
        note = "PMKID and a full handshake -- strongest material"
    elif pmkid:
        grade, label = "pmkid", "PMKID"
        note = "clientless PMKID -- cracks on its own, no client needed"
    elif handshake:
        grade, label = "handshake", "4-way"
        note = ("4-way handshake" + (", AP-confirmed" if ap_confirmed
                else " (client-side; AP reply not seen)"))
    else:
        grade, label = "none", "no handshake"
        note = "no crackable material captured yet"
    return Quality(grade=grade, label=label, score=GRADE_SCORE[grade],
                   pmkid=pmkid, handshake=handshake,
                   ap_confirmed=bool(ap_confirmed), note=note)


def classify_lines(lines: Iterable[str]) -> Quality:
    """The :class:`Quality` for an AP from all of its raw hashlines."""
    pmkid = handshake = 0
    ap_confirmed = False
    for line in lines or ():
        sig = signal(line)
        if sig.kind == "pmkid":
            pmkid += 1
        elif sig.kind == "eapol":
            handshake += 1
            ap_confirmed = ap_confirmed or sig.ap_confirmed
    return from_signals(pmkid, handshake, ap_confirmed)


def summarize(qualities: Iterable[Quality]) -> Tuple[int, Optional[str]]:
    """``(crackable_ap_count, best_grade)`` across a set of APs -- a one-glance
    capture-quality readout for the dashboard. ``best_grade`` is ``None`` when the
    set is empty or all ``none``."""
    count = 0
    best: Optional[str] = None
    best_score = 0
    for q in qualities or ():
        if q.grade == "none":
            continue
        count += 1
        if q.score >= best_score:
            best_score, best = q.score, q.grade
    return count, best
