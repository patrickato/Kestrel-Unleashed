"""Home in on an access point on foot: turn a stream of signal samples into a
warmer/colder reading.

Finding where an AP physically is means walking around watching whether its
signal is rising or falling. Raw Wi-Fi signal jumps around a lot, so this
smooths a stream of 0..100 signal-quality samples (an EWMA) and reports whether
you are getting **warmer** (closer), **colder**, or **steady** -- plus a 0..5
bar level and a 0..100 proximity for a meter. A sample of ``None`` means the
target wasn't seen in that scan (``lost``), so the operator knows to backtrack.

Pure/stdlib, Python 3.11, unit-tested -- the scan that feeds it lives in the
plugin.
"""
from __future__ import annotations


def bars_for(level):
    """A 0..5 bar count for a 0..100 level (``None`` -> 0)."""
    if not level or level < 0:
        return 0
    return max(0, min(5, int(level / 20.0 + 0.5)))


class SignalLocator:
    """Smooths one target's signal and classifies the trend. ``alpha`` is the
    EWMA weight on the newest sample (higher = snappier, noisier); ``slack`` is
    how much the smoothed level must move between updates to count as
    warmer/colder rather than steady."""

    def __init__(self, alpha=0.4, slack=3.0):
        self.alpha = float(alpha)
        self.slack = float(slack)
        self._ewma = None

    @property
    def level(self):
        return None if self._ewma is None else round(self._ewma, 1)

    def update(self, sample):
        """Feed one 0..100 sample (or ``None`` when the target wasn't seen).
        Returns ``{level, trend, bars, seen}`` where ``trend`` is ``warmer`` /
        ``colder`` / ``steady`` / ``lost``."""
        if sample is None:
            return {"level": self.level, "trend": "lost",
                    "bars": bars_for(self._ewma), "seen": False}
        sample = max(0.0, min(100.0, float(sample)))
        prev = self._ewma
        if prev is None:
            self._ewma = sample
            trend = "steady"
        else:
            self._ewma = self.alpha * sample + (1.0 - self.alpha) * prev
            delta = self._ewma - prev
            if delta > self.slack:
                trend = "warmer"
            elif delta < -self.slack:
                trend = "colder"
            else:
                trend = "steady"
        return {"level": self.level, "trend": trend,
                "bars": bars_for(self._ewma), "seen": True}


# How the trend reads to an operator (and a plain arrow for colour-free UIs).
TREND_LABEL = {
    "warmer": "Warmer (getting closer)",
    "colder": "Colder (moving away)",
    "steady": "Steady",
    "lost": "Lost — backtrack",
}
TREND_ARROW = {"warmer": "↑", "colder": "↓", "steady": "→",
               "lost": "✕"}
