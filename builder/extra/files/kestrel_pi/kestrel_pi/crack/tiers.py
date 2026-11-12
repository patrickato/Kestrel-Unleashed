"""Crack cost tiers: decide which attacks are worth running on the Pi's CPU and
which belong on a GPU.

WPA is PBKDF2-HMAC-SHA1 (thousands of SHA1 rounds per guess), so an ARM CPU only
manages low thousands of guesses a second. A mask's keyspace is the product of
its per-position charset sizes; past a budget, grinding it on the Pi takes many
hours per AP for little yield, while a GPU finishes it in minutes. The automatic
crack loop runs only the affordable attacks on-device and defers the expensive
ones to the offload path (`kestrel crack kit` / remote-crack / a cloud cracker),
so the Pi spends its cycles on the cheap, high-yield tiers (credential reuse and
wordlists) instead of a week-long numeric sweep it can't finish.
"""
from __future__ import annotations

# hashcat built-in charset sizes: ?d 0-9, ?l a-z, ?u A-Z, ?s symbols, ?a all
# printable, ?h/?H hex, ?b every byte.
_CLASS_SIZES = {"d": 10, "l": 26, "u": 26, "s": 33, "a": 95,
                "h": 16, "H": 16, "b": 256}

# The largest mask keyspace the auto loop will run on the CPU. ~5M candidates is
# minutes per AP at the Pi's WPA rate; the 8-digit numeric default-key mask
# (1e8), 10-digit (1e10) and the hex masks are far above it and belong on a GPU.
# An operator with no GPU can raise `[crack] max_onpi_mask_keyspace` to grind
# more on-device at the cost of time.
DEFAULT_PI_MASK_KEYSPACE = 5_000_000


def mask_keyspace(mask):
    """Candidates a hashcat-style mask expands to, or ``None`` when it can't be
    known here (a custom ``?1``-``?4`` charset, whose definition lives outside
    the mask). A literal character contributes a factor of 1."""
    total = 1
    i, n = 0, len(mask or "")
    while i < n:
        if mask[i] == "?" and i + 1 < n:
            cls = mask[i + 1]
            if cls in _CLASS_SIZES:
                total *= _CLASS_SIZES[cls]
            elif cls == "?":
                total *= 1                 # an escaped literal '?'
            else:
                return None                # ?1-?4 custom charset: size unknown
            i += 2
        else:
            i += 1                         # a literal character
    return total


def affordable_on_pi(mask, budget=DEFAULT_PI_MASK_KEYSPACE):
    """True when ``mask`` is cheap enough to grind on the Pi within ``budget``.
    An unknown-size mask (custom charset) counts as too expensive, so it defers
    to the GPU rather than surprising the operator with a week-long run."""
    keyspace = mask_keyspace(mask)
    return keyspace is not None and keyspace <= budget


def split_masks(masks, budget=DEFAULT_PI_MASK_KEYSPACE):
    """Partition mask strings into ``(on_pi, deferred)`` by affordability."""
    on_pi, deferred = [], []
    for mask in masks or ():
        (on_pi if affordable_on_pi(mask, budget) else deferred).append(mask)
    return on_pi, deferred
