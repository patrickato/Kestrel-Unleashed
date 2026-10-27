"""Tests for device-aware crack suggestions (crack/suggest.py)."""

from kestrel_pi.crack import suggest


def _vals(sug):
    return [a["value"] for a in sug["attacks"]]


def test_ssid_pattern_upc_router():
    s = suggest.suggest(essid="UPC1234567")
    assert s["match"] == "ssid-pattern"
    assert "UPC" in s["headline"]
    # the keygen is advisory (not runnable), the blind mask is a fallback
    kinds = {a["kind"] for a in s["attacks"]}
    assert "keygen" in kinds
    assert any(not a["runnable"] for a in s["attacks"])


def test_ssid_pattern_printer_wifi_direct():
    s = suggest.suggest(essid="DIRECT-A2-HP OfficeJet")
    assert s["match"] == "ssid-pattern"
    assert suggest.MASK_8_DIGIT in _vals(s)      # 8-digit sweeps HP's 12345678


def test_camera_is_honest_fallback():
    # a camera (identified by name) must NOT claim a vendor default -- it falls
    # back to the generic order and says so
    s = suggest.suggest(essid="ARLO_VMB_1672948336")
    assert s["category"] == "camera" and s["match"] == "category"
    assert "no crackable default" in s["headline"] or "generic" in s["headline"]
    assert suggest.MASK_8_DIGIT in _vals(s)      # generic order still offered


def test_generic_includes_defaults_list_only_when_present():
    without = suggest.suggest(essid="SomeUnknownNet", have_defaults=False)
    assert suggest.DEFAULTS_LIST not in _vals(without)
    with_ = suggest.suggest(essid="SomeUnknownNet", have_defaults=True)
    assert _vals(with_)[0] == suggest.DEFAULTS_LIST   # curated list tried first


def test_8_digit_mask_is_the_universal_attack():
    for essid in ("SomeUnknownNet", "ARLO_VMB_1", "DIRECT-xx-HP"):
        assert suggest.MASK_8_DIGIT in _vals(suggest.suggest(essid=essid))


def test_render_text_has_runnable_commands():
    s = suggest.suggest(essid="DIRECT-A2-HP", have_defaults=True)
    text = suggest.render_text(s, essid="DIRECT-A2-HP")
    assert "kestrel crack run" in text and "--mask" in text
    assert "DIRECT-A2-HP" in text
