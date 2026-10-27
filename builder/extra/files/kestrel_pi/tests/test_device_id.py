"""Device identification from a captured network's ESSID (+ optional OUI vendor)."""

from kestrel_pi.device_id import identify, label


def test_essid_names_the_device():
    g = identify(bssid="aa:bb:cc:dd:ee:ff", essid="Ring-Front-Door")
    assert g["category"] == "doorbell" and g["product"] == "Ring"
    assert g["confidence"] == "high"
    assert any("ESSID" in r for r in g["reasons"])


def test_common_device_essids():
    cases = {
        "MyWyzeCam": ("camera", "Wyze Cam"),
        "DIRECT-a1-HP OfficeJet": ("printer", "printer"),
        "NETGEAR57-5G": ("router", "NETGEAR router"),
        "echo-dot-2": ("voice-assistant", "Amazon Echo"),
        "Chromecast1234": ("streamer", "Google Chromecast"),
        "SETUP-AB12": ("setup-ap", "device in setup mode"),
    }
    for essid, (cat, prod) in cases.items():
        g = identify(essid=essid)
        assert g["category"] == cat, f"{essid} → {g}"
        assert g["product"] == prod


def test_vendor_fills_in_when_essid_is_silent():
    # a hidden/cryptic ESSID, but the OUI vendor is known
    g = identify(bssid="00:11:22:33:44:55", essid="", vendor="Hikvision Digital Technology")
    assert g["category"] == "camera" and "Hikvision" in g["product"]
    assert g["confidence"] == "medium"


def test_essid_beats_vendor():
    # ESSID is the stronger signal: a Ring SSID on a generic-vendor AP is a Ring
    g = identify(essid="ring-doorbell", vendor="Espressif Inc")
    assert g["category"] == "doorbell"


def test_unknown_is_honest():
    g = identify(bssid="de:ad:be:ef:00:01", essid="xyz9", vendor="")
    assert g["category"] == "unknown" and g["confidence"] == "low"
    assert label(essid="xyz9") == ""          # nothing to show rather than a guess


def test_label_is_compact():
    assert label(essid="Ring Front") == "Ring · doorbell"
    assert label(essid="NETGEAR57") == "NETGEAR router · router"
    assert label(essid="", vendor="Amazon Technologies") == "Amazon device · iot"
