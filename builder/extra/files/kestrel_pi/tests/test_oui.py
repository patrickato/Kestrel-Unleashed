"""OUI → vendor lookup (the 'who makes it' enrichment)."""

from kestrel_pi import device_id, oui


def test_vendor_resolves_a_known_oui():
    assert oui.vendor("3C:52:A1:1A:64:EA") == "TP-Link Systems Inc"
    assert oui.vendor("9C:3D:CF:59:AC:14") == "NETGEAR"
    # formatting-insensitive: no separators, lower case
    assert oui.vendor("3c52a11a64ea") == "TP-Link Systems Inc"


def test_randomized_mac_has_no_vendor():
    # locally-administered (bit 1 of the first octet set) -> randomized/private
    assert oui.is_locally_administered("AA:54:35:60:7E:45")
    assert oui.vendor("AA:54:35:60:7E:45") == ""
    # a globally-unique OUI is not locally administered
    assert not oui.is_locally_administered("3C:52:A1:1A:64:EA")


def test_short_or_unknown_input_is_empty():
    assert oui.vendor("") == ""
    assert oui.vendor("3C:52") == ""
    assert oui.vendor("FFFFFF000000") == ""   # unassigned OUI


def test_identify_fills_vendor_from_the_bssid():
    # Even when the SSID says nothing, the OUI names the maker.
    g = device_id.identify(bssid="3C:52:A1:1A:64:EA", essid="DLMercure")
    assert g["vendor"] == "TP-Link Systems Inc"
    # and the name still wins for the product when it is recognisable
    g2 = device_id.identify(bssid="9C:3D:CF:59:AC:14", essid="ARLO_VMB_1")
    assert g2["product"] == "Arlo camera" and g2["vendor"] == "NETGEAR"
