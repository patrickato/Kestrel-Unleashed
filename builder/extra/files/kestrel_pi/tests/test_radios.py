"""Tests for the multi-radio inventory + role assignment (pure logic).

No hardware: the collectors are bypassed by handing :func:`inventory` /
:func:`assign_roles` radios built from captured ``iw``/sysfs facts.
"""

from kestrel_pi import radios
from kestrel_pi.radios import (
    Radio, assign_roles, bands_from_phy, chipset_for, inventory,
    make_bt_radio, make_wifi_radio, monitor_capable,
)

# A trimmed, realistic `iw phy info` for a dual-band monitor-capable adapter.
PHY_MONITOR = """
Wiphy phy1
	Supported interface modes:
		 * IBSS
		 * managed
		 * AP
		 * monitor
		 * mesh point
	Band 1:
		Frequencies:
			* 2412.0 MHz [1] (20.0 dBm)
			* 2437.0 MHz [6] (20.0 dBm)
	Band 2:
		Frequencies:
			* 5180 MHz [36] (20.0 dBm)
			* 5260 MHz [52] (23.0 dBm) (radar detection)
			* 5500 MHz [100] (disabled)
"""

# The Pi's built-in chip: managed/AP only, no monitor, 2.4GHz only.
PHY_BUILTIN = """
Wiphy phy0
	Supported interface modes:
		 * managed
		 * AP
		 * P2P-client
	Band 1:
		Frequencies:
			* 2412.0 MHz [1] (20.0 dBm)
"""


# --- pure parsers -----------------------------------------------------------
def test_monitor_capable_matches_shell_grep():
    assert monitor_capable(PHY_MONITOR) is True
    assert monitor_capable(PHY_BUILTIN) is False
    assert monitor_capable("") is False


def test_bands_from_phy_buckets_frequencies_and_skips_disabled():
    assert bands_from_phy(PHY_MONITOR) == ("2.4", "5")   # 5500 is disabled
    assert bands_from_phy(PHY_BUILTIN) == ("2.4",)
    # a 6GHz frequency lands in the 6 bucket
    assert "6" in bands_from_phy("* 6135 MHz [1]")


def test_chipset_for_known_and_unknown():
    name, inj = chipset_for("rtl8812au")
    assert "RTL8812AU" in name and inj == "yes"
    assert chipset_for("brcmfmac")[1] == "no"
    assert chipset_for("rtw_8821cu")[1] == "partial"   # TP-Link AC600 class
    assert chipset_for("some_new_driver") == ("", "unknown")


# --- building radios --------------------------------------------------------
def test_make_wifi_radio_builtin_and_mac_normalisation():
    onboard = make_wifi_radio(dev="wlan0", driver="brcmfmac", phy="phy0",
                              mac="aa:bb:cc:dd:ee:ff", bus="sdio",
                              phy_info=PHY_BUILTIN)
    assert onboard.builtin is True and onboard.monitor is False
    assert onboard.mac == "AA:BB:CC:DD:EE:FF"
    usb = make_wifi_radio(dev="wlan1", driver="rtl8812au", phy="phy1",
                          bus="usb", phy_info=PHY_MONITOR)
    assert usb.builtin is False and usb.monitor is True
    assert usb.injection == "yes" and "RTL8812AU" in usb.chipset
    assert usb.bands == ("2.4", "5")


def test_make_bt_radio_builtin_vs_usb():
    assert make_bt_radio("hci0", bus="uart").builtin is True
    assert make_bt_radio("hci1", bus="usb").builtin is False


def _onboard():
    return make_wifi_radio("wlan0", driver="brcmfmac", phy="phy0", bus="sdio",
                           phy_info=PHY_BUILTIN)


def _usb(dev, driver="rtl8812au", phy="phy1", monitor=True):
    return make_wifi_radio(dev, driver=driver, phy=phy, bus="usb",
                           phy_info=PHY_MONITOR if monitor else PHY_BUILTIN,
                           mac="00:11:22:33:44:%s" % dev[-2:])


# --- role assignment --------------------------------------------------------
def test_onboard_only_reserves_station_and_flags_no_capture():
    a = assign_roles([_onboard()])
    assert a.owner("station") == "wlan0"
    assert a.owner("capture") is None
    assert any("monitor-capable" in n for n in a.notices)


def test_one_monitor_adapter_captures_and_attack_shares_it():
    a = assign_roles([_onboard(), _usb("wlan1")])
    assert a.owner("station") == "wlan0"
    assert a.owner("capture") == "wlan1"
    # with a single monitor adapter, deauth shares the capture radio (flagged)
    assert a.owner("attack") == "wlan1"
    assert a.is_shared("attack") is True
    assert any("share the capture radio" in n for n in a.notices)


def test_two_monitor_adapters_get_dedicated_capture_and_attack():
    a = assign_roles([_onboard(), _usb("wlan1", driver="rtl8812au"),
                      _usb("wlan2", driver="mt7612u", phy="phy2")])
    assert a.owner("capture") == "wlan1"
    assert a.owner("attack") == "wlan2"
    assert a.is_shared("attack") is False
    assert a.roles["wlan2"] == "attack"


def test_attack_prefers_injection_capable_second_adapter():
    # wlan1 monitor but injection "no"? use a non-injection monitor driver by
    # faking the chipset: an unknown driver is "unknown", a brcm-like "no".
    noinj = make_wifi_radio("wlan1", driver="brcmfmac_usb_fake", phy="phy1",
                            bus="usb", phy_info=PHY_MONITOR)
    # force injection "no" via a known no-injection driver on USB
    noinj_no = Radio(dev="wlan1", kind="wifi", driver="x", bus="usb",
                     phy="phy1", monitor=True, injection="no")
    yes = _usb("wlan2", driver="mt7612u", phy="phy2")
    a = assign_roles([_onboard(), noinj_no, yes])
    # capture takes the first monitor adapter; attack should prefer the
    # injection-capable one over the injection="no" one.
    assert a.owner("attack") == "wlan2"
    assert noinj.injection == "unknown"   # sanity on the advisory default


def test_no_shared_attack_when_disabled():
    a = assign_roles([_onboard(), _usb("wlan1")], allow_shared_attack=False)
    assert a.owner("attack") is None
    assert any("no radio" in n for n in a.notices)


def test_override_wins_over_auto():
    # pin the USB adapter to station and the onboard stays station too -- the
    # operator's choice is honored and reasoned.
    a = assign_roles([_onboard(), _usb("wlan1")],
                     overrides={"wlan1": "attack"})
    assert a.roles["wlan1"] == "attack"
    assert a.owner("attack") == "wlan1"
    assert "configured" in a.reasons["wlan1"]


def test_override_by_driver_key():
    a = assign_roles([_onboard(), _usb("wlan1", driver="mt7612u")],
                     overrides={"mt7612u": "capture"})
    assert a.owner("capture") == "wlan1"


def test_override_capture_on_non_monitor_is_refused_with_notice():
    client = _usb("wlan1", monitor=False)
    a = assign_roles([_onboard(), client], overrides={"wlan1": "capture"})
    assert a.roles["wlan1"] == "idle"
    assert a.owner("capture") is None
    assert any("not monitor-capable" in n for n in a.notices)


def test_unknown_role_override_ignored_with_notice():
    a = assign_roles([_onboard(), _usb("wlan1")],
                     overrides={"wlan1": "banana"})
    assert any("unknown configured role" in n for n in a.notices)
    # falls back to the auto rule (first monitor adapter -> capture)
    assert a.owner("capture") == "wlan1"


def test_non_monitor_external_serves_station_when_onboard_absent():
    client = _usb("wlan1", monitor=False)
    a = assign_roles([client, _usb("wlan2", phy="phy2")])
    assert a.owner("capture") == "wlan2"
    assert a.owner("station") == "wlan1"


# --- bluetooth --------------------------------------------------------------
def test_bluetooth_builtin_pan_external_scan():
    a = assign_roles([make_bt_radio("hci0", bus="uart"),
                      make_bt_radio("hci1", bus="usb")])
    assert a.owner("pan") == "hci0"
    assert a.owner("scan") == "hci1"


def test_single_bluetooth_scan_shares_pan():
    a = assign_roles([make_bt_radio("hci0", bus="uart")])
    assert a.owner("pan") == "hci0"
    assert a.owner("scan") is None
    assert a.is_shared("scan") is True


# --- inventory plumbing -----------------------------------------------------
def test_inventory_combines_injected_lists():
    radios_list = inventory(wifi=[_onboard()],
                            bluetooth=[make_bt_radio("hci0", bus="uart")])
    kinds = sorted(r.kind for r in radios_list)
    assert kinds == ["bluetooth", "wifi"]


def test_collectors_are_harmless_off_a_pi():
    # No /sys/class/net wlan* or /sys/class/bluetooth here -> empty, no raise.
    assert isinstance(radios.collect_wifi(), list)
    assert isinstance(radios.collect_bluetooth(), list)


def test_radio_key_and_label():
    r = _usb("wlan1", driver="rtl8812au")
    assert r.key == r.mac          # no sysfs path set in the test builder
    assert "wlan1" in r.label() and "usb" in r.label()
