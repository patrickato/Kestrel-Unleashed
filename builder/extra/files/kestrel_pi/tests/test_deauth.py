"""Tests for the deauth planner: whitelist refusal, radio ownership, sharing."""

from kestrel_pi import deauth
from kestrel_pi.radios import assign_roles, make_wifi_radio

_PHY_MON = "* monitor\n* 2412 MHz [1]\n* 5180 MHz [36]"
_PHY_NOMON = "* 2412 MHz [1]"


def _onboard():
    return make_wifi_radio("wlan0", driver="brcmfmac", bus="sdio",
                           phy_info=_PHY_NOMON)


def _usb(dev, driver="rtl8812au", phy="phy1"):
    return make_wifi_radio(dev, driver=driver, phy=phy, bus="usb",
                           phy_info=_PHY_MON)


def test_refuses_an_invalid_bssid():
    a = assign_roles([_onboard(), _usb("wlan1")])
    assert deauth.plan_deauth("nope", a).ok is False
    assert deauth.plan_deauth("", a).ok is False


def test_refuses_a_whitelisted_bssid_or_essid():
    a = assign_roles([_onboard(), _usb("wlan1"), _usb("wlan2", phy="phy2")])
    by_bssid = deauth.plan_deauth("AA:BB:CC:DD:EE:01", a,
                                  whitelist=["AA:BB:CC:DD:EE:01"])
    assert by_bssid.ok is False and "whitelisted" in by_bssid.error
    by_essid = deauth.plan_deauth("AA:BB:CC:DD:EE:02", a, essid="HomeNet",
                                  whitelist=["HomeNet"])
    assert by_essid.ok is False and "whitelisted" in by_essid.error


def test_two_adapters_use_the_attack_radio_without_pausing():
    a = assign_roles([_onboard(), _usb("wlan1"), _usb("wlan2", phy="phy2")])
    plan = deauth.plan_deauth("AA:BB:CC:DD:EE:03", a)
    assert plan.ok is True
    assert plan.iface == a.owner("attack") and plan.iface == "wlan2"
    assert plan.pause_capture is False


def test_one_adapter_shares_the_capture_radio_and_pauses():
    a = assign_roles([_onboard(), _usb("wlan1")])
    plan = deauth.plan_deauth("AA:BB:CC:DD:EE:04", a)
    assert plan.ok is True
    assert plan.iface == "wlan1" and plan.pause_capture is True
    assert any("capture pauses" in n for n in plan.notices)


def test_sharing_can_be_refused_by_the_caller():
    # The adapter is shared (sharing on at the assignment), but the caller vetoes
    # sharing for this deauth.
    a = assign_roles([_onboard(), _usb("wlan1")])
    assert a.is_shared("attack") is True
    plan = deauth.plan_deauth("AA:BB:CC:DD:EE:05", a, allow_shared=False)
    assert plan.ok is False and "sharing" in plan.error


def test_assignment_with_sharing_off_leaves_no_attack_radio():
    # Sharing off at the assignment + one monitor adapter: attack is unowned, so
    # a deauth has no radio at all.
    a = assign_roles([_onboard(), _usb("wlan1")], allow_shared_attack=False)
    plan = deauth.plan_deauth("AA:BB:CC:DD:EE:08", a)
    assert plan.ok is False and "no radio" in plan.error


def test_no_monitor_adapter_cannot_deauth():
    a = assign_roles([_onboard()])
    plan = deauth.plan_deauth("AA:BB:CC:DD:EE:06", a)
    assert plan.ok is False and "no radio" in plan.error


def test_client_mac_is_validated_and_carried():
    a = assign_roles([_onboard(), _usb("wlan1"), _usb("wlan2", phy="phy2")])
    assert deauth.plan_deauth("AA:BB:CC:DD:EE:07", a, client="zz").ok is False
    plan = deauth.plan_deauth("AA:BB:CC:DD:EE:07", a,
                              client="11:22:33:44:55:66")
    assert plan.ok is True and plan.client == "11:22:33:44:55:66"
