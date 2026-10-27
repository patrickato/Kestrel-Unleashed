"""Tests for the WPS attack helper (command build, output parse, loot write)."""

from kestrel_pi import wps
from kestrel_pi.crack.store import LootStore

REAVER_OUTPUT = """
[+] Waiting for beacon from AA:BB:CC:DD:EE:FF
[+] Associated with AA:BB:CC:DD:EE:FF (ESSID: HomeNet)
[+] Running pixiewps with the information, wait ...
[+] WPS PIN: '12345670'
[+] WPA PSK: 'supersecret'
[+] AP SSID: 'HomeNet'
"""


def test_build_reaver_cmd():
    cmd = wps.build_reaver_cmd("mon0", "AA:BB:CC:DD:EE:FF", channel=6, pixie=True)
    assert cmd[:5] == ["reaver", "-i", "mon0", "-b", "AA:BB:CC:DD:EE:FF"]
    assert "-c" in cmd and cmd[cmd.index("-c") + 1] == "6"
    assert "-K" in cmd                                        # pixie-dust on
    assert "-K" not in wps.build_reaver_cmd("mon0", "AA:BB:CC:DD:EE:FF", pixie=False)


def test_parse_reaver_output():
    g = wps.parse_reaver_output(REAVER_OUTPUT)
    assert g["pin"] == "12345670" and g["psk"] == "supersecret"
    assert g["essid"] == "HomeNet"
    assert wps.parse_reaver_output("nothing recovered here") == {}


def test_record_to_loot(tmp_path):
    crack_dir = str(tmp_path / "crack")
    assert wps.record_to_loot("AA:BB:CC:DD:EE:FF", "NETGEAR57", "supersecret",
                              "12345670", crack_dir=crack_dir) is True
    rec = LootStore(crack_dir).load()["AA:BB:CC:DD:EE:FF"]
    assert rec["status"] == "cracked" and rec["password"] == "supersecret"
    assert rec["source"] == "wps" and rec["wps_pin"] == "12345670"
    assert rec["cracked_wordlist"].startswith("WPS")
    assert "NETGEAR" in rec["device"]                        # device-id label applied
    # a blank BSSID can't be keyed as loot
    assert wps.record_to_loot("", "x", "y", crack_dir=crack_dir) is False
