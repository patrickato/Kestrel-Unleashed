"""Tests for the WPS attack helper (command build, output parse, loot write,
and the live-progress readout)."""

import io
import json

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


# -- live progress -----------------------------------------------------------

def test_parse_reaver_progress_stages():
    assert wps.parse_reaver_progress("[+] Waiting for beacon from AA:BB")[
        "stage"] == "waiting"
    assert wps.parse_reaver_progress(
        "[+] Associated with AA:BB (ESSID: Net)")["stage"] == "associated"
    brute = wps.parse_reaver_progress(
        "[+] Trying pin \"12345670\"\n[+] 42.50% complete @ ... (3 seconds/pin)")
    assert brute["stage"] == "pin-brute"
    assert brute["percent"] == 42.5 and brute["rate"] == "3 s/pin"
    assert wps.parse_reaver_progress(
        "[+] Running pixiewps with the information, wait ...")[
            "stage"] == "pixie-dust"
    locked = wps.parse_reaver_progress(
        "[!] WARNING: Detected AP rate limiting, waiting 60 seconds")
    assert locked["stage"] == "rate-limited" and locked["locked"] is True
    assert wps.parse_reaver_progress("[-] WPS pin not found!")[
        "stage"] == "failed"
    # the latest line wins when reaver advances through pins
    assert wps.parse_reaver_progress("[+] 1.00% complete\n[+] 9.90% complete")[
        "percent"] == 9.9


def test_progress_last_line_scrubs_secrets():
    # a tail whose last line would leak the recovered key must be redacted
    prog = wps.parse_reaver_progress(
        "[+] Trying pin \"99887766\"\n[+] WPA PSK: 'topsecretpw'")
    assert "topsecretpw" not in json.dumps(prog)
    prog2 = wps.parse_reaver_progress("[+] Trying pin \"99887766\"")
    assert "99887766" not in json.dumps(prog2) and "####" in prog2["last"]


def test_live_attack_records_key_and_keeps_progress_secret_free(tmp_path):
    wps_dir = str(tmp_path / "wps")
    crack_dir = str(tmp_path / "crack")
    echo = io.StringIO()
    res = wps.live_attack(io.StringIO(REAVER_OUTPUT), wps_dir=wps_dir,
                          bssid="aa:bb:cc:dd:ee:ff", crack_dir=crack_dir,
                          echo=echo, flush_interval=0)
    assert res["outcome"] == "recovered" and res["recorded"] is True
    # the recovered key reached the loot store...
    rec = LootStore(crack_dir).load()["AA:BB:CC:DD:EE:FF"]
    assert rec["password"] == "supersecret" and rec["source"] == "wps"
    # ...and reaver's output was echoed through for the console/journal
    assert "WPA PSK" in echo.getvalue()
    # ...but the on-disk progress file never holds the PSK or PIN
    prog = wps.read_progress(wps_dir)
    assert prog["done"] is True and prog["outcome"] == "recovered"
    blob = json.dumps(prog)
    assert "supersecret" not in blob and "12345670" not in blob


def test_live_attack_no_key(tmp_path):
    wps_dir = str(tmp_path / "wps")
    crack_dir = str(tmp_path / "crack")
    transcript = ("[+] Associated with AA:BB:CC:DD:EE:FF\n"
                  "[+] Trying pin \"00000000\"\n[-] WPS pin not found!\n")
    res = wps.live_attack(io.StringIO(transcript), wps_dir=wps_dir,
                          bssid="AA:BB:CC:DD:EE:FF", crack_dir=crack_dir,
                          echo=io.StringIO(), flush_interval=0)
    assert res["outcome"] == "failed" and res["recorded"] is False
    assert LootStore(crack_dir).load() == {}
    assert wps.read_progress(wps_dir)["done"] is True


def test_is_fresh():
    assert wps.is_fresh({"updated_at": 100.0, "done": False}, now=110.0) is True
    assert wps.is_fresh({"updated_at": 100.0, "done": False}, now=200.0) is False
    assert wps.is_fresh({"updated_at": 100.0, "done": True}, now=100.0) is False
    assert wps.is_fresh({}, now=100.0) is False
