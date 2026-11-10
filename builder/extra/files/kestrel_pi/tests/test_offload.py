"""Tests for kestrel_pi.crack.offload - the GPU crack-kit + ingest core.

No GPU and no hashcat: we feed the module the text a GPU box's `hashcat --show`
would produce and check the kit it builds and the loot updates it queues.
"""

import os

from kestrel_pi.capture import CaptureInterface
from kestrel_pi.crack import offload
from kestrel_pi.crack.store import LootStore


def _hashline(ap_hex, essid, htype="02"):
    return "WPA*%s*%s*%s*112233445566*%s*0*0*00" % (
        htype, "a" * 32, ap_hex, essid.encode().hex())


def _bssid(ap_hex):
    return ":".join(ap_hex[i:i + 2] for i in range(0, 12, 2)).upper()


def _store(tmp_path, items):
    """Write one .hc22000 per (ap_hex, essid[, htype]) and return a capture view."""
    for i, it in enumerate(items):
        ap_hex, essid = it[0], it[1]
        htype = it[2] if len(it) > 2 else "02"
        with open(os.path.join(str(tmp_path), "c%d.hc22000" % i), "w") as fh:
            fh.write(_hashline(ap_hex, essid, htype) + "\n")
    return CaptureInterface(str(tmp_path))


# --- parse_recovered --------------------------------------------------------
def test_parse_recovered_pulls_bssid_essid_password():
    line = _hashline("aabbccddee01", "HomeNet") + ":s3cretpass!"
    out = offload.parse_recovered(line + "\n")
    assert out == [("AA:BB:CC:DD:EE:01", "HomeNet", "s3cretpass!")]


def test_parse_recovered_skips_junk_and_keeps_colon_passwords():
    good = _hashline("aabbccddee02", "Cafe") + ":pa:ss:word"   # password has colons
    text = "not a hashline:whatever\n" + good + "\n\n"
    out = offload.parse_recovered(text)
    assert out == [("AA:BB:CC:DD:EE:02", "Cafe", "pa:ss:word")]


# --- append_recovered (dedup) ----------------------------------------------
def test_append_recovered_writes_and_dedupes(tmp_path):
    crack = str(tmp_path)
    line = _hashline("aabbccddee01", "HomeNet") + ":pw12345678\n"
    assert offload.append_recovered(crack, line) == 1
    # same content again adds nothing
    assert offload.append_recovered(crack, line) == 0
    assert os.path.exists(os.path.join(crack, offload.RECOVERED_NAME))
    # a different AP adds one
    line2 = _hashline("aabbccddee02", "Other") + ":pw99998888\n"
    assert offload.append_recovered(crack, line2) == 1


def test_append_recovered_nothing_useful_is_zero(tmp_path):
    assert offload.append_recovered(str(tmp_path), "garbage\nlines\n") == 0


# --- reconcile --------------------------------------------------------------
def test_reconcile_marks_uncracked_and_skips_cracked(tmp_path):
    crack = str(tmp_path)
    b1, b2 = "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"
    aps = {
        b1: {"bssid": b1, "essid": "HomeNet", "status": "pending", "password": ""},
        b2: {"bssid": b2, "essid": "Done", "status": "cracked", "password": "already"},
    }
    offload.append_recovered(crack, _hashline("aabbccddee01", "HomeNet") + ":newpass12\n")
    offload.append_recovered(crack, _hashline("aabbccddee02", "Done") + ":ignored99\n")
    marked = offload.reconcile(aps, crack, now=123)
    assert marked == 1
    assert aps[b1]["status"] == "cracked" and aps[b1]["password"] == "newpass12"
    assert aps[b2]["password"] == "already"        # untouched


def test_reconcile_creates_record_for_unknown_bssid(tmp_path):
    crack = str(tmp_path)
    aps = {}
    offload.append_recovered(crack, _hashline("aabbccddee03", "Ghost") + ":found1234\n")
    assert offload.reconcile(aps, crack, now=5) == 1
    rec = aps["AA:BB:CC:DD:EE:03"]
    assert rec["password"] == "found1234" and rec["essid"] == "Ghost"


def test_reconcile_missing_file_is_zero(tmp_path):
    assert offload.reconcile({}, str(tmp_path)) == 0


# --- uncracked_hashlines + build_kit ---------------------------------------
def test_uncracked_hashlines_filters_cracked(tmp_path):
    cap = _store(tmp_path, [("aabbccddee01", "A"), ("aabbccddee02", "B")])
    aps = {"AA:BB:CC:DD:EE:01": {"password": "x"}}       # A already cracked
    lines = offload.uncracked_hashlines(cap.hashline_files(), aps, cap.read_events)
    assert len(lines) == 1 and "aabbccddee02" in lines[0]


def test_build_kit_writes_targets_scripts_and_readme(tmp_path):
    store = tmp_path / "store"
    store.mkdir()
    cap = _store(store, [("aabbccddee01", "A"),
                         ("aabbccddee02", "B", "01")])   # 01 = PMKID
    out = str(tmp_path / "kit")
    res = offload.build_kit(out, cap.hashline_files(), {}, cap.read_events)
    assert res["targets"] == 2                          # PMKID included
    for name in ("targets.hc22000", "crack.bat", "crack.sh", "README.txt"):
        assert os.path.exists(os.path.join(out, name))
    bat = open(os.path.join(out, "crack.bat")).read()
    sh = open(os.path.join(out, "crack.sh")).read()
    assert "-m 22000" in bat and "--show" in bat        # produces recovered.txt
    assert "-m 22000" in sh and sh.startswith("#!")
    readme = open(os.path.join(out, "README.txt")).read()
    assert "kestrel crack ingest recovered.txt" in readme


# --- end to end: build -> (GPU cracks) -> ingest -> reconcile ---------------
def test_full_round_trip(tmp_path):
    store = tmp_path / "store"
    store.mkdir()
    cap = _store(store, [("aabbccddee01", "HomeNet")])
    crack = str(tmp_path / "crack")
    os.makedirs(crack)
    # the loot store as the worker would have it (pending, uncracked)
    aps = {}
    LootStore.upsert(aps, {"bssid": "AA:BB:CC:DD:EE:01", "essid": "HomeNet"})
    # build the kit -> targets.hc22000 holds the one uncracked line
    res = offload.build_kit(str(tmp_path / "kit"), cap.hashline_files(), aps, cap.read_events)
    target_line = open(res["files"]["targets.hc22000"]).read().strip()
    # the GPU box "cracks" it: recovered.txt is `<hashline>:<password>`
    recovered = target_line + ":correcthorse\n"
    assert offload.append_recovered(crack, recovered) == 1
    # the worker's next pass reconciles it into loot
    assert offload.reconcile(aps, crack) == 1
    assert aps["AA:BB:CC:DD:EE:01"]["password"] == "correcthorse"
    assert aps["AA:BB:CC:DD:EE:01"]["status"] == "cracked"
