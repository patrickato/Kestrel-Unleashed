"""Tests for the on-device quick-crack package (kestrel_pi.crack).

No hashcat and no real time: the worker's subprocess, thermometer and clock are
injected, and a FakeHashcat stands in for the real cracker with a potfile that
grows exactly as hashcat's would, so the whole crack loop is exercised offline.
"""

import os

import pytest

from kestrel_pi.crack import CRACK_DEFAULTS, HARD_MAX_TEMP_C
from kestrel_pi.crack import aircrack as ac
from kestrel_pi.crack import controller, hashcat, readout
from kestrel_pi.crack import store as store_mod
from kestrel_pi.crack import wordlists as wl_mod
from kestrel_pi.crack.store import LootStore


def test_aircrack_classify_verdicts():
    assert ac.classify("KEY FOUND! [ hunter2 ]") == "cracked"
    assert ac.classify("KEY NOT FOUND") == "exhausted"
    assert ac.classify("Passphrase not in dictionary") == "exhausted"
    # the PMKID-only / no-EAPOL family -> benign no-handshake, not an error
    assert ac.classify(
        "Packets contained no EAPOL data; unable to process this AP.") == "no-handshake"
    assert ac.classify("No valid WPA handshakes found") == "no-handshake"
    assert ac.classify("No matching network found") == "no-handshake"
    assert ac.classify("Read 0 packets") == "no-handshake"
    # a genuinely broken run is still an error
    assert ac.classify("Unsupported file format") == "error"
    assert ac.classify("") == "error"


def _hashline(bssid_hex, essid, htype="02", mic="a" * 32, sta="665544332211"):
    """A minimal valid hc22000 line for a given AP MAC (12 hex) and ESSID."""
    essid_hex = essid.encode().hex()
    return "WPA*%s*%s*%s*%s*%s*00*00" % (htype, mic, bssid_hex, sta, essid_hex)


# AP MACs as 12-hex (no colons, as hc22000 stores them) and their : form.
AP1, AP1C = "001122334455", "00:11:22:33:44:55"
AP2, AP2C = "aabbccddeeff", "AA:BB:CC:DD:EE:FF"


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def _config(tmp_path, wordlists_dir, **over):
    """Write a config.toml with a [crack] table and return its path."""
    conf = dict(CRACK_DEFAULTS)
    conf.update(over)
    lines = ["[crack]",
             "enabled = %s" % ("true" if conf["enabled"] else "false"),
             'wordlists_dir = "%s"' % wordlists_dir,
             'order = "%s"' % conf["order"],
             "rules = %s" % ("[" + ", ".join('"%s"' % r for r in conf["rules"]) + "]"),
             "masks = %s" % ("[" + ", ".join('"%s"' % m for m in conf["masks"]) + "]"),
             "nice = %d" % conf["nice"],
             "workload = %d" % conf["workload"],
             "max_temp_c = %d" % conf["max_temp_c"],
             "resume_temp_c = %d" % conf["resume_temp_c"],
             "max_job_seconds = %d" % conf["max_job_seconds"],
             "recrack_on_new_wordlist = %s" % ("true" if conf["recrack_on_new_wordlist"] else "false")]
    path = os.path.join(tmp_path, "config.toml")
    _write(path, "\n".join(lines) + "\n")
    return path


class FakeHashcat:
    """Stand-in for hashcat + its potfile. Configure ``cracks`` as
    ``{wordlist_basename: {BSSID: password}}``; a crack run adds matching lines
    to the potfile, and a --show run reports the potfile lines for its hashfile,
    exactly like the real two-step flow the worker uses."""

    def __init__(self, cracks=None):
        self.cracks = cracks or {}
        self.pot = {}          # hashline -> password
        self.crack_calls = []

    def __call__(self, cmd, timeout=None):
        if "--show" in cmd:
            hashfile = cmd[-1]
            out = []
            for line in self._lines(hashfile):
                if line in self.pot:
                    out.append("%s:%s" % (line, self.pot[line]))
            return 0, "\n".join(out) + ("\n" if out else ""), ""
        # a crack run: last arg is the wordlist, second-last the hashfile
        wordlist, hashfile = cmd[-1], cmd[-2]
        self.crack_calls.append(os.path.basename(wordlist))
        table = self.cracks.get(os.path.basename(wordlist), {})
        from kestrel_pi.capture import parse_hashline
        for line in self._lines(hashfile):
            ev = parse_hashline(line)
            if ev and ev.bssid and ev.bssid.upper() in table:
                self.pot[line] = table[ev.bssid.upper()]
        return (0 if self.pot else 1), "", ""

    @staticmethod
    def _lines(path):
        with open(path, encoding="utf-8") as handle:
            return [ln.strip() for ln in handle if ln.strip()]


class FakeAircrack:
    """Stand-in for tcpdump + aircrack-ng. ``cracks`` = ``{wordlist_basename:
    {BSSID: pass}}`` for dictionary runs; ``mask_cracks`` = ``{BSSID: pass}`` for
    a mask run (routed through :meth:`run_mask`, which the worker calls instead of
    the plain runner for the crunch|aircrack pipe). A tcpdump convert touches the
    output pcap; an aircrack run reports KEY FOUND for a match, else NOT FOUND."""

    def __init__(self, cracks=None, mask_cracks=None):
        self.cracks = cracks or {}
        self.mask_cracks = mask_cracks or {}
        self.crack_calls = []

    def __call__(self, cmd, timeout=None):
        if cmd[0] == "tcpdump":
            open(cmd[cmd.index("-w") + 1], "w").close()      # create the fake pcap
            return 0, "", ""
        if cmd[0] == "aircrack-ng":
            wl = os.path.basename(cmd[cmd.index("-w") + 1])
            bssid = cmd[cmd.index("-b") + 1].upper()
            self.crack_calls.append(wl)
            pw = self.cracks.get(wl, {}).get(bssid)
            return (0, "KEY FOUND! [ %s ]\n" % pw, "") if pw is not None \
                else (1, "KEY NOT FOUND\n", "")
        return 0, "", ""

    def run_mask(self, pcaps, bssid, crunch_args, timeout=None):
        self.crack_calls.append("mask")
        pw = self.mask_cracks.get(bssid.upper())
        return (0, "KEY FOUND! [ %s ]\n" % pw, "") if pw is not None \
            else (1, "KEY NOT FOUND\n", "")


def _worker(tmp_path, config_path, runner, temp=50.0, pcapng=True):
    """A worker wired to a fake runner. Patches aircrack/tcpdump as present and
    (by default) drops a rolling pcapng in the capture store so the worker has a
    capture to crack from."""
    store = os.path.join(tmp_path, "capture")
    crack_dir = os.path.join(tmp_path, "crack")
    if pcapng:
        _write(os.path.join(store, ".run", "cap.pcapng"), "pkts")
    import kestrel_pi.crack.controller as ctl
    ctl.ac.have_aircrack = lambda: True
    ctl.ac.have_tcpdump = lambda: True
    worker = controller.CrackWorker(
        config_path=config_path, crack_dir=crack_dir, capture_store=store,
        runner=runner, temp_reader=lambda: temp, clock=lambda: 1000.0)
    if isinstance(runner, FakeAircrack):
        worker._run_mask = runner.run_mask
    return worker


# --- wordlists -------------------------------------------------------------

def test_wordlists_order_size_and_signature(tmp_path):
    d = str(tmp_path)
    _write(os.path.join(d, "big.txt"), "x\n" * 50)
    _write(os.path.join(d, "small.txt"), "x\n")
    _write(os.path.join(d, "best64.rule"), "noop\n")   # a rule, not a wordlist
    _write(os.path.join(d, "empty.txt"), "")           # zero-length, skipped
    lists = wl_mod.discover(d, "size")
    names = [w["name"] for w in lists]
    assert names == ["small.txt", "big.txt"]            # smallest first, no rule/empty
    sig_before = lists[0]["sig"]
    _write(os.path.join(d, "small.txt"), "x\ny\nz\n")   # grow it
    assert wl_mod.discover(d, "size")[0]["sig"] != sig_before   # signature changed


def test_resolve_rules_searches_wordlists_then_hashcat_dir(tmp_path):
    wl = tmp_path / "wl"; wl.mkdir()
    hc = tmp_path / "hcrules"; hc.mkdir()
    (wl / "mine.rule").write_text("noop\n")
    (hc / "best64.rule").write_text("noop\n")
    # a bare name is found in the wordlists dir, then in the hashcat rules dir;
    # an absolute path is used as-is; a typo resolves to nothing (never aborts).
    got = wl_mod.resolve_rules(
        ["mine.rule", "best64.rule", str(hc / "best64.rule"), "nope.rule"],
        str(wl), extra_dirs=(str(hc),))
    assert got == [str(wl / "mine.rule"), str(hc / "best64.rule"),
                   str(hc / "best64.rule")]


def test_wordlists_explicit_order(tmp_path):
    d = str(tmp_path)
    for n, body in (("a.txt", "x\n" * 9), ("b.txt", "x\n"), ("c.txt", "x\n" * 3)):
        _write(os.path.join(d, n), body)
    names = [w["name"] for w in wl_mod.discover(d, "c.txt, a.txt")]
    assert names[:2] == ["c.txt", "a.txt"] and names[2] == "b.txt"  # named first, rest by size


# --- store logic -----------------------------------------------------------

def test_upsert_identifies_device_and_keeps_result():
    aps = {}
    rec = LootStore.upsert(aps, {"bssid": AP1C, "essid": "Ring-Front",
                                 "type": "eapol", "hashline": "WPA*02*x",
                                 "hashlines": 1, "files": ["Ring-Front.hc22000"]})
    assert rec["bssid"] == AP1C and rec["product"] == "Ring"
    assert rec["device"] == "Ring · doorbell" and rec["category"] == "doorbell"
    LootStore.mark_cracked(rec, "hunter2!", "small.txt", now=5.0)
    # a later re-capture must not wipe the recovered password
    rec2 = LootStore.upsert(aps, {"bssid": AP1C, "essid": "Ring-Front",
                                  "type": "eapol", "hashlines": 2})
    assert rec2["password"] == "hunter2!" and rec2["status"] == "cracked"


def test_derive_status_pending_exhausted_cracked():
    rec = {"tried": [], "password": ""}
    sigs = {"a:1:1", "b:2:2"}
    assert LootStore.derive_status(rec, sigs) == "pending"
    rec["tried"] = ["a:1:1", "b:2:2"]
    assert LootStore.derive_status(rec, sigs) == "exhausted"
    # a new wordlist signature re-arms it (recrack_on_new)
    assert LootStore.derive_status(rec, sigs | {"c:3:3"}) == "pending"
    rec["password"] = "x"
    assert LootStore.derive_status(rec, sigs) == "cracked"


def test_next_auto_batch_is_wordlist_first():
    aps = {AP1C: {"tried": [], "password": ""}, AP2C: {"tried": [], "password": ""}}
    targets = [{"bssid": AP1C}, {"bssid": AP2C}]
    wls = [{"name": "s.txt", "sig": "s:1:1", "path": "/s"},
           {"name": "big.txt", "sig": "b:1:1", "path": "/b"}]
    wl, batch = store_mod.next_auto_batch(aps, targets, wls)
    assert wl["name"] == "s.txt" and len(batch) == 2       # smallest list, all targets
    # once both tried the small list and one is cracked, only the other is offered big
    aps[AP1C]["tried"] = ["s:1:1"]; aps[AP1C]["password"] = "x"
    aps[AP2C]["tried"] = ["s:1:1"]
    wl, batch = store_mod.next_auto_batch(aps, targets, wls)
    assert wl["name"] == "big.txt" and [t["bssid"] for t in batch] == [AP2C]
    # nothing left to try => None (this is "leave it alone")
    aps[AP2C]["tried"] = ["s:1:1", "b:1:1"]
    assert store_mod.next_auto_batch(aps, targets, wls) is None


# --- hashcat command + parse -----------------------------------------------

def test_build_crack_cmd_clamps_and_prefixes():
    cmd = hashcat.build_crack_cmd("/h", "/w", "/pot", rules=["/r.rule"],
                                  nice=99, workload=9)
    assert cmd[:3] == ["nice", "-n", "19"]                 # clamped to 19
    assert "-w" in cmd and cmd[cmd.index("-w") + 1] == "4"  # clamped to 4
    assert cmd[-2:] == ["/h", "/w"] and "-r" in cmd and "22000" in cmd
    assert "--force" in cmd        # required for the Pi's CPU/pocl OpenCL device
    # kernel_accel caps the per-batch size (fits the Pi's 256 MB alloc limit).
    # Use nice=0 so the only "-n" is the kernel-accel flag, not the nice prefix.
    plain = hashcat.build_crack_cmd("/h", "/w", "/pot", nice=0)
    assert "-n" not in plain                    # no cap unless asked
    capped = hashcat.build_crack_cmd("/h", "/w", "/pot", nice=0, kernel_accel=4)
    assert "-n" in capped and capped[capped.index("-n") + 1] == "4"
    assert capped[-2:] == ["/h", "/w"]          # hash/wordlist still last


def test_parse_show_splits_on_last_colon():
    line = _hashline(AP1, "Net")
    pairs = hashcat.parse_show("%s:pa:ss:word\n\n" % line)
    assert pairs == [(line, "pa:ss:word")]                 # split on FIRST colon; pw keeps ':'


# --- worker end to end ------------------------------------------------------

def test_run_once_cracks_and_marks(tmp_path):
    d = str(tmp_path)
    _write(os.path.join(d, "wordlists", "small.txt"), "hunter2!\n")
    _write(os.path.join(d, "capture", "nets.hc22000"),
           _hashline(AP1, "HomeWiFi") + "\n" + _hashline(AP2, "Office") + "\n")
    cfg = _config(d, os.path.join(d, "wordlists"))
    fake = FakeAircrack(cracks={"small.txt": {AP1C: "hunter2!"}})
    worker = _worker(tmp_path, cfg, fake)

    state, did = worker.run_once()
    assert state == "cracking" and did
    aps = worker.loot.load()
    assert aps[AP1C]["status"] == "cracked" and aps[AP1C]["password"] == "hunter2!"
    assert aps[AP1C]["cracked_wordlist"] == "small.txt"
    # AP2 tried the only wordlist and didn't crack => exhausted (nothing more to try)
    assert aps[AP2C]["status"] == "exhausted"
    assert aps[AP2C]["tried"] and aps[AP2C]["tried"][0].startswith("small.txt:")

    # second pass: AP1 cracked => left alone; AP2 already tried the only list => idle
    state2, did2 = worker.run_once()
    assert state2 == "idle" and not did2
    status = readout.read_status(worker.crack_dir)
    assert status["cracked"] == 1 and status["targets"] == 2


def test_no_handshake_is_its_own_state_not_an_error(tmp_path):
    # An AP with no crackable handshake in the capture (PMKID-only, or no EAPOL)
    # is a benign per-AP condition: it is marked "no-handshake", NOT tried (so it
    # retries once a handshake lands), and it must NOT flip the whole worker to
    # "error" -- the worker stays healthy (idle here, since it's the only AP).
    d = str(tmp_path)
    _write(os.path.join(d, "wordlists", "small.txt"), "hunter2!\n")
    _write(os.path.join(d, "capture", "nets.hc22000"),
           _hashline(AP1, "HomeWiFi") + "\n")
    cfg = _config(d, os.path.join(d, "wordlists"))

    def runner(cmd, timeout=None):
        if cmd[0] == "tcpdump":
            open(cmd[cmd.index("-w") + 1], "w").close()
            return 0, "", ""
        # the exact aircrack message the hardware printed for a PMKID-only AP
        return 1, "Packets contained no EAPOL data; unable to process this AP.\n", ""

    worker = _worker(tmp_path, cfg, runner)

    worker.run_once()
    aps = worker.loot.load()
    assert aps[AP1C]["status"] == "no-handshake"   # not pending, not exhausted
    assert not aps[AP1C].get("tried")              # retries once a handshake lands
    status = readout.read_status(worker.crack_dir)
    assert status["state"] != "error"              # a healthy worker, not red
    assert not status["error"]                     # nothing surfaced as an error
    assert status["no_handshake"] == 1


def test_real_aircrack_error_surfaces_and_stays_pending(tmp_path):
    # A genuine aircrack failure (a bad/unreadable capture, not just a missing
    # handshake) still flips the worker to "error", surfaces the reason, and must
    # NOT mark the wordlist tried (so a failure never masquerades as "exhausted").
    d = str(tmp_path)
    _write(os.path.join(d, "wordlists", "small.txt"), "hunter2!\n")
    _write(os.path.join(d, "capture", "nets.hc22000"),
           _hashline(AP1, "HomeWiFi") + "\n")
    cfg = _config(d, os.path.join(d, "wordlists"))

    def runner(cmd, timeout=None):
        if cmd[0] == "tcpdump":
            open(cmd[cmd.index("-w") + 1], "w").close()
            return 0, "", ""
        return 1, "Unsupported file format\n", ""          # a real error

    worker = _worker(tmp_path, cfg, runner)

    worker.run_once()
    aps = worker.loot.load()
    assert aps[AP1C]["status"] == "pending"        # not falsely exhausted
    assert not aps[AP1C].get("tried")
    status = readout.read_status(worker.crack_dir)
    assert status["state"] == "error"
    assert "Unsupported file format" in status["error"]


def test_thermal_gate(tmp_path):
    cfg = _config(str(tmp_path), os.path.join(str(tmp_path), "wordlists"))
    worker = _worker(tmp_path, cfg, FakeAircrack(), temp=90.0)
    conf = worker.config()
    assert worker.thermal_ok(conf) is False                 # 90 >= max_temp_c
    worker2 = _worker(tmp_path, cfg, FakeAircrack(), temp=50.0)
    assert worker2.thermal_ok(worker2.config()) is True
    # hard cap: even an absurd max_temp_c won't run at/above 85
    hot = _worker(tmp_path, cfg, FakeAircrack(), temp=HARD_MAX_TEMP_C + 1.0)
    assert hot.thermal_ok({"max_temp_c": 200, "resume_temp_c": 50}) is False


def test_manual_job_overrides_and_runs(tmp_path):
    d = str(tmp_path)
    _write(os.path.join(d, "wordlists", "small.txt"), "x\n")
    big = os.path.join(d, "wordlists", "rockyou.txt")
    _write(big, "sekret99\n")
    capfile = os.path.join(d, "capture", "nets.hc22000")
    _write(capfile, _hashline(AP1, "HomeWiFi") + "\n")
    cfg = _config(d, os.path.join(d, "wordlists"))
    fake = FakeAircrack(cracks={"rockyou.txt": {AP1C: "sekret99"}})
    worker = _worker(tmp_path, cfg, fake)
    # exhaust AP1 against small.txt so auto would leave it alone...
    worker.run_once()
    assert worker.loot.load()[AP1C]["status"] == "pending"  # only small tried; still pending vs rockyou? no: rockyou present
    # ...now the operator queues rockyou explicitly against the file
    store_mod.enqueue_job(worker.crack_dir, [capfile], big, label="retry")
    worker.run_once()
    aps = worker.loot.load()
    assert aps[AP1C]["status"] == "cracked" and aps[AP1C]["password"] == "sekret99"
    assert store_mod.queue_len(worker.crack_dir) == 0       # job consumed


def test_disabled_and_no_wordlists(tmp_path):
    d = str(tmp_path)
    _write(os.path.join(d, "capture", "nets.hc22000"), _hashline(AP1, "Net") + "\n")
    # disabled => state disabled, but targets still tracked
    cfg_off = _config(d, os.path.join(d, "wordlists"), enabled=False)
    w = _worker(tmp_path, cfg_off, FakeAircrack())
    assert w.run_once()[0] == "disabled"
    assert AP1C in w.loot.load()                             # loot still populated
    # enabled but no wordlists => no-wordlists
    cfg_on = _config(d, os.path.join(d, "wordlists_empty"))
    os.makedirs(os.path.join(d, "wordlists_empty"), exist_ok=True)
    w2 = _worker(tmp_path, cfg_on, FakeAircrack())
    assert w2.run_once()[0] == "no-wordlists"


# --- mask / brute-force attacks ---------------------------------------------

def test_build_mask_cmd_and_attacks():
    cmd = hashcat.build_mask_cmd("/h", "?d?d?d?d", "/pot", nice=15, workload=2)
    assert "-a" in cmd and cmd[cmd.index("-a") + 1] == "3"   # mask mode
    assert cmd[-2:] == ["/h", "?d?d?d?d"] and "22000" in cmd
    assert "--force" in cmd        # required for the Pi's CPU/pocl OpenCL device
    # build_attacks: wordlists (dict) first, masks (mask) last
    wls = [{"name": "s.txt", "sig": "s:1:1", "path": "/s", "size": 1}]
    attacks = store_mod.build_attacks(wls, ["?d?d", "?l?l"])
    assert [a["kind"] for a in attacks] == ["dict", "mask", "mask"]
    assert attacks[0]["path"] == "/s"                        # wordlist fields kept
    assert attacks[1]["sig"] == "mask:?d?d" and attacks[1]["mask"] == "?d?d"


def test_masks_run_after_wordlists(tmp_path):
    d = str(tmp_path)
    _write(os.path.join(d, "wordlists", "small.txt"), "nope\n")   # won't crack it
    _write(os.path.join(d, "capture", "nets.hc22000"), _hashline(AP1, "HomeWiFi") + "\n")
    cfg = _config(d, os.path.join(d, "wordlists"), masks=["?d?d?d?d?d?d?d?d"])
    fake = FakeAircrack(mask_cracks={AP1C: "12345678"})
    worker = _worker(tmp_path, cfg, fake)

    worker.run_once()                       # wordlist pass first — no crack
    assert worker.loot.load()[AP1C]["status"] == "pending"   # mask still untried
    worker.run_once()                       # mask pass — cracks it
    rec = worker.loot.load()[AP1C]
    assert rec["status"] == "cracked" and rec["password"] == "12345678"
    assert rec["cracked_wordlist"] == "?d?d?d?d?d?d?d?d"


def test_manual_mask_job(tmp_path):
    d = str(tmp_path)
    _write(os.path.join(d, "wordlists", "small.txt"), "x\n")
    capfile = os.path.join(d, "capture", "nets.hc22000")
    _write(capfile, _hashline(AP1, "HomeWiFi") + "\n")
    cfg = _config(d, os.path.join(d, "wordlists"))
    fake = FakeAircrack(mask_cracks={AP1C: "4815"})
    worker = _worker(tmp_path, cfg, fake)
    store_mod.enqueue_job(worker.crack_dir, [capfile], mask="?d?d?d?d", label="pin")
    worker.run_once()
    rec = worker.loot.load()[AP1C]
    assert rec["status"] == "cracked" and rec["password"] == "4815"
    assert store_mod.queue_len(worker.crack_dir) == 0


# --- readout ----------------------------------------------------------------

def test_readout_widget_elements():
    status = {"state": "cracking", "targets": 10, "cracked": 3, "pending": 6,
              "exhausted": 1, "wordlists": 2, "queue": 1, "temp_c": 61.0,
              "current": {"essid": "HomeWiFi", "wordlist": "rockyou.txt"},
              "last_crack": {"essid": "Office", "at": 900.0}}
    els = {e["name"]: e for e in readout.widget_elements(status, now=1000.0)}
    assert els["cracked"]["value"] == "3 / 10"
    assert els["cracked_pct"]["kind"] == "percent"
    assert els["current"]["value"].startswith("HomeWiFi")
    assert readout.widget_elements(None) == []
    assert readout.face_summary(status)["cracked"] == 3
