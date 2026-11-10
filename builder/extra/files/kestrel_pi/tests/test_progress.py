"""Tests for the live crack view: the aircrack progress parser, the progress
file, the readout overlay, the `kestrel crack watch` renderer, and the worker
writing/clearing ``crack-progress.json``.

No aircrack and no real time: the parser is fed canned aircrack text, and the
worker reuses the injected-runner fixtures from :mod:`test_crack`.
"""

import os

from kestrel_pi.crack import progress, readout, watchcli

# Reuse the offline worker fixtures (injected runner, fake clock at t=1000).
from test_crack import FakeAircrack, _config, _hashline, _worker, _write, AP1, AP1C


# A realistic aircrack-ng 1.7 running block (what it repaints without -q).
AIRCRACK_BLOCK = """
                               Aircrack-ng 1.7

      [00:00:08] 10464/10303727 keys tested (1308.00 k/s)

      Time left: 2 hours, 11 minutes, 23 seconds                     0.10%

                           Current passphrase: superman
"""


# --- parse_progress ---------------------------------------------------------
def test_parse_progress_pulls_every_field():
    p = progress.parse_progress(AIRCRACK_BLOCK)
    assert p["tested"] == 10464 and p["total"] == 10303727
    assert p["rate_kps"] == 1308.00
    assert p["percent"] == 0.10
    assert p["eta"] == "2 hours, 11 minutes, 23 seconds"
    assert p["passphrase"] == "superman"
    assert p["elapsed"] == "00:00:08"


def test_parse_progress_takes_the_latest_repaint():
    # aircrack overwrites in place; two blocks in the buffer -> the last wins.
    two = AIRCRACK_BLOCK + """
      [00:00:16] 41000/10303727 keys tested (1280.00 k/s)

      Time left: 2 hours, 9 minutes                                  0.40%

                           Current passphrase: liverpool
"""
    p = progress.parse_progress(two)
    assert p["tested"] == 41000 and p["passphrase"] == "liverpool"
    assert p["percent"] == 0.40


def test_parse_progress_handles_commas_and_derives_percent():
    # grouped digits, and no explicit % -> percent derived from the counts.
    p = progress.parse_progress("[00:01:00] 1,000,000/4,000,000 keys tested (900.00 k/s)")
    assert p["tested"] == 1000000 and p["total"] == 4000000
    assert p["percent"] == 25.0


def test_parse_progress_empty_is_blank():
    assert progress.parse_progress("") == {}
    assert progress.parse_progress("Aircrack-ng 1.7\nReading packets...\n") == {}


# --- progress file + freshness ----------------------------------------------
def test_write_read_clear_roundtrip(tmp_path):
    d = str(tmp_path)
    rec = progress.write_progress(d, {"state": "cracking", "wordlist": "rockyou.txt"},
                                  now=1000.0)
    assert rec["updated_at"] == 1000.0
    got = progress.read_progress(d)
    assert got["wordlist"] == "rockyou.txt" and got["state"] == "cracking"
    # world-readable so the daemon (also pi) and `crack watch` can read it
    assert (os.stat(progress.progress_path(d)).st_mode & 0o044) == 0o044
    progress.clear_progress(d)
    assert progress.read_progress(d) is None
    progress.clear_progress(d)                 # clearing a missing file is fine


def test_is_fresh_true_only_for_recent_cracking():
    base = {"state": "cracking", "updated_at": 1000.0}
    assert progress.is_fresh(base, now=1005.0) is True
    assert progress.is_fresh(base, now=1000.0 + progress.STALE_SECONDS + 1) is False
    assert progress.is_fresh({"state": "idle", "updated_at": 1000.0}, now=1001.0) is False
    assert progress.is_fresh({"updated_at": "nope"}, now=1001.0) is False
    assert progress.is_fresh(None) is False


# --- readout overlay --------------------------------------------------------
def _status():
    return {"state": "cracking", "targets": 10, "cracked": 3, "pending": 6,
            "exhausted": 1, "wordlists": 2, "temp_c": 61.0,
            "current": {"essid": "HomeWiFi", "wordlist": "rockyou.txt"}}


def test_readout_overlays_live_progress_when_fresh():
    prog = {"state": "cracking", "essid": "HomeWiFi", "wordlist": "rockyou.txt",
            "percent": 12.3, "rate_kps": 1.24, "eta": "2h 11m",
            "passphrase": "superman", "updated_at": 1000.0}
    els = {e["name"]: e for e in readout.widget_elements(_status(), prog, now=1001.0)}
    assert els["progress"]["kind"] == "gauge" and "12.3%" in els["progress"]["value"]
    assert els["rate"]["value"] == "1.24 k/s"
    assert els["eta"]["value"] == "2h 11m"
    assert els["trying"]["value"] == "superman"


def test_readout_ignores_stale_progress():
    stale = {"state": "cracking", "percent": 99.0, "updated_at": 1.0}
    els = {e["name"]: e for e in readout.widget_elements(_status(), stale, now=1000.0)}
    assert "progress" not in els and "trying" not in els      # overlay suppressed
    assert els["current"]["value"].startswith("HomeWiFi")     # falls back to status


# --- watch renderer ---------------------------------------------------------
def test_render_frame_shows_live_crack():
    prog = {"state": "cracking", "essid": "HomeWiFi", "wordlist": "rockyou.txt",
            "percent": 41.2, "rate_kps": 1.24, "eta": "2h 11m",
            "passphrase": "superman", "updated_at": 1000.0}
    out = watchcli.render_frame(_status(), prog, now=1001.0)
    assert "HomeWiFi" in out and "rockyou.txt" in out
    assert "41.2%" in out and "1.24 k/s" in out and "superman" in out
    assert "#" in out                                 # the progress bar drew


def test_render_frame_idle_has_no_crack_line():
    status = {"state": "no-capture", "targets": 5, "cracked": 0, "pending": 5,
              "exhausted": 0}
    out = watchcli.render_frame(status, None, now=1000.0)
    assert "waiting for a capture" in out
    assert "nothing cracking" in out


def test_render_frame_without_status():
    assert "has not reported" in watchcli.render_frame(None, None)


# --- worker writes/clears the live record -----------------------------------
def test_worker_writes_progress_when_a_dict_pass_starts(tmp_path):
    d = str(tmp_path)
    _write(os.path.join(d, "wordlists", "small.txt"), "hunter2!\n")
    _write(os.path.join(d, "capture", "nets.hc22000"), _hashline(AP1, "HomeWiFi") + "\n")
    cfg = _config(d, os.path.join(d, "wordlists"))
    worker = _worker(tmp_path, cfg, FakeAircrack(cracks={"small.txt": {AP1C: "hunter2!"}}))

    worker.run_once()                                 # one dict pass vs AP1
    rec = progress.read_progress(worker.crack_dir)
    assert rec is not None
    assert rec["wordlist"] == "small.txt"             # which list is running
    assert rec["essid"] == "HomeWiFi" and rec["origin"] == "auto"
    assert rec["state"] == "cracking"


def test_worker_clears_progress_when_it_goes_idle(tmp_path):
    d = str(tmp_path)
    _write(os.path.join(d, "wordlists", "small.txt"), "hunter2!\n")
    _write(os.path.join(d, "capture", "nets.hc22000"), _hashline(AP1, "HomeWiFi") + "\n")
    cfg = _config(d, os.path.join(d, "wordlists"))
    worker = _worker(tmp_path, cfg, FakeAircrack(cracks={"small.txt": {AP1C: "hunter2!"}}))

    for _ in range(10):                               # drain to idle
        _s, did = worker.run_once()
        if not did:
            break
    assert progress.read_progress(worker.crack_dir) is None   # retired on idle
