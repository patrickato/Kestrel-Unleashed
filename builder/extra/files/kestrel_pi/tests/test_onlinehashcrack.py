"""Tests for the onlinehashcrack uploader plugin (HTTP mocked at _post)."""

import importlib.util
import json
import os
import types

from kestrel_pi.capture import CaptureInterface
from kestrel_pi.context import PluginContext, ServiceRegistry

PLUGIN_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "..", "plugins")


def _load():
    path = os.path.join(PLUGIN_DIR, "onlinehashcrack.py")
    spec = importlib.util.spec_from_file_location("ohc_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = _load()


def _hashline(ap_hex="aabbccddee01", essid="Net", kind="02"):
    if kind == "01":
        return "WPA*01*%s*%s*112233445566*%s" % ("a" * 32, ap_hex,
                                                  essid.encode().hex())
    return "WPA*02*%s*%s*112233445566*%s*%s*%s*02" % (
        "b" * 32, ap_hex, essid.encode().hex(), "c" * 64, "d" * 10)


def _make(tmp_path, online=True, options=None):
    plugin = MOD.OnlineHashCrack()
    # poll_results off by default so the worker's initial tick makes no real
    # network call before a test replaces _post (mirrors wpa-sec's test setup).
    opts = {"api_key": "testkey", "timeout": 5, "poll_results": False}
    opts.update(options or {})
    plugin.options = opts
    plugin.context = PluginContext(
        name="onlinehashcrack", options=opts,
        capture=CaptureInterface(str(tmp_path)),
        connectivity=types.SimpleNamespace(online=online),
        services=ServiceRegistry(), capabilities=("capture-read", "network", "ui"))
    plugin.on_loaded()
    # stop the worker so tests drive _flush / _poll_results synchronously
    plugin._stop.set()
    plugin._wake.set()
    plugin._worker.join(timeout=2)
    return plugin


# --- declarations -----------------------------------------------------------
def test_declarations():
    assert MOD.OnlineHashCrack.__target_api__ == 2
    assert "network" in MOD.OnlineHashCrack.__capabilities__   # ack required
    assert MOD.OnlineHashCrack.__actions__[0]["path"] == "results"
    assert MOD.OnlineHashCrack.__options__["api_key"]["secret"] is True


# --- submit -----------------------------------------------------------------
def test_flush_submits_add_tasks_and_persists(tmp_path):
    p = _make(tmp_path)
    posted = {}

    def fake_post(body):
        posted["body"] = body
        return {"success": True, "accepted": {"count": len(body["hashes"])},
                "skipped": {"count": 0}, "rejected": {"count": 0}}

    p._post = fake_post
    p._enqueue(_hashline("aabbccddee01", "A"))
    p._enqueue(_hashline("aabbccddee02", "B", kind="01"))
    p._flush()

    assert posted["body"]["action"] == "add_tasks"
    assert posted["body"]["algo_mode"] == 22000
    assert posted["body"]["agree_terms"] == "yes"
    assert len(posted["body"]["hashes"]) == 2
    assert p._queue == [] and len(p._uploaded) == 2
    with open(p._state_path) as fh:
        assert len(json.load(fh)) == 2


def test_algo_mode_is_configurable(tmp_path):
    p = _make(tmp_path, options={"algo_mode": 2500})
    posted = {}
    p._post = lambda body: posted.update(body) or {"success": True}
    p._enqueue(_hashline())
    p._flush()
    assert posted["algo_mode"] == 2500


def test_batch_is_capped_at_50(tmp_path):
    p = _make(tmp_path)
    seen = {}
    p._post = lambda body: seen.update({"n": len(body["hashes"])}) or {"success": True}
    for i in range(60):
        p._enqueue(_hashline("aabbccddee%02d" % i, "N%d" % i))
    p._flush()
    assert seen["n"] == MOD.MAX_BATCH            # only 50 in the first call
    assert len(p._queue) == 10                   # the rest stay queued


def test_oversize_hashline_is_skipped(tmp_path):
    p = _make(tmp_path)
    p._enqueue("WPA*02*" + "a" * 600)            # > 512 chars
    assert p._queue == []


def test_refused_submit_is_not_resent(tmp_path):
    # A non-transient refusal (success:false) marks the batch attempted so it is
    # not resent forever.
    p = _make(tmp_path)
    p._post = lambda body: {"success": False, "error_code": "bad_key",
                            "message": "invalid api_key"}
    p._enqueue(_hashline())
    p._flush()
    assert p._queue == [] and len(p._uploaded) == 1


def test_transient_failure_keeps_the_queue(tmp_path):
    p = _make(tmp_path)
    p._post = lambda body: None                  # transport error
    p._enqueue(_hashline())
    p._flush()
    assert len(p._queue) == 1 and p._uploaded == set()


# --- results ----------------------------------------------------------------
def test_poll_results_counts_found(tmp_path):
    p = _make(tmp_path)
    h1, h2 = _hashline("aabbccddee01", "A"), _hashline("aabbccddee02", "B")
    p._post = lambda body: {
        "success": True,
        "tasks": [
            {"hash": h1, "status": "FOUND",
             "cleartext_location": "https://onlinehashcrack.com/x"},
            {"hash": h2, "status": "In queue"},
        ]}
    p._poll_results()
    assert p._found == 1
    assert p._tasks[h1]["status"] == "FOUND"
    assert p._tasks[h1]["location"].endswith("/x")


# --- gating + hooks ---------------------------------------------------------
def test_offline_tick_does_nothing(tmp_path):
    p = _make(tmp_path, online=False)
    hit = {"n": 0}
    p._flush = lambda: hit.__setitem__("n", hit["n"] + 1)
    p._tick()
    assert hit["n"] == 0


def test_handshake_hook_only_enqueues_and_wakes(tmp_path):
    p = _make(tmp_path)
    hit = {"n": 0}
    p._flush = lambda: hit.__setitem__("n", hit["n"] + 1)
    p._wake.clear()
    raw = _hashline("aabbccddee07", "G")
    p.on_handshake(types.SimpleNamespace(raw=raw))
    assert p._wake.is_set() and raw in p._queue and hit["n"] == 0


# --- readout + page ---------------------------------------------------------
def test_readout(tmp_path):
    from kestrel_pi.ui import StubUI
    p = _make(tmp_path)
    p._post = lambda body: {"success": True, "accepted": {"count": 1}}
    p._enqueue(_hashline())
    p._flush()
    p._found = 3
    ui = StubUI().for_plugin("onlinehashcrack")
    p.on_ui_setup(ui)
    p.on_ui_update(ui, None)
    assert ui.get("submitted") == "1" and ui.get("found") == "3"


def _req(token=""):
    return types.SimpleNamespace(args=types.SimpleNamespace(
        get=lambda k, d=None: token))


def test_results_page_needs_login(tmp_path):
    p = _make(tmp_path)
    p.context.web_authed = False
    page = p.on_webhook("results", _req())
    assert "login" in page.body.lower()


def test_results_page_shows_found_with_link(tmp_path):
    p = _make(tmp_path)
    p.context.web_authed = True
    h = _hashline("aabbccddee01", "HomeNet")
    p._tasks = {h: {"status": "FOUND",
                    "location": "https://onlinehashcrack.com/key/1"}}
    page = p.on_webhook("results", _req())
    assert "HomeNet" in page.body and "FOUND" in page.body
    assert "view key" in page.body and "onlinehashcrack.com/key/1" in page.body
