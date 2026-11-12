"""Tests for the remote-crack plugin's device-side logic.

The SSH/rsync host operations are stubbed, so the launch decision, the finished-
run collection and the shared ingest are exercised with no network and no GPU.
"""

import importlib.util
import os
import types

from kestrel_pi.capture import CaptureInterface
from kestrel_pi.context import PluginContext, ServiceRegistry
from kestrel_pi.crack import offload

PLUGIN_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "..", "plugins")


def _mod():
    path = os.path.join(PLUGIN_DIR, "remote-crack.py")
    spec = importlib.util.spec_from_file_location("remote_crack_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RC = _mod()


def _hashline(ap_hex, essid):
    return "WPA*02*%s*%s*112233445566*%s*0*0*00" % ("a" * 32, ap_hex,
                                                     essid.encode().hex())


def _plugin(tmp_path, options=None, online=True):
    store = tmp_path / "store"; store.mkdir(exist_ok=True)
    p = RC.RemoteCrack()
    opts = options or {}
    p.options = opts
    p.context = PluginContext(
        name="remote-crack", options=opts,
        capture=CaptureInterface(str(store)),
        connectivity=types.SimpleNamespace(online=online),
        services=ServiceRegistry(),
        capabilities=("capture-read", "network", "ui"))
    # on_loaded starts a worker thread; set up state by hand instead so the test
    # drives cycles deterministically.
    import threading
    p.log = p.context.logger
    p._lock = threading.Lock()
    p._run_lock = threading.Lock()
    p._stop = threading.Event()
    p._wake = threading.Event()
    p._crack_now = threading.Event()
    p._status = "idle"
    p._last_result = None
    p._offloaded = set()
    return p, store


def _configured(tmp_path, **extra):
    opts = {"crack_host": "gpubox", "crack_user": "me", "crack_path": "/work",
            "wordlist": "/home/me/rockyou.txt"}
    opts.update(extra)
    p, store = _plugin(tmp_path, opts)
    return p, store


# --- declarations -----------------------------------------------------------
def test_declarations_network_gated():
    assert "network" in RC.RemoteCrack.__capabilities__      # takes the ack
    assert RC.RemoteCrack.__actions__[0]["path"] == "crack"


# --- config gating ----------------------------------------------------------
def test_missing_config_and_actions_hidden(tmp_path):
    p, _ = _plugin(tmp_path, {})
    assert p._missing_config() == ["crack_host", "crack_user", "crack_path"]
    assert p.webhook_actions() == ()          # not offered until configured


def test_webhook_needs_setup(tmp_path):
    p, _ = _configured(tmp_path)
    # no key on disk -> the button explains, doesn't fire
    r = p.on_webhook("crack", None)
    assert r.__class__.__name__ == "PluginRedirect" and r.error


def test_webhook_fires_when_ready(tmp_path, monkeypatch):
    p, _ = _configured(tmp_path)
    monkeypatch.setattr(p, "_key_ready", lambda: True)
    r = p.on_webhook("crack", None)
    assert not r.error                       # queued
    assert p._crack_now.is_set()


# --- uncracked selection ----------------------------------------------------
def test_uncracked_filters_cracked(tmp_path):
    p, store = _configured(tmp_path)
    for i, (ap, es) in enumerate([("aabbccddee01", "A"), ("aabbccddee02", "B")]):
        (store / ("c%d.hc22000" % i)).write_text(_hashline(ap, es) + "\n")
    aps = {"AA:BB:CC:DD:EE:01": {"password": "x"}}      # A cracked
    lines, bssids = p._uncracked(aps)
    assert bssids == {"AA:BB:CC:DD:EE:02"} and len(lines) == 1


# --- full cycle: launch, then collect + ingest ------------------------------
def test_cycle_launches_then_collects_and_ingests(tmp_path, monkeypatch):
    crack_dir = tmp_path / "crack"; crack_dir.mkdir()
    monkeypatch.setattr(RC, "CRACK_DIR", str(crack_dir))
    p, store = _configured(tmp_path)
    monkeypatch.setattr(p, "_key_ready", lambda: True)
    ap_hex = "aabbccddee01"
    hashline = _hashline(ap_hex, "HomeNet")
    (store / "c.hc22000").write_text(hashline + "\n")

    state = {"job": "none"}
    launched = {"v": False}

    def fake_remote(script, timeout=None):
        if "run-crack.sh" in script:         # the launch script
            launched["v"] = True
            return (True, "launched")
        return (True, "")                    # job-state query: idle

    def fake_job_state():
        return state["job"]

    monkeypatch.setattr(p, "_remote", fake_remote)
    monkeypatch.setattr(p, "_rsync_up_file", lambda local, remote: (True, ""))
    monkeypatch.setattr(p, "_job_state", fake_job_state)

    # Phase A: host idle + an uncracked target -> launch
    p._run_cycle(manual=True)
    assert launched["v"] is True
    assert p._offloaded == {"AA:BB:CC:DD:EE:01"}
    assert "cracking" in p._status

    # Phase B: host finished -> pull recovered.txt + ingest
    state["job"] = "finished"
    recovered = hashline + ":gpupassword1\n"

    def fake_down(remote, local):
        with open(local, "w", encoding="utf-8") as fh:
            fh.write(recovered)
        return (True, "")

    monkeypatch.setattr(p, "_rsync_down", fake_down)
    p._run_cycle(manual=False)
    assert p._last_result and p._last_result[0] == 1

    # the recovered key is queued; a worker reconcile would mark it cracked
    aps = {"AA:BB:CC:DD:EE:01": {"bssid": "AA:BB:CC:DD:EE:01", "essid": "HomeNet",
                                 "status": "pending", "password": "", "tried": []}}
    assert offload.reconcile(aps, str(crack_dir)) == 1
    assert aps["AA:BB:CC:DD:EE:01"]["password"] == "gpupassword1"


def test_cycle_idle_when_offline(tmp_path, monkeypatch):
    p, _ = _configured(tmp_path)
    monkeypatch.setattr(p, "_key_ready", lambda: True)
    p.context.connectivity.online = False
    p._crack_now.set()
    p._cycle(force=True)
    assert "offline" in p._status


# --- the launch script is safe + correct -----------------------------------
def test_launch_script_quotes_and_uses_mode_22000(tmp_path):
    p, _ = _configured(tmp_path, wordlist="/home/me/my lists/rock.txt",
                       extra_args="-O -w 3")
    script = p._launch_script()
    assert "-m 22000" in script and "--show" in script
    assert "'/home/me/my lists/rock.txt'" in script      # shlex-quoted (has space)
    assert "setsid" in script and "crack.lock" in script


# --- the deferred device masks ride the SSH offload too ---------------------
def test_launch_script_runs_deferred_masks(tmp_path):
    # The GPU runs the masks the Pi deferred with -a 3, after the wordlist and
    # into the same potfile --show reads, guarded by -s so an empty or stale
    # mask file is skipped rather than erroring or re-running last cycle's.
    p, _ = _configured(tmp_path)
    script = p._launch_script()
    assert "-a 3" in script and "masks.hcmask" in script
    assert "[ -s masks.hcmask ]" in script


def test_launch_uploads_device_masks_when_deferred(tmp_path, monkeypatch):
    monkeypatch.setattr(RC, "CRACK_DIR", str(tmp_path / "crack"))
    p, _ = _configured(tmp_path)
    monkeypatch.setattr(p, "_remote", lambda script, timeout=None: (True, "ok"))
    uploads = {}

    def fake_up(local, remote):
        with open(local, encoding="utf-8") as fh:
            uploads[os.path.basename(remote)] = fh.read()
        return (True, "")

    monkeypatch.setattr(p, "_rsync_up_file", fake_up)

    # A printer AP: the 8-digit sweep the Pi defers rides along as masks.hcmask.
    masks = offload.kit_masks({"AA:BB:CC:DD:EE:02":
                               {"essid": "DIRECT-ab-HP OfficeJet"}})
    assert p._launch(["WPA*02*deadbeef"], masks) is True
    assert "?d?d?d?d?d?d?d?d" in uploads.get("masks.hcmask", "")

    # A plain AP with no device default: an empty mask file, so the remote -s
    # guard skips the mask pass (and a prior cycle's mask file is overwritten).
    uploads.clear()
    masks = offload.kit_masks({"AA:BB:CC:DD:EE:03": {"essid": "PlainHomeNet"}})
    assert p._launch(["WPA*02*deadbeef"], masks) is True
    assert uploads.get("masks.hcmask", "unset") == ""
