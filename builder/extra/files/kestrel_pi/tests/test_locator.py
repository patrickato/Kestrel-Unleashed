"""Tests for the signal locator (pure warmer/colder smoothing)."""

from kestrel_pi import locator
from kestrel_pi.locator import SignalLocator, bars_for


def test_bars_for():
    assert bars_for(None) == 0 and bars_for(0) == 0
    assert bars_for(10) == 1 and bars_for(50) == 3 and bars_for(100) == 5
    assert bars_for(-5) == 0 and bars_for(200) == 5


def test_first_sample_is_steady():
    out = SignalLocator().update(40)
    assert out["trend"] == "steady" and out["level"] == 40 and out["seen"] is True


def test_rising_signal_reads_warmer():
    loc = SignalLocator(alpha=1.0, slack=3.0)   # alpha 1 = follow the sample
    loc.update(20)
    out = loc.update(60)
    assert out["trend"] == "warmer" and out["seen"] is True


def test_falling_signal_reads_colder():
    loc = SignalLocator(alpha=1.0, slack=3.0)
    loc.update(70)
    assert loc.update(40)["trend"] == "colder"


def test_small_change_is_steady():
    loc = SignalLocator(alpha=1.0, slack=5.0)
    loc.update(50)
    assert loc.update(52)["trend"] == "steady"   # within the slack


def test_missing_sample_is_lost_but_keeps_the_level():
    loc = SignalLocator()
    loc.update(60)
    out = loc.update(None)
    assert out["trend"] == "lost" and out["seen"] is False
    assert out["level"] == 60        # last smoothed level is kept


def test_smoothing_dampens_a_single_spike():
    loc = SignalLocator(alpha=0.4, slack=3.0)
    loc.update(50)
    out = loc.update(100)            # a spike moves the EWMA only part-way
    assert 50 < out["level"] < 100


def test_labels_cover_every_trend():
    for t in ("warmer", "colder", "steady", "lost"):
        assert t in locator.TREND_LABEL and t in locator.TREND_ARROW


# -- the locator plugin (scan mocked) ---------------------------------------
import importlib.util   # noqa: E402
import os               # noqa: E402
import types            # noqa: E402

from kestrel_pi.capture import CaptureInterface   # noqa: E402
from kestrel_pi.context import PluginContext, ServiceRegistry   # noqa: E402

_PLUGIN_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "plugins")


def _load_plugin():
    path = os.path.join(_PLUGIN_DIR, "locator.py")
    spec = importlib.util.spec_from_file_location("locator_plugin_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _plugin(tmp_path, signals):
    mod = _load_plugin()
    p = mod.Locator()
    p.options = {}
    p.context = PluginContext(
        name="locator", options={}, capture=CaptureInterface(str(tmp_path)),
        connectivity=types.SimpleNamespace(online=False),
        services=ServiceRegistry(), capabilities=("ui",))
    p.on_loaded()
    p._scan_signals = lambda: signals
    return mod, p


def _req(**kw):
    return types.SimpleNamespace(
        args=types.SimpleNamespace(get=lambda k, d=None: kw.get(k, "")))


def test_plugin_picker_lists_scanned_aps(tmp_path):
    _mod, p = _plugin(tmp_path, {"AA:BB:CC:DD:EE:01": 72,
                                 "AA:BB:CC:DD:EE:02": 40})
    page = p.on_webhook("view", _req())
    assert "AP locator" in page.body
    assert "AA:BB:CC:DD:EE:01" in page.body and "AA:BB:CC:DD:EE:02" in page.body


def test_plugin_meter_reads_warmer_as_signal_rises(tmp_path):
    _mod, p = _plugin(tmp_path, {"AA:BB:CC:DD:EE:01": 30})
    p.on_webhook("view", _req(bssid="AA:BB:CC:DD:EE:01"))     # first: steady
    p._scan_signals = lambda: {"AA:BB:CC:DD:EE:01": 80}       # stronger
    page = p.on_webhook("view", _req(bssid="AA:BB:CC:DD:EE:01"))
    assert "Locating" in page.body and "Warmer" in page.body


def test_plugin_meter_is_lost_when_target_absent(tmp_path):
    _mod, p = _plugin(tmp_path, {"AA:BB:CC:DD:EE:01": 50})
    p.on_webhook("view", _req(bssid="AA:BB:CC:DD:EE:01"))
    p._scan_signals = lambda: {}                              # target gone
    page = p.on_webhook("view", _req(bssid="AA:BB:CC:DD:EE:01"))
    assert "Lost" in page.body
