"""Enumerate the device's radios and give each one a role.

Kestrel runs more than one radio at a time. The Pi's built-in Wi-Fi plus one or
two USB adapters (an Alfa, a TP-Link AC600 ...), and the built-in Bluetooth plus
an optional USB BT dongle. The offensive features each want a radio of their own:
capture monitors on one, active deauth injects on another, and the uplink /
connect-to-a-cracked-network station associates on a third. If nothing owns the
assignment they fight over a single interface -- deauth tears down the capture
monitor, the station reconfigures the adapter mid-sweep, and so on.

This module is that owner. It inventories what is present and assigns a role to
each radio by a small, explainable rule set with per-radio operator overrides.
Every assignment carries a human-readable reason, and every thing it *can't* do
(no second monitor adapter, no dongle at all) comes back as a plain-language
notice rather than a silent gap -- glass-box, like the rest of Kestrel.

The core (``assign_roles`` and the ``parse_*`` / ``make_*`` helpers) is pure: no
I/O, unit-tested with captured ``iw``/``sysfs`` output. The ``collect_*`` /
``inventory`` collectors are the only part that touches hardware, so the logic is
testable off a Pi. Python 3.11, stdlib only.

Lab / authorized use only: role assignment decides *which* radio a feature aims
with, never widens *what* a feature may do -- the Scope still governs that.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

# --- roles ------------------------------------------------------------------
# Wi-Fi roles. "capture" monitors + harvests handshakes; "attack" injects
# (deauth/assoc); "station" associates as a client (the uplink and the loot-page
# connect-to-a-cracked-network feature); "idle" is a present-but-unassigned spare.
WIFI_ROLES = ("capture", "attack", "station", "idle")
# Bluetooth roles. "pan" is the phone-tether uplink (bt-pan); "scan" is BLE/CLASSIC
# discovery; "idle" a spare.
BT_ROLES = ("pan", "scan", "idle")

# The built-in Pi Wi-Fi chip. It is not monitor-capable and NetworkManager drives
# it for connectivity, so it is reserved for the station role and never captures
# (this mirrors common.sh's PWN_WIFI_DRIVER, kept in sync by the operator).
BUILTIN_WIFI_DRIVER = "brcmfmac"

# --- advisory chipset table -------------------------------------------------
# driver (kernel module) -> (friendly chipset name, injection advisory). The
# injection column is ADVISORY ONLY -- monitor capability is always confirmed
# live from `iw phy info`; this just tells the operator what a radio is and
# whether deauth is likely to work, so an "attack" radio isn't picked blind.
# "yes" known-good for injection, "partial" works with caveats / out-of-tree
# driver, "no" client-only. Unlisted drivers come back "unknown" and are trusted
# only as far as the live monitor probe allows.
_WIFI_CHIPSETS: Dict[str, Tuple[str, str]] = {
    "brcmfmac": ("Broadcom (Pi onboard)", "no"),
    # Realtek USB -- the common Alfa / generic injection adapters
    "rtl8812au": ("Realtek RTL8812AU (Alfa AWUS036ACH class)", "yes"),
    "88XXau": ("Realtek RTL8812AU (aircrack-ng driver)", "yes"),
    "rtl8811au": ("Realtek RTL8811AU", "yes"),
    "rtl8188eus": ("Realtek RTL8188EUS", "yes"),
    "8188eu": ("Realtek RTL8188EU", "yes"),
    "rtl8188fu": ("Realtek RTL8188FU", "partial"),
    "rtl88x2bu": ("Realtek RTL8812BU", "yes"),
    "88x2bu": ("Realtek RTL8812BU", "yes"),
    "rtl8821au": ("Realtek RTL8821AU", "yes"),
    "rtw_8821cu": ("Realtek RTL8821CU (TP-Link AC600 T2 Nano)", "partial"),
    "rtl8821cu": ("Realtek RTL8821CU (TP-Link AC600 T2 Nano)", "partial"),
    "8821cu": ("Realtek RTL8821CU (TP-Link AC600 T2 Nano)", "partial"),
    "rtl8xxxu": ("Realtek (rtl8xxxu in-tree)", "partial"),
    # MediaTek USB -- the modern injection-friendly adapters (Alfa ACM etc.)
    "mt7612u": ("MediaTek MT7612U (Alfa AWUS036ACM class)", "yes"),
    "mt7610u": ("MediaTek MT7610U", "yes"),
    "mt76x2u": ("MediaTek MT76x2U", "yes"),
    "mt76x0u": ("MediaTek MT76x0U", "yes"),
    "mt7921u": ("MediaTek MT7921U", "partial"),
    # Atheros USB -- the classic 2.4GHz injection workhorses
    "ath9k_htc": ("Atheros AR9271 (Alfa AWUS036NHA class)", "yes"),
    "carl9170": ("Atheros AR9170", "yes"),
    # Ralink legacy
    "rt2800usb": ("Ralink RT2800 USB", "yes"),
    "rt2870": ("Ralink RT2870", "yes"),
}

_CHIP_UNKNOWN = ("", "unknown")


def chipset_for(driver: str) -> Tuple[str, str]:
    """``(friendly name, injection advisory)`` for a kernel driver, or
    ``("", "unknown")`` when the driver isn't in the advisory table."""
    return _WIFI_CHIPSETS.get((driver or "").strip(), _CHIP_UNKNOWN)


# --- the radio record -------------------------------------------------------
@dataclass(frozen=True)
class Radio:
    """One radio interface. ``kind`` is ``"wifi"`` or ``"bluetooth"``. ``path`` is
    a stable sysfs device path used as identity so a role override survives an
    interface rename (wlan1 <-> wlan2) across reboots."""
    dev: str
    kind: str
    driver: str = ""
    chipset: str = ""
    injection: str = "unknown"        # wifi: yes/partial/no/unknown (advisory)
    phy: str = ""                     # wifi: phyN
    mac: str = ""
    bus: str = ""                     # usb / pci / sdio / platform / uart / ""
    builtin: bool = False
    monitor: bool = False             # wifi: monitor-mode capable (live probe)
    bands: Tuple[str, ...] = ()       # wifi: ("2.4", "5", "6")
    path: str = ""

    @property
    def key(self) -> str:
        """The preferred stable override key: the sysfs path if known, else MAC,
        else the device name."""
        return self.path or (self.mac or self.dev)

    def label(self) -> str:
        """A short human label for the UI/CLI, e.g.
        ``wlan1 (Realtek RTL8812AU ..., usb)``."""
        what = self.chipset or self.driver or "unknown"
        where = self.bus or ("builtin" if self.builtin else "")
        return "%s (%s%s)" % (self.dev, what, (", " + where) if where else "")


# --- pure parsers over `iw phy info` ----------------------------------------
def monitor_capable(phy_info: str) -> bool:
    """True when the wiphy lists monitor as a supported interface mode. Matches
    common.sh's ``grep -F '* monitor'`` so Python and shell agree."""
    return "* monitor" in (phy_info or "")


# 2.4GHz 2400-2500, 5GHz 5150-5895, 6GHz 5925-7125 (MHz).
_FREQ_RE = re.compile(r"\*\s*(\d{4,5})(?:\.\d+)?\s*MHz")


def bands_from_phy(phy_info: str) -> Tuple[str, ...]:
    """The bands the adapter has enabled channels on, as ``("2.4", "5", "6")``,
    derived from the frequency lines in ``iw phy info`` (disabled channels are
    skipped). Empty when the text names no usable frequency."""
    found = set()
    for line in (phy_info or "").splitlines():
        if "disabled" in line:
            continue
        m = _FREQ_RE.search(line)
        if not m:
            continue
        mhz = int(m.group(1))
        if 2400 <= mhz < 2500:
            found.add("2.4")
        elif 5150 <= mhz <= 5895:
            found.add("5")
        elif 5925 <= mhz <= 7125:
            found.add("6")
    return tuple(b for b in ("2.4", "5", "6") if b in found)


# --- building radios from gathered facts ------------------------------------
def make_wifi_radio(dev: str, driver: str = "", phy: str = "", mac: str = "",
                    bus: str = "", path: str = "", phy_info: str = "",
                    builtin_driver: str = BUILTIN_WIFI_DRIVER) -> Radio:
    """Assemble a Wi-Fi :class:`Radio` from already-gathered facts (the collector
    reads sysfs/iw; this stays pure so it is unit-testable). ``phy_info`` is the
    raw ``iw phy <phy> info`` text used for the live monitor + band probe."""
    chip, inj = chipset_for(driver)
    builtin = (driver == builtin_driver) or bus in ("sdio", "mmc", "platform")
    return Radio(
        dev=dev, kind="wifi", driver=driver, chipset=chip, injection=inj,
        phy=phy, mac=(mac or "").upper(), bus=bus, builtin=builtin,
        monitor=monitor_capable(phy_info), bands=bands_from_phy(phy_info),
        path=path)


def make_bt_radio(dev: str, mac: str = "", bus: str = "",
                  path: str = "") -> Radio:
    """Assemble a Bluetooth :class:`Radio`. A UART-attached controller is the Pi's
    built-in one; a USB controller is an external dongle."""
    builtin = bus in ("uart", "platform", "")
    return Radio(dev=dev, kind="bluetooth", mac=(mac or "").upper(), bus=bus,
                 builtin=builtin, path=path)


# --- the assignment ---------------------------------------------------------
@dataclass(frozen=True)
class Assignment:
    """The outcome of :func:`assign_roles`. ``roles`` maps each present radio's
    device name to its role; ``owners`` maps each role to the device that owns it
    (or ``None``); ``reasons`` explains every radio's role; ``shared`` records a
    role that had to borrow another role's radio (e.g. attack sharing the capture
    adapter when only one monitor adapter is present); ``notices`` are the
    glass-box explanations of anything that couldn't be satisfied."""
    roles: Dict[str, str]
    owners: Dict[str, Optional[str]]
    reasons: Dict[str, str]
    shared: Dict[str, str]
    notices: Tuple[str, ...]

    def owner(self, role: str) -> Optional[str]:
        """The device owning ``role`` (``None`` if unassigned)."""
        return self.owners.get(role)

    def is_shared(self, role: str) -> bool:
        """True when ``role`` is borrowing another role's radio rather than owning
        a dedicated one (the caller must coordinate: e.g. pause capture to deauth)."""
        return role in self.shared


def _override_for(radio: Radio,
                  overrides: Dict[str, str]) -> Optional[str]:
    """The operator-configured role for this radio, matched by (in order) sysfs
    path, MAC, device name, or driver -- case-insensitively. ``None`` when no
    override applies. An override to an unknown role is ignored (the notice is
    raised by the caller)."""
    if not overrides:
        return None
    norm = {str(k).strip().lower(): str(v).strip().lower()
            for k, v in overrides.items() if str(k).strip()}
    for candidate in (radio.path, radio.mac, radio.dev, radio.driver):
        if candidate and candidate.lower() in norm:
            return norm[candidate.lower()]
    return None


def assign_roles(radios: Sequence[Radio],
                 overrides: Optional[Dict[str, str]] = None,
                 allow_shared_attack: bool = True,
                 builtin_driver: str = BUILTIN_WIFI_DRIVER) -> Assignment:
    """Assign a role to every present radio.

    Wi-Fi, in order: operator overrides win first; the built-in chip is reserved
    for ``station`` (connectivity); the first monitor-capable USB adapter becomes
    ``capture``; the next monitor-capable USB adapter (injection-preferred)
    becomes ``attack``; anything left is an ``idle`` spare, promoted to
    ``station`` only if nothing else took it. With a single monitor adapter,
    ``attack`` shares the capture radio when ``allow_shared_attack`` (flagged in
    ``shared`` + a notice), otherwise it goes unowned with a notice.

    Bluetooth: the built-in controller is ``pan`` (phone tether); an external
    dongle is ``scan``; with one controller, ``scan`` shares ``pan``.
    """
    overrides = overrides or {}
    roles: Dict[str, str] = {}
    reasons: Dict[str, str] = {}
    shared: Dict[str, str] = {}
    notices: List[str] = []
    owners: Dict[str, Optional[str]] = {r: None for r in WIFI_ROLES + BT_ROLES}

    wifi = [r for r in radios if r.kind == "wifi"]
    bt = [r for r in radios if r.kind == "bluetooth"]

    # 1) explicit overrides first, so the auto rules never fight the operator.
    pending_wifi: List[Radio] = []
    for r in wifi:
        ov = _override_for(r, overrides)
        if ov is None:
            pending_wifi.append(r)
            continue
        if ov not in WIFI_ROLES:
            notices.append("%s: ignoring unknown configured role %r"
                           % (r.dev, ov))
            pending_wifi.append(r)
            continue
        if ov == "capture" and not r.monitor:
            notices.append("%s configured for capture but it is not "
                           "monitor-capable; leaving it idle" % r.dev)
            roles[r.dev] = "idle"
            reasons[r.dev] = "configured for capture but no monitor mode"
            continue
        roles[r.dev] = ov
        reasons[r.dev] = "configured by operator"
        if owners.get(ov) is None and ov != "idle":
            owners[ov] = r.dev

    # 2) built-in chip -> station (unless an override already placed it).
    rest: List[Radio] = []
    for r in pending_wifi:
        if r.builtin:
            roles[r.dev] = "station"
            reasons[r.dev] = "built-in chip, reserved for connectivity/uplink"
            if owners["station"] is None:
                owners["station"] = r.dev
        else:
            rest.append(r)

    # 3) external adapters: capture first, then attack, then spares. Monitor-
    #    capable ones lead; injection-capable preferred for the attack slot.
    monitors = [r for r in rest if r.monitor]
    non_monitor = [r for r in rest if not r.monitor]

    def _take(dev: str, role: str, reason: str) -> None:
        roles[dev] = role
        reasons[dev] = reason
        if owners.get(role) is None and role != "idle":
            owners[role] = dev

    if owners["capture"] is None and monitors:
        cap = monitors.pop(0)
        _take(cap.dev, "capture", "first monitor-capable USB adapter")
    # attack: prefer a remaining monitor adapter whose injection isn't "no".
    if owners["attack"] is None and monitors:
        inj = [r for r in monitors if r.injection != "no"]
        pick = (inj or monitors)[0]
        monitors.remove(pick)
        note = "" if pick.injection in ("yes", "partial") else \
               " (injection unverified -- confirm deauth works)"
        _take(pick.dev, "attack",
              "second monitor-capable adapter, for injection" + note)

    # leftover monitor adapters and all non-monitor externals become spares,
    # except a non-monitor external can serve as station if none exists yet.
    for r in monitors:
        roles.setdefault(r.dev, "idle")
        reasons.setdefault(r.dev, "spare monitor-capable adapter")
    for r in non_monitor:
        if owners["station"] is None:
            _take(r.dev, "station",
                  "client-only adapter used for connectivity/uplink")
        else:
            roles.setdefault(r.dev, "idle")
            reasons.setdefault(r.dev, "spare (client-only) adapter")

    # 4) single-monitor-adapter reality: let attack borrow the capture radio.
    if owners["attack"] is None and owners["capture"] is not None:
        if allow_shared_attack:
            owners["attack"] = owners["capture"]
            shared["attack"] = owners["capture"]
            notices.append(
                "only one monitor-capable adapter: active deauth will share the "
                "capture radio (%s) and briefly interrupt capture -- add a second "
                "adapter for simultaneous capture + deauth" % owners["capture"])
        else:
            notices.append(
                "active deauth has no radio: only one monitor-capable adapter is "
                "present and sharing is disabled (allow_shared_attack=false)")

    # Wi-Fi coverage notices.
    if owners["capture"] is None:
        if any(r.kind == "wifi" for r in radios):
            notices.append(
                "no monitor-capable Wi-Fi adapter present: capture needs a USB "
                "dongle (the Pi's built-in chip can't monitor)")
        else:
            notices.append("no Wi-Fi radios present")
    if owners["station"] is None and owners["capture"] is not None:
        notices.append(
            "no spare radio for the station role: connecting to a cracked "
            "network would reuse the capture adapter and pause capture")

    # 5) Bluetooth: built-in -> pan, external -> scan, with sharing for one.
    pending_bt: List[Radio] = []
    for r in bt:
        ov = _override_for(r, overrides)
        if ov in BT_ROLES:
            roles[r.dev] = ov
            reasons[r.dev] = "configured by operator"
            if owners.get(ov) is None and ov != "idle":
                owners[ov] = r.dev
        else:
            if ov is not None and ov not in BT_ROLES:
                notices.append("%s: ignoring unknown configured role %r"
                               % (r.dev, ov))
            pending_bt.append(r)
    for r in pending_bt:
        if r.builtin and owners["pan"] is None:
            _take(r.dev, "pan", "built-in Bluetooth, for the phone tether")
        elif owners["scan"] is None:
            _take(r.dev, "scan", "external Bluetooth, for BLE/scan")
        else:
            roles.setdefault(r.dev, "idle")
            reasons.setdefault(r.dev, "spare Bluetooth controller")
    if owners["scan"] is None and owners["pan"] is not None:
        shared["scan"] = owners["pan"]

    return Assignment(roles=roles, owners=owners, reasons=reasons,
                      shared=shared, notices=tuple(notices))


# --- collectors (the only hardware-touching part) ---------------------------
def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _devpath(sys_iface: str) -> str:
    """The stable device path behind a ``/sys/class/net/<dev>`` (or bluetooth)
    entry: the realpath of its ``device`` symlink, trimmed to the sysfs root so it
    is stable across reboots. Empty when there is no backing device."""
    link = os.path.join(sys_iface, "device")
    try:
        real = os.path.realpath(link)
    except OSError:
        return ""
    if not os.path.exists(real):
        return ""
    marker = "/devices/"
    idx = real.find(marker)
    return real[idx:] if idx >= 0 else real


def _bus_of(devpath: str) -> str:
    """Classify the bus from a sysfs device path."""
    if not devpath:
        return ""
    if "/usb" in devpath:
        return "usb"
    if "/mmc" in devpath or "/sdio" in devpath:
        return "sdio"
    if "/pci" in devpath:
        return "pci"
    if "/platform/" in devpath:
        return "platform"
    return ""


def _run(cmd: Sequence[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=10, check=False)
        return out.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def collect_wifi(builtin_driver: str = BUILTIN_WIFI_DRIVER) -> List[Radio]:
    """Inventory the Wi-Fi interfaces from sysfs + ``iw phy info``. Returns
    ``[]`` on a host without them (so it is harmless off a Pi)."""
    out: List[Radio] = []
    net = "/sys/class/net"
    try:
        names = sorted(n for n in os.listdir(net) if n.startswith("wlan"))
    except OSError:
        return out
    for dev in names:
        base = os.path.join(net, dev)
        phy = _read(os.path.join(base, "phy80211", "name"))
        driver = os.path.basename(
            os.path.realpath(os.path.join(base, "device", "driver"))) \
            if os.path.exists(os.path.join(base, "device", "driver")) else ""
        mac = _read(os.path.join(base, "address"))
        devpath = _devpath(base)
        phy_info = _run(["iw", "phy", phy, "info"]) if phy else ""
        out.append(make_wifi_radio(
            dev=dev, driver=driver, phy=phy, mac=mac, bus=_bus_of(devpath),
            path=devpath, phy_info=phy_info, builtin_driver=builtin_driver))
    return out


def collect_bluetooth() -> List[Radio]:
    """Inventory the Bluetooth controllers from sysfs. Returns ``[]`` when none
    (or no bluetooth class) are present."""
    out: List[Radio] = []
    base_dir = "/sys/class/bluetooth"
    try:
        names = sorted(n for n in os.listdir(base_dir) if n.startswith("hci"))
    except OSError:
        return out
    for dev in names:
        base = os.path.join(base_dir, dev)
        mac = _read(os.path.join(base, "address"))
        devpath = _devpath(base)
        bus = _bus_of(devpath) or "uart"
        out.append(make_bt_radio(dev=dev, mac=mac, bus=bus, path=devpath))
    return out


def inventory(wifi: Optional[Sequence[Radio]] = None,
              bluetooth: Optional[Sequence[Radio]] = None,
              builtin_driver: str = BUILTIN_WIFI_DRIVER) -> List[Radio]:
    """All present radios. Pass ``wifi`` / ``bluetooth`` to bypass the collectors
    (tests); otherwise they are gathered from the host."""
    w = list(wifi) if wifi is not None else collect_wifi(builtin_driver)
    b = list(bluetooth) if bluetooth is not None else collect_bluetooth()
    return w + b


# --- config overrides -------------------------------------------------------
def load_overrides(radios_conf: Optional[dict]) -> Dict[str, str]:
    """Parse the ``[radios] assign`` table into ``{key: role}``. The config form
    is a list of ``"<key>=<role>"`` strings (e.g. ``["wlan1=attack",
    "rtl8812au=capture"]``) so a colon-bearing MAC or sysfs path needs no TOML key
    quoting. Malformed entries are skipped."""
    out: Dict[str, str] = {}
    for item in (radios_conf or {}).get("assign") or []:
        s = str(item)
        if "=" not in s:
            continue
        key, role = s.split("=", 1)
        key, role = key.strip(), role.strip()
        if key:
            out[key] = role
    return out


def allow_shared_attack(radios_conf: Optional[dict]) -> bool:
    """Whether active deauth may share the capture radio when only one monitor
    adapter is present (``[radios] allow_shared_attack``, default on)."""
    return bool((radios_conf or {}).get("allow_shared_attack", True))


# --- readout (dashboard card + CLI + status payload) ------------------------
# The widget-group key is also the card's display title (like the agent's
# "Learning agent" and quick-crack's "Quick-crack"). Unlike those two, this card
# is meant to stay ON the dashboard, so it is not in web.py's dashboard-exclusion
# set -- the operator sees their adapters and role assignment on the main screen.
CARD_NAME = "Radios"

_ROLE_LABEL = {
    "capture": "Capture",
    "attack": "Deauth",
    "station": "Station / uplink",
    "pan": "BT tether",
    "scan": "BT scan",
}


def widget_elements(radios_list: Sequence[Radio],
                    assignment: Assignment) -> List[dict]:
    """The grouped ``{name,label,value,kind}`` elements for the dashboard
    "Radios" card: one row per owned role, a detected count, and the first
    glass-box notice (so "plug in a dongle" shows on the screen, not just logs)."""
    by_dev = {r.dev: r for r in radios_list}
    out: List[dict] = []
    for role in ("capture", "attack", "station", "pan", "scan"):
        dev = assignment.owner(role)
        if not dev:
            continue
        r = by_dev.get(dev)
        chip = (r.chipset or r.driver) if r else ""
        value = dev + (" · " + chip if chip else "")
        if assignment.is_shared(role):
            value += " (shared)"
        out.append({"name": role, "label": _ROLE_LABEL.get(role, role),
                    "value": value, "kind": "text"})
    if radios_list:
        out.append({"name": "detected", "label": "Radios detected",
                    "value": str(len(radios_list)), "kind": "number"})
    if assignment.notices:
        out.append({"name": "notice", "label": "Note",
                    "value": assignment.notices[0], "kind": "text"})
    return out


def summary(radios_list: Sequence[Radio], assignment: Assignment) -> dict:
    """A JSON-friendly snapshot for the status payload and the CLI."""
    return {
        "radios": [{
            "dev": r.dev, "kind": r.kind,
            "role": assignment.roles.get(r.dev, "idle"),
            "chipset": r.chipset, "driver": r.driver, "bus": r.bus,
            "monitor": r.monitor, "builtin": r.builtin,
            "bands": list(r.bands), "injection": r.injection,
            "reason": assignment.reasons.get(r.dev, ""),
        } for r in radios_list],
        "owners": dict(assignment.owners),
        "shared": dict(assignment.shared),
        "notices": list(assignment.notices),
    }


def render_text(radios_list: Sequence[Radio],
                assignment: Assignment) -> str:
    """A plain-text inventory + role table for ``kestrel radios`` (glass-box, no
    keyboard needed to read it over SSH or on the console)."""
    if not radios_list:
        return "No radios detected."
    lines = ["Radios (%d):" % len(radios_list)]
    for r in radios_list:
        role = assignment.roles.get(r.dev, "idle")
        facts = []
        if r.kind == "wifi":
            facts.append("monitor" if r.monitor else "no-monitor")
            if r.bands:
                facts.append("/".join(r.bands) + "GHz")
            if r.injection != "unknown":
                facts.append("inj:" + r.injection)
        shared = " (shared)" if (assignment.is_shared(role)
                                 and assignment.owner(role) == r.dev) else ""
        detail = r.label()
        if facts:
            detail += " [" + ", ".join(facts) + "]"
        lines.append("  %-6s %-16s %s%s" % (r.dev, role.upper(), detail, shared))
        why = assignment.reasons.get(r.dev)
        if why:
            lines.append("           - %s" % why)
    if assignment.notices:
        lines.append("")
        lines.append("Notes:")
        for n in assignment.notices:
            lines.append("  * %s" % n)
    return "\n".join(lines)
