"""usb-dump - copy the loot + capture store to a labelled USB stick on insertion.

Insert a stick whose filesystem label matches (``KESTREL`` by default) and this
copies the recovered keys and the capture store onto it automatically -- a quick
field grab with no keyboard. It fires once per insertion (a rising edge), so a
stick left plugged in is not re-copied every cycle. The copy itself (mount +
write + unmount) is the root ``usb-dump`` apply helper; this plugin only watches
for the stick and triggers it. Local, physical operator action -- nothing leaves
over a network -- so no authorized-use acknowledgment. Opt-in, ships disabled.

Target Python 3.11.
"""

from __future__ import annotations

import threading

from kestrel_pi import Plugin
from kestrel_pi import usbdump


class UsbDump(Plugin):
    __author__ = "kestrel"
    __version__ = "0.1.0"
    __license__ = "GPL3"
    __description__ = ("Copy the loot and capture store to a labelled USB stick "
                       "when it is inserted.")

    __target_api__ = 2
    __capabilities__ = ("ui",)
    __options__ = {
        # The filesystem label a stick must have to be dumped to.
        "label": {"type": "str", "default": "KESTREL"},
    }

    def on_loaded(self):
        self.log = self.context.logger
        self._lock = threading.Lock()
        self._present = False      # was a matching stick present last check
        self._last = "no dump yet"
        self.log.info("usb-dump loaded (label=%s)",
                      self.options.get("label", "KESTREL"))

    def on_epoch(self, epoch, info):
        label = str(self.options.get("label") or "KESTREL")
        present = usbdump.device_for(label) is not None
        if present and not self._present:
            self._dump(label)      # rising edge: a stick was just inserted
        self._present = present

    def _dump(self, label):
        reply = self.context.apply({"target": "usb-dump", "label": label})
        if reply.get("ok"):
            msg = "copied to %s" % reply.get("usb_dump")
            self.log.info("usb-dump: %s on the %r stick", msg, label)
        else:
            msg = "failed: %s" % (reply.get("error") or "unknown error")
            self.log.warning("usb-dump: %s", msg)
        with self._lock:
            self._last = msg

    # -- dashboard readout ----------------------------------------------
    def on_ui_setup(self, ui):
        ui.add_element("stick", "none", label="USB stick")
        ui.add_element("last", "no dump yet", label="Last dump")

    def on_ui_update(self, ui, state):
        with self._lock:
            last = self._last
        ui.set("stick", "present" if self._present else "none")
        ui.set("last", last)
