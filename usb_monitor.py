#!/usr/bin/env python3
"""
usb_monitor.py
==============
Watches udev for USB device add/remove events and fires callbacks when the
*registered* security key (identified by a SHA256 hash of its serial number)
is inserted or removed.

Why serial and not vendor/product id?
--------------------------------------
Vendor / product IDs identify a *model* of device and are trivially spoofed:
any USB stick of the same model would unlock your vault. The per-device serial
number (``ID_SERIAL_SHORT`` / ``ID_SERIAL``) is unique to the physical device,
so we key off a hash of that instead.

We store only a SHA256 hash of the serial in the config so the raw serial is
never written to disk.
"""

from __future__ import annotations

import hashlib
import threading
from typing import Callable, Dict, List, Optional

try:
    import pyudev
except ImportError:  # pragma: no cover - import guard for clearer errors
    pyudev = None


def hash_serial(serial: str) -> str:
    """Return the SHA256 hex digest of a device serial string."""
    return hashlib.sha256(serial.strip().encode("utf-8")).hexdigest()


def _device_serial(device) -> Optional[str]:
    """Best-effort extraction of a stable per-device serial from a udev device."""
    for key in ("ID_SERIAL_SHORT", "ID_SERIAL", "ID_USB_SERIAL_SHORT",
                "ID_USB_SERIAL"):
        val = device.get(key)
        if val:
            return val
    return None


def list_usb_devices() -> List[Dict[str, str]]:
    """Return a list of currently plugged-in USB storage devices.

    Each entry: {"serial": raw_serial, "serial_hash": sha256,
                 "name": human label, "devnode": /dev/... }
    Only devices exposing a serial are returned (a key without a serial
    can't be uniquely identified and is therefore unusable as a token).
    """
    if pyudev is None:
        raise RuntimeError("pyudev is not installed. pip install pyudev")

    ctx = pyudev.Context()
    seen: Dict[str, Dict[str, str]] = {}

    # Enumerate USB block devices (thumb drives) and raw USB devices.
    for device in ctx.list_devices(subsystem="block"):
        if device.get("ID_BUS") != "usb":
            continue
        # Only whole disks, not partitions, to avoid duplicates.
        if device.get("DEVTYPE") != "disk":
            continue
        serial = _device_serial(device)
        if not serial:
            continue
        vendor = device.get("ID_VENDOR", "") or device.get("ID_VENDOR_ENC", "")
        model = device.get("ID_MODEL", "") or device.get("ID_MODEL_ENC", "")
        name = f"{vendor} {model}".strip() or device.get("DEVNAME", "USB device")
        h = hash_serial(serial)
        seen[h] = {
            "serial": serial,
            "serial_hash": h,
            "name": name,
            "devnode": device.get("DEVNAME", ""),
        }

    # Also enumerate pure-HID security keys (YubiKey etc.) via usb subsystem.
    for device in ctx.list_devices(subsystem="usb", DEVTYPE="usb_device"):
        serial = _device_serial(device)
        if not serial:
            continue
        vendor = device.get("ID_VENDOR", "") or device.get("ID_VENDOR_ENC", "")
        model = device.get("ID_MODEL", "") or device.get("ID_MODEL_ENC", "")
        name = f"{vendor} {model}".strip() or "USB security key"
        h = hash_serial(serial)
        if h not in seen:
            seen[h] = {
                "serial": serial,
                "serial_hash": h,
                "name": name,
                "devnode": device.get("DEVNAME", ""),
            }

    return list(seen.values())


class USBMonitor:
    """Background udev monitor that fires callbacks for the registered key.

    Parameters
    ----------
    registered_hash:
        SHA256 hash of the serial of the key that should unlock the vault.
    on_key_insert / on_key_remove:
        Callables invoked (from the monitor thread) when the registered key
        appears / disappears. Keep these fast or dispatch to your own queue.
    """

    def __init__(
        self,
        registered_hash: str,
        on_key_insert: Callable[[], None],
        on_key_remove: Callable[[], None],
    ) -> None:
        if pyudev is None:
            raise RuntimeError("pyudev is not installed. pip install pyudev")
        self.registered_hash = registered_hash
        self.on_key_insert = on_key_insert
        self.on_key_remove = on_key_remove

        self._ctx = pyudev.Context()
        self._monitor = pyudev.Monitor.from_netlink(self._ctx)
        # Watch both block devices (thumb drives) and usb devices (keys).
        self._monitor.filter_by(subsystem="block")
        self._monitor.filter_by(subsystem="usb")
        self._observer: Optional[pyudev.MonitorObserver] = None
        self._lock = threading.Lock()
        # Track hashes we currently consider "present" to debounce
        # partition-level duplicate events.
        self._present = False

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        """Begin monitoring in a background thread."""
        # Reconcile initial state: the key may already be plugged in.
        if self.is_key_present():
            self._present = True
            self._safe(self.on_key_insert)

        self._observer = pyudev.MonitorObserver(
            self._monitor, callback=self._handle_event, name="vg-usb-monitor"
        )
        self._observer.daemon = True
        self._observer.start()

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer = None

    # -- helpers -----------------------------------------------------------
    def is_key_present(self) -> bool:
        """True if the registered key is currently plugged in."""
        try:
            for dev in list_usb_devices():
                if dev["serial_hash"] == self.registered_hash:
                    return True
        except Exception:
            pass
        return False

    def _safe(self, fn: Callable[[], None]) -> None:
        try:
            fn()
        except Exception as exc:  # never let a callback kill the thread
            import sys
            print(f"[usb_monitor] callback error: {exc}", file=sys.stderr)

    def _handle_event(self, device) -> None:
        action = device.action
        serial = _device_serial(device)

        # For remove events udev often no longer carries all properties, so
        # we fall back to re-scanning present devices to decide state.
        with self._lock:
            if action == "add":
                if serial and hash_serial(serial) == self.registered_hash:
                    if not self._present:
                        self._present = True
                        self._safe(self.on_key_insert)
            elif action == "remove":
                # Re-check: is the registered key still present anywhere?
                still = self.is_key_present()
                if self._present and not still:
                    self._present = False
                    self._safe(self.on_key_remove)


if __name__ == "__main__":
    # CLI: list currently attached USB devices with their serial hashes.
    print("Currently attached USB devices with serials:\n")
    for d in list_usb_devices():
        print(f"  {d['name']}")
        print(f"    serial      : {d['serial']}")
        print(f"    serial_hash : {d['serial_hash']}")
        print(f"    devnode     : {d['devnode']}\n")
