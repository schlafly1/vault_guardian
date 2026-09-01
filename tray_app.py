#!/usr/bin/env python3
"""
tray_app.py
===========
The main Vault Guardian system-tray application. It wires together:

  * usb_monitor   - detects the registered USB key add/remove
  * vault_manager - gocryptfs mount/unmount as the login user
  * setup_wizard  - config load/save

State machine
-------------
  LOCKED  --(key inserted / manual unlock)-->  OPEN
  OPEN    --(key removed / Lock Now / suspend / quit)--> LOCKED

When OPEN, gocryptfs mounts ~/.vault-encrypted onto ~/Vault as the login
user. ~/Vault is a normal folder: ls, firefox, and your editor all work.
While unlocked, any same-UID process can read it. USB + password is the gate.

Headless: if DISPLAY/WAYLAND_DISPLAY is missing the tray is skipped, but
the USB monitor still runs so unplug-to-lock works. Do not crash.

Auto-unlock blobs are ignored and wiped: a same-user agent can read them.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Optional

import setup_wizard as cfgmod
import usb_monitor
import vault_manager

APP_DIR = os.path.dirname(os.path.realpath(__file__))


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def log_event(kind: str, message: str) -> None:
    os.makedirs(cfgmod.DATA_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} [{kind}] {message}\n"
    try:
        with open(cfgmod.LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass
    print(line, end="", file=sys.stderr)


# ---------------------------------------------------------------------------
# GTK helpers (dialogs). Imported lazily so headless testing still imports.
# ---------------------------------------------------------------------------
def _gtk():
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk, GLib
    return Gtk, GLib


def ask_password(prompt: str = "Enter vault password") -> Optional[str]:
    """Modal password dialog. Returns the password or None if cancelled."""
    try:
        Gtk, _ = _gtk()
    except Exception:
        try:
            import getpass
            return getpass.getpass(prompt + ": ")
        except Exception:
            return None

    dialog = Gtk.Dialog(title="Vault Guardian")
    dialog.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                       Gtk.STOCK_OK, Gtk.ResponseType.OK)
    dialog.set_default_response(Gtk.ResponseType.OK)
    box = dialog.get_content_area()
    box.set_spacing(8)
    box.set_border_width(12)
    box.add(Gtk.Label(label=prompt))
    entry = Gtk.Entry()
    entry.set_visibility(False)
    entry.set_activates_default(True)
    box.add(entry)
    dialog.show_all()
    resp = dialog.run()
    pw = entry.get_text() if resp == Gtk.ResponseType.OK else None
    dialog.destroy()
    return pw


def show_message(title: str, text: str) -> None:
    try:
        Gtk, _ = _gtk()
    except Exception:
        print(f"{title}: {text}", file=sys.stderr)
        return
    md = Gtk.MessageDialog(text=title, secondary_text=text,
                           buttons=Gtk.ButtonsType.OK)
    md.run()
    md.destroy()


# ---------------------------------------------------------------------------
# Tray icons (Pillow generated)
# ---------------------------------------------------------------------------
def _make_icon(locked: bool):
    from PIL import Image, ImageDraw
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    body = (200, 40, 40, 255) if locked else (40, 170, 70, 255)  # red / green
    if locked:
        d.arc([18, 8, 46, 40], start=180, end=360, fill=body, width=6)
    else:
        d.arc([12, 8, 40, 40], start=180, end=350, fill=body, width=6)
    d.rounded_rectangle([16, 26, 48, 54], radius=5, fill=body)
    d.ellipse([29, 34, 35, 40], fill=(255, 255, 255, 255))
    d.rectangle([31, 38, 33, 48], fill=(255, 255, 255, 255))
    return img


def _purge_pystray() -> None:
    for name in list(sys.modules):
        if name == "pystray" or name.startswith("pystray."):
            del sys.modules[name]


def _ensure_display_env() -> None:
    """systemd --user often starts with DISPLAY unset. Infer a session."""
    if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        return
    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    for w in ("wayland-0", "wayland-1", "wayland-2"):
        if os.path.exists(os.path.join(runtime, w)):
            os.environ["WAYLAND_DISPLAY"] = w
            break
    for sock, display in (("/tmp/.X11-unix/X0", ":0"),
                          ("/tmp/.X11-unix/X1", ":1")):
        if os.path.exists(sock):
            os.environ.setdefault("DISPLAY", display)
            break


# ---------------------------------------------------------------------------
# Core controller
# ---------------------------------------------------------------------------
class VaultGuardian:
    def __init__(self) -> None:
        self.cfg = cfgmod.load_config()
        self.state_lock = threading.Lock()
        self.monitor: Optional[usb_monitor.USBMonitor] = None
        self.icon = None
        self._suspend_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # -- state -------------------------------------------------------------
    @property
    def is_open(self) -> bool:
        return vault_manager.is_mounted(self.cfg["mount_point"])

    # -- unlock / lock -----------------------------------------------------
    def _get_password(self) -> Optional[str]:
        # Auto-unlock stores a decryptable blob in the user's config. Any
        # same-uid agent can read it, so it is incompatible with the threat
        # model. Wipe a leftover blob if we find one, then always prompt.
        if self.cfg.get("auto_unlock") or self.cfg.get("autounlock_blob"):
            self.cfg["auto_unlock"] = False
            self.cfg["autounlock_blob"] = None
            try:
                cfgmod.save_config(self.cfg)
            except OSError:
                pass
            log_event("CONFIG",
                      "disabled auto-unlock (same-user agent can recover the blob)")
        return ask_password("Enter vault password to unlock")

    def open_vault(self, reason: str = "manual") -> bool:
        with self.state_lock:
            if self.is_open:
                return True
            log_event("OPEN", f"unlock requested ({reason})")
            password = self._get_password()
            if not password:
                log_event("OPEN", "aborted - no password provided")
                return False

            enc = self.cfg["encrypted_dir"]
            mount = self.cfg["mount_point"]

            try:
                ok = vault_manager.mount_vault(enc, mount, password)
            except vault_manager.VaultError as e:
                password = "\x00" * len(password)
                del password
                log_event("ERROR", str(e))
                show_message("Unlock failed", str(e))
                return False
            password = "\x00" * len(password)
            del password
            if not ok:
                log_event("ERROR", "mount did not appear; vault stays locked")
                show_message(
                    "Unlock failed",
                    "gocryptfs did not mount. Check the password. If leftover "
                    "files in ~/Vault blocked the mount, empty that folder "
                    "(or keep -nonempty, which is the default).")
                return False

            log_event("OPEN", f"vault open at {mount}")
            self._refresh_icon()
            return True

    def lock_vault(self, reason: str = "manual") -> None:
        with self.state_lock:
            mount = self.cfg["mount_point"]
            log_event("LOCK", f"lock requested ({reason})")
            try:
                vault_manager.unmount_vault(mount)
            except vault_manager.VaultError as e:
                log_event("WARN", f"unmount: {e}")

            log_event("LOCK", "vault locked")
            self._refresh_icon()

    # -- USB callbacks -----------------------------------------------------
    def _on_key_insert(self) -> None:
        log_event("USB", f"registered key inserted ({self.cfg.get('usb_label')})")
        self.open_vault(reason="usb-insert")

    def _on_key_remove(self) -> None:
        log_event("USB", "registered key removed")
        self.lock_vault(reason="usb-remove")

    def _start_monitor(self) -> None:
        h = self.cfg.get("usb_serial_hash")
        if not h:
            log_event("WARN", "no USB key registered; USB monitoring disabled")
            return
        try:
            self.monitor = usb_monitor.USBMonitor(
                h, self._on_key_insert, self._on_key_remove)
            self.monitor.start()
            log_event("INFO", "USB monitor started")
        except Exception as e:
            log_event("ERROR", f"USB monitor failed: {e}")

    # -- suspend/sleep hook ------------------------------------------------
    def _start_suspend_watch(self) -> None:
        """Lock the vault when the system is about to sleep (logind signal)."""
        def worker():
            try:
                import gi
                gi.require_version("Gio", "2.0")
                from gi.repository import Gio, GLib
            except Exception as e:
                log_event("INFO", f"suspend watch unavailable: {e}")
                return
            try:
                bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

                def on_signal(conn, sender, path, iface, sig, params):
                    try:
                        going = params.get_child_value(0).get_boolean()
                    except Exception:
                        going = True
                    if going and self.is_open:
                        log_event("SUSPEND", "system suspending - locking vault")
                        self.lock_vault(reason="suspend")

                bus.signal_subscribe(
                    "org.freedesktop.login1",
                    "org.freedesktop.login1.Manager",
                    "PrepareForSleep",
                    "/org/freedesktop/login1",
                    None, Gio.DBusSignalFlags.NONE, on_signal)
                loop = GLib.MainLoop()
                self._sleep_loop = loop
                while not self._stop.is_set():
                    ctx = loop.get_context()
                    ctx.iteration(False)
                    time.sleep(0.2)
            except Exception as e:
                log_event("INFO", f"suspend watch error: {e}")

        self._suspend_thread = threading.Thread(target=worker, daemon=True,
                                                 name="vg-suspend")
        self._suspend_thread.start()

    # -- tray icon ---------------------------------------------------------
    def _refresh_icon(self) -> None:
        if self.icon is None:
            return
        try:
            self.icon.icon = _make_icon(locked=not self.is_open)
            self.icon.title = ("Vault Guardian - Open" if self.is_open
                               else "Vault Guardian - Locked")
            self.icon.update_menu()
        except Exception:
            pass

    def _build_menu(self):
        from pystray import MenuItem as Item, Menu

        def status_text(_):
            return "🔓 Vault Open" if self.is_open else "🔒 Vault Locked"

        def do_lock(icon, item):
            self.lock_vault(reason="tray")

        def do_open(icon, item):
            self.open_vault(reason="tray")

        def do_usb(icon, item):
            self._reregister_usb()

        def do_log(icon, item):
            self._open_log()

        def do_quit(icon, item):
            self.shutdown()

        return Menu(
            Item(status_text, None, enabled=False),
            Menu.SEPARATOR,
            Item("Unlock Now",
                 do_open,
                 enabled=lambda i: (not self.is_open)
                 and bool(cfgmod.load_config())),
            Item("Lock Now", do_lock, enabled=lambda i: self.is_open),
            Menu.SEPARATOR,
            Item("Change USB Key...", do_usb),
            Item("View Access Log", do_log),
            Menu.SEPARATOR,
            Item("Quit", do_quit),
        )

    def _reregister_usb(self) -> None:
        try:
            devices = usb_monitor.list_usb_devices()
        except Exception as e:
            show_message("Vault Guardian", f"USB scan failed: {e}")
            return
        if not devices:
            show_message("Vault Guardian",
                         "No USB devices with a serial detected. Plug the key "
                         "in and try again.")
            return
        try:
            Gtk, _ = _gtk()
        except Exception:
            return
        dialog = Gtk.Dialog(title="Vault Guardian - Select USB Key")
        dialog.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                           Gtk.STOCK_OK, Gtk.ResponseType.OK)
        box = dialog.get_content_area()
        box.set_border_width(12)
        box.add(Gtk.Label(label="Choose the device to use as your key:"))
        combo = Gtk.ComboBoxText()
        for d in devices:
            combo.append_text(f"{d['name']}  ({d['serial_hash'][:10]}...)")
        combo.set_active(0)
        box.add(combo)
        dialog.show_all()
        resp = dialog.run()
        idx = combo.get_active()
        dialog.destroy()
        if resp == Gtk.ResponseType.OK and 0 <= idx < len(devices):
            d = devices[idx]
            self.cfg["usb_serial_hash"] = d["serial_hash"]
            self.cfg["usb_label"] = d["name"]
            self.cfg["auto_unlock"] = False
            self.cfg["autounlock_blob"] = None
            cfgmod.save_config(self.cfg)
            log_event("CONFIG", f"USB key changed to {d['name']}")
            if self.monitor:
                self.monitor.stop()
            self._start_monitor()

    def _open_log(self) -> None:
        os.makedirs(cfgmod.DATA_DIR, exist_ok=True)
        if not os.path.isfile(cfgmod.LOG_PATH):
            open(cfgmod.LOG_PATH, "a").close()
        for opener in ("xdg-open", "gedit", "kate", "gnome-text-editor"):
            path = shutil.which(opener)
            if not path:
                continue
            try:
                subprocess.Popen([path, cfgmod.LOG_PATH],
                                 start_new_session=True)
                return
            except Exception:
                continue
        show_message("Access Log", f"Log file: {cfgmod.LOG_PATH}")

    # -- lifecycle ---------------------------------------------------------
    def _run_tray(self) -> bool:
        """Blocking tray loop. Returns False if no backend could start."""
        _ensure_display_env()
        for backend in ("appindicator", "gtk", "xorg"):
            os.environ["PYSTRAY_BACKEND"] = backend
            _purge_pystray()
            try:
                import pystray
                self.icon = pystray.Icon(
                    "vault-guardian",
                    icon=_make_icon(locked=not self.is_open),
                    title="Vault Guardian",
                    menu=self._build_menu(),
                )
                log_event("INFO", f"tray icon started (backend={backend})")
                self.icon.run()
                return True
            except Exception as e:
                log_event("WARN", f"tray backend {backend} failed: {e}")
                self.icon = None
        return False

    def run(self) -> None:
        log_event("INFO", "Vault Guardian starting")

        try:
            self.lock_vault(reason="startup-clean")
        except Exception:
            pass

        # USB monitor MUST start even if the tray cannot. Unplug-to-lock is
        # the whole point; a missing DISPLAY must not take it down.
        self._start_monitor()
        self._start_suspend_watch()

        signal.signal(signal.SIGTERM, lambda *a: self.shutdown())
        signal.signal(signal.SIGINT, lambda *a: self.shutdown())

        _ensure_display_env()
        if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
            if self._run_tray():
                return
            log_event("WARN", "no tray icon available; USB lock is still active")
        else:
            log_event("INFO", "no display; running headless (USB lock still active)")

        while not self._stop.is_set():
            self._stop.wait(timeout=1.0)

    def shutdown(self, *_a) -> None:
        log_event("INFO", "Vault Guardian shutting down - locking vault")
        self._stop.set()
        try:
            self.lock_vault(reason="shutdown")
        except Exception:
            pass
        if self.monitor:
            try:
                self.monitor.stop()
            except Exception:
                pass
        if self.icon:
            try:
                self.icon.stop()
            except Exception:
                pass


def main() -> None:
    if os.geteuid() == 0:
        print("Do NOT run Vault Guardian as root. Run it as your normal user.",
              file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(cfgmod.CONFIG_PATH):
        print("No config found. Running first-time setup...", file=sys.stderr)
        try:
            cfgmod.run_wizard()
        except Exception as e:
            print(f"Setup failed: {e}", file=sys.stderr)
            sys.exit(1)

    VaultGuardian().run()


if __name__ == "__main__":
    main()
