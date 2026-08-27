#!/usr/bin/env python3
"""
tray_app.py
===========
The main Vault Guardian system-tray application. It wires together:

  * usb_monitor   - detects the registered USB key add/remove
  * vault_manager - unmount of the user-visible FUSE mount
  * no_sudo_fuse_guard - private mount ns + gocryptfs + per-app allowlist
  * apparmor_manager - optional kernel hardening
  * setup_wizard  - config load/save

State machine
-------------
  LOCKED  --(key inserted / manual mount)-->  OPEN
  OPEN    --(key removed / Lock Now / suspend)--> LOCKED

When OPEN the guard subprocess:
  1. unshares a user+mount namespace
  2. mounts gocryptfs onto a private tmpfs (invisible to other same-uid tasks)
  3. FUSE-exports that onto mount_point (visible on the host to allowed apps)
Only the calling executable is allow-listed (no parent-walk). Everything else
gets EACCES. Auto-unlock blobs are ignored: a same-user agent can read them.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import List, Optional

import setup_wizard as cfgmod
import usb_monitor
import vault_manager

APP_DIR = os.path.dirname(os.path.realpath(__file__))
GUARD_SCRIPT = os.path.join(APP_DIR, "no_sudo_fuse_guard.py")


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
        # No GTK - fall back to console (systemd may not have a tty though).
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


def edit_allowed_apps(current: List[str]) -> Optional[List[str]]:
    """GTK dialog to add/remove allowed apps. Returns new list or None."""
    try:
        Gtk, _ = _gtk()
    except Exception:
        return None

    dialog = Gtk.Dialog(title="Vault Guardian - Allowed Apps")
    dialog.set_default_size(360, 320)
    dialog.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                       Gtk.STOCK_SAVE, Gtk.ResponseType.OK)
    box = dialog.get_content_area()
    box.set_border_width(12)
    box.set_spacing(6)
    box.add(Gtk.Label(label="Only these apps may read the open vault:"))

    store = Gtk.ListStore(str)
    for a in current:
        store.append([a])
    tree = Gtk.TreeView(model=store)
    renderer = Gtk.CellRendererText()
    col = Gtk.TreeViewColumn("Application", renderer, text=0)
    tree.append_column(col)
    scroll = Gtk.ScrolledWindow()
    scroll.set_vexpand(True)
    scroll.add(tree)
    box.add(scroll)

    entry = Gtk.Entry()
    entry.set_placeholder_text("app name or /path/to/binary")
    box.add(entry)

    btnbox = Gtk.Box(spacing=6)
    add_btn = Gtk.Button(label="Add")
    rm_btn = Gtk.Button(label="Remove selected")
    btnbox.add(add_btn)
    btnbox.add(rm_btn)
    box.add(btnbox)

    def on_add(_):
        name = entry.get_text().strip()
        if name:
            store.append([name])
            entry.set_text("")

    def on_remove(_):
        model, it = tree.get_selection().get_selected()
        if it is not None:
            model.remove(it)

    add_btn.connect("clicked", on_add)
    rm_btn.connect("clicked", on_remove)

    dialog.show_all()
    resp = dialog.run()
    result = None
    if resp == Gtk.ResponseType.OK:
        result = [row[0] for row in store]
    dialog.destroy()
    return result


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
    # Shackle
    if locked:
        d.arc([18, 8, 46, 40], start=180, end=360, fill=body, width=6)
    else:
        # open shackle - rotated a bit
        d.arc([12, 8, 40, 40], start=180, end=350, fill=body, width=6)
    # Lock body
    d.rounded_rectangle([16, 26, 48, 54], radius=5, fill=body)
    # Keyhole
    d.ellipse([29, 34, 35, 40], fill=(255, 255, 255, 255))
    d.rectangle([31, 38, 33, 48], fill=(255, 255, 255, 255))
    return img


# ---------------------------------------------------------------------------
# Core controller
# ---------------------------------------------------------------------------
class VaultGuardian:
    def __init__(self) -> None:
        self.cfg = cfgmod.load_config()
        self.state_lock = threading.Lock()
        self.guard_proc: Optional[subprocess.Popen] = None
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

            # Guard enters a private mount ns, mounts gocryptfs there, then
            # FUSE-exports mount_point. Password goes on stdin, never argv.
            ok = self._start_guard(enc, mount, password)
            password = "\x00" * len(password)
            del password
            if not ok:
                log_event("ERROR", "FUSE guard failed to start; vault stays locked")
                show_message(
                    "Unlock failed",
                    "Could not start the vault guard. If this machine disables "
                    "unprivileged user namespaces, unlock cannot hide the "
                    "plaintext from other same-user processes, so it refuses "
                    "rather than mounting in the clear. See the log.")
                return False

            # 3) optional AppArmor hardening.
            if self.cfg.get("use_apparmor"):
                try:
                    import apparmor_manager
                    if apparmor_manager.write_profile(
                            mount, self.cfg["allowed_apps"]):
                        apparmor_manager.apply_profile()
                        log_event("APPARMOR", "profile applied")
                except Exception as e:
                    log_event("WARN", f"apparmor apply skipped: {e}")

            log_event("OPEN", f"vault open at {mount}")
            self._refresh_icon()
            return True

    def _start_guard(self, cipherdir: str, mount: str, password: str) -> bool:
        # Ensure any stale guard mount is cleared first.
        if vault_manager.is_mounted(mount):
            vault_manager.unmount_vault(mount)

        os.makedirs(mount, exist_ok=True)
        os.makedirs(cfgmod.DATA_DIR, exist_ok=True)
        logf = open(cfgmod.LOG_PATH, "a", encoding="utf-8")
        cmd = [sys.executable, "-u", GUARD_SCRIPT, cipherdir, mount, "--apps"] \
            + list(self.cfg["allowed_apps"])
        try:
            self.guard_proc = subprocess.Popen(
                cmd, stdin=subprocess.PIPE, stdout=logf, stderr=logf,
                start_new_session=True)
            try:
                self.guard_proc.stdin.write((password + "\n").encode("utf-8"))
                self.guard_proc.stdin.close()
            except BrokenPipeError:
                log_event("ERROR", "guard closed stdin before receiving password")
                return False
        except Exception as e:
            log_event("ERROR", f"could not launch guard: {e}")
            return False

        # Wait for the guard mount to appear.
        for _ in range(150):
            if vault_manager.is_mounted(mount):
                return True
            if self.guard_proc.poll() is not None:
                log_event("ERROR", "guard process exited early")
                return False
            time.sleep(0.1)
        return vault_manager.is_mounted(mount)

    def lock_vault(self, reason: str = "manual") -> None:
        with self.state_lock:
            mount = self.cfg["mount_point"]
            plain = self.cfg.get("plain_dir")
            log_event("LOCK", f"lock requested ({reason})")

            # 1) unmount the user-visible FUSE export FIRST.
            try:
                vault_manager.unmount_vault(mount)
            except vault_manager.VaultError as e:
                log_event("WARN", f"guard unmount: {e}")

            # 2) kill the guard process group (gocryptfs is a child).
            if self.guard_proc and self.guard_proc.poll() is None:
                try:
                    os.killpg(self.guard_proc.pid, signal.SIGTERM)
                    self.guard_proc.wait(timeout=3)
                except Exception:
                    try:
                        os.killpg(self.guard_proc.pid, signal.SIGKILL)
                    except Exception:
                        try:
                            self.guard_proc.kill()
                        except Exception:
                            pass
            self.guard_proc = None

            # 3) leftover host plaintext mount from older versions.
            if plain:
                try:
                    vault_manager.unmount_vault(plain)
                except vault_manager.VaultError as e:
                    log_event("WARN", f"legacy plaintext unmount: {e}")

            # 4) remove AppArmor profile.
            if self.cfg.get("use_apparmor"):
                try:
                    import apparmor_manager
                    apparmor_manager.remove_profile()
                except Exception:
                    pass

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
                    # PrepareForSleep(True) => about to suspend.
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
        import pystray
        from pystray import MenuItem as Item, Menu

        def status_text(_):
            return "🔓 Vault Open" if self.is_open else "🔒 Vault Locked"

        def do_lock(icon, item):
            self.lock_vault(reason="tray")

        def do_open(icon, item):
            self.open_vault(reason="tray")

        def do_apps(icon, item):
            new = edit_allowed_apps(list(self.cfg["allowed_apps"]))
            if new is not None:
                self.cfg["allowed_apps"] = new
                cfgmod.save_config(self.cfg)
                log_event("CONFIG", f"allowed apps updated: {new}")
                if self.is_open:
                    show_message("Vault Guardian",
                                 "Allowed apps saved. Re-lock and unlock (or "
                                 "re-plug the key) for changes to take effect.")

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
            Item("Allowed Apps...", do_apps),
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
        # Pick via a simple GTK chooser.
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
            # Restart monitor with new hash.
            if self.monitor:
                self.monitor.stop()
            self._start_monitor()

    def _open_log(self) -> None:
        os.makedirs(cfgmod.DATA_DIR, exist_ok=True)
        if not os.path.isfile(cfgmod.LOG_PATH):
            open(cfgmod.LOG_PATH, "a").close()
        for opener in ("xdg-open", "gedit", "kate", "gnome-text-editor"):
            import shutil
            if shutil.which(opener):
                try:
                    subprocess.Popen([opener, cfgmod.LOG_PATH],
                                     start_new_session=True)
                    return
                except Exception:
                    continue
        show_message("Access Log", f"Log file: {cfgmod.LOG_PATH}")

    # -- lifecycle ---------------------------------------------------------
    def run(self) -> None:
        import pystray
        log_event("INFO", "Vault Guardian starting")

        # Safety: ensure we start LOCKED (clear any stale mounts).
        try:
            self.lock_vault(reason="startup-clean")
        except Exception:
            pass

        self._start_monitor()
        self._start_suspend_watch()

        self.icon = pystray.Icon(
            "vault-guardian",
            icon=_make_icon(locked=not self.is_open),
            title="Vault Guardian",
            menu=self._build_menu(),
        )
        # Handle termination signals to lock before exit.
        signal.signal(signal.SIGTERM, lambda *a: self.shutdown())
        signal.signal(signal.SIGINT, lambda *a: self.shutdown())

        self.icon.run()

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
    # Refuse to run as root - this tool is designed for the unprivileged user.
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
