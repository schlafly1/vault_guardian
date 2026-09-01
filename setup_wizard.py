#!/usr/bin/env python3
"""
setup_wizard.py
===============
First-time setup for Vault Guardian. Run once (the installer runs it for you):

    python3 setup_wizard.py

It will:
  1. Create the encrypted gocryptfs vault (~/.vault-encrypted) with a password.
     Existing ciphertext is kept; this never wipes it.
  2. Show currently plugged-in USB devices and let you pick your security key.
     Only a SHA256 hash of the device serial is stored (never the raw serial,
     never the spoofable vendor/product id).
  3. Write config to ~/.config/vault-guardian/config.json

Password is asked at every unlock. Auto-unlock is not offered: a blob in
your config is readable by any same-user process (including an AI agent).
Leftover blobs from older installs are wiped.

This module also exposes config load/save helpers used by the tray app.
"""

from __future__ import annotations

import base64
import getpass
import json
import os
import sys
from typing import Dict, Optional

# Local modules
import usb_monitor
import vault_manager

# --- paths -----------------------------------------------------------------
CONFIG_DIR = os.path.expanduser("~/.config/vault-guardian")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
DATA_DIR = os.path.expanduser("~/.local/share/vault-guardian")
LOG_PATH = os.path.join(DATA_DIR, "access.log")

DEFAULT_ENC_DIR = os.path.expanduser("~/.vault-encrypted")
DEFAULT_MOUNT = os.path.expanduser("~/Vault")


# --- config helpers --------------------------------------------------------
def default_config() -> Dict:
    return {
        "encrypted_dir": DEFAULT_ENC_DIR,
        "mount_point": DEFAULT_MOUNT,
        "usb_serial_hash": None,
        "usb_label": None,
        # Unused leftover (older builds used this as a security feature).
        "allowed_apps": [],
        "auto_unlock": False,
        # leftover field; always wiped. A same-user agent can read this file.
        "autounlock_blob": None,
    }


def load_config() -> Dict:
    if os.path.isfile(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        merged = default_config()
        merged.update(cfg)
        return merged
    return default_config()


def save_config(cfg: Dict) -> None:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    # Always refuse to persist an auto-unlock blob.
    cfg["auto_unlock"] = False
    cfg["autounlock_blob"] = None
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    os.replace(tmp, CONFIG_PATH)
    os.chmod(CONFIG_PATH, 0o600)


# --- auto-unlock key derivation (kept so leftover blobs can be ignored) ----
def _machine_id() -> str:
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                mid = fh.read().strip()
                if mid:
                    return mid
        except OSError:
            continue
    return f"nomid-{os.getuid()}"


def _derive_key(serial_hash: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256(serial_hash + machine_id, salt, 100000)."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    material = (serial_hash + ":" + _machine_id()).encode("utf-8")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=100000)
    return kdf.derive(material)


def encrypt_autounlock(vault_password: str, serial_hash: str) -> str:
    """Encrypt *vault_password*. Unused at runtime (auto-unlock is disabled)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(serial_hash, salt)
    ct = AESGCM(key).encrypt(nonce, vault_password.encode("utf-8"), None)
    return base64.b64encode(salt + nonce + ct).decode("ascii")


def decrypt_autounlock(blob_b64: str, serial_hash: str) -> Optional[str]:
    """Recover the vault password from an auto-unlock blob. None on failure."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        raw = base64.b64decode(blob_b64)
        salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
        key = _derive_key(serial_hash, salt)
        pw = AESGCM(key).decrypt(nonce, ct, None)
        return pw.decode("utf-8")
    except Exception:
        return None


# --- interactive wizard ----------------------------------------------------
def _prompt(msg: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"{msg}{suffix}: ").strip()
    except EOFError:
        val = ""
    return val or default


def _pick_usb_device() -> Optional[Dict[str, str]]:
    devices = usb_monitor.list_usb_devices()
    if not devices:
        print("\n  No USB devices with a readable serial are currently "
              "plugged in.")
        print("  Plug in the USB stick / security key you want to use, then "
              "press Enter to rescan (or type 's' to skip).")
        choice = _prompt("  Action", "rescan")
        if choice.lower() in ("s", "skip"):
            return None
        devices = usb_monitor.list_usb_devices()
        if not devices:
            print("  Still nothing detected - skipping USB registration.")
            return None

    print("\n  Detected USB devices:")
    for i, d in enumerate(devices, 1):
        print(f"    {i}) {d['name']}  (serial hash {d['serial_hash'][:12]}...)")
    sel = _prompt("  Pick the number of your security key", "1")
    try:
        idx = int(sel) - 1
        if 0 <= idx < len(devices):
            return devices[idx]
    except ValueError:
        pass
    print("  Invalid selection - skipping USB registration.")
    return None


def _makedirs_ok(path: str, mode: int = 0o700) -> None:
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def run_wizard(non_interactive: bool = False) -> Dict:
    print("=" * 64)
    print(" Vault Guardian - First-time Setup")
    print("=" * 64)

    cfg = load_config()

    if non_interactive:
        _makedirs_ok(cfg["encrypted_dir"])
        _makedirs_ok(cfg["mount_point"])
        cfg["auto_unlock"] = False
        cfg["autounlock_blob"] = None
        save_config(cfg)
        print("Non-interactive setup: wrote default config. Re-run "
              "'vault-guardian-setup' in a terminal to finish.")
        return cfg

    # 1) Vault creation ----------------------------------------------------
    enc = _prompt("Encrypted vault directory", cfg["encrypted_dir"])
    mount = _prompt("Mount point (normal folder while unlocked)", cfg["mount_point"])
    cfg["encrypted_dir"] = enc
    cfg["mount_point"] = mount

    _makedirs_ok(enc)
    _makedirs_ok(mount)

    if vault_manager.vault_is_initialized(enc):
        print(f"\nA vault already exists at {enc} - keeping it.")
        print("You will be prompted for its password at unlock time.")
    else:
        print("\nCreate a strong password for your encrypted vault.")
        while True:
            pw1 = getpass.getpass("  Vault password: ")
            pw2 = getpass.getpass("  Confirm password: ")
            if pw1 != pw2:
                print("  Passwords do not match, try again.")
                continue
            if len(pw1) < 6:
                print("  Please use at least 6 characters.")
                continue
            vault_password = pw1
            break
        print("  Initialising encrypted vault (AES-256-GCM)...")
        vault_manager.init_vault(enc, vault_password)
        print("  Vault created.")

    # 2) USB key registration ---------------------------------------------
    print("\nRegister the USB device that will unlock the vault.")
    dev = _pick_usb_device()
    if dev:
        cfg["usb_serial_hash"] = dev["serial_hash"]
        cfg["usb_label"] = dev["name"]
        print(f"  Registered '{dev['name']}' (only its serial hash is stored).")
    else:
        print("  No USB key registered - you can add one later from the tray "
              "menu ('Change USB Key...').")

    # 3) Auto-unlock is not offered.
    cfg["auto_unlock"] = False
    cfg["autounlock_blob"] = None
    print("\nAuto-unlock is disabled: storing a decryptable password blob "
          "in your home directory would let any same-user process "
          "(including an AI agent) unlock the vault. You will type the "
          "password every time.")

    save_config(cfg)

    print("\n" + "=" * 64)
    print(" Setup complete. Config saved to:")
    print(f"   {CONFIG_PATH}")
    print()
    print(" Day to day:")
    print("   Plug the USB key in, type the password, use ~/Vault as a")
    print("   normal folder (ls, firefox, editor). Unplug to lock.")
    print()
    print(" Honest limit: while unlocked, any process running as you can")
    print(" read ~/Vault. USB + password is the gate.")
    print()
    print(" Start the tray app with:  vault-guardian   (or via systemd)")
    print("=" * 64)
    return cfg


if __name__ == "__main__":
    ni = "--non-interactive" in sys.argv
    try:
        run_wizard(non_interactive=ni)
    except KeyboardInterrupt:
        print("\nSetup cancelled.")
        sys.exit(1)
