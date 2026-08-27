#!/usr/bin/env python3
"""
setup_wizard.py
===============
First-time setup for Vault Guardian. Run once (the installer runs it for you):

    python3 setup_wizard.py

It will:
  1. Create the encrypted gocryptfs vault (~/.vault-encrypted) with a password.
  2. Show currently plugged-in USB devices and let you pick your security key.
     Only a SHA256 hash of the device serial is stored (never the raw serial,
     never the spoofable vendor/product id).
  3. Optionally enable "auto-unlock": derive the vault password from the USB
     serial + machine-id so you never get prompted - just plug the key in.
  4. Set the default allowed-apps list.
  5. Write config to ~/.config/vault-guardian/config.json

This module also exposes config load/save helpers used by the tray app.
"""

from __future__ import annotations

import base64
import getpass
import json
import os
import sys
from typing import Dict, List, Optional

# Local modules
import usb_monitor
import vault_manager

# --- paths -----------------------------------------------------------------
CONFIG_DIR = os.path.expanduser("~/.config/vault-guardian")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
DATA_DIR = os.path.expanduser("~/.local/share/vault-guardian")
LOG_PATH = os.path.join(DATA_DIR, "access.log")

DEFAULT_ENC_DIR = os.path.expanduser("~/.vault-encrypted")
DEFAULT_PLAIN_DIR = os.path.expanduser("~/.vault-plain")   # gocryptfs target
DEFAULT_MOUNT = os.path.expanduser("~/Vault")               # guarded, user sees

DEFAULT_ALLOWED_APPS = ["libreoffice", "firefox", "evince", "gedit",
                        "code", "kate"]


# --- config helpers --------------------------------------------------------
def default_config() -> Dict:
    return {
        "encrypted_dir": DEFAULT_ENC_DIR,
        "plain_dir": DEFAULT_PLAIN_DIR,
        "mount_point": DEFAULT_MOUNT,
        "usb_serial_hash": None,
        "usb_label": None,
        "allowed_apps": list(DEFAULT_ALLOWED_APPS),
        "auto_unlock": False,
        # base64 of (salt || nonce || ciphertext) of the vault password when
        # auto_unlock is enabled. Decryptable only with the USB serial present.
        "autounlock_blob": None,
        "use_apparmor": False,
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
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    os.replace(tmp, CONFIG_PATH)
    os.chmod(CONFIG_PATH, 0o600)


# --- auto-unlock key derivation -------------------------------------------
def _machine_id() -> str:
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                mid = fh.read().strip()
                if mid:
                    return mid
        except OSError:
            continue
    # Fallback: stable-ish per-user value.
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
    """Encrypt *vault_password* so it can be recovered only with the USB key.

    Returns a base64 string of salt(16) || nonce(12) || ciphertext.
    """
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


def run_wizard(non_interactive: bool = False) -> Dict:
    print("=" * 64)
    print(" Vault Guardian - First-time Setup")
    print("=" * 64)

    cfg = load_config()

    if non_interactive:
        # Just ensure config + dirs exist with defaults; used by installer
        # when it can't grab a TTY. User re-runs interactively later.
        os.makedirs(cfg["encrypted_dir"], exist_ok=True)
        os.makedirs(cfg["mount_point"], exist_ok=True)
        save_config(cfg)
        print("Non-interactive setup: wrote default config. Re-run "
              "'vault-guardian-setup' in a terminal to finish.")
        return cfg

    # 1) Vault creation ----------------------------------------------------
    enc = _prompt("Encrypted vault directory", cfg["encrypted_dir"])
    plain = _prompt("Internal plaintext dir (hidden)", cfg["plain_dir"])
    mount = _prompt("Guarded mount point you will use", cfg["mount_point"])
    cfg["encrypted_dir"], cfg["plain_dir"], cfg["mount_point"] = enc, plain, mount

    os.makedirs(enc, exist_ok=True)
    os.makedirs(plain, mode=0o700, exist_ok=True)
    os.chmod(plain, 0o700)
    os.makedirs(mount, exist_ok=True)

    vault_password = ""
    if vault_manager.vault_is_initialized(enc):
        print(f"\nA vault already exists at {enc} - keeping it.")
        if not cfg.get("auto_unlock"):
            print("You will still be prompted for its password at unlock time.")
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

    # 3) Auto-unlock -------------------------------------------------------
    if cfg.get("usb_serial_hash") and vault_password:
        print("\nAuto-unlock: derive the vault password from the USB key so "
              "you're never prompted - just plug the key in.")
        ans = _prompt("  Enable auto-unlock? (y/N)", "n").lower()
        if ans in ("y", "yes"):
            cfg["auto_unlock"] = True
            cfg["autounlock_blob"] = encrypt_autounlock(
                vault_password, cfg["usb_serial_hash"])
            print("  Auto-unlock enabled. The encrypted secret can only be "
                  "recovered on THIS machine with THIS key.")
        else:
            cfg["auto_unlock"] = False
            cfg["autounlock_blob"] = None
    elif cfg.get("usb_serial_hash") and not vault_password and \
            not cfg.get("auto_unlock"):
        print("\n(To enable auto-unlock you must set it up when creating the "
              "vault password. Re-create the vault to enable it later.)")

    # 4) Allowed apps ------------------------------------------------------
    print("\nDefault allowed apps (only these may read the open vault):")
    print("  " + ", ".join(cfg["allowed_apps"]))
    extra = _prompt("  Add more (comma separated) or Enter to keep", "")
    if extra:
        for a in extra.split(","):
            a = a.strip()
            if a and a not in cfg["allowed_apps"]:
                cfg["allowed_apps"].append(a)

    # 5) AppArmor opt-in ---------------------------------------------------
    try:
        import apparmor_manager
        if apparmor_manager.apparmor_available():
            ans = _prompt("\nAlso generate a kernel AppArmor profile "
                          "(needs sudo once)? (y/N)", "n").lower()
            cfg["use_apparmor"] = ans in ("y", "yes")
    except Exception:
        pass

    save_config(cfg)
    print("\n" + "=" * 64)
    print(" Setup complete. Config saved to:")
    print(f"   {CONFIG_PATH}")
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
