#!/usr/bin/env python3
"""
vault_manager.py
================
Handles mounting and unmounting of the gocryptfs encrypted vault.

Design notes
------------
* All subprocess calls use argument lists (NEVER shell=True) so vault
  paths / passwords can't be interpreted by a shell.
* gocryptfs reads the password from stdin (``-extpass`` is avoided so the
  password never appears in the process list / argv).
* ``mount_vault`` is idempotent: if the mount point is already a live
  gocryptfs mount it returns True without doing anything.
"""

from __future__ import annotations

import os
import subprocess
import shutil
import time
from typing import Optional


class VaultError(Exception):
    """Raised when a mount / unmount operation fails."""


def _which(binary: str) -> str:
    path = shutil.which(binary)
    if not path:
        raise VaultError(
            f"Required binary '{binary}' not found on PATH. "
            f"Install it (e.g. 'sudo apt install {binary}')."
        )
    return path


def is_mounted(mount_point: str) -> bool:
    """Return True if *mount_point* is currently a mounted filesystem.

    We consult /proc/mounts directly rather than shelling out to
    ``mountpoint`` so this is fast and dependency-free.
    """
    mount_point = os.path.realpath(mount_point)
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2:
                    # /proc/mounts escapes spaces as \040 - unescape target
                    target = parts[1].replace("\\040", " ")
                    if os.path.realpath(target) == mount_point:
                        return True
    except FileNotFoundError:
        pass
    return False


def vault_is_initialized(vault_path: str) -> bool:
    """Return True if *vault_path* already contains a gocryptfs vault."""
    return os.path.isfile(os.path.join(vault_path, "gocryptfs.conf"))


def init_vault(vault_path: str, password: str) -> None:
    """Initialise a brand new gocryptfs vault at *vault_path*.

    Raises VaultError on failure. No-op if the vault already exists.
    """
    gocryptfs = _which("gocryptfs")
    os.makedirs(vault_path, exist_ok=True)

    if vault_is_initialized(vault_path):
        return

    # gocryptfs -init reads password twice (confirm) from stdin.
    proc = subprocess.run(
        [gocryptfs, "-init", "-q", vault_path],
        input=f"{password}\n{password}\n".encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise VaultError(
            "Failed to initialise vault: "
            + proc.stderr.decode("utf-8", "replace").strip()
        )


def mount_vault(
    vault_path: str,
    mount_point: str,
    password: str,
    allow_other: bool = False,
) -> bool:
    """Mount the gocryptfs vault at *vault_path* onto *mount_point*.

    Parameters
    ----------
    allow_other:
        When True the mount is created with ``-allow_other`` so a separate
        FUSE guard process (or root-owned services) can read the plaintext.
        The FUSE guard needs this to passthrough.

    Returns True on success. Raises VaultError on failure.
    """
    gocryptfs = _which("gocryptfs")

    if not vault_is_initialized(vault_path):
        raise VaultError(
            f"No gocryptfs vault found at {vault_path}. Run the setup wizard first."
        )

    os.makedirs(mount_point, exist_ok=True)

    if is_mounted(mount_point):
        return True

    args = [gocryptfs, "-q"]
    if allow_other:
        args.append("-allow_other")
    args += [vault_path, mount_point]

    proc = subprocess.run(
        args,
        input=f"{password}\n".encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise VaultError(
            "Failed to mount vault: "
            + proc.stderr.decode("utf-8", "replace").strip()
        )

    # Give the kernel a moment to register the mount.
    for _ in range(20):
        if is_mounted(mount_point):
            return True
        time.sleep(0.05)
    return is_mounted(mount_point)


def unmount_vault(mount_point: str, force: bool = True) -> bool:
    """Unmount *mount_point* using fusermount.

    Returns True if the mount point ends up unmounted (including the case
    where it was already unmounted). ``force`` adds lazy unmount fallback so
    a busy handle can't keep the vault decrypted.
    """
    if not is_mounted(mount_point):
        return True

    fusermount = shutil.which("fusermount") or shutil.which("fusermount3")
    if not fusermount:
        raise VaultError("fusermount not found - cannot unmount vault.")

    # Try a clean unmount first.
    proc = subprocess.run(
        [fusermount, "-u", mount_point],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode == 0 and not is_mounted(mount_point):
        return True

    if force:
        # Lazy unmount detaches the filesystem immediately even if busy so
        # the plaintext view disappears the instant the USB key is pulled.
        proc = subprocess.run(
            [fusermount, "-u", "-z", mount_point],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(20):
            if not is_mounted(mount_point):
                return True
            time.sleep(0.05)

    if is_mounted(mount_point):
        raise VaultError(
            "Failed to unmount vault: "
            + proc.stderr.decode("utf-8", "replace").strip()
        )
    return True


if __name__ == "__main__":
    # Tiny manual smoke test / CLI helper.
    import argparse

    ap = argparse.ArgumentParser(description="Vault Guardian mount helper")
    ap.add_argument("action", choices=["status", "unmount"])
    ap.add_argument("mount_point")
    ns = ap.parse_args()

    if ns.action == "status":
        print("mounted" if is_mounted(ns.mount_point) else "unmounted")
    elif ns.action == "unmount":
        unmount_vault(ns.mount_point)
        print("unmounted")
