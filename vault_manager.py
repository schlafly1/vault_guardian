#!/usr/bin/env python3
"""
vault_manager.py
================
Mount / unmount the gocryptfs vault as the *login user*.

Design notes
------------
* All subprocess calls use argument lists (NEVER shell=True) so vault
  paths / passwords can't be interpreted by a shell.
* gocryptfs reads the password from stdin (never argv, never ``-extpass``).
* Only ``-q`` (and optional ``-nonempty``) are passed. No ``-allow_other``.
* The plaintext mount is a normal folder owned by the login user
  (mode 0700). Any same-UID process can read it while it is unlocked.
* ``mount_vault`` is idempotent: if the mount point is already a live
  gocryptfs mount it returns True without doing anything.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import List

# gocryptfs registers as fuse.gocryptfs (fuse3) or gocryptfs in /proc/mounts.
_GOCRYPTFS_TYPES = frozenset({"fuse.gocryptfs", "gocryptfs", "fuse"})


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


def _gocryptfs_path() -> str:
    for p in ("/usr/bin/gocryptfs", "/usr/local/bin/gocryptfs"):
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return _which("gocryptfs")


def _fusermount_paths() -> List[str]:
    """Prefer fusermount3, then fusermount. Absolute paths first."""
    found: List[str] = []
    for p in ("/usr/bin/fusermount3", "/usr/bin/fusermount"):
        if os.path.isfile(p) and os.access(p, os.X_OK) and p not in found:
            found.append(p)
    for name in ("fusermount3", "fusermount"):
        w = shutil.which(name)
        if w and w not in found:
            found.append(w)
    return found


def is_mounted(mount_point: str) -> bool:
    """Return True if *mount_point* is currently a mounted filesystem.

    Consults /proc/mounts. Recognises both ``fuse.gocryptfs`` and
    ``gocryptfs`` (and a generic ``fuse`` fstype at that path).
    """
    try:
        mount_point = os.path.realpath(mount_point)
    except OSError:
        pass
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                target = parts[1].replace("\\040", " ")
                fstype = parts[2]
                try:
                    same = os.path.realpath(target) == mount_point
                except OSError:
                    same = target == mount_point
                if not same:
                    continue
                if fstype in _GOCRYPTFS_TYPES or "gocryptfs" in fstype:
                    return True
                # Something else is mounted here (stale FUSE, etc.).
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
    Does not wipe an existing ~/.vault-encrypted.
    """
    gocryptfs = _gocryptfs_path()
    os.makedirs(vault_path, exist_ok=True)

    if vault_is_initialized(vault_path):
        return

    # gocryptfs -init reads password twice (confirm) from stdin. Never argv.
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


def _ensure_mount_point(mount_point: str) -> None:
    """Create *mount_point* if missing. Mode 0700, owned by the login user."""
    os.makedirs(mount_point, exist_ok=True)
    try:
        os.chmod(mount_point, 0o700)
    except OSError:
        pass


def mount_vault(
    vault_path: str,
    mount_point: str,
    password: str,
    nonempty: bool = True,
) -> bool:
    """Mount the gocryptfs vault as the current user onto *mount_point*.

    Password is sent on stdin, never argv. Only ``-q`` is always passed.
    ``-nonempty`` is on by default so leftover files in ~/Vault do not
    block the mount (empty the directory yourself if you prefer).

    Returns True on success. Raises VaultError on failure.
    """
    gocryptfs = _gocryptfs_path()

    if not vault_is_initialized(vault_path):
        raise VaultError(
            f"No gocryptfs vault found at {vault_path}. Run the setup wizard first."
        )

    _ensure_mount_point(mount_point)

    if is_mounted(mount_point):
        return True

    args = [gocryptfs, "-q"]
    if nonempty:
        args.append("-nonempty")
    args += [vault_path, mount_point]

    proc = subprocess.run(
        args,
        input=f"{password}\n".encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        low = err.lower()
        if "password incorrect" in low or "password" in low:
            raise VaultError("Failed to mount vault: bad password.")
        raise VaultError("Failed to mount vault: " + (err or "gocryptfs failed"))

    for _ in range(20):
        if is_mounted(mount_point):
            return True
        time.sleep(0.05)
    return is_mounted(mount_point)


def unmount_vault(mount_point: str, force: bool = True) -> bool:
    """Unmount *mount_point* using fusermount3, then fusermount.

    Order: each binary with ``-u``, then (if *force*) each binary with
    ``-u -z`` (lazy) so a busy handle cannot keep the vault decrypted.

    Returns True if the mount point ends up unmounted (including the case
    where it was already unmounted).
    """
    if not is_mounted(mount_point):
        return True

    bins = _fusermount_paths()
    if not bins:
        raise VaultError("fusermount3/fusermount not found - cannot unmount vault.")

    proc = None
    for fm in bins:
        proc = subprocess.run(
            [fm, "-u", mount_point],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if not is_mounted(mount_point):
            return True

    if force:
        for fm in bins:
            proc = subprocess.run(
                [fm, "-u", "-z", mount_point],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for _ in range(20):
                if not is_mounted(mount_point):
                    return True
                time.sleep(0.05)

    if is_mounted(mount_point):
        err = ""
        if proc is not None:
            err = proc.stderr.decode("utf-8", "replace").strip()
        raise VaultError("Failed to unmount vault: " + (err or "mount still busy"))
    return True


if __name__ == "__main__":
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
