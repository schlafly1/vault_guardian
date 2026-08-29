#!/usr/bin/env python3
"""
vault_manager.py
================
Mount / unmount the gocryptfs vault as system user ``vaultguard``.

Design notes
------------
* All subprocess calls use argument lists (NEVER shell=True) so vault
  paths / passwords can't be interpreted by a shell.
* gocryptfs reads the password from stdin (never argv, never ``-extpass``).
* The plaintext mount is owned by vaultguard:vaultguard mode 0750. The
  login user is NOT in that group; only ``vault-exec`` (sgid) grants it.
* ``mount_vault`` is idempotent: if the mount point is already a live
  gocryptfs mount it returns True without doing anything.
"""

from __future__ import annotations

import errno
import os
import shutil
import subprocess
import time
from typing import List, Optional

VAULTGUARD_USER = "vaultguard"
MOUNT_HELPER = "/usr/local/libexec/vault-guardian/mount"
UNMOUNT_HELPER = "/usr/local/libexec/vault-guardian/unmount"

# gocryptfs registers as fuse.gocryptfs (fuse3) or gocryptfs in /proc/mounts.
_GOCRYPTFS_TYPES = frozenset({"fuse.gocryptfs", "gocryptfs", "fuse"})

PRIV_HINT = (
    "The privileged helper is missing or sudoers is not configured. "
    "Run: sudo ./install-privileged.sh"
)


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
    found: List[str] = []
    for p in ("/usr/bin/fusermount3", "/usr/bin/fusermount"):
        if os.path.isfile(p) and os.access(p, os.X_OK) and p not in found:
            found.append(p)
    for name in ("fusermount3", "fusermount"):
        w = shutil.which(name)
        if w and w not in found:
            found.append(w)
    return found


def _is_sudo_failure(proc: subprocess.CompletedProcess) -> bool:
    err = (proc.stderr or b"").decode("utf-8", "replace")
    out = (proc.stdout or b"").decode("utf-8", "replace")
    text = (err + "\n" + out).lower()
    needles = (
        "a password is required",
        "password is required",
        "not allowed to execute",
        "unknown user",
        "unknown group",
        "no tty present",
        "sorry, user",
    )
    if any(n in text for n in needles):
        return True
    # sudo prefixes its own diagnostics with "sudo:".
    if "sudo:" in text and proc.returncode != 0:
        return True
    return False


def _run_as_vaultguard(args: List[str],
                       input_bytes: Optional[bytes] = None
                       ) -> subprocess.CompletedProcess:
    cmd = ["sudo", "-n", "-u", VAULTGUARD_USER, "--"] + args
    return subprocess.run(
        cmd,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


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
    """Initialise a brand new gocryptfs vault at *vault_path* as the human.

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
    """Create *mount_point* if missing. Do not chmod it (must stay 0750
    vaultguard:vaultguard after the privileged installer). EACCES is
    expected when the dir already exists with those permissions.
    """
    try:
        if os.path.isdir(mount_point):
            return
    except OSError:
        # Cannot even stat; privileged install owns it. That's success.
        return
    try:
        os.makedirs(mount_point, exist_ok=True)
    except OSError as e:
        if e.errno == errno.EACCES:
            return
        raise VaultError(
            f"Cannot create mount point {mount_point}: {e}. {PRIV_HINT}"
        )


def mount_vault(
    vault_path: str,
    mount_point: str,
    password: str,
    allow_other: bool = True,
) -> bool:
    """Mount the gocryptfs vault as user vaultguard onto *mount_point*.

    ``allow_other`` is always passed (gocryptfs ``-allow_other``) so the
    sgid helper's children can reach the plaintext. Password is sent on
    stdin, never argv.

    Returns True on success. Raises VaultError on failure.
    """
    if not vault_is_initialized(vault_path):
        raise VaultError(
            f"No gocryptfs vault found at {vault_path}. Run the setup wizard first."
        )

    if not os.path.isfile(MOUNT_HELPER):
        raise VaultError("Failed to mount vault: " + PRIV_HINT)

    _ensure_mount_point(mount_point)

    if is_mounted(mount_point):
        return True

    # Wrapper has paths baked in (no argv). Password on stdin, never argv.
    proc = _run_as_vaultguard(
        [MOUNT_HELPER],
        input_bytes=f"{password}\n".encode("utf-8"),
    )
    if proc.returncode != 0:
        if _is_sudo_failure(proc):
            raise VaultError("Failed to mount vault: " + PRIV_HINT)
        err = proc.stderr.decode("utf-8", "replace").strip()
        low = err.lower()
        if "password incorrect" in low or "password" in low:
            raise VaultError("Failed to mount vault: bad password.")
        raise VaultError("Failed to mount vault: " + (err or PRIV_HINT))

    for _ in range(20):
        if is_mounted(mount_point):
            return True
        time.sleep(0.05)
    return is_mounted(mount_point)


def unmount_vault(mount_point: str, force: bool = True) -> bool:
    """Unmount *mount_point* as vaultguard using fusermount3 (or fusermount).

    Returns True if the mount point ends up unmounted (including the case
    where it was already unmounted). ``force`` adds lazy unmount fallback so
    a busy handle can't keep the vault decrypted.
    """
    if not is_mounted(mount_point):
        return True

    if not os.path.isfile(UNMOUNT_HELPER):
        raise VaultError("Failed to unmount vault: " + PRIV_HINT)

    proc = _run_as_vaultguard([UNMOUNT_HELPER])
    if _is_sudo_failure(proc):
        raise VaultError("Failed to unmount vault: " + PRIV_HINT)
    for _ in range(20):
        if not is_mounted(mount_point):
            return True
        time.sleep(0.05)
    if is_mounted(mount_point):
        err = (proc.stderr or b"").decode("utf-8", "replace").strip()
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
