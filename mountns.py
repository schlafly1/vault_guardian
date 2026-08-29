#!/usr/bin/env python3
"""Unprivileged mount-namespace helpers for Vault Guardian.

The plaintext gocryptfs mount must not be visible to other processes of the
same user. We enter a user+mount namespace, park that mount on a private
tmpfs, and let the ~/Vault FUSE mount propagate back to the host because it
sits on the still-shared /home tree.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from pathlib import Path
from typing import Optional

CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
MS_BIND = 0x1000
MS_NOSUID = 0x2
MS_NODEV = 0x4
MS_PRIVATE = 0x40000
MS_SLAVE = 0x80000
MS_REC = 0x4000
MS_SHARED = 0x100000

_libc = None


def _lib():
    global _libc
    if _libc is None:
        lib = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        lib.unshare.argtypes = [ctypes.c_int]
        lib.unshare.restype = ctypes.c_int
        lib.mount.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_ulong, ctypes.c_void_p,
        ]
        lib.mount.restype = ctypes.c_int
        _libc = lib
    return _libc


def _err(op: str) -> OSError:
    e = ctypes.get_errno()
    return OSError(e, f"{op}: {os.strerror(e)}")


def unshare(flags: int) -> None:
    if _lib().unshare(flags) != 0:
        raise _err("unshare")


def mount(source: Optional[str], target: str, fstype: Optional[str],
          flags: int, data: Optional[str] = None) -> None:
    src = source.encode() if source else None
    fs = fstype.encode() if fstype else None
    dt = data.encode() if data else None
    if _lib().mount(src, target.encode(), fs, flags, dt) != 0:
        raise _err(f"mount {target}")


def _write_proc(path: str, data: str) -> None:
    """Write a procfs control file. Must not use O_CREAT (EACCES on L4T)."""
    fd = os.open(path, os.O_WRONLY)
    try:
        os.write(fd, data.encode("ascii"))
    finally:
        os.close(fd)


def write_userns_maps(uid: int, gid: int) -> None:
    """Map root-in-namespace to the real uid/gid so mount(2) works."""
    # setgroups MUST be deny'd before gid_map, and uid_map last-or-first
    # is fine as long as setgroups precedes gid_map.
    _write_proc("/proc/self/setgroups", "deny\n")
    _write_proc("/proc/self/uid_map", f"0 {uid} 1\n")
    _write_proc("/proc/self/gid_map", f"0 {gid} 1\n")


def in_private_userns() -> bool:
    """True if this process is already uid 0 in a mapped user namespace."""
    if os.geteuid() != 0:
        return False
    try:
        parts = Path("/proc/self/uid_map").read_text().split()
        return len(parts) >= 3 and int(parts[0]) == 0 and int(parts[2]) >= 1
    except (OSError, ValueError):
        return False


def enter_user_mount_ns() -> None:
    """Become uid 0 in a new user+mount namespace (still the same user on disk).

    User ns first, then maps, then mount ns: after mapping to root we have
    CAP_SYS_ADMIN in the ns so unshare(NEWNS) is allowed.
    """
    uid, gid = os.getuid(), os.getgid()
    unshare(CLONE_NEWUSER)
    write_userns_maps(uid, gid)
    unshare(CLONE_NEWNS)


def reexec_via_unshare() -> None:
    """Re-exec this process under util-linux `unshare` (does not return).

    Ubuntu 24.04 / some L4T kernels let the unshare binary create a userns
    when a raw unshare(2)+/proc write from Python is denied.
    stdin/stdout/stderr (including the vault password pipe) are preserved.
    """
    import shutil
    unshare_bin = shutil.which("unshare")
    if not unshare_bin:
        raise OSError("unshare binary not found on PATH")
    script = os.path.realpath(sys.argv[0])
    os.execv(unshare_bin, [
        "unshare",
        "--user", "--map-root-user", "--mount",
        "--setgroups=deny",
        "--",
        sys.executable, script, *sys.argv[1:],
    ])


def private_tmpfs(path: str) -> None:
    """Mount a private tmpfs on *path* that does not propagate to the host."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    # Bind + make-private first so the tmpfs does not leak onto the shared /
    mount(path, path, None, MS_BIND)
    mount(None, path, None, MS_PRIVATE)
    mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV, "mode=0700,size=512M")


def isolate_for_guard(plain_dir: str) -> None:
    """Enter a private ns and hide *plain_dir* from every other process.

    ~/Vault is left on the shared host tree so the FUSE mount we create
    afterwards is visible to allowed apps. *plain_dir* becomes a private
    tmpfs that only this process (and its children) can see.
    """
    if not in_private_userns():
        enter_user_mount_ns()
    private_tmpfs(plain_dir)
