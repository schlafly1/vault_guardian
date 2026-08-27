#!/usr/bin/env python3
"""
no_sudo_fuse_guard.py
=====================
The PRIMARY per-app enforcement layer. Works entirely in userspace as the
current user - no root, no AppArmor required.

How it fits together
---------------------
    ~/.vault-encrypted/      <- gocryptfs ciphertext (on disk)
            |  gocryptfs mount (allow_other)
            v
    ~/.vault-plain/          <- decrypted plaintext, restrictive perms,
            |                    only THIS guard process reads it
            |  FUSE passthrough with per-caller allowlist check
            v
    ~/Vault/                 <- what the user & apps actually see

Every VFS operation that arrives at ~/Vault/ carries the PID of the calling
process (via fuse_get_context()). We resolve /proc/<pid>/exe to the real
executable path and compare it (and its parent chain) against the allowlist.
Anything not on the list gets EACCES - including an AI agent driving the
machine through python/bash/xdotool, because *its* executable is
python3/bash, not libreoffice.

Why check the parent chain too?
-------------------------------
Some allowed apps spawn helper processes (e.g. LibreOffice's soffice.bin).
We walk up a few parents so a legitimately-allowed app's own children are
also permitted, while still blocking unrelated processes.

Security caveats (documented honestly)
--------------------------------------
* An attacker running as the same user who can *rename/replace* an allowed
  binary, or ptrace an allowed process, could bypass this. That requires more
  than a naive file read, and combined with the USB-gated mount it raises the
  bar substantially.
* This guard's plaintext backing dir (~/.vault-plain) is chmod 700 and is
  only meant to be reached *through* the guard. We also refuse to serve it to
  callers whose exe we cannot resolve.
"""

from __future__ import annotations

import errno
import os
import sys
import threading
from typing import List, Optional, Set

try:
    # NOTE: fusepy raises OSError (not ImportError) at import time when the
    # libfuse shared library is missing, so catch broadly - the pure-Python
    # policy logic below must remain importable even without libfuse present.
    from fuse import FUSE, FuseOSError, Operations, fuse_get_context
except Exception:  # pragma: no cover
    FUSE = None
    Operations = object

    def fuse_get_context():  # type: ignore
        return (0, 0, 0)

    class FuseOSError(OSError):  # type: ignore
        # Mirror fusepy's behaviour: FuseOSError(errno) sets .errno so callers
        # (and tests) can inspect it even when libfuse is absent.
        def __init__(self, err_code):
            super().__init__(err_code, os.strerror(err_code))


# Executable basenames that are ALWAYS allowed to traverse (never leak data
# themselves) so the desktop can stat the mount. 'ls'/'stat' from a shell are
# deliberately NOT here - listing is treated as access.
_INFRA_ALWAYS: Set[str] = set()


def _read_exe(pid: int) -> Optional[str]:
    """Return the real executable path for *pid*, or None if unavailable."""
    try:
        return os.path.realpath(f"/proc/{pid}/exe")
    except OSError:
        return None


def _read_ppid(pid: int) -> Optional[int]:
    """Return the parent PID of *pid* from /proc/<pid>/stat."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read()
        # Format: pid (comm) state ppid ...  - comm may contain spaces/parens
        rparen = data.rfind(b")")
        rest = data[rparen + 2:].split()
        # rest[0] = state, rest[1] = ppid
        return int(rest[1])
    except (OSError, IndexError, ValueError):
        return None


class AllowlistPolicy:
    """Decides whether a calling PID may access the vault."""

    def __init__(self, allowed_apps: List[str], self_pid: int,
                 max_parent_depth: int = 4) -> None:
        # Store both basenames and resolved absolute paths of allowed apps.
        self.allowed_names: Set[str] = set()
        self.allowed_paths: Set[str] = set()
        self.self_pid = self_pid
        self.max_parent_depth = max_parent_depth
        self.update(allowed_apps)

    def update(self, allowed_apps: List[str]) -> None:
        import shutil
        names: Set[str] = set()
        paths: Set[str] = set()
        for app in allowed_apps:
            app = app.strip()
            if not app:
                continue
            if os.path.isabs(app):
                paths.add(os.path.realpath(app))
                names.add(os.path.basename(app))
            else:
                names.add(app)
                resolved = shutil.which(app)
                if resolved:
                    paths.add(os.path.realpath(resolved))
                # LibreOffice launches soffice.bin - allow that helper too.
                if app in ("libreoffice", "soffice"):
                    names.update({"soffice", "soffice.bin", "oosplash"})
        self.allowed_names = names
        self.allowed_paths = paths

    def _exe_allowed(self, exe: Optional[str]) -> bool:
        if not exe:
            return False
        if exe in self.allowed_paths:
            return True
        base = os.path.basename(exe)
        if base in self.allowed_names:
            return True
        # Allow "app" to match "app-bin"/"app.bin" style helpers.
        for name in self.allowed_names:
            if base == name or base.startswith(name + ".") or \
               base.startswith(name + "-"):
                return True
        return False

    def is_pid_allowed(self, pid: int) -> bool:
        """True if *pid* (or a near ancestor) is an allowed application."""
        if pid <= 0:
            return False
        # Never allow the guard's own process to recurse into itself in a way
        # that would create loops, but the guard reads the backing dir
        # directly (not through FUSE), so its pid arriving here is external.
        seen: Set[int] = set()
        current = pid
        for _ in range(self.max_parent_depth + 1):
            if current in seen or current <= 1:
                break
            seen.add(current)
            exe = _read_exe(current)
            if self._exe_allowed(exe):
                return True
            parent = _read_ppid(current)
            if parent is None:
                break
            current = parent
        return False


class VaultGuardFS(Operations):
    """A passthrough FUSE filesystem gated by an AllowlistPolicy.

    All operations forward to *backing* (the plaintext gocryptfs mount) but
    only after the calling process passes the allowlist check.
    """

    def __init__(self, backing: str, policy: AllowlistPolicy,
                 log_fn=None) -> None:
        self.backing = os.path.realpath(backing)
        self.policy = policy
        self.log_fn = log_fn or (lambda *a, **k: None)
        self.rwlock = threading.Lock()

    # -- helpers -----------------------------------------------------------
    def _full(self, partial: str) -> str:
        partial = partial.lstrip("/")
        return os.path.join(self.backing, partial)

    def _check(self, op: str, path: str) -> None:
        """Raise EACCES if the calling process is not allowed."""
        uid, gid, pid = fuse_get_context()
        if not self.policy.is_pid_allowed(pid):
            exe = _read_exe(pid) or "<unknown>"
            self.log_fn("DENY", op, path, pid, exe)
            raise FuseOSError(errno.EACCES)
        # Only log actual data-bearing operations to keep the log readable.
        if op in ("open", "read", "write", "create", "unlink", "readdir"):
            exe = _read_exe(pid) or "<unknown>"
            self.log_fn("ALLOW", op, path, pid, exe)

    # -- filesystem methods ------------------------------------------------
    def access(self, path, mode):
        self._check("access", path)
        if not os.access(self._full(path), mode):
            raise FuseOSError(errno.EACCES)

    def getattr(self, path, fh=None):
        # getattr is extremely chatty and needed for the mount to exist at
        # all; we still gate it so a denied process can't even stat contents.
        self._check("getattr", path)
        st = os.lstat(self._full(path))
        return {key: getattr(st, key) for key in (
            "st_atime", "st_ctime", "st_gid", "st_mode", "st_mtime",
            "st_nlink", "st_size", "st_uid")}

    def readdir(self, path, fh):
        self._check("readdir", path)
        full = self._full(path)
        entries = [".", ".."]
        if os.path.isdir(full):
            entries.extend(os.listdir(full))
        for e in entries:
            yield e

    def readlink(self, path):
        self._check("readlink", path)
        target = os.readlink(self._full(path))
        if target.startswith("/"):
            return os.path.relpath(target, self.backing)
        return target

    def mknod(self, path, mode, dev):
        self._check("mknod", path)
        return os.mknod(self._full(path), mode, dev)

    def rmdir(self, path):
        self._check("rmdir", path)
        return os.rmdir(self._full(path))

    def mkdir(self, path, mode):
        self._check("mkdir", path)
        return os.mkdir(self._full(path), mode)

    def statfs(self, path):
        self._check("statfs", path)
        stv = os.statvfs(self._full(path))
        return {key: getattr(stv, key) for key in (
            "f_bavail", "f_bfree", "f_blocks", "f_bsize", "f_favail",
            "f_ffree", "f_files", "f_flag", "f_frsize", "f_namemax")}

    def unlink(self, path):
        self._check("unlink", path)
        return os.unlink(self._full(path))

    def symlink(self, name, target):
        self._check("symlink", name)
        return os.symlink(target, self._full(name))

    def rename(self, old, new):
        self._check("rename", old)
        return os.rename(self._full(old), self._full(new))

    def link(self, target, name):
        self._check("link", name)
        return os.link(self._full(name), self._full(target))

    def utimens(self, path, times=None):
        self._check("utimens", path)
        return os.utime(self._full(path), times)

    def chmod(self, path, mode):
        self._check("chmod", path)
        return os.chmod(self._full(path), mode)

    def chown(self, path, uid, gid):
        self._check("chown", path)
        return os.chown(self._full(path), uid, gid)

    def truncate(self, path, length, fh=None):
        self._check("truncate", path)
        with open(self._full(path), "r+") as f:
            f.truncate(length)

    # -- file handle ops ---------------------------------------------------
    def open(self, path, flags):
        self._check("open", path)
        return os.open(self._full(path), flags)

    def create(self, path, mode, fi=None):
        self._check("create", path)
        return os.open(self._full(path),
                       os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)

    def read(self, path, length, offset, fh):
        self._check("read", path)
        with self.rwlock:
            os.lseek(fh, offset, os.SEEK_SET)
            return os.read(fh, length)

    def write(self, path, buf, offset, fh):
        self._check("write", path)
        with self.rwlock:
            os.lseek(fh, offset, os.SEEK_SET)
            return os.write(fh, buf)

    def flush(self, path, fh):
        # No allowlist check on flush/release: the handle was already gated
        # at open() time; blocking flush could corrupt an allowed writer.
        return os.fsync(fh)

    def release(self, path, fh):
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        return os.fsync(fh)


def run_guard(backing: str, mountpoint: str, allowed_apps: List[str],
              log_fn=None, foreground: bool = True,
              allow_other: bool = False) -> None:
    """Mount the guard FS. Blocks until unmounted (when foreground=True)."""
    if FUSE is None:
        raise RuntimeError("fusepy is not installed. pip install fusepy")

    os.makedirs(mountpoint, exist_ok=True)
    policy = AllowlistPolicy(allowed_apps, self_pid=os.getpid())
    fs = VaultGuardFS(backing, policy, log_fn=log_fn)

    FUSE(
        fs,
        mountpoint,
        foreground=foreground,
        nothreads=False,
        allow_other=allow_other,
        # default_permissions lets the kernel also enforce unix perms.
        default_permissions=True,
    )


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(
        description="Vault Guardian userspace FUSE allowlist guard")
    ap.add_argument("backing", help="Plaintext gocryptfs mount to protect")
    ap.add_argument("mountpoint", help="User-visible guarded mount point")
    ap.add_argument("--apps", nargs="*",
                    default=["libreoffice", "firefox", "evince", "gedit",
                             "code", "kate"],
                    help="Allowed application names / paths")
    ap.add_argument("--allow-other", action="store_true")
    ns = ap.parse_args()

    def _log(action, op, path, pid, exe):
        print(f"[{action}] {op} {path} pid={pid} exe={exe}", file=sys.stderr)

    run_guard(ns.backing, ns.mountpoint, ns.apps, log_fn=_log,
              foreground=True, allow_other=ns.allow_other)
