#!/usr/bin/env python3
"""
no_sudo_fuse_guard.py
=====================
The PRIMARY per-app enforcement layer. Works entirely in userspace as the
current user - no root, no AppArmor required.

How it fits together
---------------------
    ~/.vault-encrypted/      <- gocryptfs ciphertext (on disk)
            |  gocryptfs, mounted inside this process's private mount ns
            v
    private tmpfs            <- decrypted plaintext, invisible to other
            |                    same-user processes (including agents)
            |  FUSE passthrough with per-caller allowlist check
            v
    ~/Vault/                 <- what the user & allowed apps actually see
                                (FUSE mount propagates to the host ns)

Every VFS operation that arrives at ~/Vault/ carries the PID of the calling
process (via fuse_get_context()). We resolve /proc/<pid>/exe to the real
executable path and compare it against the allowlist. Ancestors are NOT
consulted: an agent spawned from VS Code/Cursor must not inherit access
just because `code` is allowed.

Security caveats (documented honestly)
--------------------------------------
* An attacker running as the same user who can *replace* an allowed
  binary, or ptrace an allowed process, could bypass the allowlist.
  The private mount ns still keeps ~/.vault-plain from a naive `open()`.
* PID reuse between fuse_get_context() and /proc/<pid>/exe is a known
  FUSE TOCTOU. Fail closed if the exe cannot be resolved.
"""

from __future__ import annotations

import errno
import os
import signal
import subprocess
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
        def __init__(self, err_code):
            super().__init__(err_code, os.strerror(err_code))


# Helpers launched by an allowed app under a different basename. These are
# added only when the corresponding app is on the allowlist; we do not walk
# parent PIDs.
_APP_HELPERS = {
    "libreoffice": {"soffice", "soffice.bin", "oosplash"},
    "soffice": {"soffice.bin", "oosplash"},
}


def _read_exe(pid: int) -> Optional[str]:
    """Return the real executable path for *pid*, or None if unavailable."""
    try:
        return os.path.realpath(f"/proc/{pid}/exe")
    except OSError:
        return None


class AllowlistPolicy:
    """Decides whether a calling PID may access the vault.

    Only the calling process is considered, never its parents. A Cursor
    agent whose parent is `code` must not get a free pass.
    """

    def __init__(self, allowed_apps: List[str], self_pid: int) -> None:
        self.allowed_names: Set[str] = set()
        self.allowed_paths: Set[str] = set()
        self.self_pid = self_pid
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
                names.update(_APP_HELPERS.get(app, set()))
        self.allowed_names = names
        self.allowed_paths = paths

    def _exe_allowed(self, exe: Optional[str]) -> bool:
        if not exe:
            return False
        if exe in self.allowed_paths:
            return True
        return os.path.basename(exe) in self.allowed_names

    def is_pid_allowed(self, pid: int) -> bool:
        if pid <= 0:
            return False
        # The FUSE daemon itself must be able to getattr the mount root.
        # It already has the plaintext tmpfs; this is not a new hole.
        if pid == self.self_pid:
            return True
        return self._exe_allowed(_read_exe(pid))


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
        if op in ("open", "read", "write", "create", "unlink", "readdir"):
            exe = _read_exe(pid) or "<unknown>"
            self.log_fn("ALLOW", op, path, pid, exe)

    def access(self, path, mode):
        self._check("access", path)
        if not os.access(self._full(path), mode):
            raise FuseOSError(errno.EACCES)

    def getattr(self, path, fh=None):
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
        return os.fsync(fh)

    def release(self, path, fh):
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        return os.fsync(fh)


def _pdeathsig():
    """Kill this process if the parent guard dies."""
    try:
        import ctypes
        import ctypes.util
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        PR_SET_PDEATHSIG = 1
        libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM)
    except Exception:
        pass


def _mount_gocryptfs(cipherdir: str, backing: str, password: bytes) -> None:
    import shutil
    import time
    import vault_manager
    gocryptfs = shutil.which("gocryptfs")
    if not gocryptfs:
        raise RuntimeError("gocryptfs not found on PATH")
    pw = password if password.endswith(b"\n") else password + b"\n"
    # Stay in the foreground so we remain a child of the guard. Daemonizing
    # would reparent to init and drop PR_SET_PDEATHSIG.
    proc = subprocess.Popen(
        [gocryptfs, "-q", "-fg", cipherdir, backing],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        preexec_fn=_pdeathsig,
    )
    try:
        proc.stdin.write(pw)
        proc.stdin.close()
    except BrokenPipeError:
        pass
    for _ in range(80):
        if vault_manager.is_mounted(backing):
            return
        if proc.poll() is not None:
            raise RuntimeError(
                f"gocryptfs mount failed (exit {proc.returncode})"
            )
        time.sleep(0.05)
    if not vault_manager.is_mounted(backing):
        try:
            proc.terminate()
        except Exception:
            pass
        raise RuntimeError("gocryptfs did not come up in time")


def run_guard(cipherdir: str, mountpoint: str, allowed_apps: List[str],
              password: bytes, log_fn=None, foreground: bool = True) -> None:
    """Isolate plaintext, mount gocryptfs, then FUSE-export *mountpoint*.

    Refuses to run if the private mount namespace cannot be entered: falling
    back to a world-visible ~/.vault-plain would re-open the same-user hole.
    """
    if FUSE is None:
        raise RuntimeError("fusepy is not installed. pip install fusepy")

    import mountns

    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    backing = os.path.join(runtime, "vault-guardian-plain")

    try:
        mountns.isolate_for_guard(backing)
    except OSError as e:
        raise RuntimeError(
            "Could not enter a private mount namespace "
            f"({e}). Unlock aborted rather than exposing plaintext "
            "to every same-user process."
        ) from e

    _mount_gocryptfs(cipherdir, backing, password)

    os.makedirs(mountpoint, exist_ok=True)
    policy = AllowlistPolicy(allowed_apps, self_pid=os.getpid())
    fs = VaultGuardFS(backing, policy, log_fn=log_fn)

    FUSE(
        fs,
        mountpoint,
        foreground=foreground,
        nothreads=False,
        allow_other=False,
        default_permissions=True,
    )


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(
        description="Vault Guardian userspace FUSE allowlist guard")
    ap.add_argument("cipherdir", help="gocryptfs ciphertext directory")
    ap.add_argument("mountpoint", help="User-visible guarded mount point")
    ap.add_argument("--apps", nargs="*",
                    default=["libreoffice", "firefox", "evince", "gedit",
                             "kate"],
                    help="Allowed application names / paths")
    ns = ap.parse_args()
    password = sys.stdin.buffer.readline()
    if not password:
        sys.exit("vault password required on stdin")

    def _log(action, op, path, pid, exe):
        print(f"[{action}] {op} {path} pid={pid} exe={exe}", file=sys.stderr)

    run_guard(ns.cipherdir, ns.mountpoint, ns.apps, password,
              log_fn=_log, foreground=True)
