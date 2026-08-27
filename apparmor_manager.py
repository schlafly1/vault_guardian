#!/usr/bin/env python3
"""
apparmor_manager.py
===================
Optional *kernel-level* per-app enforcement using AppArmor.

This is the strongest layer when it is available, but it requires root once
(to write /etc/apparmor.d/ and load the profile). Because Vault Guardian is
designed to run as an unprivileged user, AppArmor is treated as an *optional
hardening layer*; the userspace FUSE guard (no_sudo_fuse_guard.py) is the
primary enforcement mechanism and needs no root.

Strategy
--------
AppArmor path-based rules alone cannot easily express "deny everyone except
these apps for this directory" because AppArmor confines a profile, not a
path. So we generate one profile *per allowed app* that grants that app read
access to the mount point, and rely on the fact that AppArmor is combined
with the FUSE guard's default-deny. In addition we generate a broad profile
that can be attached (via aa-exec) to untrusted launchers to explicitly deny
the vault path.

The functions here degrade gracefully: if apparmor_parser / aa-status are not
present, they return False and the tray app simply relies on the FUSE guard.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import List

PROFILE_PATH = "/etc/apparmor.d/vault-guardian"


def apparmor_available() -> bool:
    """True if AppArmor tooling is present and the LSM is enabled."""
    if not shutil.which("apparmor_parser"):
        return False
    # /sys/module/apparmor/parameters/enabled contains 'Y' when active.
    try:
        with open("/sys/module/apparmor/parameters/enabled") as fh:
            return fh.read().strip() == "Y"
    except OSError:
        return False


def _profile_text(mount_point: str, allowed_apps: List[str]) -> str:
    """Build the AppArmor policy text.

    We emit:
      * a ``deny`` template comment documenting intent
      * one child profile per allowed app that is permitted to read/write the
        vault, transitioned into via the app's binary path.

    Note: this is a best-effort generated profile. Administrators should
    review it before relying on it in production.
    """
    mp = os.path.realpath(mount_point)
    lines: List[str] = []
    lines.append("# === Vault Guardian generated AppArmor policy ===")
    lines.append("# Default posture: no profile grants access to the vault,")
    lines.append("# so any confined process is denied. Allowed apps below get")
    lines.append(f"# explicit read/write to {mp}/**")
    lines.append("")

    abi = "  # (abi/3.0 omitted for compatibility)\n"
    for app in allowed_apps:
        binpath = shutil.which(app) or f"/usr/bin/{app}"
        pname = f"vault-guardian-{os.path.basename(app)}"
        lines.append(f"profile {pname} {binpath} flags=(attach_disconnected) {{")
        lines.append("  #include <abstractions/base>")
        lines.append("  # Allow this app full access to its own binary + libs")
        lines.append(f"  {binpath} mr,")
        lines.append("  /usr/** mr,")
        lines.append("  /lib/** mr,")
        lines.append("  /etc/** r,")
        lines.append("  owner @{HOME}/** rw,")
        lines.append(f"  # Explicit access to the vault mount")
        lines.append(f"  {mp}/ rw,")
        lines.append(f"  {mp}/** rwk,")
        lines.append("}")
        lines.append("")

    # A restrictive profile that can be attached to untrusted launchers.
    lines.append("profile vault-guardian-deny flags=(attach_disconnected) {")
    lines.append("  #include <abstractions/base>")
    lines.append("  owner @{HOME}/** rw,")
    lines.append("  /usr/** mr,")
    lines.append("  /lib/** mr,")
    lines.append(f"  # Explicitly deny the vault to anything run under this profile")
    lines.append(f"  deny {mp}/ rwklx,")
    lines.append(f"  deny {mp}/** rwklx,")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def generate_profile(mount_point: str, allowed_apps: List[str]) -> str:
    """Return the AppArmor profile text for the given config.

    Does not write anything to disk (that needs root); use write_profile().
    """
    return _profile_text(mount_point, allowed_apps)


def write_profile(mount_point: str, allowed_apps: List[str],
                  path: str = PROFILE_PATH) -> bool:
    """Write the generated profile to *path* (needs write permission / root).

    Returns True on success, False if permission denied.
    """
    text = generate_profile(mount_point, allowed_apps)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return True
    except PermissionError:
        return False


def apply_profile(path: str = PROFILE_PATH) -> bool:
    """Load the profile into the kernel with apparmor_parser.

    Returns True on success. Requires root (will attempt ``sudo -n`` so it
    fails fast when non-interactive and no cached credentials exist).
    """
    if not apparmor_available():
        return False
    if not os.path.isfile(path):
        return False
    parser = shutil.which("apparmor_parser")
    # Try without sudo first (works if already root), then sudo -n.
    for cmd in ([parser, "-r", "-W", path],
                ["sudo", "-n", parser, "-r", "-W", path]):
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            if proc.returncode == 0:
                return True
        except FileNotFoundError:
            continue
    return False


def remove_profile(path: str = PROFILE_PATH) -> bool:
    """Unload and delete the profile. Best-effort; requires root."""
    parser = shutil.which("apparmor_parser")
    ok = False
    if parser and os.path.isfile(path):
        for cmd in ([parser, "-R", path], ["sudo", "-n", parser, "-R", path]):
            try:
                proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
                if proc.returncode == 0:
                    ok = True
                    break
            except FileNotFoundError:
                continue
    try:
        if os.path.isfile(path):
            os.remove(path)
    except PermissionError:
        pass
    return ok


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Vault Guardian AppArmor helper")
    ap.add_argument("--mount", default=os.path.expanduser("~/Vault"))
    ap.add_argument("--apps", nargs="*",
                    default=["libreoffice", "firefox", "evince", "gedit",
                             "code", "kate"])
    ap.add_argument("--print", action="store_true",
                    help="Print the generated profile and exit")
    ns = ap.parse_args()

    if ns.print or not apparmor_available():
        if not apparmor_available():
            print("# AppArmor not available on this system - profile is for "
                  "reference only.\n")
        print(generate_profile(ns.mount, ns.apps))
    else:
        print("AppArmor available. Use write_profile()/apply_profile() as root.")
