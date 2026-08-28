# Vault Guardian

**A USB-gated, per-app encrypted vault for Linux — designed to keep an AI
agent (or any other process) running as *you* from reading your sensitive
files.**

Your secrets live in an encrypted folder that is only decrypted while a
specific USB key you registered is plugged in. Even while it is unlocked,
**only apps you explicitly allow** (LibreOffice, your browser, your editor…)
can read the files. Pull the USB key — or click **Lock Now** in the tray —
and the plaintext instantly disappears.

---

## Why this exists

If an AI agent runs with the *same user account* as you, it has, in principle,
the same file permissions you do. Ordinary file permissions can't help. Vault
Guardian raises the bar with two independent gates:

1. **Possession gate (USB key):** the vault is encrypted with `gocryptfs`
   (AES-256-GCM). It is only mounted while your registered USB device is
   physically present. No key → the files are ciphertext no one can read.
2. **Identity gate (app allowlist):** even when mounted, access goes through a
   userspace **FUSE guard** that inspects *which program* is making each
   request (`/proc/<pid>/exe`). Only allow-listed apps get through; everything
   else — including a Python/bash/xdotool-driven agent — gets `Permission
   denied`.

Both gates run **entirely as your normal user. No root required** for the core
protection. (An optional AppArmor layer adds kernel enforcement if you want it
and can `sudo` once.)

---

## How it works (plain English)

```
   ~/.vault-encrypted/     encrypted files on disk (safe at rest)
          │  gocryptfs decrypts inside the guard's private mount namespace
          ▼
   private tmpfs           plaintext, visible only to the guard process
          │  FUSE guard checks the *calling* executable (no parent-walk)
          ▼
   ~/Vault/                what you and your allowed apps actually open
```

The plaintext directory is *not* `~/.vault-plain` on the host. Older versions
left decrypted files there at mode 700, which any same-user process could
read. Unlock now fails closed if a private mount namespace cannot be created
(for example if unprivileged user namespaces are disabled).

- Plug in your registered USB key → the tray icon turns **green** and `~/Vault`
  fills with your files (visible only to allowed apps).
- Remove the key (or click **Lock Now**, or the machine suspends) → the tray
  icon turns **red**, `~/Vault` is unmounted, and the plaintext is gone.
- An agent that opens `~/Vault/secret.txt` with Python or a shell is denied,
  because its executable is `python3`/`bash`, not an allowed app.

---

## Installation (Ubuntu)

Python packages go into a **venv** at `~/.local/share/vault-guardian/venv`.
That keeps the system interpreter clean: no `pip install --user`, no
breaking Ubuntu's PEP 668 externally-managed environment.

GTK / `gi` still come from apt (`python3-gi` and the gir packages). The venv
is created with `--system-site-packages` so `import gi` works for the tray
icon.

On the Ubuntu machine you want to protect:

```bash
sudo apt-get update
sudo apt-get install -y git
git clone https://github.com/schlafly1/vault_guardian.git
cd vault_guardian
./install.sh
```

Run `./install.sh` as your **normal user**, not root. It uses `sudo` only for
apt, the udev rule, and (optionally) AppArmor.

On NVIDIA Jetson (L4T) the installer holds every `nvidia-l4t-*` package,
refuses to upgrade or pull recommends, skips any apt action that would change
the display stack, and only udev-triggers USB/block. Older versions did
none of that, which could kill HDMI/desktop output.

The installer will:

1. Install missing system deps via apt: `gocryptfs`, FUSE (if `fusermount` is
   absent), `python3` / `python3-venv`. GTK/AppIndicator only if they are not
   already importable. `apparmor-utils` is skipped on Jetson.
2. Copy the app to `~/.local/share/vault-guardian/`.
3. Create the venv there and pip-install `pyudev`, `pystray`, `Pillow`,
   `cryptography`, `fusepy` **into that venv only**.
4. Install launchers `vault-guardian` and `vault-guardian-setup` into
   `~/.local/bin/` (they call the venv's Python).
5. Install a udev rule (`/etc/udev/rules.d/99-vault-guardian.rules`).
6. Install and enable a **systemd user service** whose `ExecStart` is the
   venv interpreter.
7. Run the **first-time setup wizard**.

To have it run even when you're not logged in graphically:

```bash
sudo loginctl enable-linger "$USER"
```

### Manual venv (if you are not using install.sh)

```bash
sudo apt-get install -y python3 python3-venv python3-gi gir1.2-gtk-3.0 \
    gir1.2-appindicator3-0.1 gocryptfs fuse apparmor-utils
python3 -m venv --system-site-packages ~/.local/share/vault-guardian/venv
~/.local/share/vault-guardian/venv/bin/pip install -r requirements.txt
```

Then point launchers and the systemd unit at
`~/.local/share/vault-guardian/venv/bin/python`, same as `install.sh`.

### Other distros

`./install.sh` still tries dnf/pacman for system packages, then uses the same
venv path. A systemd-based distro with FUSE and a system tray is required.
`gocryptfs` must be available from your package manager.

## First-time setup (registering your USB key)

The wizard (`vault-guardian-setup`) walks you through:

1. **Vault location & password.** Creates `~/.vault-encrypted` and asks for a
   strong password (used to derive the AES key).
2. **Pick your USB key.** It lists plugged-in USB devices that expose a serial.
   Choose the stick or security key you want to use.
   - Only a **SHA256 hash of the device serial** is stored — never the raw
     serial, and never the vendor/product ID (which any identical model would
     share and is trivially spoofed).
3. **Password prompt on every unlock.** Auto-unlock is not offered. A blob in
   `~/.config/vault-guardian/config.json` is readable by any same-user process
   (including an AI agent), so storing a decryptable copy of the vault password
   there would defeat the point. Existing blobs are ignored and wiped.
4. **Allowed apps.** Defaults to
   `libreoffice, firefox, evince, gedit, kate`. Add your own. `code` is
   intentionally not a default: the allowlist checks only the calling process,
   so a terminal or agent spawned *from* an editor is denied unless that
   child binary is itself listed.

Re-run any time with:

```bash
vault-guardian-setup
```

You can also change the USB key later from the tray menu → **Change USB Key…**

---

## Using it day to day

Look for the padlock icon in your system tray:

| Menu item | What it does |
|-----------|--------------|
| 🔒/🔓 status line | Shows whether the vault is Locked or Open |
| **Unlock Now** | Manually mount the vault (asks for password unless auto-unlock) |
| **Lock Now** | Immediately unmount — plaintext disappears |
| **Allowed Apps…** | Add/remove which programs may read the vault |
| **Change USB Key…** | Register a different USB device as your key |
| **View Access Log** | Opens the log of every allow/deny decision |
| **Quit** | Locks the vault and exits |

### Adding files to the vault
1. Unlock the vault (plug in your key).
2. Open `~/Vault` in your file manager or an allowed app.
3. Copy files in / edit them as normal. They're transparently encrypted into
   `~/.vault-encrypted`.
4. Lock when done. Only ciphertext remains on disk.

> Tip: because the file manager itself must read `~/Vault` to show it, add your
> file manager (e.g. `nautilus`, `dolphin`, `nemo`, `thunar`) to the allowed
> apps if you want to browse the vault graphically.

### Access log
Every decision is recorded at
`~/.local/share/vault-guardian/access.log`, e.g.:

```
2026-08-26 10:22:01 [OPEN] vault open at /home/you/Vault
[ALLOW] read /secret.txt pid=4812 exe=/usr/lib/libreoffice/program/soffice.bin
[DENY] open /secret.txt pid=5501 exe=/usr/bin/python3
```

The `[DENY]` lines are exactly the AI-agent access attempts you wanted to see.

---

## Security model — and its honest limits

**What this stops well:**
- An AI agent (or any process) reading your files via Python, shell, `cat`,
  `scp`, a scripting tool, or an un-allowed application — blocked with EACCES
  on `~/Vault`.
- Direct reads of the decrypted backing store by other same-user processes —
  the plaintext lives on a private tmpfs inside the guard's mount namespace,
  not in `~/.vault-plain`.
- Anyone reading the files when the USB key is absent — they're just
  AES-256-GCM ciphertext.
- Files lingering decrypted after you unplug, click Lock, or the machine
  sleeps — the vault is force-unmounted (lazy unmount) immediately.
- Inheriting access through a parent editor (`code`, Cursor, etc.). Only the
  calling PID's executable is checked.

**What it does *not* fully stop (same-user threat model is inherently hard):**
- A process running as you that can **replace or modify an allowed binary**, or
  **`ptrace`/inject into an already-allowed app**, could get data through that
  app's identity. That's a much higher bar than a naive file read, but it's
  possible for a determined same-user attacker. Combining with the optional
  AppArmor profile and keeping allowed apps to a minimum reduces this.
- The FUSE guard is not a substitute for a full MAC/sandbox; it's a pragmatic,
  no-root barrier. `/proc/<pid>/exe` is also a TOCTOU against PID reuse.
- Root on the machine can bypass everything. This tool protects against
  same-*user* threats, not against a compromised root.
- Unlock requires unprivileged user namespaces (`kernel.unprivileged_userns_clone=1`,
  Ubuntu default). If they are disabled, unlock refuses rather than exposing
  plaintext on the host.

**Defense-in-depth recommendation:** for the highest-value secrets, the
strongest option remains a separate, network-limited machine. Vault Guardian is
the convenient middle ground you asked for: strong, USB-gated, per-app control
without a second box.

### Optional AppArmor layer
If you answered "yes" to AppArmor during setup (and have `apparmor-utils`), a
profile is generated at `/etc/apparmor.d/vault-guardian` and loaded with
`apparmor_parser`. This adds kernel-enforced deny rules for the vault path on
top of the FUSE guard. It needs `sudo` once when applied. See
`apparmor_manager.py --print` to inspect the generated policy before using it.

---

## Files in this project

| File | Purpose |
|------|---------|
| `install.sh` | One-command installer (Ubuntu-first; Python deps go in a venv) |
| `setup_wizard.py` | First-time setup + config/crypto helpers |
| `vault_manager.py` | gocryptfs mount / unmount (safe subprocess) |
| `usb_monitor.py` | udev USB add/remove detection by serial hash |
| `no_sudo_fuse_guard.py` | **Primary** per-app allowlist FUSE guard (no root) |
| `mountns.py` | Unprivileged user+mount namespace helper |
| `apparmor_manager.py` | Optional kernel AppArmor profile generator |
| `tray_app.py` | System-tray UI + orchestration |
| `vault_guardian.py` | Entry point launched by systemd/CLI |
| `vault-guardian.service` | systemd **user** service unit (ExecStart = venv Python) |
| `requirements.txt` | Python dependencies (installed into the venv) |

The venv itself is created at install time under
`~/.local/share/vault-guardian/venv` and is not part of the git repo.

---

## Troubleshooting

**Tray icon doesn't appear.**
- Ensure your desktop shows app-indicators. On GNOME install the
  *AppIndicator and KStatusNotifierItem* extension. Verify GTK/appindicator
  with the venv Python:
  `~/.local/share/vault-guardian/venv/bin/python -c "import gi; gi.require_version('Gtk','3.0')"`.
- Check the service: `systemctl --user status vault-guardian` and
  `journalctl --user -u vault-guardian`.

**`~/Vault` is empty even with the key inserted.**
- Confirm the key is the registered one: tray → *Change USB Key…* re-selects.
- Check the log: `tail -f ~/.local/share/vault-guardian/access.log`.
- Make sure `gocryptfs` is installed: `which gocryptfs`.

**My allowed app still can't open files.**
- Some apps launch helper binaries with different names (e.g. LibreOffice →
  `soffice.bin`). Those are handled, but for others add the real binary path.
  Find it with `ps -e -o pid,comm,exe` or `readlink /proc/<pid>/exe` while the
  app runs, then add that path in *Allowed Apps…*.
- After changing allowed apps, **lock and unlock** (or re-plug the key) so the
  guard restarts with the new list.

**"Transport endpoint is not connected" on `~/Vault`.**
- A stale mount. Run: `fusermount -u ~/Vault` then unlock again.
  (Older installs may also need `fusermount -u ~/.vault-plain`.)

**Unlock fails with "Could not enter a private mount namespace".**
- This machine has unprivileged user namespaces disabled. Vault Guardian
  will not fall back to a host-visible plaintext mount. On Ubuntu check
  `sysctl kernel.unprivileged_userns_clone` (should be 1).

**NVIDIA Jetson: display died after install (black HDMI, no desktop).**
- An older installer ran `apt-get install` of GTK/FUSE/AppArmor after
  `apt-get update`, which on L4T can remove `nvidia-l4t-x11` /
  `nvidia-l4t-3d-core`. It also ran an unfiltered `udevadm trigger`.
  Recover over SSH (this is what NVIDIA documents):
  `sudo apt install --reinstall nvidia-l4t-x11 nvidia-l4t-3d-core`
  Current `install.sh` holds all `nvidia-l4t-*` packages, uses
  `--no-upgrade --no-install-recommends`, skips any package whose dry-run
  would touch that stack, and only udev-triggers USB/block.

**pip fails with an externally managed environment.**
- The installer no longer uses user-site pip. If you see this, you are not
  using the venv. Use `~/.local/share/vault-guardian/venv/bin/pip`, or re-run
  `./install.sh`.

**`import gi` fails inside the venv.**
- Install the system packages: `sudo apt-get install python3-gi gir1.2-gtk-3.0 gir1.2-appindicator3-0.1`.
- Recreate the venv with system site packages, then pip-install requirements
  into `~/.local/share/vault-guardian/venv`.

**FUSE "allow_other" errors.** The core setup does not require `allow_other`
because the guard runs as you. If you customize it and hit this, add
`user_allow_other` to `/etc/fuse.conf`.

---

## Uninstall

```bash
systemctl --user disable --now vault-guardian
rm -rf ~/.local/share/vault-guardian ~/.config/vault-guardian
rm -f ~/.config/systemd/user/vault-guardian.service
rm -f ~/.local/bin/vault-guardian ~/.local/bin/vault-guardian-setup
sudo rm -f /etc/udev/rules.d/99-vault-guardian.rules
sudo rm -f /etc/apparmor.d/vault-guardian   # if you used AppArmor
```

`rm -rf ~/.local/share/vault-guardian` also removes the venv. Your encrypted data in `~/.vault-encrypted` is left untouched — delete it
yourself if you no longer need it (make sure you can decrypt it elsewhere
first if you want to keep the contents).
