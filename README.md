# Vault Guardian

**A USB-gated encrypted folder for Linux.** Plug in a registered USB key,
type your password, and `~/Vault` is a normal folder. Unplug (or Lock /
suspend) and the plaintext disappears.

This is the simple product. There is no second FUSE layer, no user
namespace, no `vaultguard` system user, no `vault-exec`, no sudoers
helpers, no AppArmor, and no fusepy.

**Honest limit:** while unlocked, **any process running as you** can read
`~/Vault`. USB + password is the gate. That is the whole design.

---

## Day to day

1. Plug in your registered USB key.
2. Type the vault password in the dialog.
3. Use `~/Vault` normally: `ls`, Firefox, your editor, a file manager.
   Files are transparently encrypted into `~/.vault-encrypted`.
4. Unplug the key (or click **Lock Now**, or the machine suspends) — the
   tray turns red, `fusermount` unmounts `~/Vault`, only ciphertext remains.

The padlock icon in the system tray:

| Menu item | What it does |
|-----------|--------------|
| status line | Locked (red) or Open (green) |
| **Unlock Now** | Password dialog, then `gocryptfs` as you |
| **Lock Now** | `fusermount3 -u` then `fusermount`, then `-u -z` |
| **Change USB Key...** | Register a different USB device |
| **View Access Log** | Opens `~/.local/share/vault-guardian/access.log` |
| **Quit** | Locks the vault and exits |

USB unplug-to-lock still works with no tray icon (headless: no `DISPLAY`).
The process does not crash; it just waits for USB events.

---

## How it works

```
   ~/.vault-encrypted/     ciphertext (AES-256-GCM via gocryptfs)
          |  gocryptfs -q  (password on stdin, never argv)
          v
   ~/Vault/                plaintext, owned by you, mode 0700
                           a normal folder while unlocked
```

- Plug the registered USB key → password dialog → `gocryptfs` mounts
  `~/.vault-encrypted` onto `~/Vault` as **the login user**.
- `~/Vault` is a normal folder. `ls`, Firefox, and your editor all work.
- Remove the key / Lock Now / suspend / quit → `fusermount3` then
  `fusermount`, `-u` then `-u -z`.
- Existing `~/.vault-encrypted` is **kept**. Nothing here wipes ciphertext
  on install. Init only runs if the vault is missing.

`gocryptfs` is passed `-q` only, plus optional `-nonempty` so leftover
files in `~/Vault` do not block the mount. Empty that folder yourself if
you prefer a strictly empty mount point.

---

## Installation (Ubuntu / Jetson)

One-time, as your **normal user**. `sudo` is used only for apt and the
udev rule.

```bash
./install.sh
```

Python packages go into a **venv** at `~/.local/share/vault-guardian/venv`.
No `pip install --user`, no privileged installer, no gcc, no acl, no
libfuse2, no fusepy.

On NVIDIA Jetson (L4T) the installer holds every `nvidia-l4t-*` package,
refuses to upgrade or pull recommends, skips any apt action that would
change the display stack, and only udev-triggers USB/block. Do not
`apt-get upgrade` and do not touch `nvidia-l4t`.

### What `./install.sh` does

1. Jetson-safe apt: `gocryptfs`, fuse3/`fusermount3`, `python3` /
   `python3-venv`. GTK/AppIndicator only if they are not already
   importable. Does **not** install `libfuse2`, gcc, acl, or
   `apparmor-utils` on tegra.
2. Copy the app to `~/.local/share/vault-guardian/`.
3. Create the venv and pip-install `pyudev`, `pystray`, `Pillow`,
   `cryptography` **into that venv only**.
4. Install launchers `vault-guardian` and `vault-guardian-setup`.
5. Install a udev rule (`/etc/udev/rules.d/99-vault-guardian.rules`).
   `udevadm trigger` is USB/block only.
6. Enable a systemd **user** service.
7. Run the first-time setup wizard (init vault if missing, pick USB,
   password every time).

To have the tray run even when you are not logged in graphically:

```bash
sudo loginctl enable-linger "$USER"
```

### Manual venv (if you are not using install.sh)

```bash
sudo apt-get install -y python3 python3-venv python3-gi gir1.2-gtk-3.0 \
    gir1.2-appindicator3-0.1 gocryptfs fuse3
python3 -m venv --system-site-packages ~/.local/share/vault-guardian/venv
~/.local/share/vault-guardian/venv/bin/pip install -r requirements.txt
```

---

## First-time setup (registering your USB key)

The wizard (`vault-guardian-setup`) walks you through:

1. **Vault location and password.** Creates `~/.vault-encrypted` if missing
   (or keeps it). Password is asked at every unlock — never stored.
2. **Pick your USB key.** Only a **SHA256 hash of the device serial** is
   stored. Vendor/product IDs are not used (they identify a model, not a
   stick).

Auto-unlock is not offered. A blob in `~/.config/vault-guardian/config.json`
is readable by any same-user process, so leftover blobs from older installs
are wiped.

Re-run any time with:

```bash
vault-guardian-setup
```

You can also change the USB key later from the tray menu → **Change USB Key...**

---

## Security model — and its honest limits

**What this stops well:**

- Direct reads of ciphertext when the USB key is absent — AES-256-GCM.
- Files lingering decrypted after unplug / Lock / suspend — lazy unmount.
- Password never appears in argv or a shell command line (stdin only).

**What it does *not* stop:**

- **While unlocked, any same-UID process can read `~/Vault`.** That includes
  `python`, `cat`, Cursor, an AI agent, a terminal. USB + password is the
  gate, not an app allowlist.
- Root can read anything. This is not anti-root.
- Copies you make outside `~/Vault` stay decrypted.

If you need same-user isolation (agents cannot read while you can), that
is a different, more complicated product. This one is the USB-gated folder.

---

## How to wipe

Stop the service, unmount, delete ciphertext and the empty mount point.
Keep or remove the config as you like.

```bash
systemctl --user stop vault-guardian
fusermount3 -u ~/Vault 2>/dev/null || fusermount -u ~/Vault 2>/dev/null || true
rm -rf ~/.vault-encrypted ~/Vault
# keep config, or:
# rm -rf ~/.config/vault-guardian
```

Then `vault-guardian-setup` (or `./install.sh`) will init a new vault
because ciphertext is gone. Install never wipes an existing
`~/.vault-encrypted`.

---

## Files in this project

| File | Purpose |
|------|---------|
| `install.sh` | One-command installer (venv, udev, systemd user unit) |
| `setup_wizard.py` | First-time setup + config helpers |
| `vault_manager.py` | gocryptfs mount/unmount as the login user |
| `usb_monitor.py` | udev USB add/remove detection by serial hash |
| `tray_app.py` | System-tray UI + USB lock (headless-safe) |
| `vault_guardian.py` | Entry point launched by systemd/CLI |
| `vault-guardian.service` | systemd **user** service |
| `requirements.txt` | Python deps (no FUSE Python bindings) |

---

## Troubleshooting

**Unlock failed: bad password.**
The password is sent on stdin to gocryptfs, never argv. Re-enter it.

**Unlock failed because ~/Vault is not empty.**
Default mount uses `-nonempty`. Empty `~/Vault` yourself if a leftover
file still blocks, then unlock again.

**Tray icon does not appear.**
USB lock still works. `systemctl --user status vault-guardian`.
On GNOME you need the AppIndicator extension.

**Unplugging the USB key does nothing.**
`systemctl --user restart vault-guardian`. The monitor is the same process.

**Transport endpoint is not connected on `~/Vault`.**
Stale mount. Lock runs `fusermount3 -u` then `fusermount -u`, then `-u -z`.
Or: `fusermount3 -u ~/Vault`.

**NVIDIA Jetson: display died after an *old* install.**
Recover over SSH: `sudo apt install --reinstall nvidia-l4t-x11 nvidia-l4t-3d-core`.
Current `install.sh` holds `nvidia-l4t-*`, uses
`--no-upgrade --no-install-recommends`, and only udev-triggers USB/block.

---

## Uninstall

```bash
systemctl --user disable --now vault-guardian
rm -rf ~/.local/share/vault-guardian ~/.config/vault-guardian
rm -f ~/.config/systemd/user/vault-guardian.service
rm -f ~/.local/bin/vault-guardian ~/.local/bin/vault-guardian-setup
sudo rm -f /etc/udev/rules.d/99-vault-guardian.rules
```

Your encrypted data in `~/.vault-encrypted` is left untouched — delete it
yourself if you no longer need it (see **How to wipe**).
