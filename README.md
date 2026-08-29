# Vault Guardian

**A USB-gated, Unix-DAC encrypted vault for Linux — designed to keep an AI
agent (or any other process) running as *you* from reading your sensitive
files.**

Your secrets live in an encrypted folder that is only decrypted while a
specific USB key you registered is plugged in. Even while it is unlocked,
**your own login user cannot read `~/Vault`**. Only apps you launch through
the sgid helper `vault-exec` inherit group `vaultguard` and can open the
files. Pull the USB key — or click **Lock Now** in the tray — and the
plaintext instantly disappears.

This is a **DAC + sgid** design. It does **not** use unprivileged user
namespaces, nested FUSE, or fusepy. Those were unreliable on NVIDIA Jetson
Orin Nano (L4T).

---

## Why this exists

If an AI agent runs with the *same user account* as you, it has, in principle,
the same file permissions you do. Ordinary file mode bits on files you own
cannot help, because the agent *is* you.

Vault Guardian raises the bar with two independent gates:

1. **Possession gate (USB key):** the vault is encrypted with `gocryptfs`
   (AES-256-GCM). It is only mounted while your registered USB device is
   physically present. No key -> the files are ciphertext no one can read.
2. **Identity gate (Unix DAC + sgid helper):** the plaintext is mounted as
   system user `vaultguard`, mode `0750`, group `vaultguard`. **Your login
   user is never added to that group.** Human apps get the group *only* by
   being launched through `/usr/local/bin/vault-exec` (owner `root:vaultguard`,
   mode `2755` sgid). python / cat / Cursor running as you get `EACCES`.

The privileged bits are a **one-time sudo**. Day-to-day unlock/lock uses
`sudo -n -u vaultguard` on two no-argument wrappers (`mount` / `unmount`).

---

## How it works

```
   ~/.vault-encrypted/     ciphertext (roger-owned; ACL lets vaultguard read)
          |  sudo -n -u vaultguard /usr/local/libexec/vault-guardian/mount
          v
   ~/Vault/                plaintext, vaultguard:vaultguard 0750
          |  login user: EACCES
          |  vault-exec (sgid vaultguard) -> allowed app: group access
          v
   /usr/bin/evince etc.    only binaries listed in /etc/vault-guardian/allowed-apps
```

- Plug in your registered USB key -> tray icon turns **green**, `gocryptfs`
  mounts `~/Vault` as `vaultguard`.
- `ls ~/Vault` as yourself fails with Permission denied. **That is success.**
- Open files with the tray action **Open with allowed app...** (runs
  `/usr/local/bin/vault-exec <resolved-binary>` with no shell).
- Remove the key (or **Lock Now**, or suspend) -> tray turns **red**,
  `fusermount3 -u` as `vaultguard`. Unmount is enough: gocryptfs *is* the
  FUSE server.
- Existing `~/.vault-encrypted` is **kept**. Nothing here wipes ciphertext.

---

## Installation (Ubuntu / Jetson)

Python packages go into a **venv** at `~/.local/share/vault-guardian/venv`.

```bash
./install.sh
sudo ./install-privileged.sh
```

Run `./install.sh` as your **normal user**. Then run the privileged installer
**once** with sudo. It will **not** add you to group `vaultguard`.

On NVIDIA Jetson (L4T) both scripts hold every `nvidia-l4t-*` package,
refuse to upgrade or pull recommends, skip any apt action that would change
the display stack, and only udev-trigger USB/block. Do not `apt-get upgrade`
and do not touch `nvidia-l4t`.

### What `./install.sh` does

1. Jetson-safe apt: `gocryptfs`, fuse3/`fusermount3`, `python3` / `python3-venv`.
   GTK/AppIndicator only if they are not already importable.
   Does **not** install `libfuse2`. Skips `apparmor-utils` on tegra.
2. Copy the app to `~/.local/share/vault-guardian/` (including `vault-exec.c`
   and `install-privileged.sh`).
3. Create the venv and pip-install `pyudev`, `pystray`, `Pillow`,
   `cryptography` **into that venv only**.
4. Install launchers `vault-guardian` and `vault-guardian-setup`.
5. Install a udev rule (`/etc/udev/rules.d/99-vault-guardian.rules`).
6. Enable a systemd **user** service.
7. Run the first-time setup wizard.
8. Print: now run `sudo ./install-privileged.sh`.

### What `sudo ./install-privileged.sh` does (one-time)

1. `groupadd --system vaultguard` and `useradd --system` with nologin.
   **Never** `usermod -aG vaultguard` the login user.
2. Ensure `user_allow_other` in `/etc/fuse.conf`.
3. `mkdir -p ~/Vault`; `chown vaultguard:vaultguard`; `chmod 0750`.
4. ACL `u:vaultguard:rx` on `~/.vault-encrypted` (and default ACL). If `setfacl`
   is missing, falls back to `chmod 0750` with group `vaultguard`.
5. `/etc/sudoers.d/vault-guardian`: **only** the login user, NOPASSWD, absolute
   paths, argument-filtered:
   `gocryptfs -q -allow_other <cipher> <mount>` and
   `fusermount3 -u` / `-u -z` (and `fusermount` if present).
6. `gcc -O2 -Wall -Werror vault-exec.c -o /usr/local/bin/vault-exec`;
   `chown root:vaultguard`; `chmod 2755`. **Not** sgid Python.
7. Write `/etc/vault-guardian/allowed-apps` from config (resolved with
   `command -v` / `realpath`).
8. Install `gcc` / `acl` only if missing, using the same Jetson-safe apt
   (`--no-upgrade --no-install-recommends`, hold `nvidia-l4t-*`).

To rewrite the allowlist later:

```bash
sudo ./install-privileged.sh --sync-allowlist
```

(`sudo ./install.sh --privileged` is an alias for the same script.)

To have the tray run even when you are not logged in graphically:

```bash
sudo loginctl enable-linger "$USER"
```

### Manual venv (if you are not using install.sh)

```bash
sudo apt-get install -y python3 python3-venv python3-gi gir1.2-gtk-3.0 \
    gir1.2-appindicator3-0.1 gocryptfs fuse3 gcc acl
python3 -m venv --system-site-packages ~/.local/share/vault-guardian/venv
~/.local/share/vault-guardian/venv/bin/pip install -r requirements.txt
```

Then run `sudo ./install-privileged.sh`.

---

## First-time setup (registering your USB key)

The wizard (`vault-guardian-setup`) walks you through:

1. **Vault location and password.** Creates `~/.vault-encrypted` (or keeps it).
   Password is asked at every unlock — never stored.
2. **Pick your USB key.** Only a **SHA256 hash of the device serial** is stored.
3. **Allowed apps.** Defaults to
   `libreoffice, firefox, evince, gedit, kate` — resolved to absolute paths.
   No `code`, no `bash`, no `python`.
4. Tells you to run `sudo ./install-privileged.sh`. After that,
   `ls ~/Vault` as yourself will `EACCES` while unlocked. That is success.

Re-run any time with:

```bash
vault-guardian-setup
```

You can also change the USB key later from the tray menu -> **Change USB Key...**

---

## Using it day to day

Look for the padlock icon in your system tray:

| Menu item | What it does |
|-----------|--------------|
| status line | Shows whether the vault is Locked or Open |
| **Unlock Now** | Password dialog, then `sudo -n -u vaultguard gocryptfs` |
| **Lock Now** | `sudo -n -u vaultguard fusermount3 -u` (then `-u -z`) |
| **Open with allowed app...** | `vault-exec <resolved-binary>` (no shell) |
| **Allowed Apps...** | Edit the list; tries to update `/etc/vault-guardian/allowed-apps` |
| **Change USB Key...** | Register a different USB device |
| **View Access Log** | Opens `~/.local/share/vault-guardian/access.log` |
| **Quit** | Locks the vault and exits |

USB unplug-to-lock works even without a tray icon (headless).

If saving allowed apps cannot write the system file, a copy is stored at
`~/.config/vault-guardian/allowed-apps` and you need:

```bash
sudo ./install-privileged.sh --sync-allowlist
```

### Adding files to the vault

1. Unlock (plug in the key, enter the password).
2. Tray -> **Open with allowed app...** (file manager or editor on the allowlist).
3. Edit as normal. Data is encrypted into `~/.vault-encrypted`.
4. Lock when done (unplug). Only ciphertext remains on disk.

Do not `chmod ~/Vault` back to yourself. It must stay `vaultguard:vaultguard 0750`.

If an allowed app cannot write files that were created before the DAC
switch (they may still be mode `0644`), one-time as root after unlock:

```bash
sudo -u vaultguard chmod -R g+rwX ~/Vault
```

New files use umask `007` (group-readable, not world-readable). Old files are remapped with gocryptfs `-force_owner` so they are not owned by your login uid.

---

## Security model — and its honest limits

**What this stops well:**

- python / cat / Cursor / a shell running **as you** reading `~/Vault` -> `EACCES`
  (you are not in group `vaultguard`; the mount is `0750`).
- Direct reads of ciphertext when the USB key is absent — AES-256-GCM.
- Files lingering decrypted after unplug / Lock / suspend — lazy unmount.
- Opening `~/Vault` from Cursor or a terminal as yourself.

**Residual (be honest):**

- **Allowed app as oracle.** Anything on the allowlist can read the vault.
  Keep the list tiny. Do not add terminals, python, or IDEs.
- **Copies to `/tmp`.** An allowed app can export a copy outside `~/Vault`.
  Those copies are yours again.
- **Root bypass.** Root can switch to `vaultguard` or read the mount. This is
  same-user protection, not anti-root.
- **sgid is not a sandbox.** `vault-exec` only adds a group and execs a
  realpath-matched binary. It sanitizes `LD_*` / `PYTHON*` and related
  env vars; it does not confine the child. Children of an allowed app inherit
  `egid=vaultguard` (needed for LibreOffice helpers) — that is why `code` /
  `bash` / `python` are not defaults.
- **Password in your head, not on disk.** Auto-unlock blobs are wiped.

**Defense-in-depth:** for the highest-value secrets, a separate
network-limited machine is still stronger. This is the convenient middle
ground: USB-gated, DAC isolation, one-time sudo, works on Jetson.

AppArmor is optional and typically unusable on L4T. It is **not** called
from the unlock path.

---

## Files in this project

| File | Purpose |
|------|---------|
| `install.sh` | User-level installer (venv, udev, systemd). Prints run privileged. |
| `install-privileged.sh` | One-time sudo: vaultguard user, sgid helper, sudoers, ACLs |
| `vault-exec.c` | Tiny C sgid helper (never sgid Python) |
| `setup_wizard.py` | First-time setup + config/crypto helpers |
| `vault_manager.py` | gocryptfs mount/unmount as vaultguard (`sudo -n`) |
| `usb_monitor.py` | udev USB add/remove detection by serial hash |
| `tray_app.py` | System-tray UI + orchestration (headless USB lock) |
| `vault_guardian.py` | Entry point launched by systemd/CLI |
| `vault-guardian.service` | systemd **user** service |
| `requirements.txt` | Python deps (no FUSE Python bindings) |
| `tests/test_vault_exec.sh` | Compile + allow/deny smoke test |

---

## Troubleshooting

**Unlock failed / privileged helper is missing.**
Run `sudo ./install-privileged.sh`. Confirm `/etc/sudoers.d/vault-guardian`.

**Unlock failed: bad password.**
The password is sent on stdin to gocryptfs, never argv. Re-enter it.

**`ls ~/Vault` says Permission denied while unlocked.**
Success. Use **Open with allowed app...**.

**Tray icon does not appear.**
USB lock still works. `systemctl --user status vault-guardian`.
On GNOME you need the AppIndicator extension.

**Unplugging the USB key does nothing.**
`systemctl --user restart vault-guardian`. The monitor is the same process.

**Transport endpoint is not connected on `~/Vault`.**
Stale mount. Lock runs `fusermount3 -u` then `-u -z` as vaultguard.

**NVIDIA Jetson: display died after an *old* install.**
Recover over SSH: `sudo apt install --reinstall nvidia-l4t-x11 nvidia-l4t-3d-core`.
Current scripts hold `nvidia-l4t-*`, use `--no-upgrade --no-install-recommends`,
and only udev-trigger USB/block.

**FUSE allow_other errors.**
`install-privileged.sh` adds `user_allow_other` to `/etc/fuse.conf`.

---

## Uninstall

```bash
systemctl --user disable --now vault-guardian
rm -rf ~/.local/share/vault-guardian ~/.config/vault-guardian
rm -f ~/.config/systemd/user/vault-guardian.service
rm -f ~/.local/bin/vault-guardian ~/.local/bin/vault-guardian-setup
sudo rm -f /etc/udev/rules.d/99-vault-guardian.rules
sudo rm -f /etc/sudoers.d/vault-guardian
sudo rm -f /usr/local/bin/vault-exec
sudo rm -rf /etc/vault-guardian
```

Your encrypted data in `~/.vault-encrypted` is left untouched — delete it
yourself if you no longer need it (make sure you can decrypt it elsewhere
first if you want to keep the contents).
