#!/usr/bin/env bash
#
# install.sh - user-level installer for Vault Guardian
#
# Installs system + Python dependencies, copies the app into
# ~/.local/share/vault-guardian, creates a Python venv there (so pip never
# touches the system interpreter), installs a systemd *user* service, sets up
# a udev rule, and runs the first-time setup wizard.
#
# Run as your NORMAL user (NOT root). sudo is used only for apt and the
# udev rule. There is no privileged helper, no vaultguard user, no
# vault-exec, no sudoers.
#
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${HOME}/.local/share/vault-guardian"
VENV_DIR="${APP_DIR}/venv"
BIN_DIR="${HOME}/.local/bin"
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
UDEV_RULE="/etc/udev/rules.d/99-vault-guardian.rules"

info()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()   { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }

if [[ "${EUID}" -eq 0 ]]; then
    err "Do not run this installer as root. Run it as your normal user."
    err "sudo is used only for apt and the udev rule."
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. System dependencies
# ---------------------------------------------------------------------------
# Jetson / L4T: a naive `apt-get update && apt-get install gtk/fuse/...` is a
# well-known way to remove nvidia-l4t-x11 / nvidia-l4t-3d-core and kill the
# display. Detect that board, hold every installed nvidia-l4t-* package, never
# upgrade, never install recommends, and skip anything whose dry-run would
# touch the NVIDIA stack.
is_tegra() {
    [[ -e /etc/nv_tegra_release ]] && return 0
    [[ -e /usr/lib/aarch64-linux-gnu/tegra ]] && return 0
    grep -qi tegra /proc/device-tree/compatible 2>/dev/null && return 0
    return 1
}

pkg_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

tegra_pkgs() {
    dpkg-query -W -f='${Package}\n' 2>/dev/null | grep -E '^nvidia-l4t-' || true
}

hold_tegra_stack() {
    local pkgs
    mapfile -t pkgs < <(tegra_pkgs)
    if ((${#pkgs[@]} == 0)); then
        return 0
    fi
    info "NVIDIA L4T detected: holding ${#pkgs[@]} nvidia-l4t packages so apt cannot change the display stack"
    sudo apt-mark hold "${pkgs[@]}" >/dev/null || warn "apt-mark hold failed (continuing)"
}

# True if a simulated install would install/remove/upgrade any nvidia-l4t-* pkg.
apt_would_touch_tegra() {
    local sim
    sim="$(apt-get -s -o Debug::NoLocking=1 install --no-install-recommends --no-upgrade "$1" 2>/dev/null || true)"
    echo "$sim" | grep -qE '(^Inst |^Remv |^Purg )nvidia-l4t-'
}

safe_apt_install() {
    # $1=package  $2=1 if optional
    local p="$1" optional="${2:-0}"
    if pkg_installed "$p"; then
        return 0
    fi
    if is_tegra && apt_would_touch_tegra "$p"; then
        warn "Skipping $p: apt would change nvidia-l4t display/kernel packages"
        return 1
    fi
    local extra=(--no-install-recommends)
    if is_tegra; then
        extra+=(--no-upgrade)
    fi
    if sudo apt-get install -y "${extra[@]}" "$p"; then
        return 0
    fi
    if [[ "$optional" == 1 ]]; then
        warn "could not install optional $p (continuing)"
    else
        warn "could not install $p"
    fi
    return 1
}

gtk_already_ok() {
    python3 -c 'import gi; gi.require_version("Gtk", "3.0"); from gi.repository import Gtk' 2>/dev/null
}

install_system_deps() {
    info "Installing system dependencies (needs sudo)..."
    if command -v apt-get >/dev/null 2>&1; then
        if is_tegra; then
            hold_tegra_stack
            info "Jetson/L4T: will not upgrade existing packages or pull recommends"
        fi
        sudo apt-get update -y || warn "apt update failed (continuing)"

        # Required for the vault itself. Do NOT install libfuse2/libfuse2t64
        # (no fusepy). Need gocryptfs + fuse3/fusermount3.
        # Do NOT install gcc, acl, apparmor-utils.
        safe_apt_install gocryptfs 0 || true
        if ! command -v fusermount3 >/dev/null 2>&1 && ! command -v fusermount >/dev/null 2>&1; then
            safe_apt_install fuse3 0 || safe_apt_install fuse 0 || true
        fi
        if ! command -v fusermount3 >/dev/null 2>&1; then
            safe_apt_install fuse3 1 || true
        fi
        safe_apt_install python3 0 || true
        safe_apt_install python3-pip 0 || true
        safe_apt_install python3-venv 0 || true

        # GTK / GI are only needed for the tray. Skip if they already import,
        # and treat them as optional so a missing appindicator cannot pull Mesa
        # over NVIDIA's GL stack.
        if gtk_already_ok; then
            ok "GTK/GI already usable; not installing desktop packages"
        else
            safe_apt_install python3-gi 1 || true
            safe_apt_install gir1.2-gtk-3.0 1 || true
        fi
        safe_apt_install gir1.2-ayatanaappindicator3-0.1 1 || \
            safe_apt_install gir1.2-appindicator3-0.1 1 || true

        # AppArmor is not used. Never install it on tegra; skip everywhere.
        if is_tegra; then
            info "Skipping apparmor-utils on Jetson (not used)"
        fi
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y gocryptfs fuse3 python3-pip python3-gobject \
            gtk3 libappindicator-gtk3 || \
            warn "some dnf packages missing"
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm gocryptfs fuse3 python-pip python-gobject \
            gtk3 libappindicator-gtk3 || warn "some pacman pkgs missing"
    else
        warn "Unknown distro. Please install manually: gocryptfs, fuse3, "
        warn "python3-gi, GTK3, libappindicator3, python3-venv."
    fi
    ok "System dependencies step complete."
}

# ---------------------------------------------------------------------------
# 2. Copy application files
# ---------------------------------------------------------------------------
write_launcher() {
    # $1=dest  $2=python target
    local dest="$1" target="$2"
    cat > "${dest}" <<LAUNCH
#!/usr/bin/env bash
# systemd --user often has empty DISPLAY. Infer a live session so the tray
# can start; the Python process still runs headless if none exists.
if [[ -z "\${DISPLAY:-}" && -z "\${WAYLAND_DISPLAY:-}" ]]; then
  runtime="\${XDG_RUNTIME_DIR:-/run/user/\$(id -u)}"
  [[ -S /tmp/.X11-unix/X0 ]] && export DISPLAY=:0
  [[ -S /tmp/.X11-unix/X1 && -z "\${DISPLAY:-}" ]] && export DISPLAY=:1
  for w in wayland-0 wayland-1 wayland-2; do
    if [[ -S "\$runtime/\$w" ]]; then
      export WAYLAND_DISPLAY="\$w"
      break
    fi
  done
fi
exec "${VENV_DIR}/bin/python" "${APP_DIR}/${target}" "\$@"
LAUNCH
    chmod 0755 "${dest}"
}

copy_app() {
    info "Installing application to ${APP_DIR}"
    mkdir -p "${APP_DIR}" "${BIN_DIR}"
    for f in vault_guardian.py tray_app.py setup_wizard.py vault_manager.py \
             usb_monitor.py requirements.txt README.md vault-guardian.service; do
        if [[ ! -f "${SRC_DIR}/${f}" ]]; then
            warn "missing ${f} (skipping)"
            continue
        fi
        install -m 0644 "${SRC_DIR}/${f}" "${APP_DIR}/${f}"
    done
    chmod 0755 "${APP_DIR}/vault_guardian.py" \
               "${APP_DIR}/tray_app.py" \
               "${APP_DIR}/setup_wizard.py" \
               "${APP_DIR}/vault_manager.py" \
               "${APP_DIR}/usb_monitor.py"

    write_launcher "${BIN_DIR}/vault-guardian" "vault_guardian.py"
    cat > "${BIN_DIR}/vault-guardian-setup" <<SETUP
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/python" "${APP_DIR}/setup_wizard.py" "\$@"
SETUP
    chmod 0755 "${BIN_DIR}/vault-guardian-setup"
    ok "Application files installed."

    case ":${PATH}:" in
        *":${BIN_DIR}:"*) : ;;
        *) warn "Add ${BIN_DIR} to your PATH: echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc" ;;
    esac
}

# ---------------------------------------------------------------------------
# 3. Python venv (never pip --user / --break-system-packages)
# ---------------------------------------------------------------------------
install_python_deps() {
    info "Creating Python venv at ${VENV_DIR} (keeps system Python clean)..."
    if ! python3 -m venv --help >/dev/null 2>&1; then
        err "python3-venv is not available. On Ubuntu: sudo apt-get install python3-venv"
        exit 1
    fi
    python3 -m venv --system-site-packages "${VENV_DIR}"
    local pip="${VENV_DIR}/bin/pip"
    local py="${VENV_DIR}/bin/python"
    "${py}" -m pip install --upgrade pip
    "${pip}" install -r "${SRC_DIR}/requirements.txt"
    ok "Python dependencies installed into the venv."
}

# ---------------------------------------------------------------------------
# 4. udev rule
# ---------------------------------------------------------------------------
install_udev_rule() {
    info "Installing udev rule (needs sudo) so USB events wake the monitor..."
    local tmp
    tmp="$(mktemp)"
    cat > "${tmp}" <<'RULE'
# Vault Guardian: tag USB storage / devices so the user monitor is notified.
# The tray app uses pyudev netlink monitoring; this rule simply ensures udev
# processes USB add/remove events promptly for all users.
ACTION=="add|remove", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", TAG+="vault_guardian"
ACTION=="add|remove", SUBSYSTEM=="usb", TAG+="vault_guardian"
RULE
    if sudo install -m 0644 "${tmp}" "${UDEV_RULE}"; then
        sudo udevadm control --reload-rules || true
        # Never `udevadm trigger` with no filter: that replays EVERY device,
        # including DRM/display on Jetson, and can drop the video output.
        sudo udevadm trigger --subsystem-match=usb --action=add || true
        sudo udevadm trigger --subsystem-match=block --action=add || true
        ok "udev rule installed."
    else
        warn "Could not install udev rule; USB monitoring still works via "
        warn "netlink but this rule improves responsiveness."
    fi
    rm -f "${tmp}"
}

# ---------------------------------------------------------------------------
# 5. systemd user service
# ---------------------------------------------------------------------------
install_service() {
    info "Installing systemd user service..."
    mkdir -p "${SYSTEMD_USER_DIR}"
    install -m 0644 "${SRC_DIR}/vault-guardian.service" \
        "${SYSTEMD_USER_DIR}/vault-guardian.service"
    systemctl --user daemon-reload || warn "systemctl --user daemon-reload failed"
    systemctl --user reset-failed vault-guardian.service 2>/dev/null || true
    systemctl --user enable vault-guardian.service || \
        warn "could not enable service (no user systemd session?)"
    systemctl --user restart vault-guardian.service || \
        warn "could not start service yet; it will start on next login"
    ok "Service installed."
    info "USB unplug-to-lock works even without a tray icon (headless)."
}

# ---------------------------------------------------------------------------
# 6. First-time setup wizard
# ---------------------------------------------------------------------------
run_setup() {
    info "Launching first-time setup wizard..."
    local py="${VENV_DIR}/bin/python"
    if [[ -t 0 ]]; then
        "${py}" "${APP_DIR}/setup_wizard.py" || \
            warn "Setup wizard exited early; run 'vault-guardian-setup' later."
    else
        warn "No interactive terminal detected. Run 'vault-guardian-setup' "
        warn "in a terminal to create your vault and register your USB key."
        "${py}" "${APP_DIR}/setup_wizard.py" --non-interactive || true
    fi
}

# ---------------------------------------------------------------------------
main() {
    echo "=================================================="
    echo "  Vault Guardian installer"
    echo "=================================================="
    install_system_deps
    copy_app
    install_python_deps
    install_udev_rule
    install_service
    run_setup
    echo
    ok "Installation complete."
    echo
    echo "Then:"
    echo "  1. Start it:   systemctl --user start vault-guardian"
    echo "     (or just:   vault-guardian )"
    echo "  2. Look for the padlock icon in your system tray."
    echo "  3. Plug the USB key, type the password, use ~/Vault normally."
    echo "  4. Unplug the USB key to lock."
    echo
    echo "While unlocked, any process running as you can read ~/Vault."
    echo "USB + password is the gate."
    echo
    echo "Python packages live in ${VENV_DIR} (not system Python)."
    echo "Read the README for the security model and its honest limits."
}

main "$@"
