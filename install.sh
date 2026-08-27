#!/usr/bin/env bash
#
# install.sh - one-command installer for Vault Guardian
#
# Installs system + Python dependencies, copies the app into
# ~/.local/share/vault-guardian, installs a systemd *user* service, sets up
# a udev rule, and runs the first-time setup wizard.
#
# Run as your NORMAL user (NOT root). It will call sudo only for the few
# steps that genuinely need it (apt install, udev rule, optional AppArmor).
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${HOME}/.local/share/vault-guardian"
BIN_DIR="${HOME}/.local/bin"
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
UDEV_RULE="/etc/udev/rules.d/99-vault-guardian.rules"

info()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()   { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }

if [[ "${EUID}" -eq 0 ]]; then
    err "Do not run this installer as root. Run it as your normal user."
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. System dependencies
# ---------------------------------------------------------------------------
install_system_deps() {
    info "Installing system dependencies (needs sudo)..."
    local pkgs=(
        gocryptfs
        fuse
        python3
        python3-pip
        python3-venv
        python3-gi
        gir1.2-appindicator3-0.1
        gir1.2-gtk-3.0
        apparmor-utils
    )
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -y || warn "apt update failed (continuing)"
        # Install what we can; don't abort if one optional pkg is missing.
        for p in "${pkgs[@]}"; do
            if ! dpkg -s "$p" >/dev/null 2>&1; then
                sudo apt-get install -y "$p" || warn "could not install $p"
            fi
        done
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y gocryptfs fuse python3-pip python3-gobject \
            gtk3 libappindicator-gtk3 apparmor-utils || \
            warn "some dnf packages missing"
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm gocryptfs fuse2 python-pip python-gobject \
            gtk3 libappindicator-gtk3 apparmor || warn "some pacman pkgs missing"
    else
        warn "Unknown distro. Please install manually: gocryptfs, fuse, "
        warn "python3-gi, GTK3, libappindicator3, apparmor-utils."
    fi
    ok "System dependencies step complete."
}

# ---------------------------------------------------------------------------
# 2. Python dependencies (user install)
# ---------------------------------------------------------------------------
install_python_deps() {
    info "Installing Python dependencies (pip --user)..."
    python3 -m pip install --user --upgrade pip >/dev/null 2>&1 || true
    if ! python3 -m pip install --user -r "${SRC_DIR}/requirements.txt"; then
        warn "pip --user failed; retrying with --break-system-packages"
        python3 -m pip install --user --break-system-packages \
            -r "${SRC_DIR}/requirements.txt"
    fi
    ok "Python dependencies installed."
}

# ---------------------------------------------------------------------------
# 3. Copy application files
# ---------------------------------------------------------------------------
copy_app() {
    info "Installing application to ${APP_DIR}"
    mkdir -p "${APP_DIR}" "${BIN_DIR}"
    for f in vault_guardian.py tray_app.py setup_wizard.py vault_manager.py \
             usb_monitor.py apparmor_manager.py no_sudo_fuse_guard.py mountns.py \
             requirements.txt README.md; do
        install -m 0644 "${SRC_DIR}/${f}" "${APP_DIR}/${f}"
    done
    # Executables
    chmod 0755 "${APP_DIR}/vault_guardian.py" \
               "${APP_DIR}/tray_app.py" \
               "${APP_DIR}/setup_wizard.py" \
               "${APP_DIR}/no_sudo_fuse_guard.py" \
               "${APP_DIR}/vault_manager.py" \
               "${APP_DIR}/usb_monitor.py" \
               "${APP_DIR}/apparmor_manager.py"

    # Convenience launchers on PATH.
    cat > "${BIN_DIR}/vault-guardian" <<EOF
#!/usr/bin/env bash
exec python3 "${APP_DIR}/vault_guardian.py" "\$@"
EOF
    cat > "${BIN_DIR}/vault-guardian-setup" <<EOF
#!/usr/bin/env bash
exec python3 "${APP_DIR}/setup_wizard.py" "\$@"
EOF
    chmod 0755 "${BIN_DIR}/vault-guardian" "${BIN_DIR}/vault-guardian-setup"
    ok "Application files installed."

    case ":${PATH}:" in
        *":${BIN_DIR}:"*) : ;;
        *) warn "Add ${BIN_DIR} to your PATH: echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc" ;;
    esac
}

# ---------------------------------------------------------------------------
# 4. udev rule
# ---------------------------------------------------------------------------
install_udev_rule() {
    info "Installing udev rule (needs sudo) so USB events wake the monitor..."
    local tmp
    tmp="$(mktemp)"
    cat > "${tmp}" <<'EOF'
# Vault Guardian: tag USB storage / devices so the user monitor is notified.
# The tray app uses pyudev netlink monitoring; this rule simply ensures udev
# processes USB add/remove events promptly for all users.
ACTION=="add|remove", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", TAG+="vault_guardian"
ACTION=="add|remove", SUBSYSTEM=="usb", TAG+="vault_guardian"
EOF
    if sudo install -m 0644 "${tmp}" "${UDEV_RULE}"; then
        sudo udevadm control --reload-rules || true
        sudo udevadm trigger || true
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
    systemctl --user enable vault-guardian.service || \
        warn "could not enable service (no user systemd session?)"
    ok "Service installed. It will start on next login."
    info "Tip: enable lingering so it runs without an active login:"
    info "     sudo loginctl enable-linger ${USER}"
}

# ---------------------------------------------------------------------------
# 6. First-time setup wizard
# ---------------------------------------------------------------------------
run_setup() {
    info "Launching first-time setup wizard..."
    if [[ -t 0 ]]; then
        python3 "${APP_DIR}/setup_wizard.py" || \
            warn "Setup wizard exited early; run 'vault-guardian-setup' later."
    else
        warn "No interactive terminal detected. Run 'vault-guardian-setup' "
        warn "in a terminal to create your vault and register your USB key."
        python3 "${APP_DIR}/setup_wizard.py" --non-interactive || true
    fi
}

# ---------------------------------------------------------------------------
main() {
    echo "=================================================="
    echo "  Vault Guardian installer"
    echo "=================================================="
    install_system_deps
    install_python_deps
    copy_app
    install_udev_rule
    install_service
    run_setup
    echo
    ok "Installation complete."
    echo
    echo "Next steps:"
    echo "  1. Start it now:   systemctl --user start vault-guardian"
    echo "     (or just run:   vault-guardian )"
    echo "  2. Look for the padlock icon in your system tray."
    echo "  3. Put files into your vault by opening ~/Vault while unlocked."
    echo
    echo "Read the README for the security model and its honest limits."
}

main "$@"
