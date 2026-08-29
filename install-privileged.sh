#!/usr/bin/env bash
#
# install-privileged.sh - one-time root setup for Vault Guardian (DAC)
#
# Creates system user/group vaultguard, the sgid vault-exec helper,
# sudoers rules so the login user can mount/unmount as vaultguard, and
# the /etc/vault-guardian allowlist.
#
# MUST NOT add the login user to group vaultguard.
# MUST NOT sgid Python.
#
# Run once after ./install.sh:
#   sudo ./install-privileged.sh
#
# To rewrite the allowlist later:
#   sudo ./install-privileged.sh --sync-allowlist
#
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()   { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }

if [[ "${EUID}" -ne 0 ]]; then
    err "Run as: sudo $0"
    exit 1
fi

SYNC_ONLY=0
if [[ "${1:-}" == "--sync-allowlist" ]]; then
    SYNC_ONLY=1
    shift
fi

# ---------------------------------------------------------------------------
# Jetson / L4T: never upgrade nvidia-l4t, never install recommends.
# ---------------------------------------------------------------------------
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
    apt-mark hold "${pkgs[@]}" >/dev/null || warn "apt-mark hold failed (continuing)"
}

apt_would_touch_tegra() {
    local sim
    sim="$(apt-get -s -o Debug::NoLocking=1 install --no-install-recommends --no-upgrade "$1" 2>/dev/null || true)"
    echo "$sim" | grep -qE '(^Inst |^Remv |^Purg )nvidia-l4t-'
}

safe_apt_install() {
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
    if apt-get install -y "${extra[@]}" "$p"; then
        return 0
    fi
    if [[ "$optional" == 1 ]]; then
        warn "could not install optional $p (continuing)"
    else
        warn "could not install $p"
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Identify the login user (the one who invoked sudo). NEVER add them to
# group vaultguard.
# ---------------------------------------------------------------------------
if [[ -z "${SUDO_USER:-}" || "${SUDO_USER}" == "root" ]]; then
    err "Run this from your login account: sudo $0"
    err "SUDO_USER must be the human who owns the vault, not root."
    exit 1
fi
LOGIN_USER="${SUDO_USER}"
LOGIN_HOME="$(getent passwd "${LOGIN_USER}" | cut -d: -f6)"
if [[ -z "${LOGIN_HOME}" || ! -d "${LOGIN_HOME}" ]]; then
    err "Cannot resolve home directory for ${LOGIN_USER}"
    exit 1
fi
LOGIN_UID="$(id -u "${LOGIN_USER}")"
LOGIN_GID="$(id -g "${LOGIN_USER}")"

ENC="${LOGIN_HOME}/.vault-encrypted"
MOUNT="${LOGIN_HOME}/Vault"
ALLOWLIST_DIR="/etc/vault-guardian"
ALLOWLIST="${ALLOWLIST_DIR}/allowed-apps"
SUDOERS="/etc/sudoers.d/vault-guardian"
VAULT_EXEC="/usr/local/bin/vault-exec"
CFG="${LOGIN_HOME}/.config/vault-guardian/config.json"
USER_ALLOWLIST="${LOGIN_HOME}/.config/vault-guardian/allowed-apps"

info "Privileged install for login user ${LOGIN_USER} (${LOGIN_HOME})"

install_build_deps() {
    if ! command -v apt-get >/dev/null 2>&1; then
        return 0
    fi
    if is_tegra; then
        hold_tegra_stack
        info "Jetson/L4T: will not upgrade existing packages or pull recommends"
    fi
    if ! command -v gcc >/dev/null 2>&1 || ! pkg_installed acl; then
        apt-get update -y || warn "apt update failed (continuing)"
    fi
    if ! command -v gcc >/dev/null 2>&1; then
        safe_apt_install gcc 0 || true
        safe_apt_install build-essential 1 || true
    fi
    if ! command -v setfacl >/dev/null 2>&1; then
        safe_apt_install acl 1 || true
    fi
}

ensure_vaultguard_ids() {
    getent group vaultguard >/dev/null 2>&1 || groupadd --system vaultguard
    if ! getent passwd vaultguard >/dev/null 2>&1; then
        local nologin=/usr/sbin/nologin
        [[ -x "${nologin}" ]] || nologin=/sbin/nologin
        useradd --system --gid vaultguard --home-dir /nonexistent \
            --shell "${nologin}" vaultguard
    fi
    # Belt and suspenders: never add the login user to this group.
    if id -nG "${LOGIN_USER}" | tr ' ' '\n' | grep -qx vaultguard; then
        err "Refusing to continue: ${LOGIN_USER} is in group vaultguard."
        err "Remove them with: gpasswd -d ${LOGIN_USER} vaultguard"
        err "The whole point is that only vault-exec (sgid) grants the group."
        exit 1
    fi
    ok "system user/group vaultguard ready (login user is NOT a member)"
}

ensure_fuse_allow_other() {
    local conf=/etc/fuse.conf
    touch "${conf}"
    if grep -qE '^[[:space:]]*user_allow_other' "${conf}"; then
        ok "user_allow_other already set in ${conf}"
        return 0
    fi
    printf '\n# Vault Guardian: gocryptfs -allow_other as user vaultguard\nuser_allow_other\n' >> "${conf}"
    ok "enabled user_allow_other in ${conf}"
}

fix_vault_dirs() {
    mkdir -p "${MOUNT}"
    chown vaultguard:vaultguard "${MOUNT}"
    chmod 0750 "${MOUNT}"
    ok "${MOUNT} -> vaultguard:vaultguard 0750"

    mkdir -p "${ENC}"
    chown "${LOGIN_UID}:${LOGIN_GID}" "${ENC}"
    chmod 0700 "${ENC}"

    if command -v setfacl >/dev/null 2>&1; then
        # vaultguard must read ciphertext; login user stays owner.
        setfacl -m u:vaultguard:rx "${ENC}" || warn "setfacl on ${ENC} failed"
        setfacl -d -m u:vaultguard:rx "${ENC}" || true
        # If $HOME is 0700, vaultguard cannot even reach ENC.
        setfacl -m u:vaultguard:x "${LOGIN_HOME}" || true
        ok "ACL: vaultguard can read ${ENC}"
    else
        chown "${LOGIN_UID}:vaultguard" "${ENC}"
        chmod 0750 "${ENC}"
        warn "acl package missing; ${ENC} is ${LOGIN_USER}:vaultguard 0750"
        warn "Install 'acl' and re-run for a user-ACL instead of group-read."
    fi
}

LIBEXEC="/usr/local/libexec/vault-guardian"
MOUNT_HELPER="${LIBEXEC}/mount"
UNMOUNT_HELPER="${LIBEXEC}/unmount"

write_mount_helpers() {
    local gocryptfs fusermount vg_uid vg_gid
    gocryptfs="$(command -v gocryptfs || true)"
    [[ -x /usr/bin/gocryptfs ]] && gocryptfs=/usr/bin/gocryptfs
    fusermount=""
    [[ -x /usr/bin/fusermount3 ]] && fusermount=/usr/bin/fusermount3
    [[ -z "${fusermount}" && -x /usr/bin/fusermount ]] && fusermount=/usr/bin/fusermount
    if [[ -z "${gocryptfs}" ]]; then
        err "gocryptfs not found. Install it first (./install.sh)."
        exit 1
    fi
    if [[ -z "${fusermount}" ]]; then
        err "fusermount3/fusermount not found. Install fuse3 first."
        exit 1
    fi
    vg_uid="$(id -u vaultguard)"
    vg_gid="$(id -g vaultguard)"
    mkdir -p "${LIBEXEC}"
    # Fixed paths, no argv. umask 007 so files are not world-readable.
    # -force_owner remaps old login-user inodes so DAC cannot see them as owner.
    cat > "${MOUNT_HELPER}" <<EOF
#!/bin/sh
# Generated by install-privileged.sh. Takes no arguments. Password on stdin.
umask 007
exec ${gocryptfs} -q -allow_other -force_owner ${vg_uid}:${vg_gid} -- ${ENC} ${MOUNT}
EOF
    cat > "${UNMOUNT_HELPER}" <<EOF
#!/bin/sh
# Generated by install-privileged.sh. Takes no arguments.
${fusermount} -u ${MOUNT} >/dev/null 2>&1 || true
exec ${fusermount} -u -z ${MOUNT}
EOF
    chmod 0755 "${MOUNT_HELPER}" "${UNMOUNT_HELPER}"
    chown root:root "${MOUNT_HELPER}" "${UNMOUNT_HELPER}"
    ok "installed ${MOUNT_HELPER} and ${UNMOUNT_HELPER}"
}

write_sudoers() {
    local tmp
    tmp="$(mktemp)"
    {
        echo "# Vault Guardian - generated by install-privileged.sh"
        echo "# Login user may mount/unmount ONLY as vaultguard, NOPASSWD."
        echo "# Wrappers take no arguments (paths baked in)."
        echo "# Do NOT add ${LOGIN_USER} to group vaultguard."
        echo "${LOGIN_USER} ALL=(vaultguard) NOPASSWD: ${MOUNT_HELPER}"
        echo "${LOGIN_USER} ALL=(vaultguard) NOPASSWD: ${UNMOUNT_HELPER}"
    } > "${tmp}"
    chmod 0440 "${tmp}"
    if command -v visudo >/dev/null 2>&1; then
        if ! visudo -c -f "${tmp}"; then
            err "visudo rejected sudoers fragment:"
            cat "${tmp}" >&2
            rm -f "${tmp}"
            exit 1
        fi
    fi
    install -m 0440 "${tmp}" "${SUDOERS}"
    rm -f "${tmp}"
    ok "wrote ${SUDOERS} (NOPASSWD, wrappers only)"
}

install_vault_exec() {
    local src="${SRC_DIR}/vault-exec.c"
    if [[ ! -f "${src}" ]]; then
        err "missing ${src}"
        exit 1
    fi
    if ! command -v gcc >/dev/null 2>&1; then
        err "gcc not found; cannot compile vault-exec"
        exit 1
    fi
    gcc -O2 -Wall -Werror -o "${VAULT_EXEC}" "${src}"
    chown root:vaultguard "${VAULT_EXEC}"
    chmod 2755 "${VAULT_EXEC}"
    ok "installed ${VAULT_EXEC} (root:vaultguard 2755 sgid)"
}

resolve_apps() {
    python3 - "$LOGIN_HOME" "$CFG" "$USER_ALLOWLIST" <<'PY'
import json, os, shutil, sys
home, cfg_path, user_al = sys.argv[1], sys.argv[2], sys.argv[3]
apps = ["libreoffice", "firefox", "evince", "gedit", "kate"]
if os.path.isfile(cfg_path):
    try:
        with open(cfg_path, encoding="utf-8") as fh:
            cfg = json.load(fh)
        apps = list(cfg.get("allowed_apps") or apps)
    except Exception:
        pass
if os.path.isfile(user_al):
    extra = []
    with open(user_al, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                extra.append(line)
    if extra:
        apps = extra
seen = set()
for a in apps:
    a = a.strip()
    if not a:
        continue
    path = a
    if not os.path.isabs(a):
        w = shutil.which(a)
        if not w:
            print(f"# missing: {a}", file=sys.stderr)
            continue
        path = w
    try:
        path = os.path.realpath(path)
    except OSError:
        pass
    if path in seen:
        continue
    if not os.path.isfile(path):
        print(f"# not a file: {path}", file=sys.stderr)
        continue
    seen.add(path)
    print(path)
    if path.endswith("/libreoffice") or path.endswith("/soffice"):
        for cand in (
            "/usr/lib/libreoffice/program/soffice.bin",
            "/usr/lib/libreoffice/program/soffice",
        ):
            if os.path.isfile(cand) and cand not in seen:
                seen.add(cand)
                print(os.path.realpath(cand))
PY
}

write_allowlist() {
    mkdir -p "${ALLOWLIST_DIR}"
    chmod 0755 "${ALLOWLIST_DIR}"
    local tmp
    tmp="$(mktemp)"
    {
        echo "# Vault Guardian allowed apps (absolute paths)"
        echo "# Regenerated by install-privileged.sh --sync-allowlist"
        resolve_apps
    } > "${tmp}"
    install -m 0640 -o root -g vaultguard "${tmp}" "${ALLOWLIST}"
    rm -f "${tmp}"
    ok "wrote ${ALLOWLIST}"
    cat "${ALLOWLIST}"
}

# ---------------------------------------------------------------------------
if [[ "${SYNC_ONLY}" -eq 1 ]]; then
    info "Syncing allowlist only"
    write_allowlist
    exit 0
fi

install_build_deps
ensure_vaultguard_ids
ensure_fuse_allow_other
fix_vault_dirs
write_mount_helpers
write_sudoers
install_vault_exec
write_allowlist

echo
ok "Privileged install complete."
echo
echo "The login user ${LOGIN_USER} is NOT in group vaultguard."
echo "Unlock from the tray (password on stdin to gocryptfs as vaultguard)."
echo "Open files with:  ${VAULT_EXEC} /usr/bin/evince ${MOUNT}"
echo "ls ${MOUNT} as ${LOGIN_USER} will get Permission denied — that is success."
echo
echo "Do not usermod -aG vaultguard ${LOGIN_USER}."
echo "Do not sgid Python."
