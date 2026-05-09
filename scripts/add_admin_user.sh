#!/bin/sh
# add_admin_user.sh
# POSIX-compliant script to add admin users for cyber competition sysadmin work.
# Detects available admin groups and adds each user to them.

# --- Admin groups to check (order doesn't matter) ---
CANDIDATE_GROUPS="sudo wheel admin adm systemd-journal docker lxd libvirt disk storage plugdev"

# --- Preferred shell: bash if available, fallback to /bin/sh ---
if command -v bash > /dev/null 2>&1; then
    LOGIN_SHELL="$(command -v bash)"
else
    LOGIN_SHELL="/bin/sh"
fi

# --------------------------------------------------------
# Helpers
# --------------------------------------------------------

# Print to stderr
err() { printf '[ERROR] %s\n' "$*" >&2; }

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "This script must be run as root (or via sudo)."
        exit 1
    fi
}

# Build the list of groups that actually exist on this system
build_group_list() {
    AVAILABLE_GROUPS=""
    for g in $CANDIDATE_GROUPS; do
        if getent group "$g" > /dev/null 2>&1; then
            AVAILABLE_GROUPS="$AVAILABLE_GROUPS $g"
        fi
    done
    # Trim leading space
    AVAILABLE_GROUPS="${AVAILABLE_GROUPS# }"
}

# Prompt for a non-empty value; result stored in REPLY
prompt_required() {
    label="$1"
    REPLY=""
    while [ -z "$REPLY" ]; do
        printf '%s: ' "$label"
        read -r REPLY
        [ -z "$REPLY" ] && printf 'Value cannot be empty. Try again.\n'
    done
}

# Add a single admin user
add_user() {
    username="$1"

    # ---- Check username doesn't already exist ----
    if id "$username" > /dev/null 2>&1; then
        err "User '$username' already exists. Skipping."
        return 1
    fi

    # ---- Create user with home directory ----
    # useradd is not POSIX, but it's universal on Linux.
    # -m  = create home dir
    # -s  = login shell
    if useradd -m -s "$LOGIN_SHELL" "$username"; then
        printf '[OK] User "%s" created.\n' "$username"
    else
        err "Failed to create user '$username'."
        return 1
    fi

    # ---- Set password interactively via passwd ----
    printf 'Setting password for "%s" (you will be prompted twice):\n' "$username"
    if passwd "$username"; then
        printf '[OK] Password set for "%s".\n' "$username"
    else
        err "passwd failed for '$username'. Set it manually: passwd $username"
    fi

    # ---- Add to all available admin groups ----
    if [ -z "$AVAILABLE_GROUPS" ]; then
        printf '[WARN] No known admin groups found on this system.\n'
    else
        for grp in $AVAILABLE_GROUPS; do
            if usermod -aG "$grp" "$username" 2>/dev/null; then
                printf '[OK]   Added "%s" to group "%s".\n' "$username" "$grp"
            else
                err "Could not add '$username' to group '$grp'."
            fi
        done
    fi

    printf '\n[DONE] Admin user "%s" fully configured.\n' "$username"
    printf '       Groups: %s\n\n' "$(id -Gn "$username")"
}

# --------------------------------------------------------
# Main
# --------------------------------------------------------

check_root
build_group_list

printf '\n=== Admin User Creation Script ===\n'
printf 'Login shell for new users: %s\n' "$LOGIN_SHELL"
if [ -n "$AVAILABLE_GROUPS" ]; then
    printf 'Admin groups found on this system: %s\n\n' "$AVAILABLE_GROUPS"
else
    printf '[WARN] None of the known admin groups were found.\n\n'
fi

while true; do
    prompt_required "Enter username"
    USERNAME="$REPLY"

    add_user "$USERNAME"

    printf 'Add another admin user? [y/N]: '
    read -r AGAIN
    case "$AGAIN" in
        [Yy]|[Yy][Ee][Ss])
            printf '\n'
            continue
            ;;
        *)
            break
            ;;
    esac
done

printf '=== All done. Review users with: cut -d: -f1 /etc/passwd ===\n'
