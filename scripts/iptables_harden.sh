#!/bin/sh
# iptables_harden.sh
# POSIX-compliant iptables hardening script
# Detects iptables version and uses appropriate module syntax

# ─────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────

print_banner() {
    echo ""
    echo "========================================"
    echo "     iptables Hardening Script"
    echo "========================================"
    echo ""
}

print_section() {
    echo ""
    echo "--- $1 ---"
    echo ""
}

# Ask a yes/no question, return 0 for yes, 1 for no
ask_yn() {
    while true; do
        printf "%s [y/n]: " "$1"
        read answer
        case "$answer" in
            [Yy]*) return 0 ;;
            [Nn]*) return 1 ;;
            *) echo "Please answer y or n." ;;
        esac
    done
}

# ─────────────────────────────────────────────
# CHECK ROOT
# ─────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root or with sudo."
    exit 1
fi

# ─────────────────────────────────────────────
# CHECK IPTABLES IS AVAILABLE
# ─────────────────────────────────────────────

if ! command -v iptables > /dev/null 2>&1; then
    echo "Error: iptables not found. Install it and try again."
    exit 1
fi

print_banner

# ─────────────────────────────────────────────
# DETECT IPTABLES BACKEND
# Determines whether to use -m conntrack or -m state
# ─────────────────────────────────────────────

print_section "Detecting iptables version"

IPTABLES_VER=$(iptables --version 2>&1)
echo "Detected: $IPTABLES_VER"

# Test if conntrack module works
if iptables -m conntrack --ctstate ESTABLISHED -j ACCEPT -C INPUT > /dev/null 2>&1 || \
   iptables -m conntrack --ctstate ESTABLISHED -j ACCEPT -n > /dev/null 2>&1; then
    CONNTRACK_MODULE="conntrack"
    CONNTRACK_OPT="--ctstate"
else
    # Test state module as fallback
    if iptables -m state --state ESTABLISHED -j ACCEPT -C INPUT > /dev/null 2>&1 || \
       iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT > /dev/null 2>&1; then
        CONNTRACK_MODULE="state"
        CONNTRACK_OPT="--state"
        # Remove the test rule if it was added
        iptables -D INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT > /dev/null 2>&1
    else
        # Default: try conntrack, if it fails at apply time we will catch it
        CONNTRACK_MODULE="conntrack"
        CONNTRACK_OPT="--ctstate"
    fi
fi

echo "Using module: -m $CONNTRACK_MODULE $CONNTRACK_OPT"

# ─────────────────────────────────────────────
# BACKUP EXISTING RULES
# ─────────────────────────────────────────────

print_section "Checking existing iptables rules"

BACKUP_FILE="/tmp/iptables_backup_$(date +%Y%m%d_%H%M%S).rules"
EXISTING_RULES=$(iptables -L -n -v 2>&1)

# Check if any non-default rules exist
RULE_COUNT=$(iptables -L INPUT --line-numbers -n 2>/dev/null | grep -c "^[0-9]")
RULE_COUNT=${RULE_COUNT:-0}

if [ "$RULE_COUNT" -gt 0 ]; then
    echo "Existing rules found:"
    echo ""
    echo "$EXISTING_RULES"
    echo ""

    # Save backup
    if iptables-save > "$BACKUP_FILE" 2>/dev/null; then
        echo "Rules backed up to: $BACKUP_FILE"
    else
        echo "Warning: Could not save backup with iptables-save."
        echo "$EXISTING_RULES" > "$BACKUP_FILE"
        echo "Raw rules saved to: $BACKUP_FILE"
    fi

    echo ""
    if ask_yn "Flush existing rules and continue?"; then
        iptables -F
        iptables -X
        iptables -Z
        echo "Rules flushed."
    else
        echo "Aborted. Existing rules were not changed."
        exit 0
    fi
else
    echo "No existing rules found. Continuing."
fi

# ─────────────────────────────────────────────
# APPLY BASE RULES
# ─────────────────────────────────────────────

print_section "Applying base rules"

# Flag to track if all rules applied successfully
# 1 = all good, 0 = one or more rules failed
RULES_OK=1

# Allow loopback in and out
iptables -A INPUT  -i lo -j ACCEPT \
    && echo "Added: INPUT  loopback ACCEPT" \
    || { echo "Failed: INPUT loopback"; RULES_OK=0; }

iptables -A OUTPUT -o lo -j ACCEPT \
    && echo "Added: OUTPUT loopback ACCEPT" \
    || { echo "Failed: OUTPUT loopback"; RULES_OK=0; }

# Allow established/related connections
iptables -A INPUT -m "$CONNTRACK_MODULE" "$CONNTRACK_OPT" ESTABLISHED,RELATED -j ACCEPT \
    && echo "Added: ESTABLISHED,RELATED ACCEPT (module: $CONNTRACK_MODULE)" \
    || { echo "Failed: ESTABLISHED,RELATED rule — try switching iptables backend"; RULES_OK=0; }

# ─────────────────────────────────────────────
# OPEN PORTS
# ─────────────────────────────────────────────

print_section "Opening ports"

# Always allow SSH on port 22
iptables -A INPUT -p tcp --dport 22 -j ACCEPT \
    && echo "Added: SSH port 22 ACCEPT" \
    || { echo "Failed: port 22"; RULES_OK=0; }

# Ask for additional ports in a loop
while true; do
    if ask_yn "Do you want to open an additional port?"; then
        printf "Enter port number: "
        read PORT
        printf "Protocol (tcp/udp) [tcp]: "
        read PROTO
        PROTO=${PROTO:-tcp}
        PROTO=$(echo "$PROTO" | tr '[:upper:]' '[:lower:]')
        case "$PROTO" in
            tcp|udp) ;;
            *) echo "Invalid protocol '$PROTO'. Defaulting to tcp."; PROTO="tcp" ;;
        esac

        case "$PORT" in
            ''|*[!0-9]*)
                echo "Invalid port number. Skipping."
                ;;
            *)
                if [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; then
                    iptables -A INPUT -p "$PROTO" --dport "$PORT" -j ACCEPT \
                        && echo "Added: port $PORT/$PROTO ACCEPT" \
                        || { echo "Failed: port $PORT/$PROTO"; RULES_OK=0; }
                else
                    echo "Port must be between 1 and 65535. Skipping."
                fi
                ;;
        esac
    else
        break
    fi
done

# ─────────────────────────────────────────────
# DEFAULT DENY
# ─────────────────────────────────────────────

print_section "Default deny rule"

if [ "$RULES_OK" -eq 0 ]; then
    echo "ERROR: One or more rules failed to apply correctly."
    echo "Default DROP rule will NOT be added to avoid locking you out."
    echo "Review the failed rules above and rerun the script."
else
    echo "Warning: Adding a default deny INPUT rule will block all traffic"
    echo "not explicitly allowed above. Make sure your SSH session is working"
    echo "in a second terminal before proceeding."
    echo ""

    if ask_yn "Add default DROP rule for INPUT?"; then
        iptables -A INPUT -j DROP && echo "Added: INPUT default DROP" || echo "Failed: INPUT DROP"
    else
        echo "Skipped: no default DROP rule added."
    fi
fi

# ─────────────────────────────────────────────
# SHOW FINAL RULES
# ─────────────────────────────────────────────

print_section "Final iptables rules"

iptables -L -n -v

echo ""
echo "========================================"
if [ "$RULES_OK" -eq 0 ]; then
    echo "  COMPLETED WITH ERRORS."
    echo "  One or more rules failed — review output above."
    echo "  Default DROP was NOT applied."
else
    echo "  Done. All rules applied successfully."
fi
echo "  Rules are NOT persistent."
echo "  Backup saved to: $BACKUP_FILE"
echo "========================================"
echo ""
