#!/bin/sh

# ==============================================================================
# VPN LOG ANALYZER v1.3.2 (AUTO-DETECT LOG)
# Features:
# - LOG SOURCE: Automatically switches between vpn.log and messages.
# - INTERACTIVE: Echoes status to terminal.
# - SYNC: Restores IPs from local file to RAM.
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# --- PATHS ---
# Auto-detect Log Source based on Keentool Modular Logging
if [ -f "/opt/var/log/vpn.log" ]; then
    LOG_FILE="/opt/var/log/vpn.log"
    echo -e " -> Mode: ${GREEN}Modular Log${RESET} (Reading vpn.log)"
else
    LOG_FILE="/opt/var/log/messages"
    echo -e " -> Mode: ${YELLOW}Standard Log${RESET} (Reading messages)"
fi

BANNED_IPS_FILE="/opt/etc/vpn_banned_ips.txt"
DIFF_FILE_VPN="/opt/etc/firewall_vpn_diff.dat"

IPSET_VPN="VPNBlock"
IPSET_MAIN="FirewallBlock"
LOG_TAG="VPN_Blocker"

# Regex for Attack Patterns
# 1. TLS Error (OpenVPN)
# 2. Bad Packet Length (WireGuard/OpenVPN overflow)
SEARCH_PATTERN='TLS handshake failed|Bad encapsulated packet length'

# Colors
ESC=$(printf '\033')
RESET="${ESC}[0m"
BOLD="${ESC}[1m"
RED="${ESC}[31m"; GREEN="${ESC}[32m"; YELLOW="${ESC}[33m"; CYAN="${ESC}[36m"

# Counters
CNT_RESTORED=0
CNT_OPTIMIZED=0
CNT_BANNED=0
CNT_SKIPPED=0

# Init
touch "$BANNED_IPS_FILE"
echo -e "${BOLD}=== VPN Security Scanner v1.3.2 ===${RESET}"

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}Error: Log file not found ($LOG_FILE).${RESET}"
    logger -t "${LOG_TAG}" "Error: Log file missing."
    exit 1
fi

# ==============================================================================
# 1. RESTORE PERSISTENT BANS (File -> RAM)
# ==============================================================================
echo -n " -> Syncing persistent bans... "
if [ -s "$BANNED_IPS_FILE" ]; then
    # Filter valid IPs only to avoid garbage
    VALID_IPS=$(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$BANNED_IPS_FILE" | sort -u)
    
    IFS=$'\n'
    for IP in $VALID_IPS; do
        # Check Main Firewall First (Optimization)
        if ipset test "$IPSET_MAIN" "$IP" 2>/dev/null; then
            CNT_OPTIMIZED=$((CNT_OPTIMIZED + 1))
            continue
        fi
        
        # Check/Add to VPN Set
        if ! ipset test "$IPSET_VPN" "$IP" 2>/dev/null; then
            ipset add "$IPSET_VPN" "$IP" 2>/dev/null
            CNT_RESTORED=$((CNT_RESTORED + 1))
        fi
    done
    unset IFS
fi
echo "Done."

# ==============================================================================
# 2. SCAN LOGS FOR NEW THREATS
# ==============================================================================
echo -n " -> Scanning logs for threats... "

# Extract IPs from Log lines matching the pattern
# Grep logic: Find pattern -> Extract IP using regex
ATTACKER_IPS=$(grep -E "$SEARCH_PATTERN" "$LOG_FILE" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)

if [ -n "$ATTACKER_IPS" ]; then
    echo ""
    for IP in $ATTACKER_IPS; do
        # 1. Check if already Global Banned (Skip)
        if ipset test "$IPSET_MAIN" "$IP" 2>/dev/null; then
            echo -e "    - $IP: ${CYAN}Global Blocked${RESET}"
            continue
        fi
        
        # 2. Check if already VPN Banned
        if ipset test "$IPSET_VPN" "$IP" 2>/dev/null; then
            echo -e "    - $IP: ${YELLOW}Already Banned${RESET}"
            CNT_SKIPPED=$((CNT_SKIPPED + 1))
        else
            # 3. BAN HAMMER
            echo -e "    - $IP: ${RED}BANNING${RESET}"
            
            # Add to RAM
            ipset add "$IPSET_VPN" "$IP" 2>/dev/null
            
            # Add to Persistent File (if not present)
            if ! grep -q "$IP" "$BANNED_IPS_FILE"; then
                echo "$IP" >> "$BANNED_IPS_FILE"
            fi
            
            # Kill active states
            ndmc -c "show ip hotspot" | grep -B 5 "$IP" | grep "mac" | awk '{print $3}' | tr -d ',' | while read MAC; do
                [ -n "$MAC" ] && ndmc -c "ip hotspot disconnect $MAC" >/dev/null 2>&1
            done
            
            # Log action
            logger -t "${LOG_TAG}" "ACTION: Banned IP $IP (VPN Attack)"
            
            CNT_BANNED=$((CNT_BANNED + 1))
        fi
    done
else
    echo -e "${GREEN}Clean.${RESET}"
fi

# ==============================================================================
# 3. DASHBOARD UPDATE & SUMMARY
# ==============================================================================
if [ "$CNT_BANNED" -gt 0 ]; then
    CURRENT_DIFF=0
    if [ -f "$DIFF_FILE_VPN" ]; then
        VAL=$(cat "$DIFF_FILE_VPN"); case "$VAL" in ''|*[!0-9+\-]*) VAL=0 ;; esac
        CURRENT_DIFF="$VAL"
    fi
    NEW_DIFF=$((CURRENT_DIFF + CNT_BANNED))
    if [ "$NEW_DIFF" -ge 0 ]; then SIGN="+"; else SIGN=""; fi
    echo "${SIGN}${NEW_DIFF}" > "$DIFF_FILE_VPN"
fi

# Visual Summary
echo -e "-----------------------------------"
echo -e " ${BOLD}Summary:${RESET}"
echo -e "  - RAM Restored : ${GREEN}${CNT_RESTORED}${RESET}"
echo -e "  - Optimized    : ${CYAN}${CNT_OPTIMIZED}${RESET} (Handled by Global)"
echo -e "  - Skipped      : ${YELLOW}${CNT_SKIPPED}${RESET} (Already Blocked)"
echo -e "  - New Bans     : ${RED}${CNT_BANNED}${RESET}"
echo -e "-----------------------------------"

# System Log Summary (Always log if there was ANY activity/check)
if [ "$CNT_BANNED" -gt 0 ] || [ "$CNT_RESTORED" -gt 0 ]; then
    logger -t "${LOG_TAG}" "Scan Finished. Restored: $CNT_RESTORED | New Bans: $CNT_BANNED"
fi
