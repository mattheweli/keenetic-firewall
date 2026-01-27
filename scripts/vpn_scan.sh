#!/bin/sh

# ==============================================================================
# VPN LOG ANALYZER v1.3.1 (FULL LOGGING)
# Features:
# - INTERACTIVE: Echoes status to terminal.
# - LOGGING: Logs Summary even if IPs were just skipped (already blocked).
# - SYNC: Restores IPs from local file to RAM.
# ==============================================================================

# --- PATHS ---
LOG_FILE="/opt/var/log/messages"
BANNED_IPS_FILE="/opt/etc/vpn_banned_ips.txt"
DIFF_FILE_VPN="/opt/etc/firewall_vpn_diff.dat"

IPSET_VPN="VPNBlock"
IPSET_MAIN="FirewallBlock"
LOG_TAG="VPN_Blocker"

# Regex
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
echo -e "${BOLD}=== VPN Security Scanner v1.3.1 ===${RESET}"

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}Error: Log file not found ($LOG_FILE).${RESET}"
    logger -t "${LOG_TAG}" "Error: Log file missing."
    exit 1
fi

# ==============================================================================
# 1. SYNC PHASE (Persistence & Optimization)
# ==============================================================================
echo -n " -> Syncing persistence file... "

if [ -s "$BANNED_IPS_FILE" ]; then
    TMP_CLEAN="/tmp/vpn_clean_list.tmp"
    : > "$TMP_CLEAN"
    
    while read -r SAVED_IP; do
        [ -z "$SAVED_IP" ] && continue

        # Check Global List (FirewallBlock)
        if ipset test "$IPSET_MAIN" "$SAVED_IP" >/dev/null 2>&1; then
            # OPTIMIZATION: IP is globally blocked. Remove from VPN set to save RAM.
            ipset del "$IPSET_VPN" "$SAVED_IP" 2>/dev/null
            CNT_OPTIMIZED=$((CNT_OPTIMIZED + 1))
        else
            # IP needs to be in VPN RAM list
            ipset add "$IPSET_VPN" "$SAVED_IP" -exist 2>/dev/null
            echo "$SAVED_IP" >> "$TMP_CLEAN"
            CNT_RESTORED=$((CNT_RESTORED + 1))
        fi
    done < "$BANNED_IPS_FILE"
    
    mv "$TMP_CLEAN" "$BANNED_IPS_FILE"
fi
echo -e "${GREEN}Done.${RESET}"

# ==============================================================================
# 2. SCAN PHASE (Log Analysis)
# ==============================================================================
echo -n " -> Scanning OpenVPN logs... "

# Extract unique IPs
MALICIOUS_IPS=$(grep -i "openvpn" "$LOG_FILE" | grep -E "$SEARCH_PATTERN" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u)

# Count lines
NUM_FOUND=$(echo "$MALICIOUS_IPS" | grep -cE '^[0-9]')

if [ "$NUM_FOUND" -gt 0 ]; then
    echo -e "${YELLOW}Found $NUM_FOUND suspicious IPs.${RESET}"
    
    for IP in $MALICIOUS_IPS; do
        # A. Check Global List
        if ipset test "$IPSET_MAIN" "$IP" >/dev/null 2>&1; then
            CNT_SKIPPED=$((CNT_SKIPPED + 1))
            continue
        fi

        # B. Check Local File (Avoid duplicates)
        if ! grep -qF "$IP" "$BANNED_IPS_FILE"; then
            # BAN ACTION
            ipset add "$IPSET_VPN" "$IP" -exist 2>/dev/null
            echo "$IP" >> "$BANNED_IPS_FILE"
            
            # Logs
            echo -e "    ! ${RED}BANNED:${RESET} $IP"
            logger -t "${LOG_TAG}" "ACTION: Banned IP $IP (OpenVPN Attack)"
            
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

# System Log Summary (Always log if there was ANY activity/detection, even if skipped)
if [ "$CNT_OPTIMIZED" -gt 0 ] || [ "$CNT_BANNED" -gt 0 ] || [ "$CNT_SKIPPED" -gt 0 ]; then
    logger -t "${LOG_TAG}" "Scan Finished. NewBans: $CNT_BANNED | Skipped (Global): $CNT_SKIPPED | Optimized: $CNT_OPTIMIZED"
fi

exit 0
