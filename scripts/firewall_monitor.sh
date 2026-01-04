#!/bin/sh

# ==============================================================================
# FIREWALL LIVE MONITOR
# Description: Shows real-time blocking statistics in the terminal.
# Usage: Run 'firewall_monitor' from CLI. Press CTRL+C to exit.
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

IPSET_NAME="FirewallBlock"
REFRESH_RATE=2

# Colors
BOLD="\e[1m"
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

# Trap CTRL+C to exit cleanly
trap "echo; echo 'Monitor stopped.'; exit 0" INT

while true; do
    # Clear screen
    clear (or echo -e "\033c") 2>/dev/null || echo -e "\033c"

    # Get Timestamp
    NOW=$(date "+%Y-%m-%d %H:%M:%S")

    # Get Counts (Fast mode with -n to avoid DNS lookups)
    # Using iptables -v (verbose) -x (exact numbers)
    INPUT_PKTS=$(iptables -L INPUT -v -x -n | grep "match-set $IPSET_NAME" | awk '{print $1}')
    INPUT_BYTES=$(iptables -L INPUT -v -x -n | grep "match-set $IPSET_NAME" | awk '{print $2}')
    
    FORWARD_PKTS=$(iptables -L FORWARD -v -x -n | grep "match-set $IPSET_NAME" | awk '{print $1}')
    FORWARD_BYTES=$(iptables -L FORWARD -v -x -n | grep "match-set $IPSET_NAME" | awk '{print $2}')

    # Handle empty results (if rules are missing)
    [ -z "$INPUT_PKTS" ] && INPUT_PKTS=0
    [ -z "$INPUT_BYTES" ] && INPUT_BYTES=0
    [ -z "$FORWARD_PKTS" ] && FORWARD_PKTS=0
    [ -z "$FORWARD_BYTES" ] && FORWARD_BYTES=0

    # Calculate Totals
    TOTAL_PKTS=$((INPUT_PKTS + FORWARD_PKTS))
    
    # Format Bytes to KB/MB for readability (Simple shell math)
    # Note: Busybox doesn't handle floats well, keeping it simple or raw bytes
    format_bytes() {
        if [ "$1" -gt 1048576 ]; then
            echo "$(( $1 / 1048576 )) MB"
        elif [ "$1" -gt 1024 ]; then
            echo "$(( $1 / 1024 )) KB"
        else
            echo "$1 Bytes"
        fi
    }

    INPUT_HR=$(format_bytes $INPUT_BYTES)
    FORWARD_HR=$(format_bytes $FORWARD_BYTES)

    # --- DASHBOARD UI ---
    echo -e "${CYAN}==============================================${RESET}"
    echo -e "${BOLD}   KEENETIC FIREWALL LIVE MONITOR ${RESET}"
    echo -e "${CYAN}==============================================${RESET}"
    echo -e " Time: $NOW"
    echo -e " Refresh: ${REFRESH_RATE}s"
    echo -e " List: $IPSET_NAME"
    echo ""
    echo -e "${YELLOW} [ INPUT CHAIN ] ${RESET} (Attacks to Router)"
    echo -e " Blocked Packets : ${RED}${INPUT_PKTS}${RESET}"
    echo -e " Data Volume     : ${INPUT_HR}"
    echo ""
    echo -e "${YELLOW} [ FORWARD CHAIN ] ${RESET} (Attacks to LAN/IoT)"
    echo -e " Blocked Packets : ${RED}${FORWARD_PKTS}${RESET}"
    echo -e " Data Volume     : ${FORWARD_HR}"
    echo ""
    echo -e "${CYAN}----------------------------------------------${RESET}"
    echo -e "${BOLD} TOTAL BLOCKED   : ${RED}${TOTAL_PKTS}${RESET} packets"
    echo -e "${CYAN}==============================================${RESET}"
    echo -e " Press [CTRL+C] to stop"
    
    sleep $REFRESH_RATE
done