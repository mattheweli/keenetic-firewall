#!/bin/sh

# ==============================================================================
# FIREWALL STATS LOGGER (PERSISTENT)
# Description: Logs hourly dropped packet count and maintains a Grand Total
#              that survives reboots and firewall rule reloads.
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

IPTABLES_CMD="iptables"
LOGGER_CMD="logger"
LOG_TAG="Firewall_Stats"

# Files for persistency
LAST_RUN_FILE="/tmp/firewall_last_snapshot.dat"
TOTAL_FILE="/opt/etc/firewall_total.save"

# 1. Get current drop count
COUNT_IN=$($IPTABLES_CMD -L INPUT -v -x -n | grep "match-set FirewallBlock" | awk '{print $1}' | head -n 1)
COUNT_FW=$($IPTABLES_CMD -L FORWARD -v -x -n | grep "match-set FirewallBlock" | awk '{print $1}' | head -n 1)

[ -z "$COUNT_IN" ] && COUNT_IN=0
[ -z "$COUNT_FW" ] && COUNT_FW=0
CURRENT_IPTABLES_VAL=$((COUNT_IN + COUNT_FW))

# 2. Load previous states
if [ -f "$LAST_RUN_FILE" ]; then LAST_IPTABLES_VAL=$(cat "$LAST_RUN_FILE"); else LAST_IPTABLES_VAL=0; fi
if [ -f "$TOTAL_FILE" ]; then GRAND_TOTAL=$(cat "$TOTAL_FILE"); else GRAND_TOTAL=0; fi

# 3. Calculate DELTA (Detect Resets)
if [ "$CURRENT_IPTABLES_VAL" -lt "$LAST_IPTABLES_VAL" ]; then
    DELTA=$CURRENT_IPTABLES_VAL
else
    DELTA=$((CURRENT_IPTABLES_VAL - LAST_IPTABLES_VAL))
fi

# 4. Update Grand Total
GRAND_TOTAL=$((GRAND_TOTAL + DELTA))

# 5. Log to Syslog
if [ "$DELTA" -ge 0 ]; then
    if [ "$DELTA" -eq 0 ]; then
         $LOGGER_CMD -t "$LOG_TAG" "Status: No new attacks. (Lifetime Total: $GRAND_TOTAL)"
    else
         $LOGGER_CMD -t "$LOG_TAG" "REPORT: Blocked $DELTA new threats. (Lifetime Total: $GRAND_TOTAL)"
    fi
fi

# 6. Save states
echo "$CURRENT_IPTABLES_VAL" > "$LAST_RUN_FILE"
echo "$GRAND_TOTAL" > "$TOTAL_FILE"