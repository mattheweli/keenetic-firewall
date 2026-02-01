#!/bin/sh

# ==============================================================================
# ABUSEIPDB AUTO-REPORTER v1.0.7 (SHERLOCK PRIORITY)
# Description: Reports attackers to AbuseIPDB using POST method.
# Features:
#   - SHERLOCK PRIORITY: If a port is detected, report REGARDLESS of Risk Score.
#   - RISK FIX: Included Risk 0 in the query (>= operator).
#   - LOGGING: Generates execution summary on stdout and syslog.
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# --- CONFIG ---
DB_FILE="/opt/etc/firewall_stats.db"
# Retrieve Key from the updater script
API_KEY=$(grep 'ABUSEIPDB_KEY=' /opt/bin/update_blocklist.sh 2>/dev/null | cut -d'"' -f2)
LOG_TAG="Abuse_Reporter"

# Risk Thresholds (Report only if >= MIN and <= MAX)
# Note: If Sherlock finds a port, these thresholds are ignored!
RISK_MIN=1
RISK_MAX=100

# --- SERVICE CONFIGURATION ---
VPN_PORT="447"
VPN_PROTO="TCP"

# --- INITIALIZATION ---
if [ -z "$API_KEY" ]; then 
    echo "Error: API Key not found in update_blocklist.sh"
    logger -t "$LOG_TAG" "ERROR: API Key missing. Aborting."
    exit 1
fi

sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS reported_ips (ip TEXT PRIMARY KEY, last_report INTEGER);"

NOW=$(date +%s)
ONE_DAY_AGO=$((NOW - 86400))

CNT_TOTAL=0; CNT_SUCCESS=0; CNT_FAIL=0

echo "=== AbuseIPDB Reporter v1.0.7 ==="

# ENHANCED QUERY:
# 1. Select if Risk is within range (>= MIN and <= MAX)
# 2. OR if a port is detected by Sherlock (target_port > 0)
# 3. Exclude IPs already reported in the last 24h

QUERY="
SELECT DISTINCT i.ip, i.risk, i.target_port
FROM ip_info i
JOIN ip_drops d ON i.ip = d.ip
LEFT JOIN reported_ips r ON i.ip = r.ip
WHERE 
  (
    (i.risk >= $RISK_MIN AND i.risk <= $RISK_MAX)
    OR (i.target_port IS NOT NULL AND i.target_port > 0)
  )
  AND d.timestamp > $ONE_DAY_AGO
  AND (r.last_report IS NULL OR r.last_report < $ONE_DAY_AGO)
LIMIT 10;
"

CANDIDATES=$(sqlite3 -separator "|" "$DB_FILE" "$QUERY")

if [ -z "$CANDIDATES" ]; then
    echo " -> No candidates found (Risk $RISK_MIN-$RISK_MAX% or Detected Ports)."
    exit 0
fi

IFS=$'\n'
for LINE in $CANDIDATES; do
    IP=$(echo "$LINE" | cut -d'|' -f1)
    RISK=$(echo "$LINE" | cut -d'|' -f2)
    DB_PORT=$(echo "$LINE" | cut -d'|' -f3)
    CNT_TOTAL=$((CNT_TOTAL + 1))

    # --- SMART CONTEXT ---
    if ipset test VPNBlock "$IP" 2>/dev/null; then
        CATS="18,15" # Brute-Force, Hacking
        COMMENT="Brute-force attempt detected on OpenVPN Gateway (Port $VPN_PORT/$VPN_PROTO)."
        TYPE_LBL="VPN ($VPN_PORT)"
    elif [ -n "$DB_PORT" ] && [ "$DB_PORT" != "0" ] && [ "$DB_PORT" != "" ]; then
        CATS="14" # Port Scan
        COMMENT="Unauthorized connection attempt blocked by Firewall (Target Port: $DB_PORT)."
        TYPE_LBL="Sherlock ($DB_PORT)"
    else
        CATS="14" # Port Scan
        COMMENT="Unauthorized connection attempt blocked by Firewall (Port Scan)."
        TYPE_LBL="Generic"
    fi
    
    echo -n " -> Reporting $IP ($TYPE_LBL | Risk: ${RISK}%) ... "
    
    # API Call (POST)
    RESPONSE=$(curl -s -X POST https://api.abuseipdb.com/api/v2/report \
        --data-urlencode "ip=$IP" \
        --data-urlencode "categories=$CATS" \
        --data-urlencode "comment=$COMMENT" \
        -H "Key: $API_KEY" \
        -H "Accept: application/json")
    
    if echo "$RESPONSE" | grep -q '"ipAddress"'; then
        echo "SUCCESS"
        sqlite3 "$DB_FILE" "INSERT OR REPLACE INTO reported_ips (ip, last_report) VALUES ('$IP', $NOW);"
        CNT_SUCCESS=$((CNT_SUCCESS + 1))
    else
        echo "FAILED"
        echo "    ERROR MSG: $RESPONSE"
        CNT_FAIL=$((CNT_FAIL + 1))
    fi
    
    sleep 2
done
unset IFS

# --- SUMMARY & LOGGING ---
echo ""
echo "========================================"
echo "           REPORT SUMMARY               "
echo "========================================"
echo " Candidates Processed : $CNT_TOTAL"
echo " Successful Reports   : $CNT_SUCCESS"
echo " Failed Reports       : $CNT_FAIL"
echo "========================================"

if [ "$CNT_SUCCESS" -gt 0 ] || [ "$CNT_FAIL" -gt 0 ]; then
    logger -t "$LOG_TAG" "Finished. Sent: $CNT_SUCCESS, Failed: $CNT_FAIL, Total: $CNT_TOTAL"
fi

echo "Done."
