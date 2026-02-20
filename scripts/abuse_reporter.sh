#!/bin/sh

# ==============================================================================
# ABUSEIPDB AUTO-REPORTER v2.1.1 (ULOGD/NFLOG EDITION)
# ==============================================================================
# Description: 
#   Auto-reports malicious IPs to AbuseIPDB.
#
#   CHANGES v2.1.1 (Performance & Bugfix Update):
#     - PERFORMANCE: Optimized SQLite JOINs (replaced OR chains with REPLACE()) 
#       to prevent EXT4 I/O lockups and 100% CPU spikes during table scans.
#     - BUGFIX: Replaced Bash-specific IFS=$'\n' with POSIX/BusyBox compatible 
#       newline parsing to fix silent string splitting errors.
#
#   CHANGES v2.1.0:
#     - LOGIC: Uses ULOGD 'port_history' as primary evidence.
#     - REPORTING: Separates Trap hits (Hacking) from Scanners.
#     - EVIDENCE: Adds "Blocked via Kernel/NFLOG" signature.
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# ==============================================================================
# 1. CONFIGURATION & KEYS
# ==============================================================================
DB_FILE="/opt/etc/firewall_stats.db"
CONF_FILE="/opt/etc/firewall.conf"
LOG_TAG="Abuse_Reporter"

# Global Counters for Summary
G_REPORTED=0
G_SKIPPED=0
G_ERRORS=0

# Time Window Settings (24 Hours)
TIME_WINDOW=86400
NOW=$(date +%s)
LIMIT_TIME=$((NOW - TIME_WINDOW))

# Load Services from Config
if [ -f "$CONF_FILE" ]; then 
    . "$CONF_FILE"
else
    TCP_SERVICES="447 51515 22"
    UDP_SERVICES=""
    REPORT_COOLDOWN="604800"
fi

# Fallback for Cooldown if missing in config
: ${REPORT_COOLDOWN:=604800}

# Prepare SQL List for IN clause
ALL_TRAP_PORTS="$TCP_SERVICES $UDP_SERVICES"
TRAP_SQL_LIST=$(echo "$ALL_TRAP_PORTS" | tr -s ' ' ',' | sed 's/^,//;s/,$//')

KEY_FILE="/opt/etc/AbuseIPDB.key"
if [ -s "$KEY_FILE" ]; then ABUSEIPDB_KEY=$(cat "$KEY_FILE" | tr -d '[:space:]'); else ABUSEIPDB_KEY=""; fi

# ==============================================================================
# 2. INIT & HELPER FUNCTIONS
# ==============================================================================

if [ -f "$DB_FILE" ]; then
    sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS abuse_reports (ip TEXT PRIMARY KEY, last_sent INTEGER);"
fi

logger -t "$LOG_TAG" "Starting Reporter v2.1.1"

# $1=IP, $2=Categories, $3=Comment, $4=Type
send_report() {
    RAW_IP=$1; CATS=$2; BASE_COMMENT=$3; TYPE=$4
    
    # CLEAN IP: Strip /32 or /128
    IP=$(echo "$RAW_IP" | sed 's|/128||g; s|/32||g')

    # 1. Get Last Sent Timestamp
    LAST_SENT=$(sqlite3 "$DB_FILE" "SELECT last_sent FROM abuse_reports WHERE ip='$IP';")
    LAST_SENT=${LAST_SENT:-0}

    # 2. COOLDOWN CHECK (Configurable)
    if [ $((NOW - LAST_SENT)) -lt "$REPORT_COOLDOWN" ] && [ "$LAST_SENT" -gt 0 ]; then
        echo "    -> Skipped (Reported < ${REPORT_COOLDOWN}s ago)"
        G_SKIPPED=$((G_SKIPPED + 1))
        return
    fi

    # 3. NEW ACTIVITY CHECK
    NEW_HITS=$(sqlite3 "$DB_FILE" "SELECT SUM(count) FROM ip_drops WHERE ip LIKE '${IP}%' AND timestamp > $LAST_SENT;")
    NEW_HITS=${NEW_HITS:-0}

    if [ "$LAST_SENT" -gt 0 ] && [ "$NEW_HITS" -eq 0 ]; then
        echo "    -> Skipped (No new hits since last report)"
        G_SKIPPED=$((G_SKIPPED + 1))
        return
    fi

    # 4. Prepare Comment
    if [ "$LAST_SENT" -gt 0 ]; then
        FINAL_COMMENT="$BASE_COMMENT [+ $NEW_HITS new hits since last report]"
    else
        FINAL_COMMENT="$BASE_COMMENT"
    fi

    echo "    -> Reporting $IP..."

    # 5. Send to AbuseIPDB
    RESPONSE=$(curl -s https://api.abuseipdb.com/api/v2/report \
        --data-urlencode "ip=$IP" \
        --data-urlencode "categories=$CATS" \
        --data-urlencode "comment=$FINAL_COMMENT" \
        -H "Key: $ABUSEIPDB_KEY" \
        -H "Accept: application/json")

    # 6. Update DB
    if echo "$RESPONSE" | grep -q "data"; then
        sqlite3 "$DB_FILE" "INSERT OR REPLACE INTO abuse_reports (ip, last_sent) VALUES ('$IP', $NOW);"
        echo "       [OK] Reported."
        G_REPORTED=$((G_REPORTED + 1))
    else
        echo "       [ERR] API Fail: $RESPONSE"
        G_ERRORS=$((G_ERRORS + 1))
    fi
}

# ==============================================================================
# 3. PRIORITY 1: TARGETED BRUTEFORCE (Verified Trap Hits)
# ==============================================================================
process_critical_bruteforce() {
    PROTO=$1
    echo "--- Processing Targeted Bruteforce ($PROTO) ---"
    
    if [ -n "$TRAP_SQL_LIST" ]; then
        # QUERY UPDATE: Fetch port_history directly and optimized JOIN via REPLACE
        QUERY="SELECT IFNULL(i.port_history, i.target_port), d.ip, SUM(d.count) as total 
               FROM ip_drops d 
               JOIN ip_info i ON i.ip = REPLACE(REPLACE(d.ip, '/128', ''), '/32', '')
               WHERE d.list_type='trap' 
               AND d.timestamp > $LIMIT_TIME
               AND (i.target_port IN ($TRAP_SQL_LIST) OR i.port_history LIKE '%/tcp%' OR i.port_history LIKE '%/udp%')
               AND d.ip LIKE '%$(if [ "$PROTO" = "v6" ]; then echo ":"; else echo "."; fi)%'
               GROUP BY d.ip 
               ORDER BY total DESC 
               LIMIT 100;"
    else
        echo "No specific ports configured."
        return
    fi

    ROWS=$(sqlite3 -separator "|" "$DB_FILE" "$QUERY")
    
    # BusyBox Compatible IFS for newlines
    OIFS="$IFS"
    IFS='
'
    for ROW in $ROWS; do
        PORTS=$(echo "$ROW" | cut -d'|' -f1)
        IP=$(echo "$ROW" | cut -d'|' -f2)
        CNT=$(echo "$ROW" | cut -d'|' -f3)
        
        # Fallback if ports empty
        [ -z "$PORTS" ] && PORTS="High-Risk Ports"
        
        echo " -> Candidate: $IP (Ports: $PORTS | Hits: $CNT)"
        
        # EVIDENCE: "Blocked via Kernel/NFLOG"
        MSG="Keenetic Firewall: Unauthorized connection attempt to ports [$PORTS]. Blocked via Kernel/NFLOG Trap. ($CNT hits in 24h)."
        
        # CATEGORIES: 15 (Hacking Attempt) + 14 (Port Scan)
        send_report "$IP" "15,14" "$MSG" "brute"
    done
    IFS="$OIFS"
}

# ==============================================================================
# 4. PRIORITY 2: RANDOM SCANNERS (Known Port)
# ==============================================================================
process_random_scanners() {
    PROTO=$1
    echo "--- Processing Random Scanners ($PROTO) ---"

    if [ -n "$TRAP_SQL_LIST" ]; then EXTRA_SQL="AND i.target_port NOT IN ($TRAP_SQL_LIST)"; else EXTRA_SQL=""; fi

    # UPDATED: Selects port_history first, falls back to target_port + optimized JOIN
    QUERY="SELECT IFNULL(i.port_history, i.target_port), d.ip, SUM(d.count) as total 
           FROM ip_drops d 
           JOIN ip_info i ON i.ip = REPLACE(REPLACE(d.ip, '/128', ''), '/32', '')
           WHERE d.list_type='trap' 
           AND d.timestamp > $LIMIT_TIME
           AND d.ip LIKE '%$(if [ "$PROTO" = "v6" ]; then echo ":"; else echo "."; fi)%'
           $EXTRA_SQL
           GROUP BY d.ip 
           ORDER BY total DESC 
           LIMIT 15;"

    ROWS=$(sqlite3 -separator "|" "$DB_FILE" "$QUERY")

    # BusyBox Compatible IFS for newlines
    OIFS="$IFS"
    IFS='
'
    for ROW in $ROWS; do
        PORT=$(echo "$ROW" | cut -d'|' -f1)
        IP=$(echo "$ROW" | cut -d'|' -f2)
        CNT=$(echo "$ROW" | cut -d'|' -f3)
        echo " -> Candidate: $IP (Ports: $PORT | Hits: $CNT)"
        # EVIDENCE: Explicitly mentions Kernel/NFLOG Block
		MSG="Keenetic Firewall: Port Scanning detected on ports [$PORT]. Blocked via Kernel/NFLOG. ($CNT hits in 24h)."
		send_report "$IP" "14" "$MSG" "scan"
    done
    IFS="$OIFS"
}

# ==============================================================================
# 5. PRIORITY 2.5: UNKNOWN TRAFFIC (UDP/No Port)
# ==============================================================================
process_unknown_traffic() {
    PROTO=$1
    echo "--- Processing Unknown/UDP Traffic ($PROTO) ---"

    QUERY="SELECT IFNULL(i.target_port, 0), d.ip, SUM(d.count) as total 
           FROM ip_drops d 
           LEFT JOIN ip_info i ON i.ip = REPLACE(REPLACE(d.ip, '/128', ''), '/32', '')
           WHERE d.list_type='trap' 
           AND d.timestamp > $LIMIT_TIME
           AND d.ip LIKE '%$(if [ "$PROTO" = "v6" ]; then echo ":"; else echo "."; fi)%'
           AND (i.target_port IS NULL OR i.target_port = 0)
           GROUP BY d.ip 
           ORDER BY total DESC 
           LIMIT 20;"

    ROWS=$(sqlite3 -separator "|" "$DB_FILE" "$QUERY")

    # BusyBox Compatible IFS for newlines
    OIFS="$IFS"
    IFS='
'
    for ROW in $ROWS; do
        PORT=$(echo "$ROW" | cut -d'|' -f1)
        IP=$(echo "$ROW" | cut -d'|' -f2)
        CNT=$(echo "$ROW" | cut -d'|' -f3)
        echo " -> Candidate: $IP (No Port Detected | Hits: $CNT)"
        send_report "$IP" "14" "Keenetic Firewall: Blocked Traffic (No Port Detected - likely UDP). Blocked $CNT times in last 24h." "udp"
    done
    IFS="$OIFS"
}

# ==============================================================================
# 6. PRIORITY 3: STATIC BLOCKLIST HITS
# ==============================================================================
process_static() {
    PROTO=$1
    echo "--- Processing Static Blocklist Hits ($PROTO) ---"

    QUERY="SELECT d.ip, SUM(d.count) as total 
           FROM ip_drops d 
           WHERE d.list_type='main'
           AND (d.ip NOT LIKE '%/%' OR d.ip LIKE '%/128' OR d.ip LIKE '%/32')
           AND d.timestamp > $LIMIT_TIME
           AND d.ip LIKE '%$(if [ "$PROTO" = "v6" ]; then echo ":"; else echo "."; fi)%'
           GROUP BY d.ip 
           ORDER BY total DESC 
           LIMIT 15;"

    ROWS=$(sqlite3 -separator "|" "$DB_FILE" "$QUERY")

    # BusyBox Compatible IFS for newlines
    OIFS="$IFS"
    IFS='
'
    for ROW in $ROWS; do
        IP=$(echo "$ROW" | cut -d'|' -f1)
        CNT=$(echo "$ROW" | cut -d'|' -f2)
        echo " -> Candidate: $IP (Hits: $CNT)"
        # CATEGORY: 14 (Port Scan) is safe default for blocklist hits
		MSG="Keenetic Firewall: Persistent traffic from Blacklisted IP. Blocked via Kernel/NFLOG. ($CNT hits in 24h)."
		send_report "$IP" "14" "$MSG" "static"
    done
    IFS="$OIFS"
}

# ==============================================================================
# 7. PRIORITY 4: SUBNETS
# ==============================================================================
process_subnets() {
    echo "--- Processing Top 25 Subnets ---"

    QUERY="SELECT d.ip, SUM(d.count) as total FROM ip_drops d 
           WHERE d.ip LIKE '%/%' 
           AND d.ip NOT LIKE '%/32' 
           AND d.ip NOT LIKE '%/128'
           AND d.timestamp > $LIMIT_TIME
           GROUP BY d.ip ORDER BY total DESC LIMIT 25;"

    ROWS=$(sqlite3 -separator "|" "$DB_FILE" "$QUERY")

    # BusyBox Compatible IFS for newlines
    OIFS="$IFS"
    IFS='
'
    for ROW in $ROWS; do
        SUBNET=$(echo "$ROW" | cut -d'|' -f1)
        CNT=$(echo "$ROW" | cut -d'|' -f2)
        CLEAN_IP=$(echo "$SUBNET" | cut -d'/' -f1)
        echo " -> Candidate: $SUBNET (Hits: $CNT)"
        send_report "$CLEAN_IP" "14,4" "Keenetic Firewall Subnet Block: Entire subnet $SUBNET blocked ($CNT hits in 24h). Reporting network ID." "net"
    done
    IFS="$OIFS"
}

# ==============================================================================
# EXECUTION
# ==============================================================================

if [ -z "$ABUSEIPDB_KEY" ]; then
    echo "Error: AbuseIPDB Key not found in $KEY_FILE."
    exit 1
fi

process_critical_bruteforce "v4"
process_critical_bruteforce "v6"

process_random_scanners "v4"
process_random_scanners "v6"

process_unknown_traffic "v4"
process_unknown_traffic "v6"

process_static "v4"
process_static "v6"

process_subnets

# Final Summary Log
echo "---------------------------------------------------"
LOG_MSG="SUMMARY | Reported: $G_REPORTED | Skipped: $G_SKIPPED | Errors: $G_ERRORS"
echo "$LOG_MSG"
logger -t "$LOG_TAG" "$LOG_MSG"

echo "Done."
