#!/bin/sh

# ==============================================================================
# FIREWALL STATS & DASHBOARD (English + Attack Delta Logging)
# Description: Logs hourly drops into SQLite. No data expiration.
#              Generates 'vnstat-style' reports + Top 10 Days ranking.
#              Logs NEW ATTACKS count to syslog.
# REQUIRES: opkg install coreutils-date sqlite3-cli
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# --- CONFIGURATION ---
DB_FILE="/opt/etc/firewall_stats.db"
WEB_DIR="/opt/var/www/firewall"
OUTPUT_FILE="$WEB_DIR/index.html"
IPTABLES_CMD="iptables"
LOGGER_CMD="logger"
LOG_TAG="FW_Stats"
LISTS="FirewallBlock VPNBlock"

# Use coreutils-date for better handling
DATE_CMD="/opt/bin/date"
if [ ! -x "$DATE_CMD" ]; then DATE_CMD="date"; fi

# Ensure directories exist
mkdir -p "$WEB_DIR"
chmod 755 "$WEB_DIR"

# ==============================================================================
# 1. DATABASE INIT
# ==============================================================================
if [ ! -f "$DB_FILE" ]; then
    sqlite3 "$DB_FILE" "CREATE TABLE drops (id INTEGER PRIMARY KEY, timestamp INTEGER, list_name TEXT, count INTEGER);"
    sqlite3 "$DB_FILE" "CREATE INDEX idx_ts ON drops(timestamp);"
    sqlite3 "$DB_FILE" "CREATE INDEX idx_list ON drops(list_name);"
fi

# ==============================================================================
# 2. DATA COLLECTION & DELTA CALCULATION
# ==============================================================================
NOW=$($DATE_CMD +%s)

# Initialize Delta variables for the final log
DELTA_MAIN=0
DELTA_VPN=0

for LIST in $LISTS; do
    LAST_RUN_FILE="/tmp/fw_last_${LIST}.dat"

    # Get current drop counters from iptables
    COUNT_IN=$($IPTABLES_CMD -L INPUT -v -x -n | grep -w "match-set $LIST" | awk '{print $1}' | head -n 1)
    COUNT_FW=$($IPTABLES_CMD -L FORWARD -v -x -n | grep -w "match-set $LIST" | awk '{print $1}' | head -n 1)
    
    [ -z "$COUNT_IN" ] && COUNT_IN=0
    [ -z "$COUNT_FW" ] && COUNT_FW=0
    CURRENT_VAL=$((COUNT_IN + COUNT_FW))

    # Read previous value
    if [ -f "$LAST_RUN_FILE" ]; then LAST_VAL=$(cat "$LAST_RUN_FILE"); else LAST_VAL=0; fi

    # Calculate Delta (New attacks since last run)
    if [ "$CURRENT_VAL" -lt "$LAST_VAL" ]; then 
        # Handle counter reset/reboot
        DELTA=$CURRENT_VAL
    else
        DELTA=$((CURRENT_VAL - LAST_VAL))
    fi

    # Save Delta to specific variable for Summary Log
    if [ "$LIST" = "FirewallBlock" ]; then DELTA_MAIN=$DELTA; fi
    if [ "$LIST" = "VPNBlock" ]; then DELTA_VPN=$DELTA; fi

    # Insert into DB only if there are new drops
    if [ "$DELTA" -gt 0 ]; then
        sqlite3 "$DB_FILE" "INSERT INTO drops (timestamp, list_name, count) VALUES ($NOW, '$LIST', $DELTA);"
    fi
    
    # Update last run file
    echo "$CURRENT_VAL" > "$LAST_RUN_FILE"
done

# --- NEW LOGGING: SUMMARY OF NEW ATTACKS ---
# This logs exactly how many NEW blocks occurred since the last run
$LOGGER_CMD -t "$LOG_TAG" "New Attacks detected: Internet=+$DELTA_MAIN | VPN=+$DELTA_VPN"

# ==============================================================================
# 3. DASHBOARD GENERATION
# ==============================================================================

# --- A. UPTIME CALCULATION ---
UP_SECONDS=$(cut -d. -f1 /proc/uptime)
DAYS=$((UP_SECONDS / 86400))
HOURS=$(( (UP_SECONDS % 86400) / 3600 ))
MINS=$(( (UP_SECONDS % 3600) / 60 ))

if [ "$DAYS" -gt 0 ]; then
    UPTIME="${DAYS}d ${HOURS}h ${MINS}m"
else
    UPTIME="${HOURS}h ${MINS}m"
fi

# --- B. STATS QUERIES ---

ISO_MONTH_START=$($DATE_CMD "+%Y-%m-01")
TS_TODAY=$($DATE_CMD -d 'today 00:00:00' +%s 2>/dev/null); [ -z "$TS_TODAY" ] && TS_TODAY=0
TS_WEEK=$($DATE_CMD -d 'last monday 00:00:00' +%s 2>/dev/null); [ -z "$TS_WEEK" ] && TS_WEEK=0
TS_MONTH=$($DATE_CMD -d "${ISO_MONTH_START} 00:00:00" +%s 2>/dev/null); [ -z "$TS_MONTH" ] && TS_MONTH=0

get_stat() {
    if [ "$2" -eq 0 ]; then echo "0"; return; fi
    RES=$(sqlite3 "$DB_FILE" "SELECT SUM(count) FROM drops WHERE list_name='$1' AND timestamp >= $2;")
    [ -z "$RES" ] && echo "0" || echo "$RES"
}
get_total() {
    RES=$(sqlite3 "$DB_FILE" "SELECT SUM(count) FROM drops WHERE list_name='$1';")
    [ -z "$RES" ] && echo "0" || echo "$RES"
}

MAIN_DAY=$(get_stat "FirewallBlock" $TS_TODAY); MAIN_WEEK=$(get_stat "FirewallBlock" $TS_WEEK); MAIN_MONTH=$(get_stat "FirewallBlock" $TS_MONTH); MAIN_TOTAL=$(get_total "FirewallBlock")
VPN_DAY=$(get_stat "VPNBlock" $TS_TODAY); VPN_WEEK=$(get_stat "VPNBlock" $TS_WEEK); VPN_MONTH=$(get_stat "VPNBlock" $TS_MONTH); VPN_TOTAL=$(get_total "VPNBlock")

# Get List Sizes (Just for display on dashboard cards)
SIZE_MAIN=$(ipset list "FirewallBlock" | grep -E '^[0-9]' | wc -l); [ -z "$SIZE_MAIN" ] && SIZE_MAIN=0
SIZE_VPN=$(ipset list "VPNBlock" | grep -E '^[0-9]' | wc -l); [ -z "$SIZE_VPN" ] && SIZE_VPN=0

# TOP 10 Query
TOP_10_ROWS=$(sqlite3 -separator "|" "$DB_FILE" "SELECT strftime('%d/%m/%Y', timestamp, 'unixepoch', 'localtime'), SUM(count) FROM drops GROUP BY strftime('%Y-%m-%d', timestamp, 'unixepoch', 'localtime') ORDER BY SUM(count) DESC LIMIT 10;" | awk -F'|' '{print "<tr><td>"$1"</td><td class=\"num\">"$2"</td></tr>"}')
if [ -z "$TOP_10_ROWS" ]; then TOP_10_ROWS="<tr><td colspan='2' style='text-align:center; color:#999; padding:20px;'>No historical data available</td></tr>"; fi

DATE=$($DATE_CMD "+%d/%m/%Y %H:%M:%S")

# --- C. HTML TEMPLATE ---
cat << HTML > "$OUTPUT_FILE"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Keenetic Firewall Stats</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">
    
    <style>
        :root { --bg: #f4f7f6; --text: #333; --card: #fff; --accent: #007bff; --border: #e1e4e8; }
        body { font-family: -apple-system, sans-serif; background: var(--bg); color: var(--text); padding: 20px; margin: 0; }
        .container { max-width: 1000px; margin: 0 auto; }
        h1 { text-align: center; color: #2c3e50; margin-bottom: 30px; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .card { background: var(--card); padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
        .card h3 { margin: 0 0 10px; font-size: 12px; text-transform: uppercase; color: #7f8c8d; }
        .card .val { font-size: 28px; font-weight: bold; color: #2c3e50; }
        .card .sub { font-size: 12px; color: #95a5a6; }
        .tables-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
        @media (max-width: 768px) { .tables-grid { grid-template-columns: 1fr; } }
        .panel { background: #fff; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); overflow: hidden; }
        .panel-header { background: #f8f9fa; padding: 10px 15px; font-weight: 600; color: #2c3e50; border-bottom: 1px solid var(--border); font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; }
        .stats-table { width: 100%; border-collapse: collapse; }
        .stats-table th, .stats-table td { padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--border); font-size: 14px; }
        .stats-table th { color: #7f8c8d; font-size: 12px; text-transform: uppercase; font-weight: 600; }
        .stats-table tr:last-child td { border-bottom: none; }
        .stats-table .num { text-align: right; font-family: monospace; font-size: 14px; font-weight: bold; }
        .col-main { color: #e74c3c; } .col-vpn { color: #e67e22; } .total-row { background: #fdfdfd; font-weight: bold; }
        .btn { display: inline-block; background: var(--accent); color: white; padding: 8px 15px; border-radius: 4px; text-decoration: none; font-size: 12px; float: right; }
        .footer { text-align: center; font-size: 11px; color: #bdc3c7; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <a href="javascript:location.reload()" class="btn">REFRESH</a>
        <h1>🛡️ Keenetic Firewall Analytics</h1>
        <div class="cards">
            <div class="card">
                <h3>Internet Blocklist</h3>
                <div class="val" style="color: #e74c3c">$SIZE_MAIN</div>
                <div class="sub">Banned IPs</div>
            </div>
            <div class="card">
                <h3>VPN Blocklist</h3>
                <div class="val" style="color: #e67e22">$SIZE_VPN</div>
                <div class="sub">Banned IPs</div>
            </div>
            <div class="card">
                <h3>System Status</h3>
                <div class="val" style="color: #27ae60">ACTIVE</div>
                <div class="sub">$UPTIME</div>
            </div>
        </div>
        <div class="tables-grid">
            <div class="panel">
                <div class="panel-header">📊 Periodic Statistics</div>
                <table class="stats-table">
                    <thead>
                        <tr><th>Period</th><th class="num">Internet</th><th class="num">VPN</th><th class="num">Total</th></tr>
                    </thead>
                    <tbody>
                        <tr><td>Today</td><td class="num col-main">+$MAIN_DAY</td><td class="num col-vpn">+$VPN_DAY</td><td class="num">$((MAIN_DAY + VPN_DAY))</td></tr>
                        <tr><td>Week</td><td class="num col-main">+$MAIN_WEEK</td><td class="num col-vpn">+$VPN_WEEK</td><td class="num">$((MAIN_WEEK + VPN_WEEK))</td></tr>
                        <tr><td>Month</td><td class="num col-main">+$MAIN_MONTH</td><td class="num col-vpn">+$VPN_MONTH</td><td class="num">$((MAIN_MONTH + VPN_MONTH))</td></tr>
                        <tr class="total-row"><td>LIFETIME</td><td class="num col-main">$MAIN_TOTAL</td><td class="num col-vpn">$VPN_TOTAL</td><td class="num">$((MAIN_TOTAL + VPN_TOTAL))</td></tr>
                    </tbody>
                </table>
            </div>
            <div class="panel">
                <div class="panel-header">🏆 Top 10 Days</div>
                <table class="stats-table">
                    <thead><tr><th>Date</th><th class="num">Blocked</th></tr></thead>
                    <tbody>$TOP_10_ROWS</tbody>
                </table>
            </div>
        </div>
        <div class="footer">Database: SQLite3 | Last update: $DATE</div>
    </div>
</body>
</html>
HTML
