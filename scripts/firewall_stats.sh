#!/bin/sh

# ==============================================================================
# FIREWALL STATS & DASHBOARD (Optimized: Data/View Separation)
# Description: Logs hourly drops into SQLite.
#              Generates lightweight JSON data file instead of full HTML.
#              Static HTML is generated only once.
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# --- CONFIGURATION ---
DB_FILE="/opt/etc/firewall_stats.db"
WEB_DIR="/opt/var/www/firewall"
DATA_FILE="$WEB_DIR/firewall_data.js"
HTML_FILE="$WEB_DIR/index.html"
IPTABLES_CMD="iptables"
LOGGER_CMD="logger"
LOG_TAG="FW_Stats"
LISTS="FirewallBlock VPNBlock"

# Use coreutils-date if available
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
DELTA_MAIN=0
DELTA_VPN=0

for LIST in $LISTS; do
    LAST_RUN_FILE="/tmp/fw_last_${LIST}.dat"

    # Get counters
    COUNT_IN=$($IPTABLES_CMD -L INPUT -v -x -n | grep -w "match-set $LIST" | awk '{print $1}' | head -n 1)
    COUNT_FW=$($IPTABLES_CMD -L FORWARD -v -x -n | grep -w "match-set $LIST" | awk '{print $1}' | head -n 1)
    
    [ -z "$COUNT_IN" ] && COUNT_IN=0
    [ -z "$COUNT_FW" ] && COUNT_FW=0
    CURRENT_VAL=$((COUNT_IN + COUNT_FW))

    # Read previous
    if [ -f "$LAST_RUN_FILE" ]; then LAST_VAL=$(cat "$LAST_RUN_FILE"); else LAST_VAL=0; fi

    # Calculate Delta
    if [ "$CURRENT_VAL" -lt "$LAST_VAL" ]; then 
        DELTA=$CURRENT_VAL # Counter reset/reboot
    else
        DELTA=$((CURRENT_VAL - LAST_VAL))
    fi

    if [ "$LIST" = "FirewallBlock" ]; then DELTA_MAIN=$DELTA; fi
    if [ "$LIST" = "VPNBlock" ]; then DELTA_VPN=$DELTA; fi

    # Insert into DB if new drops
    if [ "$DELTA" -gt 0 ]; then
        sqlite3 "$DB_FILE" "INSERT INTO drops (timestamp, list_name, count) VALUES ($NOW, '$LIST', $DELTA);"
    fi
    
    echo "$CURRENT_VAL" > "$LAST_RUN_FILE"
done

# Log to syslog
$LOGGER_CMD -t "$LOG_TAG" "New Attacks detected: Internet=+$DELTA_MAIN | VPN=+$DELTA_VPN"

# ==============================================================================
# 3. STATS CALCULATION
# ==============================================================================

# Uptime
UP_SECONDS=$(cut -d. -f1 /proc/uptime)
DAYS=$((UP_SECONDS / 86400))
HOURS=$(( (UP_SECONDS % 86400) / 3600 ))
MINS=$(( (UP_SECONDS % 3600) / 60 ))
if [ "$DAYS" -gt 0 ]; then UPTIME="${DAYS}d ${HOURS}h ${MINS}m"; else UPTIME="${HOURS}h ${MINS}m"; fi

# Dates
ISO_MONTH_START=$($DATE_CMD "+%Y-%m-01")
TS_TODAY=$($DATE_CMD -d 'today 00:00:00' +%s 2>/dev/null); [ -z "$TS_TODAY" ] && TS_TODAY=0
TS_WEEK=$($DATE_CMD -d 'last monday 00:00:00' +%s 2>/dev/null); [ -z "$TS_WEEK" ] && TS_WEEK=0
TS_MONTH=$($DATE_CMD -d "${ISO_MONTH_START} 00:00:00" +%s 2>/dev/null); [ -z "$TS_MONTH" ] && TS_MONTH=0

# Queries Helper
get_stat() {
    if [ "$2" -eq 0 ]; then echo "0"; return; fi
    RES=$(sqlite3 "$DB_FILE" "SELECT SUM(count) FROM drops WHERE list_name='$1' AND timestamp >= $2;")
    [ -z "$RES" ] && echo "0" || echo "$RES"
}
get_total() {
    RES=$(sqlite3 "$DB_FILE" "SELECT SUM(count) FROM drops WHERE list_name='$1';")
    [ -z "$RES" ] && echo "0" || echo "$RES"
}

# Fetch Stats
MAIN_DAY=$(get_stat "FirewallBlock" $TS_TODAY); MAIN_WEEK=$(get_stat "FirewallBlock" $TS_WEEK); MAIN_MONTH=$(get_stat "FirewallBlock" $TS_MONTH); MAIN_TOTAL=$(get_total "FirewallBlock")
VPN_DAY=$(get_stat "VPNBlock" $TS_TODAY); VPN_WEEK=$(get_stat "VPNBlock" $TS_WEEK); VPN_MONTH=$(get_stat "VPNBlock" $TS_MONTH); VPN_TOTAL=$(get_total "VPNBlock")

# List Sizes
SIZE_MAIN=$(ipset list "FirewallBlock" | grep -E '^[0-9]' | wc -l); [ -z "$SIZE_MAIN" ] && SIZE_MAIN=0
SIZE_VPN=$(ipset list "VPNBlock" | grep -E '^[0-9]' | wc -l); [ -z "$SIZE_VPN" ] && SIZE_VPN=0

# Top 10 (Formatted as HTML rows for simplicity in JS injection)
TOP_10_ROWS=$(sqlite3 -separator "|" "$DB_FILE" "SELECT strftime('%d/%m/%Y', timestamp, 'unixepoch', 'localtime'), SUM(count) FROM drops GROUP BY strftime('%Y-%m-%d', timestamp, 'unixepoch', 'localtime') ORDER BY SUM(count) DESC LIMIT 10;" | awk -F'|' '{print "<tr><td>"$1"</td><td class=\"num\">"$2"</td></tr>"}')
if [ -z "$TOP_10_ROWS" ]; then TOP_10_ROWS="<tr><td colspan='2' style='text-align:center; color:#999;'>No data available</td></tr>"; fi

DATE_UPDATE=$($DATE_CMD "+%d/%m/%Y %H:%M:%S")

# ==============================================================================
# 4. GENERATE JS DATA FILE (Updates every run)
# ==============================================================================
cat <<EOF > "$DATA_FILE"
window.FW_DATA = {
    updated: "$DATE_UPDATE",
    uptime: "$UPTIME",
    lists: {
        main: "$SIZE_MAIN",
        vpn: "$SIZE_VPN"
    },
    stats: {
        day: { main: "$MAIN_DAY", vpn: "$VPN_DAY", total: $((MAIN_DAY + VPN_DAY)) },
        week: { main: "$MAIN_WEEK", vpn: "$VPN_WEEK", total: $((MAIN_WEEK + VPN_WEEK)) },
        month: { main: "$MAIN_MONTH", vpn: "$VPN_MONTH", total: $((MAIN_MONTH + VPN_MONTH)) },
        lifetime: { main: "$MAIN_TOTAL", vpn: "$VPN_TOTAL", total: $((MAIN_TOTAL + VPN_TOTAL)) }
    },
    top10: \`$TOP_10_ROWS\`
};
EOF

# ==============================================================================
# 5. GENERATE STATIC HTML (Only if missing)
# ==============================================================================
if [ ! -f "$HTML_FILE" ]; then
cat <<'HTML_EOF' > "$HTML_FILE"
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
        .btn { display: inline-block; background: var(--accent); color: white; padding: 8px 15px; border-radius: 4px; text-decoration: none; font-size: 12px; float: right; cursor: pointer; }
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
                <div class="val" style="color: #e74c3c" id="list_main">-</div>
                <div class="sub">Banned IPs</div>
            </div>
            <div class="card">
                <h3>VPN Blocklist</h3>
                <div class="val" style="color: #e67e22" id="list_vpn">-</div>
                <div class="sub">Banned IPs</div>
            </div>
            <div class="card">
                <h3>System Status</h3>
                <div class="val" style="color: #27ae60">ACTIVE</div>
                <div class="sub" id="uptime">-</div>
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
                        <tr><td>Today</td><td class="num col-main" id="d_m">-</td><td class="num col-vpn" id="d_v">-</td><td class="num" id="d_t">-</td></tr>
                        <tr><td>Week</td><td class="num col-main" id="w_m">-</td><td class="num col-vpn" id="w_v">-</td><td class="num" id="w_t">-</td></tr>
                        <tr><td>Month</td><td class="num col-main" id="m_m">-</td><td class="num col-vpn" id="m_v">-</td><td class="num" id="m_t">-</td></tr>
                        <tr class="total-row"><td>LIFETIME</td><td class="num col-main" id="l_m">-</td><td class="num col-vpn" id="l_v">-</td><td class="num" id="l_t">-</td></tr>
                    </tbody>
                </table>
            </div>
            <div class="panel">
                <div class="panel-header">🏆 Top 10 Days</div>
                <table class="stats-table">
                    <thead><tr><th>Date</th><th class="num">Blocked</th></tr></thead>
                    <tbody id="top10_body">
                        </tbody>
                </table>
            </div>
        </div>
        <div class="footer">Database: SQLite3 | Last update: <span id="last_update">Loading...</span></div>
    </div>

    <script src="firewall_data.js"></script>
    <script>
        if (typeof window.FW_DATA !== 'undefined') {
            const d = window.FW_DATA;
            
            // Header Stats
            document.getElementById('list_main').innerText = d.lists.main;
            document.getElementById('list_vpn').innerText = d.lists.vpn;
            document.getElementById('uptime').innerText = d.uptime;
            document.getElementById('last_update').innerText = d.updated;

            // Periodic Table
            document.getElementById('d_m').innerText = "+" + d.stats.day.main;
            document.getElementById('d_v').innerText = "+" + d.stats.day.vpn;
            document.getElementById('d_t').innerText = "+" + d.stats.day.total;

            document.getElementById('w_m').innerText = "+" + d.stats.week.main;
            document.getElementById('w_v').innerText = "+" + d.stats.week.vpn;
            document.getElementById('w_t').innerText = "+" + d.stats.week.total;

            document.getElementById('m_m').innerText = "+" + d.stats.month.main;
            document.getElementById('m_v').innerText = "+" + d.stats.month.vpn;
            document.getElementById('m_t').innerText = "+" + d.stats.month.total;

            document.getElementById('l_m').innerText = d.stats.lifetime.main;
            document.getElementById('l_v').innerText = d.stats.lifetime.vpn;
            document.getElementById('l_t').innerText = d.stats.lifetime.total;

            // Top 10 Table (Raw HTML injection from Shell logic)
            document.getElementById('top10_body').innerHTML = d.top10;
        }
    </script>
</body>
</html>
HTML_EOF
fi
