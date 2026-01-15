#!/bin/sh

# ==============================================================================
# KEENETIC FIREWALL STATS v2.2.4 (STABLE - NEW HEADER & VPN DIFF)
# Features: Dual Tables, AbuseIPDB Caching, System Logging, Auto-Theme
# Change Log: 
#   v2.2.4: Merged new Header Design with persistent VPN Diff logic.
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# --- CONFIGURATION ---
DB_FILE="/opt/etc/firewall_stats.db"
WEB_DIR="/opt/var/www/firewall"
DATA_FILE="$WEB_DIR/firewall_data.js"
HTML_FILE="$WEB_DIR/index.html"
IPTABLES_CMD="iptables"

# Define the IPSet lists to monitor
LISTS="FirewallBlock VPNBlock"

# Files to store the latest visual delta for the dashboard header
DIFF_FILE_MAIN="/opt/etc/firewall_main_diff.dat"
DIFF_FILE_VPN="/opt/etc/firewall_vpn_diff.dat"

# File to store the state of IP counters from the previous run
IP_LAST_STATE="/opt/etc/firewall_ip_counters.dat"

# Logging Tag
LOG_TAG="FW_Stats"

# AbuseIPDB API Key (Configured)
ABUSEIPDB_KEY="240310f3869e8b852bf5f89ecd7af5d59dae631fa82499247de2d28a755cd4c04ae064fbff708ff2"

mkdir -p "$WEB_DIR"

# --- HELPER FUNCTIONS ---
DATE_CMD="/opt/bin/date"
if [ ! -x "$DATE_CMD" ]; then DATE_CMD="date"; fi

log() { logger -t "$LOG_TAG" "$1"; }

# 1. DATABASE INITIALIZATION
init_db() {
    if [ ! -f "$DB_FILE" ]; then
        log "Initializing new database file..."
        sqlite3 "$DB_FILE" "CREATE TABLE drops (id INTEGER PRIMARY KEY, timestamp INTEGER, list_name TEXT, count INTEGER);"
        sqlite3 "$DB_FILE" "CREATE INDEX idx_ts ON drops(timestamp);"
        sqlite3 "$DB_FILE" "CREATE INDEX idx_list ON drops(list_name);"
    fi
    
    HAS_IP_TABLE=$(sqlite3 "$DB_FILE" "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='ip_drops';")
    if [ "$HAS_IP_TABLE" -eq 0 ]; then
        sqlite3 "$DB_FILE" "CREATE TABLE ip_drops (timestamp INTEGER, ip TEXT, count INTEGER);"
        sqlite3 "$DB_FILE" "CREATE INDEX idx_ip_ts ON ip_drops(timestamp);"
        sqlite3 "$DB_FILE" "CREATE INDEX idx_ip_ip ON ip_drops(ip);"
    fi

    HAS_CACHE_TABLE=$(sqlite3 "$DB_FILE" "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='ip_info';")
    if [ "$HAS_CACHE_TABLE" -eq 0 ]; then
        sqlite3 "$DB_FILE" "CREATE TABLE ip_info (ip TEXT PRIMARY KEY, country TEXT, risk INTEGER, domain TEXT, updated INTEGER);"
    fi
}
init_db

# 2. COLLECT TOTAL COUNTERS
NOW=$($DATE_CMD +%s)
for LIST in $LISTS; do
    LAST_RUN_FILE="/tmp/fw_last_${LIST}.dat"
    COUNT_IN=$($IPTABLES_CMD -L INPUT -v -x -n | grep -w "match-set $LIST" | awk '{print $1}' | head -n 1)
    COUNT_FW=$($IPTABLES_CMD -L FORWARD -v -x -n | grep -w "match-set $LIST" | awk '{print $1}' | head -n 1)
    [ -z "$COUNT_IN" ] && COUNT_IN=0; [ -z "$COUNT_FW" ] && COUNT_FW=0
    CURRENT_VAL=$((COUNT_IN + COUNT_FW))
    
    if [ -f "$LAST_RUN_FILE" ]; then LAST_VAL=$(cat "$LAST_RUN_FILE"); else LAST_VAL=0; fi
    if [ "$CURRENT_VAL" -lt "$LAST_VAL" ]; then DELTA=$CURRENT_VAL; else DELTA=$((CURRENT_VAL - LAST_VAL)); fi

    if [ "$DELTA" -gt 0 ]; then
        sqlite3 "$DB_FILE" "INSERT INTO drops (timestamp, list_name, count) VALUES ($NOW, '$LIST', $DELTA);"
    fi
    echo "$CURRENT_VAL" > "$LAST_RUN_FILE"
    
    # --- DIFF LOGIC ---
    if [ "$LIST" = "FirewallBlock" ]; then 
        SIZE_MAIN=$(ipset list "$LIST" | grep -cE '^[0-9]')
        LIST_MAIN_DIFF="="; 
        [ -f "$DIFF_FILE_MAIN" ] && LIST_MAIN_DIFF=$(cat "$DIFF_FILE_MAIN")
    fi
    
    if [ "$LIST" = "VPNBlock" ]; then 
        SIZE_VPN=$(ipset list "$LIST" | grep -cE '^[0-9]')
        LIST_VPN_DIFF="+0"
        # Now reading from the persistent file created by update_blocklist.sh or vpn_scan.sh
        [ -f "$DIFF_FILE_VPN" ] && LIST_VPN_DIFF=$(cat "$DIFF_FILE_VPN")
    fi
done

# 3. COLLECT IP STATISTICS
CURRENT_DUMP="/tmp/ipset_dump_now.dat"
SQL_IMPORT="/tmp/ip_inserts.sql"

ipset list FirewallBlock | grep "packets" | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2/p' | awk '$2 > 0' | sort > "$CURRENT_DUMP"
DB_IS_EMPTY=$(sqlite3 "$DB_FILE" "SELECT count(*) FROM ip_drops;")

NEW_RECORDS=0
if [ ! -f "$IP_LAST_STATE" ] || [ "$DB_IS_EMPTY" -eq 0 ]; then
    awk -v now="$NOW" '{printf "INSERT INTO ip_drops (timestamp, ip, count) VALUES (%d, \"%s\", %d);\n", now, $1, $2;}' "$CURRENT_DUMP" > "$SQL_IMPORT"
    NEW_RECORDS=$(wc -l < "$SQL_IMPORT")
else
    awk -v now="$NOW" 'FNR==NR { old[$1] = $2; next } { prev = (old[$1] ? old[$1] : 0); curr = $2; delta = curr - prev; if (delta < 0) delta = curr; if (delta > 0) printf "INSERT INTO ip_drops (timestamp, ip, count) VALUES (%d, \"%s\", %d);\n", now, $1, delta; }' "$IP_LAST_STATE" "$CURRENT_DUMP" > "$SQL_IMPORT"
    if [ -f "$SQL_IMPORT" ]; then NEW_RECORDS=$(wc -l < "$SQL_IMPORT"); fi
fi
cp "$CURRENT_DUMP" "$IP_LAST_STATE"

if [ -s "$SQL_IMPORT" ]; then
    echo "BEGIN TRANSACTION;" > /tmp/ip_trans.sql
    cat "$SQL_IMPORT" >> /tmp/ip_trans.sql
    echo "COMMIT;" >> /tmp/ip_trans.sql
    sqlite3 "$DB_FILE" < /tmp/ip_trans.sql
    rm /tmp/ip_trans.sql
    log "Stats updated: $NEW_RECORDS IPs had new activity."
fi
rm "$CURRENT_DUMP" "$SQL_IMPORT" 2>/dev/null

# --- TOTAL DROPS ---
TOTAL_DROPS_ALL_TIME=$(sqlite3 "$DB_FILE" "SELECT sum(count) FROM drops;")
[ -z "$TOTAL_DROPS_ALL_TIME" ] && TOTAL_DROPS_ALL_TIME="0"

# --- GENERATE HISTORY TABLES ---
gen_html_rows() {
    QUERY="SELECT $1, SUM(CASE WHEN list_name='FirewallBlock' THEN count ELSE 0 END), SUM(CASE WHEN list_name='VPNBlock' THEN count ELSE 0 END), SUM(count) FROM drops $3 GROUP BY $2 ORDER BY timestamp DESC;"
    sqlite3 -separator "|" "$DB_FILE" "$QUERY" | awk -F'|' '{print "<tr><td>"$1"</td><td class=\"num col-main\">+"$2"</td><td class=\"num col-vpn\">+"$3"</td><td class=\"num\">+"$4"</td></tr>"}'
}

ROWS_HOURLY=$(gen_html_rows "strftime('%H:00', timestamp, 'unixepoch', 'localtime')" "1" "WHERE timestamp >= strftime('%s', 'now', '-24 hours')")
ROWS_DAILY=$(gen_html_rows "strftime('%d-%m-%Y', timestamp, 'unixepoch', 'localtime')" "1" "WHERE timestamp >= strftime('%s', 'now', '-30 days')")
ROWS_MONTHLY=$(gen_html_rows "strftime('%m-%Y', timestamp, 'unixepoch', 'localtime')" "1" "WHERE timestamp >= strftime('%s', 'now', '-12 months')")
ROWS_YEARLY=$(gen_html_rows "strftime('%Y', timestamp, 'unixepoch', 'localtime')" "1" "")

# --- GENERATE TOP 10 LISTS ---
get_top10() {
    PERIOD_SEC=$1
    TYPE=$2 # "IP" or "NET"
    
    if [ "$TYPE" = "NET" ]; then
        FILTER="AND ip LIKE '%/%'"
        BADGE_TYPE="NET"; BADGE_CLS="bg-secondary"
    else
        FILTER="AND ip NOT LIKE '%/%'"
        BADGE_TYPE="IP"; BADGE_CLS="bg-primary"
    fi
    
    if [ "$PERIOD_SEC" -eq 0 ]; then
        QUERY="SELECT ip, sum(count) as total FROM ip_drops WHERE 1=1 $FILTER GROUP BY ip ORDER BY total DESC LIMIT 10;"
    else
        LIMIT_TS=$((NOW - PERIOD_SEC))
        QUERY="SELECT ip, sum(count) as total FROM ip_drops WHERE timestamp > $LIMIT_TS $FILTER GROUP BY ip ORDER BY total DESC LIMIT 10;"
    fi
    
    TOP_LIST=$(sqlite3 -separator "|" "$DB_FILE" "$QUERY")
    if [ -z "$TOP_LIST" ]; then echo "<tr><td colspan='3' class='nodata'>No data</td></tr>"; return; fi

    IFS='
'
    for LINE in $TOP_LIST; do
        IP=$(echo "$LINE" | cut -d'|' -f1)
        COUNT=$(echo "$LINE" | cut -d'|' -f2)
        CLEAN_IP=$(echo "$IP" | cut -d'/' -f1)
        
        # Cache Check
        CACHE_DATA=$(sqlite3 -separator "|" "$DB_FILE" "SELECT country, risk, domain FROM ip_info WHERE ip='$CLEAN_IP';")
        
        if [ -n "$CACHE_DATA" ]; then
            COUNTRY=$(echo "$CACHE_DATA" | cut -d'|' -f1)
            SCORE=$(echo "$CACHE_DATA" | cut -d'|' -f2)
            DOMAIN=$(echo "$CACHE_DATA" | cut -d'|' -f3)
        else
            # API Lookup
            JSON_RESP=$(curl -s -m 3 -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=$CLEAN_IP" -d maxAgeInDays=90 -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" || echo "")
            COUNTRY=$(echo "$JSON_RESP" | grep -o '"countryCode":"[^"]*"' | cut -d'"' -f4)
            SCORE=$(echo "$JSON_RESP" | grep -o '"abuseConfidenceScore":[0-9]*' | cut -d':' -f2)
            DOMAIN=$(echo "$JSON_RESP" | grep -o '"domain":"[^"]*"' | cut -d'"' -f4)
            [ -z "$SCORE" ] && SCORE=0
            if [ -n "$COUNTRY" ]; then
               sqlite3 "$DB_FILE" "INSERT OR REPLACE INTO ip_info (ip, country, risk, domain, updated) VALUES ('$CLEAN_IP', '$COUNTRY', $SCORE, '$DOMAIN', $NOW);"
            fi
        fi
        
        if [ "$SCORE" -ge 50 ]; then
            META_INFO="<span style='color:var(--red); font-weight:bold;'>Risk: ${SCORE}%</span> - $COUNTRY<br><small>$DOMAIN</small>"
        else
            META_INFO="<span style='color:var(--green);'>Risk: ${SCORE}%</span> - $COUNTRY<br><small>$DOMAIN</small>"
        fi
        
        echo "<tr><td><span class='badge bg-danger'>$COUNT</span></td><td><a href='https://www.abuseipdb.com/check/$CLEAN_IP' target='_blank'>$IP</a> <span class='badge $BADGE_CLS'>$BADGE_TYPE</span></td><td class='meta'>$META_INFO</td></tr>"
    done
    unset IFS
}

# Generate 8 Tables
TB_IPS_24H=$(get_top10 86400 "IP"); TB_NETS_24H=$(get_top10 86400 "NET")
TB_IPS_30D=$(get_top10 2592000 "IP"); TB_NETS_30D=$(get_top10 2592000 "NET")
TB_IPS_1Y=$(get_top10 31536000 "IP"); TB_NETS_1Y=$(get_top10 31536000 "NET")
TB_IPS_ALL=$(get_top10 0 "IP"); TB_NETS_ALL=$(get_top10 0 "NET")

# --- CLEANUP ---
sqlite3 "$DB_FILE" "DELETE FROM drops WHERE timestamp < $((NOW - 31536000));"
sqlite3 "$DB_FILE" "DELETE FROM ip_drops WHERE timestamp < $((NOW - 31536000));"

# Keep cache fresh (delete entries older than 90 days if you want, or keep forever)
# sqlite3 "$DB_FILE" "DELETE FROM ip_info WHERE updated < $((NOW - 7776000));"

# --- JSON EXPORT ---
DATE_UPDATE=$($DATE_CMD "+%d-%m-%Y %H:%M:%S")
UP_SECONDS=$(cut -d. -f1 /proc/uptime)
DAYS=$((UP_SECONDS / 86400)); HOURS=$(( (UP_SECONDS % 86400) / 3600 ))
UPTIME="${DAYS}d ${HOURS}h"

cat <<EOF > "$DATA_FILE"
window.FW_DATA = {
    updated: "$DATE_UPDATE", uptime: "$UPTIME", lifetime: "$TOTAL_DROPS_ALL_TIME",
    lists: { main: "$SIZE_MAIN", main_diff: "$LIST_MAIN_DIFF", vpn: "$SIZE_VPN", vpn_diff: "$LIST_VPN_DIFF" },
    tables: { 
        hourly: \`$ROWS_HOURLY\`, daily: \`$ROWS_DAILY\`, monthly: \`$ROWS_MONTHLY\`, yearly: \`$ROWS_YEARLY\`, 
        ips_24h: \`$TB_IPS_24H\`, nets_24h: \`$TB_NETS_24H\`,
        ips_30d: \`$TB_IPS_30D\`, nets_30d: \`$TB_NETS_30D\`,
        ips_1y: \`$TB_IPS_1Y\`,  nets_1y: \`$TB_NETS_1Y\`,
        ips_all: \`$TB_IPS_ALL\`, nets_all: \`$TB_NETS_ALL\`
    }
};
EOF
chmod 644 "$DATA_FILE"

# --- HTML GENERATOR ---
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
        :root { 
            --bg: #f4f7f6; --card: #ffffff; --text: #333; --muted: #6c757d; --border: #e9ecef; --th-bg: #f8f9fa;
            --red: #dc3545; --orange: #fd7e14; --blue: #0d6efd; --green: #198754; --gray: #6c757d;
            --shadow: rgba(0,0,0,0.03); --diff-pos: rgba(25, 135, 84, 0.1); --diff-neg: rgba(220, 53, 69, 0.1); --diff-eq: rgba(108, 117, 125, 0.1);
        }
        @media (prefers-color-scheme: dark) {
            :root { --bg: #121212; --card: #1e1e1e; --text: #e0e0e0; --muted: #a0a0a0; --border: #2c2c2c; --th-bg: #252525; --shadow: rgba(0,0,0,0.5); --diff-pos: rgba(25, 135, 84, 0.2); --diff-neg: rgba(220, 53, 69, 0.2); --diff-eq: rgba(108, 117, 125, 0.2); }
        }
        body { font-family: -apple-system, system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 20px; max-width: 1200px; margin: 0 auto; transition: background 0.3s; }
        
        .header-title { margin: 0 0 15px 0; color: var(--text); font-weight: 700; display: flex; align-items: center; gap: 10px; }

        /* New Status Bar / Header Design */
        .status-bar {
            display: flex; justify-content: space-between; align-items: center;
            background: var(--card); padding: 15px 20px; border-radius: 10px;
            box-shadow: 0 2px 10px var(--shadow); border: 1px solid var(--border);
            margin-bottom: 25px;
        }

        /* Mobile specific adjustments for the Header */
        @media (max-width: 600px) {
            .status-bar {
                flex-direction: column;
                text-align: center;
                gap: 15px;
            }
        }
        
        .btn-refresh {
            background-color: var(--blue); color: #fff; border: none; padding: 10px 20px; border-radius: 6px;
            font-size: 13px; font-weight: 600; text-decoration: none; cursor: pointer;
            transition: background-color 0.2s, transform 0.1s; display: inline-block;
        }
        .btn-refresh:hover { background-color: #0b5ed7; transform: translateY(-1px); }
        .btn-refresh:active { transform: translateY(1px); }

        .grid-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: var(--card); padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px var(--shadow); border: 1px solid var(--border); }
        .card h3 { margin: 0 0 10px; font-size: 11px; text-transform: uppercase; color: var(--muted); letter-spacing: 1px; font-weight: 600; }
        .card .val { font-size: 32px; font-weight: 800; line-height: 1.2; }
        .diff { font-size: 13px; font-weight: 600; padding: 2px 8px; border-radius: 12px; margin-left: 8px; }
        .diff.pos { background: var(--diff-pos); color: var(--green); } .diff.neg { background: var(--diff-neg); color: var(--red); } .diff.eq { background: var(--diff-eq); color: var(--gray); }
        
        .section-title { margin-bottom: 15px; font-size: 15px; font-weight: 700; color: var(--muted); display: flex; align-items: center; justify-content: space-between; }
        .section-title span::before { content: ''; display: inline-block; width: 4px; height: 16px; background: var(--blue); margin-right: 10px; border-radius: 2px; }
        
        .tables-grid { display: grid; grid-template-columns: 1fr; gap: 25px; margin-bottom: 25px; }
        @media(min-width: 768px) { .tables-grid { grid-template-columns: 1fr 1fr; } }
        
        .split-view { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        @media(max-width: 900px) { .split-view { grid-template-columns: 1fr; } }
        .sub-header { font-size: 12px; text-transform: uppercase; color: var(--muted); font-weight: 700; margin-bottom: 10px; border-bottom: 2px solid var(--border); padding-bottom: 5px; }

        .table-container { background: var(--card); border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px var(--shadow); border: 1px solid var(--border); }
        table { width: 100%; border-collapse: collapse; }
        th { background: var(--th-bg); padding: 10px 12px; text-align: left; font-size: 11px; text-transform: uppercase; color: var(--muted); font-weight: 700; border-bottom: 1px solid var(--border); }
        td { padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 13px; color: var(--text); }
        .num { text-align: right; font-family: monospace; font-weight: 600; }
        .col-main { color: var(--red); } .col-vpn { color: var(--orange); }
        .nodata { text-align: center; color: var(--muted); padding: 15px; font-style: italic; }

        .tabs { display: flex; gap: 5px; }
        .tab-btn { background: transparent; border: 1px solid var(--border); color: var(--muted); padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 11px; font-weight: 600; }
        .tab-btn.active { background: var(--blue); color: #fff; border-color: var(--blue); }
        .tab-content { display: none; } .tab-content.active { display: block; }
        
        .badge { font-size: 10px; padding: 2px 6px; border-radius: 4px; color: #fff; font-weight: 700; }
        .bg-danger { background: var(--red); } .bg-primary { background: var(--blue); } .bg-secondary { background: var(--gray); }
        .meta { font-size: 12px; color: var(--muted); line-height: 1.3; }
        .meta small { font-size: 11px; font-weight: 500; }
        a { color: var(--blue); text-decoration: none; } a:hover { text-decoration: underline; }
        .footer { text-align: center; font-size: 11px; color: var(--muted); margin-top: 40px; padding-bottom: 20px; }
    </style>
</head>
<body>
    <h2 class="header-title">🛡️ Keenetic Firewall Stats</h2>
    
    <div class="status-bar">
        <div>Last Update: <span id="last_update_header" style="font-weight:700">-</span></div>
        <a href="javascript:location.reload()" class="btn-refresh">Refresh Now</a>
    </div>

    <div class="grid-cards">
        <div class="card"><h3>Internet Blocklist</h3><div><span class="val" style="color:var(--red)" id="size_main">-</span><span id="diff_main"></span></div></div>
        <div class="card"><h3>VPN Blocklist</h3><div><span class="val" style="color:var(--orange)" id="size_vpn">-</span><span id="diff_vpn"></span></div></div>
        <div class="card"><h3>Total Drops</h3><div class="val" style="color:var(--blue)" id="lifetime">-</div></div>
    </div>

    <div style="margin-bottom: 25px;">
        <div class="section-title"><span>🏆 Top 10 Sources (Split View)</span>
            <div class="tabs">
                <button class="tab-btn active" onclick="showTab('24h')">24h</button>
                <button class="tab-btn" onclick="showTab('30d')">30 Days</button>
                <button class="tab-btn" onclick="showTab('1y')">1 Year</button>
                <button class="tab-btn" onclick="showTab('all')">All Time</button>
            </div>
        </div>
        
        <div id="tab_24h" class="tab-content active">
            <div class="split-view">
                <div><div class="sub-header">Top 10 Single IPs</div><div class="table-container"><table><thead><tr><th width="15%">Drops</th><th>IP Address</th><th>Info</th></tr></thead><tbody id="tb_ips_24h"></tbody></table></div></div>
                <div><div class="sub-header">Top 10 Subnets</div><div class="table-container"><table><thead><tr><th width="15%">Drops</th><th>Subnet</th><th>Info</th></tr></thead><tbody id="tb_nets_24h"></tbody></table></div></div>
            </div>
        </div>
        <div id="tab_30d" class="tab-content">
            <div class="split-view">
                <div><div class="sub-header">Top 10 Single IPs</div><div class="table-container"><table><thead><tr><th width="15%">Drops</th><th>IP Address</th><th>Info</th></tr></thead><tbody id="tb_ips_30d"></tbody></table></div></div>
                <div><div class="sub-header">Top 10 Subnets</div><div class="table-container"><table><thead><tr><th width="15%">Drops</th><th>Subnet</th><th>Info</th></tr></thead><tbody id="tb_nets_30d"></tbody></table></div></div>
            </div>
        </div>
        <div id="tab_1y" class="tab-content">
            <div class="split-view">
                <div><div class="sub-header">Top 10 Single IPs</div><div class="table-container"><table><thead><tr><th width="15%">Drops</th><th>IP Address</th><th>Info</th></tr></thead><tbody id="tb_ips_1y"></tbody></table></div></div>
                <div><div class="sub-header">Top 10 Subnets</div><div class="table-container"><table><thead><tr><th width="15%">Drops</th><th>Subnet</th><th>Info</th></tr></thead><tbody id="tb_nets_1y"></tbody></table></div></div>
            </div>
        </div>
        <div id="tab_all" class="tab-content">
            <div class="split-view">
                <div><div class="sub-header">Top 10 Single IPs</div><div class="table-container"><table><thead><tr><th width="15%">Drops</th><th>IP Address</th><th>Info</th></tr></thead><tbody id="tb_ips_all"></tbody></table></div></div>
                <div><div class="sub-header">Top 10 Subnets</div><div class="table-container"><table><thead><tr><th width="15%">Drops</th><th>Subnet</th><th>Info</th></tr></thead><tbody id="tb_nets_all"></tbody></table></div></div>
            </div>
        </div>
    </div>

    <div class="tables-grid">
        <div><div class="section-title"><span>Hourly (Last 24h)</span></div><div class="table-container"><table><thead><tr><th>Hour</th><th class="num">Net</th><th class="num">VPN</th><th class="num">Tot</th></tr></thead><tbody id="tb_hourly"></tbody></table></div></div>
        <div><div class="section-title"><span>Daily (Last 30 Days)</span></div><div class="table-container"><table><thead><tr><th>Date</th><th class="num">Net</th><th class="num">VPN</th><th class="num">Tot</th></tr></thead><tbody id="tb_daily"></tbody></table></div></div>
    </div>
    <div class="tables-grid">
        <div><div class="section-title"><span>Monthly (Last 12 Months)</span></div><div class="table-container"><table><thead><tr><th>Month</th><th class="num">Net</th><th class="num">VPN</th><th class="num">Tot</th></tr></thead><tbody id="tb_monthly"></tbody></table></div></div>
        <div><div class="section-title"><span>Yearly History</span></div><div class="table-container"><table><thead><tr><th>Year</th><th class="num">Net</th><th class="num">VPN</th><th class="num">Tot</th></tr></thead><tbody id="tb_yearly"></tbody></table></div></div>
    </div>
    <div class="footer">Uptime: <span id="uptime">-</span></div>
    
    <script src="firewall_data.js"></script>
    <script>
        function showTab(id) { 
            document.querySelectorAll('.tab-content').forEach(e => e.classList.remove('active')); 
            document.querySelectorAll('.tab-btn').forEach(e => e.classList.remove('active')); 
            document.getElementById('tab_'+id).classList.add('active'); 
            event.target.classList.add('active'); 
        }
        if (typeof window.FW_DATA !== 'undefined') {
            const d = window.FW_DATA;
            const setDiff = (elId, val) => { const el = document.getElementById(elId); if(val==='+0'||val==='0'||val==='='){ el.innerHTML=`<span class="diff eq">-</span>`; } else if(val.includes('+')){ el.innerHTML=`<span class="diff pos">${val}</span>`; } else if(val.includes('-')){ el.innerHTML=`<span class="diff neg">${val}</span>`; } else { el.innerHTML=`<span class="diff eq">-</span>`; } };
            document.getElementById('size_main').innerText = d.lists.main; setDiff('diff_main', d.lists.main_diff);
            document.getElementById('size_vpn').innerText = d.lists.vpn; setDiff('diff_vpn', d.lists.vpn_diff);
            document.getElementById('lifetime').innerText = d.lifetime; 
            document.getElementById('uptime').innerText = d.uptime; 
            
            // Header Update
            document.getElementById('last_update_header').innerText = d.updated;
            
            // History Tables
            document.getElementById('tb_hourly').innerHTML = d.tables.hourly; document.getElementById('tb_daily').innerHTML = d.tables.daily;
            document.getElementById('tb_monthly').innerHTML = d.tables.monthly; document.getElementById('tb_yearly').innerHTML = d.tables.yearly;
            
            // Dual Tables (IPs & Subnets)
            ['24h','30d','1y','all'].forEach(p => {
                document.getElementById('tb_ips_'+p).innerHTML = d.tables['ips_'+p];
                document.getElementById('tb_nets_'+p).innerHTML = d.tables['nets_'+p];
            });
        }
    </script>
</body>
</html>
HTML_EOF
chmod 644 "$HTML_FILE"
fi
