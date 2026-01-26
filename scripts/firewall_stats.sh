#!/bin/sh

# ==============================================================================
# KEENETIC FIREWALL STATS v3.0.19 (TIMEZONE FIX)
# Features: 
# - FIX: Forces system Timezone export so SQLite respects local time (e.g. 18:00 vs 17:00).
# - FIX: SQL 'ORDER BY' uses MAX(timestamp) to ensure correct sorting of grouped rows.
# - UI: Console feedback with SQLite time verification.
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# --- FORCE TIMEZONE ---
# Entware/SQLite needs TZ variable to perform localtime conversion correctly
if [ -f /etc/TZ ]; then
    export TZ=$(cat /etc/TZ)
elif [ -f /opt/etc/TZ ]; then
    export TZ=$(cat /opt/etc/TZ)
fi

# --- CONFIGURATION ---
DB_FILE="/opt/etc/firewall_stats.db"
WEB_DIR="/opt/var/www/firewall"
DATA_FILE="$WEB_DIR/firewall_data.js"
HTML_FILE="$WEB_DIR/index.html"

# Tools
IPTABLES_CMD="iptables"
IP6TABLES_CMD="ip6tables"

TARGETS="FirewallBlock|$IPTABLES_CMD| FirewallBlock6|$IP6TABLES_CMD|6 VPNBlock|$IPTABLES_CMD|"

DIFF_FILE_V4="/opt/etc/firewall_v4_diff.dat"
DIFF_FILE_V6="/opt/etc/firewall_v6_diff.dat"
DIFF_FILE_VPN="/opt/etc/firewall_vpn_diff.dat"
VPN_SIZE_FILE="/opt/etc/firewall_vpn_last_size.dat"
IP_LAST_STATE="/opt/etc/firewall_ip_counters.dat"
ABUSEIPDB_KEY="<PUT YOUR KEY HERE>"

mkdir -p "$WEB_DIR"
DATE_CMD="/opt/bin/date"; [ ! -x "$DATE_CMD" ] && DATE_CMD="date"

echo "=== Firewall Stats Updater v3.0.19 ==="

# 1. DB INIT
if [ ! -f "$DB_FILE" ]; then
    echo " -> Initializing new Database..."
    sqlite3 "$DB_FILE" "CREATE TABLE drops (id INTEGER PRIMARY KEY, timestamp INTEGER, list_name TEXT, count INTEGER); CREATE INDEX idx_ts ON drops(timestamp);"
    sqlite3 "$DB_FILE" "CREATE TABLE ip_drops (timestamp INTEGER, ip TEXT, count INTEGER); CREATE INDEX idx_ip_ts ON ip_drops(timestamp);"
    sqlite3 "$DB_FILE" "CREATE TABLE ip_info (ip TEXT PRIMARY KEY, country TEXT, risk INTEGER, domain TEXT, updated INTEGER);"
fi

NOW=$($DATE_CMD +%s)

# DEBUG TIMEZONE
SQL_TIME=$(sqlite3 "$DB_FILE" "SELECT time($NOW, 'unixepoch', 'localtime');")
SYS_TIME=$($DATE_CMD "+%H:%M:%S")
echo " -> Time Check | System: $SYS_TIME | SQLite: $SQL_TIME"
if [ "$SQL_TIME" != "$SYS_TIME" ]; then
    echo "    WARNING: SQLite time mismatch! Rows might appear in UTC."
fi

# 2. COLLECT TOTALS
echo " -> Reading counters..."
for TARGET in $TARGETS; do
    SET_NAME=$(echo "$TARGET" | cut -d'|' -f1)
    CMD=$(echo "$TARGET" | cut -d'|' -f2)
    SUFFIX=$(echo "$TARGET" | cut -d'|' -f3)
    LAST_RUN_FILE="/tmp/fw_last_${SET_NAME}.dat"

    # Read Counters
    C_IN_RAW=$($CMD -L "BLOCKLIST_IN${SUFFIX}" -v -x -n 2>/dev/null | grep -w "match-set $SET_NAME" | awk '{print $1}' | head -n 1)
    C_FW_RAW=$($CMD -L "BLOCKLIST_FWD${SUFFIX}" -v -x -n 2>/dev/null | grep -w "match-set $SET_NAME" | awk '{print $1}' | head -n 1)
    
    # Sanitize inputs
    C_IN=$C_IN_RAW; case "$C_IN" in ''|*[!0-9]*) C_IN=0 ;; esac
    C_FW=$C_FW_RAW; case "$C_FW" in ''|*[!0-9]*) C_FW=0 ;; esac
    CUR=$((C_IN + C_FW))
    
    if [ -f "$LAST_RUN_FILE" ]; then LAST=$(cat "$LAST_RUN_FILE"); else LAST=0; fi
    case "$LAST" in ''|*[!0-9]*) LAST=0 ;; esac

    if [ "$CUR" -lt "$LAST" ]; then DELTA=$CUR; else DELTA=$((CUR - LAST)); fi
    
    echo "    [$SET_NAME] Total: $CUR (Delta: +$DELTA)"

    if [ "$DELTA" -gt 0 ]; then
        sqlite3 "$DB_FILE" "INSERT INTO drops (timestamp, list_name, count) VALUES ($NOW, '$SET_NAME', $DELTA);"
    fi
    echo "$CUR" > "$LAST_RUN_FILE"
    
    # Capture Set Sizes
    SIZE=$(ipset list "$SET_NAME" 2>/dev/null | grep -cE '^[0-9]')
    case "$SIZE" in ''|*[!0-9]*) SIZE=0 ;; esac
    eval "SIZE_${SET_NAME}=$SIZE"
done

# --- DIFF MANAGEMENT ---
read_file() { if [ -f "$1" ]; then cat "$1" | tr -d '\n'; else echo "=0"; fi; }

# 1. Main Lists
DIFF_V4=$(read_file "$DIFF_FILE_V4")
DIFF_V6=$(read_file "$DIFF_FILE_V6")

# 2. VPN List
S_VPN_CUR=$SIZE_VPNBlock
case "$S_VPN_CUR" in ''|*[!0-9]*) S_VPN_CUR=0 ;; esac
S_VPN_LAST=$(read_file "$VPN_SIZE_FILE")
case "$S_VPN_LAST" in ''|*[!0-9]*) S_VPN_LAST=$S_VPN_CUR ;; esac

if [ "$S_VPN_CUR" -ne "$S_VPN_LAST" ]; then
    D_VPN=$((S_VPN_CUR - S_VPN_LAST))
    if [ "$D_VPN" -ge 0 ]; then DIFF_STR="+$D_VPN"; else DIFF_STR="$D_VPN"; fi
    echo "$DIFF_STR" > "$DIFF_FILE_VPN"
    echo "$S_VPN_CUR" > "$VPN_SIZE_FILE"
else
    DIFF_STR=$(read_file "$DIFF_FILE_VPN")
fi
DIFF_VPN=$DIFF_STR

# 3. COLLECT IP STATS
echo " -> Processing per-IP stats..."
CURRENT_DUMP="/tmp/ipset_dump_now.dat"
SQL_IMPORT="/tmp/ip_inserts.sql"
: > "$CURRENT_DUMP"

{
    ipset list FirewallBlock 2>/dev/null | grep "packets" | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2/p' | awk '$2 > 0'
    ipset list FirewallBlock6 2>/dev/null | grep "packets" | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2/p' | awk '$2 > 0'
} | sort > "$CURRENT_DUMP"

DB_IS_EMPTY=$(sqlite3 "$DB_FILE" "SELECT count(*) FROM ip_drops;")
[ -z "$DB_IS_EMPTY" ] && DB_IS_EMPTY=0

if [ ! -f "$IP_LAST_STATE" ] || [ "$DB_IS_EMPTY" -eq 0 ]; then
    awk -v now="$NOW" '{printf "INSERT INTO ip_drops (timestamp, ip, count) VALUES (%d, \"%s\", %d);\n", now, $1, $2;}' "$CURRENT_DUMP" > "$SQL_IMPORT"
else
    awk -v now="$NOW" 'FNR==NR { old[$1] = $2; next } { prev = (old[$1] ? old[$1] : 0); curr = $2; delta = curr - prev; if (delta < 0) delta = curr; if (delta > 0) printf "INSERT INTO ip_drops (timestamp, ip, count) VALUES (%d, \"%s\", %d);\n", now, $1, delta; }' "$IP_LAST_STATE" "$CURRENT_DUMP" > "$SQL_IMPORT"
fi
cp "$CURRENT_DUMP" "$IP_LAST_STATE"

if [ -s "$SQL_IMPORT" ]; then
    LINES=$(wc -l < "$SQL_IMPORT")
    echo "    Importing $LINES new IP records..."
    echo "BEGIN TRANSACTION;" > /tmp/ip_trans.sql; cat "$SQL_IMPORT" >> /tmp/ip_trans.sql; echo "COMMIT;" >> /tmp/ip_trans.sql
    sqlite3 "$DB_FILE" < /tmp/ip_trans.sql; rm /tmp/ip_trans.sql
fi
rm "$CURRENT_DUMP" "$SQL_IMPORT" 2>/dev/null

# 4. GENERATE DATA
echo " -> Generating Dashboard Data..."
TOTAL_DROPS_ALL_TIME=$(sqlite3 "$DB_FILE" "SELECT sum(count) FROM drops;")
[ -z "$TOTAL_DROPS_ALL_TIME" ] && TOTAL_DROPS_ALL_TIME="0"

gen_html_rows() {
    QUERY="SELECT $1, SUM(CASE WHEN list_name='FirewallBlock' THEN count ELSE 0 END), SUM(CASE WHEN list_name='FirewallBlock6' THEN count ELSE 0 END), SUM(CASE WHEN list_name='VPNBlock' THEN count ELSE 0 END), SUM(count) FROM drops $3 GROUP BY $2 ORDER BY MAX(timestamp) DESC;"
    sqlite3 -separator "|" "$DB_FILE" "$QUERY" | awk -F'|' '{print "<tr><td>"$1"</td><td class=\"num col-main\">+"$2"</td><td class=\"num col-v6\">+"$3"</td><td class=\"num col-vpn\">+"$4"</td><td class=\"num\">+"$5"</td></tr>"}'
}

# Robust get_avg using awk
get_avg() {
    QUERY="SELECT AVG(total) FROM (SELECT SUM(count) as total FROM drops $2 GROUP BY $1);"
    RES=$(sqlite3 "$DB_FILE" "$QUERY")
    echo "$RES" | awk '{printf "%.0f", $1}'
}

ROWS_HOURLY=$(gen_html_rows "strftime('%H:00', timestamp, 'unixepoch', 'localtime')" "1" "WHERE timestamp >= strftime('%s', 'now', '-24 hours')")
AVG_H=$(get_avg "strftime('%H:00', timestamp, 'unixepoch', 'localtime')" "WHERE timestamp >= strftime('%s', 'now', '-24 hours')")

ROWS_DAILY=$(gen_html_rows "strftime('%d-%m-%Y', timestamp, 'unixepoch', 'localtime')" "1" "WHERE timestamp >= strftime('%s', 'now', '-30 days')")
AVG_D=$(get_avg "strftime('%d-%m-%Y', timestamp, 'unixepoch', 'localtime')" "WHERE timestamp >= strftime('%s', 'now', '-30 days')")

ROWS_MONTHLY=$(gen_html_rows "strftime('%m-%Y', timestamp, 'unixepoch', 'localtime')" "1" "WHERE timestamp >= strftime('%s', 'now', '-12 months')")
AVG_M=$(get_avg "strftime('%m-%Y', timestamp, 'unixepoch', 'localtime')" "WHERE timestamp >= strftime('%s', 'now', '-12 months')")

ROWS_YEARLY=$(gen_html_rows "strftime('%Y', timestamp, 'unixepoch', 'localtime')" "1" "")
AVG_Y=$(get_avg "strftime('%Y', timestamp, 'unixepoch', 'localtime')" "")

gen_top_days() {
    QUERY="SELECT strftime('%d-%m-%Y', timestamp, 'unixepoch', 'localtime') as day, SUM(CASE WHEN list_name='FirewallBlock' THEN count ELSE 0 END), SUM(CASE WHEN list_name='FirewallBlock6' THEN count ELSE 0 END), SUM(CASE WHEN list_name='VPNBlock' THEN count ELSE 0 END), SUM(count) as total FROM drops GROUP BY day ORDER BY total DESC LIMIT 10;"
    sqlite3 -separator "|" "$DB_FILE" "$QUERY" | awk -F'|' '{print "<tr><td><b>"$1"</b></td><td class=\"num col-main\">+"$2"</td><td class=\"num col-v6\">+"$3"</td><td class=\"num col-vpn\">+"$4"</td><td class=\"num\">+"$5"</td></tr>"}'
}
ROWS_TOP_DAYS=$(gen_top_days)

get_top10() {
    PERIOD_SEC=$1; TYPE=$2
    if [ "$TYPE" = "NET" ]; then FILTER="AND ip LIKE '%/%'"; BADGE="bg-secondary"; else FILTER="AND ip NOT LIKE '%/%'"; BADGE="bg-primary"; fi
    
    if [ "$PERIOD_SEC" -eq 0 ]; then QUERY="SELECT ip, sum(count) as total FROM ip_drops WHERE 1=1 $FILTER GROUP BY ip ORDER BY total DESC LIMIT 10;"
    else LIMIT_TS=$((NOW - PERIOD_SEC)); QUERY="SELECT ip, sum(count) as total FROM ip_drops WHERE timestamp > $LIMIT_TS $FILTER GROUP BY ip ORDER BY total DESC LIMIT 10;"; fi
    
    TOP_LIST=$(sqlite3 -separator "|" "$DB_FILE" "$QUERY")
    if [ -z "$TOP_LIST" ]; then echo "<tr><td colspan='3' class='nodata'>No data</td></tr>"; return; fi

    IFS='
'
    for LINE in $TOP_LIST; do
        IP=$(echo "$LINE" | cut -d'|' -f1); COUNT=$(echo "$LINE" | cut -d'|' -f2); 
        CLEAN_IP=$(echo "$IP" | cut -d'/' -f1)
        
        CACHE=$(sqlite3 -separator "|" "$DB_FILE" "SELECT country, risk, domain FROM ip_info WHERE ip='$CLEAN_IP';")
        if [ -z "$CACHE" ]; then
            J=$(curl -s -m 3 -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=$CLEAN_IP" -d maxAgeInDays=90 -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" || echo "")
            CO=$(echo "$J"|grep -o '"countryCode":"[^"]*"'|cut -d'"' -f4); SC=$(echo "$J"|grep -o '"abuseConfidenceScore":[0-9]*'|cut -d':' -f2); DO=$(echo "$J"|grep -o '"domain":"[^"]*"'|cut -d'"' -f4)
            case "$SC" in ''|*[!0-9]*) SC=0 ;; esac
            if [ -n "$CO" ]; then sqlite3 "$DB_FILE" "INSERT OR REPLACE INTO ip_info (ip, country, risk, domain, updated) VALUES ('$CLEAN_IP', '$CO', $SC, '$DO', $NOW);"; CACHE="$CO|$SC|$DO"; fi
        fi
        CO=$(echo "$CACHE"|cut -d'|' -f1); SC=$(echo "$CACHE"|cut -d'|' -f2); DO=$(echo "$CACHE"|cut -d'|' -f3)
        case "$SC" in ''|*[!0-9]*) SC=0 ;; esac
        [ "$SC" -ge 50 ] && ST="color:var(--red);font-weight:bold;" || ST="color:var(--green);"
        echo "<tr><td><span class='badge bg-danger'>$COUNT</span></td><td><a href='https://www.abuseipdb.com/check/$CLEAN_IP' target='_blank'>$IP</a></td><td class='meta'><span style='$ST'>Risk: ${SC}%</span> - $CO<br><small>$DO</small></td></tr>"
    done; unset IFS
}

TB_IPS_24H=$(get_top10 86400 "IP"); TB_NETS_24H=$(get_top10 86400 "NET")
TB_IPS_30D=$(get_top10 2592000 "IP"); TB_NETS_30D=$(get_top10 2592000 "NET")
TB_IPS_1Y=$(get_top10 31536000 "IP"); TB_NETS_1Y=$(get_top10 31536000 "NET")
TB_IPS_ALL=$(get_top10 0 "IP"); TB_NETS_ALL=$(get_top10 0 "NET")

# --- CLEANUP ---
sqlite3 "$DB_FILE" "DELETE FROM drops WHERE timestamp < $((NOW - 31536000));"
sqlite3 "$DB_FILE" "DELETE FROM ip_drops WHERE timestamp < $((NOW - 31536000));"

# --- JSON EXPORT ---
DATE_UPDATE=$($DATE_CMD "+%d-%m-%Y %H:%M:%S"); UP_SECONDS=$(cut -d. -f1 /proc/uptime)
case "$UP_SECONDS" in ''|*[!0-9]*) UP_SECONDS=0 ;; esac
DAYS=$((UP_SECONDS / 86400)); HOURS=$(( (UP_SECONDS % 86400) / 3600 ))
UPTIME="${DAYS}d ${HOURS}h"

S_MAIN=$SIZE_FirewallBlock; S_MAIN6=$SIZE_FirewallBlock6; S_VPN=$SIZE_VPNBlock

cat <<EOF > "$DATA_FILE"
window.FW_DATA = {
    updated: "$DATE_UPDATE", uptime: "$UPTIME", lifetime: "$TOTAL_DROPS_ALL_TIME",
    lists: { 
        main: "$S_MAIN", diff_v4: "$DIFF_V4", 
        main6: "$S_MAIN6", diff_v6: "$DIFF_V6", 
        vpn: "$S_VPN", diff_vpn: "$DIFF_VPN" 
    },
    averages: { hourly: "$AVG_H", daily: "$AVG_D", monthly: "$AVG_M", yearly: "$AVG_Y" },
    tables: { 
        hourly: \`$ROWS_HOURLY\`, daily: \`$ROWS_DAILY\`, monthly: \`$ROWS_MONTHLY\`, yearly: \`$ROWS_YEARLY\`, top_days: \`$ROWS_TOP_DAYS\`,
        ips_24h: \`$TB_IPS_24H\`, nets_24h: \`$TB_NETS_24H\`,
        ips_30d: \`$TB_IPS_30D\`, nets_30d: \`$TB_NETS_30D\`,
        ips_1y: \`$TB_IPS_1Y\`, nets_1y: \`$TB_NETS_1Y\`,
        ips_all: \`$TB_IPS_ALL\`, nets_all: \`$TB_NETS_ALL\`
    }
};
EOF
chmod 644 "$DATA_FILE"

# --- HTML REGENERATION ---
if [ ! -f "$HTML_FILE" ] || [ "$1" = "force" ]; then
    echo " -> Re-generating HTML structure..."
cat <<'HTML_EOF' > "$HTML_FILE"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Keenetic Firewall Stats</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">
    <style>
        :root { --bg: #f4f7f6; --card: #ffffff; --text: #333; --muted: #6c757d; --border: #e9ecef; --th-bg: #f8f9fa; --red: #dc3545; --orange: #fd7e14; --blue: #0d6efd; --green: #198754; --purple: #6f42c1; --shadow: rgba(0,0,0,0.03); --diff-pos: rgba(25, 135, 84, 0.1); --diff-neg: rgba(220, 53, 69, 0.1); --diff-eq: rgba(108, 117, 125, 0.1); }
        @media (prefers-color-scheme: dark) { :root { --bg: #121212; --card: #1e1e1e; --text: #e0e0e0; --muted: #a0a0a0; --border: #2c2c2c; --th-bg: #252525; --shadow: rgba(0,0,0,0.5); --diff-pos: rgba(25, 135, 84, 0.2); --diff-neg: rgba(220, 53, 69, 0.2); --diff-eq: rgba(108, 117, 125, 0.2); } }
        
        body { font-family: -apple-system, sans-serif; background: var(--bg); color: var(--text); padding: 20px; max-width: 1200px; margin: 0 auto; transition: background 0.3s; }
        
        .status-bar { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; background: var(--card); padding: 15px 20px; border-radius: 8px; border: 1px solid var(--border); margin-bottom: 25px; gap: 15px; }
        .header-title { margin: 0; font-weight: 700; display: flex; align-items: center; gap: 15px; font-size: 1.5rem; }
        .btn-home { text-decoration: none; font-size: 22px; border-right: 1px solid var(--border); padding-right: 15px; transition: transform 0.2s; }
        .btn-home:hover { transform: scale(1.1); }
        .status-controls { display: flex; align-items: center; gap: 15px; }
        .btn-refresh { background-color: var(--blue); color: #fff; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; text-decoration: none; font-size: 13px; font-weight: 600;}
        .btn-refresh:hover { opacity: 0.9; }
        
        .grid-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: var(--card); padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px var(--shadow); border: 1px solid var(--border); }
        .card h3 { margin: 0 0 10px; font-size: 11px; text-transform: uppercase; color: var(--muted); letter-spacing: 1px; font-weight: 600; }
        .card .val { font-size: 28px; font-weight: 800; line-height: 1.2; }
        .diff { font-size: 12px; font-weight: 600; padding: 2px 8px; border-radius: 12px; margin-left: 8px; vertical-align: middle; }
        .diff.pos { background: var(--diff-pos); color: var(--green); } .diff.neg { background: var(--diff-neg); color: var(--red); } .diff.eq { background: var(--diff-eq); color: var(--muted); }
        
        .main-tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .main-tab-btn { flex: 1; padding: 12px; background: var(--card); border: 1px solid var(--border); border-radius: 8px; cursor: pointer; font-weight: 700; color: var(--muted); font-size: 14px; transition: all 0.2s; box-shadow: 0 2px 5px var(--shadow); }
        .main-tab-btn.active { background: var(--blue); color: #fff; border-color: var(--blue); }
        
        .view-section { display: none; } .view-section.active { display: block; }
        .section-title { margin-bottom: 15px; font-size: 15px; font-weight: 700; color: var(--muted); display: flex; align-items: center; justify-content: space-between; }
        .section-title span { display: flex; align-items: center; }
        .section-title span::before { content: ''; display: inline-block; width: 4px; height: 16px; background: var(--blue); margin-right: 10px; border-radius: 2px; }
        
        .tables-grid { display: grid; grid-template-columns: 1fr; gap: 25px; margin-bottom: 25px; }
        @media(min-width: 900px) { .tables-grid { grid-template-columns: 1fr 1fr; } }
        
        .split-view { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        @media(max-width: 900px) { .split-view { grid-template-columns: 1fr; } }
        .sub-header { font-size: 12px; text-transform: uppercase; color: var(--muted); font-weight: 700; margin-bottom: 10px; border-bottom: 2px solid var(--border); padding-bottom: 5px; }

        .table-container { background: var(--card); border-radius: 10px; box-shadow: 0 2px 10px var(--shadow); border: 1px solid var(--border); overflow-x: auto; -webkit-overflow-scrolling: touch; }
        table { width: 100%; border-collapse: collapse; white-space: nowrap; }
        th { background: var(--th-bg); padding: 10px 12px; text-align: left; font-size: 11px; text-transform: uppercase; color: var(--muted); font-weight: 700; border-bottom: 1px solid var(--border); }
        td { padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 13px; color: var(--text); }
        .num { text-align: right; font-family: monospace; font-weight: 600; }
        .col-main { color: var(--red); } .col-v6 { color: var(--purple); } .col-vpn { color: var(--orange); }
        .nodata { text-align: center; color: var(--muted); padding: 15px; font-style: italic; }
        
        .avg-badge { font-size: 13px; font-weight: 600; color: #0d6efd; background: rgba(13, 110, 253, 0.08); padding: 2px 10px; border-radius: 20px; margin-left: 12px; }
        @media (prefers-color-scheme: dark) { .avg-badge { color: #5c9eff; background: rgba(13, 110, 253, 0.15); } }

        .tabs { display: flex; gap: 5px; }
        .tab-btn { background: transparent; border: 1px solid var(--border); color: var(--muted); padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 11px; font-weight: 600; }
        .tab-btn.active { background: var(--blue); color: #fff; border-color: var(--blue); }
        .tab-content { display: none; } .tab-content.active { display: block; }
        
        .badge { font-size: 10px; padding: 2px 6px; border-radius: 4px; color: #fff; font-weight: 700; }
        .bg-danger { background: var(--red); } .bg-primary { background: var(--blue); } .bg-secondary { background: var(--gray); }
        .meta { font-size: 13px; color: var(--muted); line-height: 1.4; white-space: normal; }
        .meta small { font-size: 12px; font-weight: 500; }
        a { color: var(--blue); text-decoration: none; } a:hover { text-decoration: underline; }
        .footer { text-align: center; font-size: 11px; color: var(--muted); margin-top: 40px; }

        @media(max-width: 768px) {
            .status-bar { flex-direction: column; text-align: center; } 
            .header-title { font-size: 1.3rem; justify-content: center; }
            .status-controls { width: 100%; justify-content: center; }
        }
    </style>
</head>
<body>
    <div class="status-bar">
        <h2 class="header-title">
            <a href="../index.html" class="btn-home" title="Back to Dashboard">🏠</a>
            <span>🛡️ Keenetic Firewall Stats</span>
        </h2>
        <div class="status-controls">
            <div>Last Update: <span id="last_update_header" style="font-weight:700">-</span></div>
            <a href="javascript:location.reload()" class="btn-refresh">Refresh</a>
        </div>
    </div>

    <div class="grid-cards">
        <div class="card"><h3>IPv4 Blocklist (IP/Subnet)</h3><div><span class="val" style="color:var(--red)" id="size_main">-</span><span id="diff_v4"></span></div></div>
        <div class="card"><h3>IPv6 Blocklist (IP/Subnet)</h3><div><span class="val" style="color:var(--purple)" id="size_main6">-</span><span id="diff_v6"></span></div></div>
        <div class="card"><h3>VPN Blocklist (IP)</h3><div><span class="val" style="color:var(--orange)" id="size_vpn">-</span><span id="diff_vpn"></span></div></div>
        <div class="card"><h3>Total Drops (Lifetime)</h3><div class="val" style="color:var(--blue)" id="lifetime">-</div></div>
    </div>

    <div class="main-tabs">
        <button class="main-tab-btn active" onclick="showMainTab('sources')">📊 Threat Analysis (Sources)</button>
        <button class="main-tab-btn" onclick="showMainTab('history')">📅 Traffic History (Drops)</button>
    </div>

    <div id="view_sources" class="view-section active">
        <div class="section-title"><span>🏆 Top 10 Attack Sources (Split View)</span>
            <div class="tabs">
                <button class="tab-btn active" onclick="showTab('24h')">24h</button>
                <button class="tab-btn" onclick="showTab('30d')">30 Days</button>
                <button class="tab-btn" onclick="showTab('1y')">1 Year</button>
                <button class="tab-btn" onclick="showTab('all')">All Time</button>
            </div>
        </div>
        
        <div id="tab_24h" class="tab-content active"><div class="split-view"><div><div class="sub-header">Top 10 Single IPs</div><div class="table-container"><table><thead><tr><th style="width:60px">Cnt</th><th style="width:35%">Source</th><th>Info</th></tr></thead><tbody id="tb_ips_24h"></tbody></table></div></div><div><div class="sub-header">Top 10 Subnets</div><div class="table-container"><table><thead><tr><th style="width:60px">Cnt</th><th style="width:35%">Source</th><th>Info</th></tr></thead><tbody id="tb_nets_24h"></tbody></table></div></div></div></div>
        <div id="tab_30d" class="tab-content"><div class="split-view"><div><div class="sub-header">Top 10 Single IPs</div><div class="table-container"><table><thead><tr><th style="width:60px">Cnt</th><th style="width:35%">Source</th><th>Info</th></tr></thead><tbody id="tb_ips_30d"></tbody></table></div></div><div><div class="sub-header">Top 10 Subnets</div><div class="table-container"><table><thead><tr><th style="width:60px">Cnt</th><th style="width:35%">Source</th><th>Info</th></tr></thead><tbody id="tb_nets_30d"></tbody></table></div></div></div></div>
        <div id="tab_1y" class="tab-content"><div class="split-view"><div><div class="sub-header">Top 10 Single IPs</div><div class="table-container"><table><thead><tr><th style="width:60px">Cnt</th><th style="width:35%">Source</th><th>Info</th></tr></thead><tbody id="tb_ips_1y"></tbody></table></div></div><div><div class="sub-header">Top 10 Subnets</div><div class="table-container"><table><thead><tr><th style="width:60px">Cnt</th><th style="width:35%">Source</th><th>Info</th></tr></thead><tbody id="tb_nets_1y"></tbody></table></div></div></div></div>
        <div id="tab_all" class="tab-content"><div class="split-view"><div><div class="sub-header">Top 10 Single IPs</div><div class="table-container"><table><thead><tr><th style="width:60px">Cnt</th><th style="width:35%">Source</th><th>Info</th></tr></thead><tbody id="tb_ips_all"></tbody></table></div></div><div><div class="sub-header">Top 10 Subnets</div><div class="table-container"><table><thead><tr><th style="width:60px">Cnt</th><th style="width:35%">Source</th><th>Info</th></tr></thead><tbody id="tb_nets_all"></tbody></table></div></div></div></div>
    </div>

    <div id="view_history" class="view-section">
        <div class="tables-grid">
            <div><div class="section-title"><span>Hourly (Last 24h)<span class="avg-badge" id="avg_hourly"></span></span></div><div class="table-container"><table><thead><tr><th>Hour</th><th class="num">IPv4</th><th class="num">IPv6</th><th class="num">VPN</th><th class="num">Tot</th></tr></thead><tbody id="tb_hourly"></tbody></table></div></div>
            <div><div class="section-title"><span>Daily (Last 30 Days)<span class="avg-badge" id="avg_daily"></span></span></div><div class="table-container"><table><thead><tr><th>Date</th><th class="num">IPv4</th><th class="num">IPv6</th><th class="num">VPN</th><th class="num">Tot</th></tr></thead><tbody id="tb_daily"></tbody></table></div></div>
        </div>
        <div class="tables-grid">
            <div><div class="section-title"><span>Monthly (Last 12 Months)<span class="avg-badge" id="avg_monthly"></span></span></div><div class="table-container"><table><thead><tr><th>Month</th><th class="num">IPv4</th><th class="num">IPv6</th><th class="num">VPN</th><th class="num">Tot</th></tr></thead><tbody id="tb_monthly"></tbody></table></div></div>
            <div><div class="section-title"><span>Yearly History<span class="avg-badge" id="avg_yearly"></span></span></div><div class="table-container"><table><thead><tr><th>Year</th><th class="num">IPv4</th><th class="num">IPv6</th><th class="num">VPN</th><th class="num">Tot</th></tr></thead><tbody id="tb_yearly"></tbody></table></div></div>
        </div>
        <div class="tables-grid">
            <div style="grid-column: 1 / -1;"><div class="section-title"><span>🏆 Top 10 Days by Volume (All Time)</span></div><div class="table-container"><table><thead><tr><th>Date</th><th class="num">IPv4</th><th class="num">IPv6</th><th class="num">VPN</th><th class="num">Total</th></tr></thead><tbody id="tb_top_days"></tbody></table></div></div>
        </div>
    </div>

    <div class="footer">Uptime: <span id="uptime">-</span></div>
    
    <script src="firewall_data.js"></script>
    <script>
        function showMainTab(id) {
            document.querySelectorAll('.view-section').forEach(e => e.classList.remove('active'));
            document.querySelectorAll('.main-tab-btn').forEach(e => e.classList.remove('active'));
            document.getElementById('view_'+id).classList.add('active');
            event.target.classList.add('active');
        }
        function showTab(id) { 
            document.querySelectorAll('.tab-content').forEach(e => e.classList.remove('active')); 
            document.querySelectorAll('.tab-btn').forEach(e => e.classList.remove('active')); 
            document.getElementById('tab_'+id).classList.add('active'); 
            event.target.classList.add('active'); 
        }
        if (typeof window.FW_DATA !== 'undefined') {
            const d = window.FW_DATA;
            const setDiff = (elId, val) => { const el = document.getElementById(elId); if(!val || val==='0' || val==='=0' || val==='+0' || val==='-0'){ el.innerHTML=`<span class="diff eq">-</span>`; } else if(val.includes('+')){ el.innerHTML=`<span class="diff pos">${val}</span>`; } else if(val.includes('-')){ el.innerHTML=`<span class="diff neg">${val}</span>`; } else { el.innerHTML=`<span class="diff eq">-</span>`; } };
            document.getElementById('size_main').innerText = d.lists.main; setDiff('diff_v4', d.lists.diff_v4);
            document.getElementById('size_main6').innerText = d.lists.main6; setDiff('diff_v6', d.lists.diff_v6);
            document.getElementById('size_vpn').innerText = d.lists.vpn; setDiff('diff_vpn', d.lists.diff_vpn);
            document.getElementById('lifetime').innerText = d.lifetime; 
            document.getElementById('uptime').innerText = d.uptime; 
            document.getElementById('last_update_header').innerText = d.updated;
            
            // History Tables
            document.getElementById('tb_top_days').innerHTML = d.tables.top_days;
            document.getElementById('tb_hourly').innerHTML = d.tables.hourly; document.getElementById('tb_daily').innerHTML = d.tables.daily;
            document.getElementById('tb_monthly').innerHTML = d.tables.monthly; document.getElementById('tb_yearly').innerHTML = d.tables.yearly;
            
            // Averages
            if(d.averages) {
                document.getElementById('avg_hourly').innerText = "Avg: " + d.averages.hourly;
                document.getElementById('avg_daily').innerText = "Avg: " + d.averages.daily;
                document.getElementById('avg_monthly').innerText = "Avg: " + d.averages.monthly;
                document.getElementById('avg_yearly').innerText = "Avg: " + d.averages.yearly;
            }

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

echo "Done."
