#!/bin/sh

# ==============================================================================
# KEENETIC FIREWALL STATS v3.4.21 (FINAL)
# ==============================================================================
# AUTHOR: mattheweli
# DESCRIPTION: 
#   Aggregates firewall statistics, parses sniffer data for port mapping,
#   and generates JSON data for the web dashboard.
#   
#   CHANGES IN v3.4.21:
#     - LOGIC: Sniffer execution moved BEFORE JSON generation for real-time updates.
#     - CORE: Implemented robust "Linux Cooked" (SLL) header parsing for tcpdump.
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# ==============================================================================
# 1. CONFIGURATION & PATHS
# ==============================================================================

# Load external configuration if available
CONF_FILE="/opt/etc/firewall.conf"
if [ -f "$CONF_FILE" ]; then 
    . "$CONF_FILE"
else 
    # Default settings if config is missing
    ENABLE_IPV6="true"
    TCP_SERVICES="447 51515" 
    UDP_SERVICES=""
fi

# Database and File Paths
DB_FILE="/opt/etc/firewall_stats.db"
WEB_DIR="/opt/var/www/firewall"
LIST_DIR="$WEB_DIR/lists"
DATA_FILE="$WEB_DIR/firewall_data.js"
TEMP_DATA_FILE="/tmp/fw_data_atomic.tmp"
HTML_FILE="$WEB_DIR/index.html"
LOG_TAG="Firewall_Stats"

# Persistence File
AUTOBAN_SAVE_FILE="/opt/etc/firewall_autoban.save"

# Sniffer buffer file
PCAP_BASE="/tmp/fw_syn_ring.pcap"

# Prepare SQL safe list for Honeypot ports
ALL_TRAP_PORTS="$TCP_SERVICES $UDP_SERVICES"
TRAP_SQL_LIST=$(echo "$ALL_TRAP_PORTS" | tr -s ' ' ',' | sed 's/^,//;s/,$//')

# Define Firewall Targets (IPv4/IPv6)
IPTABLES_CMD="iptables"; IP6TABLES_CMD="ip6tables"
if [ "$ENABLE_IPV6" = "true" ]; then
    TARGETS="FirewallBlock|$IPTABLES_CMD| FirewallBlock6|$IP6TABLES_CMD|6 VPNBlock|$IPTABLES_CMD|"
else
    TARGETS="FirewallBlock|$IPTABLES_CMD| VPNBlock|$IPTABLES_CMD|"
fi

# ==============================================================================
# 2. STATE MANAGEMENT & ENVIRONMENT PREP
# ==============================================================================

# Diff files to store previous states
DIFF_FILE_V4="/opt/etc/firewall_v4_diff.dat"
DIFF_FILE_V6="/opt/etc/firewall_v6_diff.dat"
DIFF_FILE_VPN="/opt/etc/firewall_vpn_diff.dat"
DIFF_FILE_TRAP="/opt/etc/firewall_trap_diff.dat"
TRAP_SIZE_FILE="/opt/etc/firewall_trap_last_size.dat"
DIFF_FILE_TRAP6="/opt/etc/firewall_trap6_diff.dat"
TRAP6_SIZE_FILE="/opt/etc/firewall_trap6_last_size.dat"
IP_LAST_STATE="/opt/etc/firewall_ip_counters.dat"

# Load AbuseIPDB Key
KEY_FILE="/opt/etc/AbuseIPDB.key"
if [ -s "$KEY_FILE" ]; then ABUSEIPDB_KEY=$(cat "$KEY_FILE" | tr -d '[:space:]'); else ABUSEIPDB_KEY=""; fi 

# Ensure directories exist and clean old temp lists
mkdir -p "$WEB_DIR"
mkdir -p "$LIST_DIR"
rm -f "$LIST_DIR"/*.txt

# Date & Time variables
DATE_CMD="/opt/bin/date"; [ ! -x "$DATE_CMD" ] && DATE_CMD="date"
NOW=$($DATE_CMD +%s)

# Initialize counters for logging
NEW_DROPS_V4=0; NEW_DROPS_V6=0; NEW_DROPS_VPN=0; NEW_DROPS_TRAP=0; NEW_DROPS_TRAP6=0
NEW_IP_RECORDS=0

echo "=== Firewall Stats Updater v3.4.21 ==="

# ==============================================================================
# 3. DATABASE INITIALIZATION
# ==============================================================================
if [ ! -f "$DB_FILE" ]; then
    echo " -> Initializing Database Schema..."
    # Table: drops (Global counters history)
    sqlite3 "$DB_FILE" "CREATE TABLE drops (id INTEGER PRIMARY KEY, timestamp INTEGER, list_name TEXT, count INTEGER); CREATE INDEX idx_ts ON drops(timestamp);"
    # Table: ip_drops (Individual IP hit events)
    sqlite3 "$DB_FILE" "CREATE TABLE ip_drops (timestamp INTEGER, ip TEXT, count INTEGER, list_type TEXT); CREATE INDEX idx_ip_ts ON ip_drops(timestamp); CREATE INDEX idx_list ON ip_drops(list_type);"
    # Table: ip_info (Geo-data, Risk Score, Domain)
    sqlite3 "$DB_FILE" "CREATE TABLE ip_info (ip TEXT PRIMARY KEY, country TEXT, risk INTEGER, domain TEXT, updated INTEGER, target_port INTEGER, port_history TEXT);"
else
    # Migration Check: Add target_port column if missing
    HAS_COL=$(sqlite3 "$DB_FILE" "PRAGMA table_info(ip_info);" | grep target_port)
    if [ -z "$HAS_COL" ]; then
        echo " -> Migrating DB: Adding target_port column..."
        sqlite3 "$DB_FILE" "ALTER TABLE ip_info ADD COLUMN target_port INTEGER;"
    fi
    
    # Migration Check: Add port_history column if missing
    HAS_HIST=$(sqlite3 "$DB_FILE" "PRAGMA table_info(ip_info);" | grep port_history)
    if [ -z "$HAS_HIST" ]; then
        echo " -> Migrating DB: Adding port_history column..."
        sqlite3 "$DB_FILE" "ALTER TABLE ip_info ADD COLUMN port_history TEXT;"
    fi
fi

# ==============================================================================
# 4. COLLECT GLOBAL BLOCKLIST COUNTERS
# ==============================================================================
echo " -> Reading standard blocklists..."
SIZE_FirewallBlock=0; SIZE_FirewallBlock6=0; SIZE_VPNBlock=0

for TARGET in $TARGETS; do
    SET_NAME=$(echo "$TARGET" | cut -d'|' -f1)
    CMD=$(echo "$TARGET" | cut -d'|' -f2)
    SUFFIX=$(echo "$TARGET" | cut -d'|' -f3)
    LAST_RUN_FILE="/tmp/fw_last_${SET_NAME}.dat"

    # Read counters from iptables (Input + Forward chains)
    C_IN_RAW=$($CMD -L "BLOCKLIST_IN${SUFFIX}" -v -x -n 2>/dev/null | grep -w "match-set $SET_NAME" | awk '{print $1}' | head -n 1)
    C_FW_RAW=$($CMD -L "BLOCKLIST_FWD${SUFFIX}" -v -x -n 2>/dev/null | grep -w "match-set $SET_NAME" | awk '{print $1}' | head -n 1)
    
    C_IN=${C_IN_RAW:-0}; C_FW=${C_FW_RAW:-0}
    CUR=$((C_IN + C_FW))
    
    # Calculate Delta since last run
    if [ -f "$LAST_RUN_FILE" ]; then LAST=$(cat "$LAST_RUN_FILE"); else LAST=0; fi
    LAST=${LAST:-0}
    if [ "$CUR" -lt "$LAST" ]; then DELTA=$CUR; else DELTA=$((CUR - LAST)); fi
    
    # Insert into DB if there are new drops
    if [ "$DELTA" -gt 0 ]; then
        sqlite3 "$DB_FILE" "INSERT INTO drops (timestamp, list_name, count) VALUES ($NOW, '$SET_NAME', $DELTA);"
        [ "$SET_NAME" = "FirewallBlock" ] && NEW_DROPS_V4=$DELTA
        [ "$SET_NAME" = "FirewallBlock6" ] && NEW_DROPS_V6=$DELTA
        [ "$SET_NAME" = "VPNBlock" ] && NEW_DROPS_VPN=$DELTA
    fi
    echo "$CUR" > "$LAST_RUN_FILE"
    
    # Get current IPSet size
    SIZE=$(ipset list "$SET_NAME" 2>/dev/null | grep -cE '^[0-9]')
    eval "SIZE_${SET_NAME}=${SIZE:-0}"
done

# ==============================================================================
# 5. COLLECT TRAP (HONEYPOT) COUNTERS
# ==============================================================================
echo " -> Reading AutoBan Trap..."

# IPv4 Trap Processing
LAST_RUN_FILE="/tmp/fw_last_trap.dat"
C_TRAP_RAW=$($IPTABLES_CMD -L SCAN_TRAP -v -x -n 2>/dev/null | grep "DROP" | awk '{print $1}' | awk '{s+=$1} END {print s}')
C_TRAP=${C_TRAP_RAW:-0}
if [ -f "$LAST_RUN_FILE" ]; then LAST=$(cat "$LAST_RUN_FILE"); else LAST=0; fi
LAST=${LAST:-0}
if [ "$C_TRAP" -lt "$LAST" ]; then DELTA=$C_TRAP; else DELTA=$((C_TRAP - LAST)); fi

if [ "$DELTA" -gt 0 ]; then
    sqlite3 "$DB_FILE" "INSERT INTO drops (timestamp, list_name, count) VALUES ($NOW, 'AutoBan', $DELTA);"
    NEW_DROPS_TRAP=$DELTA
fi
echo "$C_TRAP" > "$LAST_RUN_FILE"
SIZE_AutoBan=$(ipset list AutoBan 2>/dev/null | grep -cE '^[0-9]')
SIZE_AutoBan=${SIZE_AutoBan:-0}

# IPv6 Trap Processing
SIZE_AutoBan6=0
if [ "$ENABLE_IPV6" = "true" ]; then
    LAST_RUN_FILE="/tmp/fw_last_trap6.dat"
    C_TRAP6_RAW=$($IP6TABLES_CMD -L SCAN_TRAP6 -v -x -n 2>/dev/null | grep "DROP" | awk '{print $1}' | awk '{s+=$1} END {print s}')
    C_TRAP6=${C_TRAP6_RAW:-0}
    if [ -f "$LAST_RUN_FILE" ]; then LAST=$(cat "$LAST_RUN_FILE"); else LAST=0; fi
    LAST=${LAST:-0}
    if [ "$C_TRAP6" -lt "$LAST" ]; then DELTA=$C_TRAP6; else DELTA=$((C_TRAP6 - LAST)); fi

    if [ "$DELTA" -gt 0 ]; then
        sqlite3 "$DB_FILE" "INSERT INTO drops (timestamp, list_name, count) VALUES ($NOW, 'AutoBan6', $DELTA);"
        NEW_DROPS_TRAP6=$DELTA
    fi
    echo "$C_TRAP6" > "$LAST_RUN_FILE"
    SIZE_AutoBan6=$(ipset list AutoBan6 2>/dev/null | grep -cE '^[0-9a-fA-F]{1,4}:')
    SIZE_AutoBan6=${SIZE_AutoBan6:-0}
fi

# ==============================================================================
# 6. CALCULATE DIFFS FOR DASHBOARD (Trends)
# ==============================================================================
read_file() { if [ -f "$1" ]; then cat "$1" | tr -d '\n'; else echo "=0"; fi; }
calc_diff() {
    CUR=$1; FILE_SIZE=$2; FILE_DIFF=$3
    if [ -f "$FILE_SIZE" ]; then LAST=$(cat "$FILE_SIZE"); else LAST=0; fi
    LAST=${LAST:-0}
    if [ "$CUR" -ne "$LAST" ]; then
        D=$((CUR - LAST)); if [ "$D" -ge 0 ]; then STR="+$D"; else STR="$D"; fi
        echo "$STR" > "$FILE_DIFF"; echo "$CUR" > "$FILE_SIZE"
    else
        STR="=0"; echo "$STR" > "$FILE_DIFF"
    fi
    echo "$STR"
}

DIFF_V4=$(read_file "$DIFF_FILE_V4")
if [ "$ENABLE_IPV6" = "true" ]; then DIFF_V6=$(read_file "$DIFF_FILE_V6"); else DIFF_V6="=0"; fi
DIFF_VPN=$(read_file "$DIFF_FILE_VPN")
DIFF_TRAP=$(calc_diff "$SIZE_AutoBan" "$TRAP_SIZE_FILE" "$DIFF_FILE_TRAP")
DIFF_TRAP6=$(calc_diff "$SIZE_AutoBan6" "$TRAP6_SIZE_FILE" "$DIFF_FILE_TRAP6")

# ==============================================================================
# 7. IP PACKET PROCESSING (PER-IP HITS)
# ==============================================================================
echo " -> Processing Per-IP stats..."
CURRENT_DUMP="/tmp/ipset_dump_now.dat"
SQL_IMPORT="/tmp/ip_inserts.sql"
: > "$CURRENT_DUMP"

# Dump active ipsets to temporary file
{
    ipset list FirewallBlock 2>/dev/null | grep "packets" | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2 main/p' | awk '$2 > 0'
    ipset list VPNBlock 2>/dev/null | grep "packets" | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2 main/p' | awk '$2 > 0'
    ipset list AutoBan 2>/dev/null | grep -E '^[0-9]{1,3}\.' | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2 trap/p' | awk '$2 > 0'
    if [ "$ENABLE_IPV6" = "true" ]; then
        ipset list FirewallBlock6 2>/dev/null | grep "packets" | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2 main/p' | awk '$2 > 0'
        ipset list AutoBan6 2>/dev/null | grep -E ':' | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2 trap/p' | awk '$2 > 0'
    fi
} | sort > "$CURRENT_DUMP"

# Calculate deltas for IPs (New Hits = Current Packets - Previous Packets)
DB_IS_EMPTY=$(sqlite3 "$DB_FILE" "SELECT count(*) FROM ip_drops;")
[ -z "$DB_IS_EMPTY" ] && DB_IS_EMPTY=0

if [ ! -f "$IP_LAST_STATE" ] || [ "$DB_IS_EMPTY" -eq 0 ]; then
    awk -v now="$NOW" '{printf "INSERT INTO ip_drops (timestamp, ip, count, list_type) VALUES (%d, \"%s\", %d, \"%s\");\n", now, $1, $2, $3;}' "$CURRENT_DUMP" > "$SQL_IMPORT"
else
    awk -v now="$NOW" 'FNR==NR { old[$1] = $2; next } { prev = (old[$1] ? old[$1] : 0); curr = $2; delta = curr - prev; if (delta < 0) delta = curr; if (delta > 0) printf "INSERT INTO ip_drops (timestamp, ip, count, list_type) VALUES (%d, \"%s\", %d, \"%s\");\n", now, $1, delta, $3; }' "$IP_LAST_STATE" "$CURRENT_DUMP" > "$SQL_IMPORT"
fi
awk '{print $1, $2}' "$CURRENT_DUMP" > "$IP_LAST_STATE"

# Bulk Insert into DB
if [ -s "$SQL_IMPORT" ]; then
    NEW_IP_RECORDS=$(wc -l < "$SQL_IMPORT")
    echo "BEGIN TRANSACTION;" > /tmp/ip_trans.sql; cat "$SQL_IMPORT" >> /tmp/ip_trans.sql; echo "COMMIT;" >> /tmp/ip_trans.sql
    sqlite3 "$DB_FILE" < /tmp/ip_trans.sql; rm /tmp/ip_trans.sql
fi
rm "$CURRENT_DUMP" "$SQL_IMPORT" 2>/dev/null

# ==============================================================================
# 8. SNIFFER PARSER (MOVED UP FOR REAL-TIME UPDATES)
# ==============================================================================
PCAP_BASE="/tmp/fw_syn_ring.pcap"
DB_CACHE="/tmp/fw_db_cache.dat"
LOG_BUFFER=$(ls ${PCAP_BASE}* 2>/dev/null | head -n 1)

if [ -n "$LOG_BUFFER" ] && [ -s "$LOG_BUFFER" ]; then
    echo " -> 🕵️ Processing WAN Sniffer Buffer..."
    
    # 1. Load DB Cache into RAM
    # Format: IP|HISTORY
    sqlite3 -separator "|" "$DB_FILE" "SELECT d.ip, IFNULL(i.port_history, '') FROM ip_drops d LEFT JOIN ip_info i ON d.ip=i.ip GROUP BY d.ip;" > "$DB_CACHE"
    
    BLOCKED_COUNT=$(wc -l < "$DB_CACHE")
    echo "    [DEBUG] Loaded $BLOCKED_COUNT blocked IPs from DB."

    echo "BEGIN TRANSACTION;" > /tmp/port_update.sql
    
    # 2. Parse Sniffer + Cross-reference Data
    # NOTE: Removed -F"|" to allow proper parsing of tcpdump spaces
    tcpdump -r "$LOG_BUFFER" -nn 2>/dev/null | awk -v now="$NOW" '
    # --- PHASE 1: Read DB Cache (File 1) ---
    FNR==NR {
        # Manual split of DB line using | as separator
        split($0, parts, "|");
        db_ip = parts[1];
        db_hist = parts[2];
        
        hist[db_ip] = db_hist;
        is_blocked[db_ip] = 1;
        next;
    }
    
    # --- PHASE 2: Read Sniffer (File 2) ---
    {
        # Find the ">" arrow using default separator (space)
        arrow_idx = 0;
        for (i=1; i<=NF; i++) { if ($i == ">") { arrow_idx = i; break; } }
        
        if (arrow_idx > 0) {
            # Example: IP 1.2.3.4.12345 > 5.6.7.8.80: ...
            src_full = $(arrow_idx-1);
            dst_full = $(arrow_idx+1);
            
            # --- SOURCE IP PARSING ---
            # Take first 4 octets (IPv4) or clean IPv6
            n = split(src_full, a, ".");
            ip = "";
            if (n >= 5) { 
                ip = a[1]"."a[2]"."a[3]"."a[4];
            } 
            else if (n == 2) {
                ip = src_full; sub(/\.[^.]*$/, "", ip);
            }
            else {
                ip = src_full; 
                if (src_full ~ /\.[0-9]+$/) sub(/\.[^.]*$/, "", ip);
            }

            # --- DESTINATION PORT PARSING ---
            m = split(dst_full, b, ".");
            port_str = b[m];
            # Clean trailing colons (e.g. "80:")
            gsub(":", "", port_str);

            # Protocol Detection
            proto = "udp"; 
            if ($0 ~ /Flags/ || $0 ~ /seq/ || $0 ~ /ack/) { proto = "tcp" }

            # --- VERIFICATION AND UPDATE ---
            if (length(ip) >= 7 && port_str + 0 > 0 && (ip in is_blocked)) {
                
                new_entry = port_str "/" proto;
                current = hist[ip];
                
                # Smart Deduplication
                is_new = 1;
                if (current != "") {
                    split(current, items, ",");
                    for (ix in items) {
                        split(items[ix], parts, "/");
                        if (parts[1] == port_str) { is_new = 0; break; }
                    }
                }
                
                if (is_new) {
                    if (current == "") {
                        new_hist = new_entry;
                        printf "INSERT OR IGNORE INTO ip_info (ip, updated, port_history) VALUES (\047%s\047, %d, \047%s\047);\n", ip, now, new_hist;
                    } else {
                        new_hist = current "," new_entry;
                    }
                    hist[ip] = new_hist;
                    printf "UPDATE ip_info SET target_port=%s, port_history=\047%s\047, updated=%d WHERE ip=\047%s\047;\n", port_str, new_hist, now, ip;
                    count++;
                }
            }
        }
    }
    END { 
        print "    [DEBUG] Generated " (count+0) " updates based on traffic analysis." > "/dev/stderr"; 
    }
    ' "$DB_CACHE" - >> /tmp/port_update.sql
    
    echo "COMMIT;" >> /tmp/port_update.sql

    # 3. Execute SQL transaction
    sqlite3 "$DB_FILE" < /tmp/port_update.sql
    
    # Cleanup
    rm "/tmp/port_update.sql" "$DB_CACHE" 2>/dev/null
else
    echo " -> 🕵️ Buffer empty or missing."
fi

# ==============================================================================
# 9. GENERATE JSON DATA FOR DASHBOARD (ATOMIC WRITE)
# ==============================================================================
echo " -> Generating JS Data..."
TOTAL_DROPS_ALL_TIME=$(sqlite3 "$DB_FILE" "SELECT sum(count) FROM drops;")
[ -z "$TOTAL_DROPS_ALL_TIME" ] && TOTAL_DROPS_ALL_TIME="0"

# Helper to generate Time Series Rows
gen_html_rows() {
    QUERY="SELECT $1, SUM(CASE WHEN list_name='FirewallBlock' THEN count ELSE 0 END), SUM(CASE WHEN list_name='FirewallBlock6' THEN count ELSE 0 END), SUM(CASE WHEN list_name='VPNBlock' THEN count ELSE 0 END), SUM(CASE WHEN list_name='AutoBan' OR list_name='AutoBan6' THEN count ELSE 0 END), SUM(count) FROM drops $3 GROUP BY $2 ORDER BY MAX(timestamp) DESC;"
    sqlite3 -separator "|" "$DB_FILE" "$QUERY" | awk -F'|' '{print "<tr><td>"$1"</td><td class=\"num col-main\">+"$2"</td><td class=\"num col-v6\">+"$3"</td><td class=\"num col-vpn\">+"$4"</td><td class=\"num col-trap\">+"$5"</td><td class=\"num\">+"$6"</td></tr>"}'
}

# Helper to get Averages
get_avg() {
    QUERY="SELECT AVG(total) FROM (SELECT SUM(count) as total FROM drops $2 GROUP BY $1);"
    RES=$(sqlite3 "$DB_FILE" "$QUERY")
    echo "$RES" | awk '{printf "%.0f", $1}'
}


# Function: Generate IP Tables (Pure DB Data)
get_ip_table() {
    WHERE=$1; TYPE=$2
    QUERY="SELECT d.ip, SUM(d.count) as total, i.country, i.risk, i.domain, i.target_port, d.list_type, i.port_history 
           FROM ip_drops d 
           LEFT JOIN ip_info i ON (
               CASE WHEN INSTR(d.ip, '/') > 0 THEN SUBSTR(d.ip, 1, INSTR(d.ip, '/') - 1) ELSE d.ip END = i.ip
           ) 
           WHERE $WHERE GROUP BY d.ip ORDER BY total DESC LIMIT 10;"
    
    sqlite3 -separator "|" "$DB_FILE" "$QUERY" | while IFS='|' read -r IP COUNT CO SC DO PORT TYPE PHIST; do
        CLEAN_IP=$(echo "$IP" | cut -d'/' -f1)
        if [ -z "$CO" ] && [ -n "$ABUSEIPDB_KEY" ]; then
             J=$(curl -s -m 3 -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=$CLEAN_IP" -d maxAgeInDays=90 -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" || echo "")
             CO=$(echo "$J"|grep -o '"countryCode":"[^"]*"'|cut -d'"' -f4); SC=$(echo "$J"|grep -o '"abuseConfidenceScore":[0-9]*'|cut -d':' -f2); DO=$(echo "$J"|grep -o '"domain":"[^"]*"'|cut -d'"' -f4)
             if [ -n "$CO" ]; then sqlite3 "$DB_FILE" "INSERT OR REPLACE INTO ip_info (ip, country, risk, domain, updated, target_port, port_history) VALUES ('$CLEAN_IP', '$CO', ${SC:-0}, '$DO', $NOW, ${PORT:-NULL}, '$PHIST');"; fi
        fi
        
        SC=${SC:-0}; [ "$SC" -ge 50 ] && ST="color:var(--red);font-weight:bold;" || ST="color:var(--green);"
        BADGE_HTML=""; if [ "$2" = "1" ]; then if [ "$TYPE" = "trap" ]; then BADGE_HTML="<span class='list-badge lb-trap'>TRAP</span>"; else BADGE_HTML="<span class='list-badge lb-main'>MAIN</span>"; fi; fi
        
        PORT_HTML=""
        STYLE_TCP="background:#333;color:#fff;font-size:11px;margin-right:2px;padding:1px 4px;border-radius:3px;"
        STYLE_UDP="background:#0d6efd;color:#fff;font-size:11px;margin-right:2px;padding:1px 4px;border-radius:3px;"
        STYLE_MORE="background:#6c757d;color:#fff;font-size:11px;cursor:help;padding:1px 4px;border-radius:3px;"

        if [ -n "$PHIST" ]; then
            PHIST_SPACE=$(echo "$PHIST" | tr ',' ' ')
            P_COUNT=$(echo "$PHIST_SPACE" | wc -w)
            LIMIT=3; CTR=0
            for p in $PHIST_SPACE; do
                if [ "$CTR" -lt "$LIMIT" ]; then
                    if echo "$p" | grep -q "/udp"; then CURR_STYLE="$STYLE_UDP"; else CURR_STYLE="$STYLE_TCP"; fi
                    PORT_HTML="${PORT_HTML}<span class='list-badge' style='${CURR_STYLE}'>:$p</span>"
                fi
                CTR=$((CTR+1))
            done
            if [ "$P_COUNT" -gt "$LIMIT" ]; then 
                REM=$((P_COUNT - LIMIT))
                START_CUT=$((LIMIT + 1))
                HIDDEN_LIST=$(echo "$PHIST_SPACE" | cut -d' ' -f${START_CUT}- | sed 's/ /, /g')
                PORT_HTML="${PORT_HTML}<span class='list-badge' style='${STYLE_MORE}' title='Other ports: $HIDDEN_LIST'>(+$REM)</span>"
            fi
        elif [ -n "$PORT" ] && [ "$PORT" != "0" ]; then
            PORT_HTML="<span class='list-badge' style='${STYLE_TCP}'>:$PORT</span>"
        fi
        echo "<tr><td><span class='badge bg-danger'>$COUNT</span></td><td><a href='https://www.abuseipdb.com/check/$CLEAN_IP' target='_blank'>$IP</a> $BADGE_HTML <br> $PORT_HTML</td><td class='meta'><span style='$ST'>Risk: ${SC}%</span> - $CO<br><small>$DO</small></td></tr>"
    done
}

# Function: Generate Port Stats (Real Protocol from DB)
get_port_stats() {
    TIME_FILTER=$1; EXTRA_SQL=$2; ID_PREFIX=$3
    
    # This query is complex: tries to associate protocol to main port.
    # Since port_history is a list (e.g. "80/tcp,443/tcp"), we take the last entry inserted 
    # or the one that matches target_port if we can parse it.
    # For simplicity and router performance, we assume the last updated port (determining target_port)
    # is the last one in the list or at least present in history.
    
    QUERY="SELECT 
            CASE 
                WHEN i.port_history LIKE '%' || i.target_port || '/udp%' THEN i.target_port || '/udp'
                WHEN i.port_history LIKE '%' || i.target_port || '/tcp%' THEN i.target_port || '/tcp'
                ELSE i.target_port || '' 
            END as full_port,
            GROUP_CONCAT(DISTINCT d.ip), 
            SUM(d.count) as total 
           FROM ip_drops d 
           JOIN ip_info i ON d.ip=i.ip 
           WHERE i.target_port IS NOT NULL AND i.target_port > 0 
           ${TIME_FILTER:+AND d.timestamp > $((NOW - $TIME_FILTER))}
           $EXTRA_SQL
           GROUP BY full_port 
           ORDER BY total DESC 
           LIMIT 10;"
    
    sqlite3 -separator "|" "$DB_FILE" "$QUERY" | awk -F'|' -v listdir="$LIST_DIR" -v prefix="$ID_PREFIX" -v q="'" '
    {
        full_port=$1; ips_raw=$2; count=$3;
        
        # Extract number only for filename (remove /tcp or /udp)
        split(full_port, a, "/"); port_num = a[1];
        
        gsub(/[ \t\r\n]+/, "", ips_raw); 
        filename = prefix "_" port_num ".txt"; filepath = listdir "/" filename;
        split(ips_raw, ip_array, ","); 
        printf "" > filepath; for (i in ip_array) { print ip_array[i] >> filepath; } close(filepath);
        
        display_ips = ""; c = 0; 
        for (i in ip_array) { c++; if (c <= 3) { if (display_ips != "") display_ips = display_ips ", "; display_ips = display_ips ip_array[i]; } }
        
        if (length(ip_array) > 3) { extra = length(ip_array) - 3; display_ips = display_ips " <a href=\"#\" onclick=\"loadList(" q filename q ", " q port_num q "); return false;\" style=\"color:#0d6efd;text-decoration:none;font-weight:600;cursor:pointer;\">(+" extra " others)</a>"; }
        
        # Dynamic styles
        style = "background:#333;color:#fff;"; # Default TCP/Gray
        if (index(full_port, "/udp") > 0) { style = "background:#0d6efd;color:#fff;"; }
        
        # If full_port is just a number (old data), add implicit formatting but keep gray
        if (index(full_port, "/") == 0) { full_port = ":" full_port; } else { full_port = ":" full_port; }

        print "<tr><td><span class=\"list-badge\" style=\"" style "font-size:11px\">" full_port "</span></td><td style=\"font-size:12.5px\">" display_ips "</td><td class=\"num\">" count "</td></tr>"
    }'
}

# --- Execute Data Generation ---

# Port Tables
PORTS_24H=$(get_port_stats 86400 "" "p24")
PORTS_30D=$(get_port_stats 2592000 "" "p30")
PORTS_1Y=$(get_port_stats 31536000 "" "p1y")
PORTS_ALL=$(get_port_stats "" "" "pall")

# Bruteforce Tables (Trap Ports Only)
if [ -n "$TRAP_SQL_LIST" ]; then
    TRAP_PORT_FILTER="AND d.list_type='trap' AND i.target_port IN ($TRAP_SQL_LIST)"
else
    TRAP_PORT_FILTER="AND d.list_type='trap'"
fi
BRUTE_24H=$(get_port_stats 86400 "$TRAP_PORT_FILTER" "b24")
BRUTE_30D=$(get_port_stats 2592000 "$TRAP_PORT_FILTER" "b30")
BRUTE_1Y=$(get_port_stats 31536000 "$TRAP_PORT_FILTER" "b1y")
BRUTE_ALL=$(get_port_stats "" "$TRAP_PORT_FILTER" "ball")

# IP Tables
IPV6_24H=$(get_ip_table "d.ip LIKE '%:%' AND d.timestamp > $((NOW - 86400))" "1")
IPV6_30D=$(get_ip_table "d.ip LIKE '%:%' AND d.timestamp > $((NOW - 2592000))" "1")
IPV6_1Y=$(get_ip_table "d.ip LIKE '%:%' AND d.timestamp > $((NOW - 31536000))" "1")
IPV6_ALL=$(get_ip_table "d.ip LIKE '%:%'" "1")

TRAP_24H=$(get_ip_table "d.list_type='trap' AND d.timestamp > $((NOW - 86400))")
OTHER_24H=$(get_ip_table "d.list_type='main' AND d.ip NOT LIKE '%/%' AND d.timestamp > $((NOW - 86400))")
NETS_24H=$(get_ip_table "d.list_type='main' AND d.ip LIKE '%/%' AND d.timestamp > $((NOW - 86400))")

TRAP_30D=$(get_ip_table "d.list_type='trap' AND d.timestamp > $((NOW - 2592000))")
OTHER_30D=$(get_ip_table "d.list_type='main' AND d.ip NOT LIKE '%/%' AND d.timestamp > $((NOW - 2592000))")
NETS_30D=$(get_ip_table "d.list_type='main' AND d.ip LIKE '%/%' AND d.timestamp > $((NOW - 2592000))")

TRAP_1Y=$(get_ip_table "d.list_type='trap' AND d.timestamp > $((NOW - 31536000))")
OTHER_1Y=$(get_ip_table "d.list_type='main' AND d.ip NOT LIKE '%/%' AND d.timestamp > $((NOW - 31536000))")
NETS_1Y=$(get_ip_table "d.list_type='main' AND d.ip LIKE '%/%' AND d.timestamp > $((NOW - 31536000))")

TRAP_ALL=$(get_ip_table "d.list_type='trap'")
OTHER_ALL=$(get_ip_table "d.list_type='main' AND d.ip NOT LIKE '%/%'")
NETS_ALL=$(get_ip_table "d.list_type='main' AND d.ip LIKE '%/%'")

# Time Series Data
ROWS_HOURLY=$(gen_html_rows "strftime('%H:00', timestamp, 'unixepoch', 'localtime')" "1" "WHERE timestamp >= strftime('%s', 'now', '-24 hours')")
ROWS_DAILY=$(gen_html_rows "strftime('%d-%m-%Y', timestamp, 'unixepoch', 'localtime')" "1" "WHERE timestamp >= strftime('%s', 'now', '-30 days')")
ROWS_MONTHLY=$(gen_html_rows "strftime('%m-%Y', timestamp, 'unixepoch', 'localtime')" "1" "WHERE timestamp >= strftime('%s', 'now', '-12 months')")
ROWS_YEARLY=$(gen_html_rows "strftime('%Y', timestamp, 'unixepoch', 'localtime')" "1" "")
QUERY_TOP="SELECT strftime('%d-%m-%Y', timestamp, 'unixepoch', 'localtime') as day, SUM(CASE WHEN list_name='FirewallBlock' THEN count ELSE 0 END), SUM(CASE WHEN list_name='FirewallBlock6' THEN count ELSE 0 END), SUM(CASE WHEN list_name='VPNBlock' THEN count ELSE 0 END), SUM(CASE WHEN list_name='AutoBan' OR list_name='AutoBan6' THEN count ELSE 0 END), SUM(count) as total FROM drops GROUP BY day ORDER BY total DESC LIMIT 10;"
ROWS_TOP_DAYS=$(sqlite3 -separator "|" "$DB_FILE" "$QUERY_TOP" | awk -F'|' '{print "<tr><td><b>"$1"</b></td><td class=\"num col-main\">+"$2"</td><td class=\"num col-v6\">+"$3"</td><td class=\"num col-vpn\">+"$4"</td><td class=\"num col-trap\">+"$5"</td><td class=\"num\">+"$6"</td></tr>"}')

# Averages
AVG_H=$(get_avg "strftime('%H:00', timestamp, 'unixepoch', 'localtime')" "WHERE timestamp >= strftime('%s', 'now', '-24 hours')")
AVG_D=$(get_avg "strftime('%d-%m-%Y', timestamp, 'unixepoch', 'localtime')" "WHERE timestamp >= strftime('%s', 'now', '-30 days')")
AVG_M=$(get_avg "strftime('%m-%Y', timestamp, 'unixepoch', 'localtime')" "WHERE timestamp >= strftime('%s', 'now', '-12 months')")
AVG_Y=$(get_avg "strftime('%Y', timestamp, 'unixepoch', 'localtime')" "")

# Misc Stats
DATE_UPDATE=$($DATE_CMD "+%d-%m-%Y %H:%M:%S"); UP_SECONDS=$(cut -d. -f1 /proc/uptime)
DAYS=$((UP_SECONDS / 86400)); HOURS=$(( (UP_SECONDS % 86400) / 3600 ))
UPTIME="${DAYS}d ${HOURS}h"
S_MAIN=${SIZE_FirewallBlock:-0}; S_MAIN6=${SIZE_FirewallBlock6:-0}; S_VPN=${SIZE_VPNBlock:-0}; S_TRAP=${SIZE_AutoBan:-0}; S_TRAP6=${SIZE_AutoBan6:-0}

# Assemble JS File (Atomic Write to Temp File first)
cat <<EOF > "$TEMP_DATA_FILE"
window.FW_DATA = {
    updated: "$DATE_UPDATE", uptime: "$UPTIME", lifetime: "$TOTAL_DROPS_ALL_TIME",
    ipv6_status: "$ENABLE_IPV6",
    lists: { 
        main: "$S_MAIN", diff_v4: "$DIFF_V4", main6: "$S_MAIN6", diff_v6: "$DIFF_V6", 
        vpn: "$S_VPN", diff_vpn: "$DIFF_VPN", trap_ips: "$S_TRAP", diff_trap: "$DIFF_TRAP",
        trap6_ips: "$S_TRAP6", diff_trap6: "$DIFF_TRAP6"
    },
    averages: { hourly: "$AVG_H", daily: "$AVG_D", monthly: "$AVG_M", yearly: "$AVG_Y" },
    tables: { 
        hourly: \`$ROWS_HOURLY\`, daily: \`$ROWS_DAILY\`, monthly: \`$ROWS_MONTHLY\`, yearly: \`$ROWS_YEARLY\`, top_days: \`$ROWS_TOP_DAYS\`,
        trap_24h: \`$TRAP_24H\`, other_24h: \`$OTHER_24H\`, nets_24h: \`$NETS_24H\`, ports_24h: \`$PORTS_24H\`, brute_24h: \`$BRUTE_24H\`, ipv6_24h: \`$IPV6_24H\`,
        trap_30d: \`$TRAP_30D\`, other_30d: \`$OTHER_30D\`, nets_30d: \`$NETS_30D\`, ports_30d: \`$PORTS_30D\`, brute_30d: \`$BRUTE_30D\`, ipv6_30d: \`$IPV6_30D\`,
        trap_1y: \`$TRAP_1Y\`, other_1y: \`$OTHER_1Y\`, nets_1y: \`$NETS_1Y\`, ports_1y: \`$PORTS_1Y\`, brute_1y: \`$BRUTE_1Y\`, ipv6_1y: \`$IPV6_1Y\`,
        trap_all: \`$TRAP_ALL\`, other_all: \`$OTHER_ALL\`, nets_all: \`$NETS_ALL\`, ports_all: \`$PORTS_ALL\`, brute_all: \`$BRUTE_ALL\`, ipv6_all: \`$IPV6_ALL\`
    }
};
EOF

# Move temp file to final location (Atomic update)
mv "$TEMP_DATA_FILE" "$DATA_FILE"
chmod 644 "$DATA_FILE"

# ==============================================================================
# 10. SMART MAINTENANCE & PERSISTENCE
# ==============================================================================
echo " -> Smart Database Cleaning..."
LIMIT_HARD=$((NOW - 2592000))
sqlite3 "$DB_FILE" "DELETE FROM ip_drops WHERE timestamp < $LIMIT_HARD;"
LIMIT_SOFT=$((NOW - 604800))
sqlite3 "$DB_FILE" "DELETE FROM ip_drops WHERE timestamp < $LIMIT_SOFT AND count < 10;"
# sqlite3 "$DB_FILE" "DELETE FROM ip_info WHERE ip NOT IN (SELECT DISTINCT ip FROM ip_drops);"
sqlite3 "$DB_FILE" "VACUUM;"

DB_SIZE_H=$(du -h "$DB_FILE" 2>/dev/null | awk '{print $1}')
echo " -> DB Optimized. Size: $DB_SIZE_H"

# SAVE IPSETS TO DISK (Auto-Save)
echo " -> Saving AutoBan states..."
ipset save AutoBan > "$AUTOBAN_SAVE_FILE" 2>/dev/null
if [ "$ENABLE_IPV6" = "true" ]; then
    ipset save AutoBan6 >> "$AUTOBAN_SAVE_FILE" 2>/dev/null
fi

T4_TOT=${SIZE_AutoBan:-0}; T4_DIF=${DIFF_TRAP:-=0}
T6_TOT=${SIZE_AutoBan6:-0}; T6_DIF=${DIFF_TRAP6:-=0}
TOTAL_NEW_DROPS=$((NEW_DROPS_V4 + NEW_DROPS_V6 + NEW_DROPS_VPN + NEW_DROPS_TRAP))

logger -t "$LOG_TAG" "SUMMARY | Drops: +$TOTAL_NEW_DROPS | Trap4: $T4_TOT ($T4_DIF) | Trap6: $T6_TOT ($T6_DIF) | Ports: $COUNT_UPDATED | DB: $DB_SIZE_H"
echo "Done."
