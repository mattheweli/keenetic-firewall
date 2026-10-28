#!/opt/bin/bash
# KEENETIC FIREWALL STATS v4.0.2
# Release: 2026-10-23 | Stable. See CHANGELOG.md for release details.

# AUTHOR: mattheweli
# DESCRIPTION: 
#   Aggregates firewall statistics, parses sniffer data for port mapping,
#   and generates JSON data for the web dashboard.
#
#     - FIX [v3.7.2]: Resolved awk scientific notation rounding bug on PCAP timestamps preventing incremental sniffer parsing.
#     - OPT [v3.7.1]: Avoid Duplicate Temporary SQL Files (Stream directly via Pipe).
#     - OPT [v3.7.1]: Optimize Port List File Writing in get_port_stats() fixing massive iowait spikes.
#     - OPT [v3.7.1]: Hard-Limit Networking Timeout in the AbuseIPDB API Loop.
#     - NEW [v3.7.0]: Integrated Interactive PHP Backend API (firewall_api.php).
#     - NEW [v3.7.0]: Added Frontend support for real-time IP Lookup, Ban, and Unban.
#     - NEW [v3.7.0]: Added Manual Blocklists (Blacklist/Blacklist6) tracking and persistence.
#     - NEW [v3.7.0]: Injected "Quick Unban" action links directly into report tables.
#     - CRITICAL FIX [v3.7.0]: Sniffer parser incorrectly treating ICMPv6 IPs as ports.
#     - FIX [v3.7.0]: Silenced SQLite PRAGMA console output (wal/5000).
#     - NEW: Anti-Loop API logic (prevents wasting AbuseIPDB credits).
#     - NEW: Private/LAN IP filtering for Geo-enrichment.
#     - NEW: Version 3.6.3 includes previous DB maintenance (Orphan/VACUUM).
#     - FIX: IPv6 regex counting fixed for lists.
#     - FIX: Database creation and optimization on first boot.
#     - FIX: Send report minor cosmetic changes. 
#     - CRITICAL FIX: ulogd PCAP rotation file.
#     - OPT: Limited tooltip port list in JS to max 20 entries to reduce file size.
#     - LOGIC: Honeypot tables now strictly enforce TCP/UDP protocol matching.
#     - CORE: Implemented robust "Linux Cooked" (SLL) header parsing for tcpdump.
# ==============================================================================

export PATH=${KT_PATH:-/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin}
# Firewall Stats 4.0.2
. "${KT_COMMON:-/opt/lib/keentool/common.sh}" || exit 1
kt_init firewall-db || exit $?
sqlite3() { kt_sqlite "$@"; }
START_SECONDS=$SECONDS


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
DB_FILE="${KT_FW_DB:-/opt/etc/firewall_stats.db}"
# Explicit maintenance runs before kernel reads, PCAP consumption or dashboard publication.
if [ "${1:-}" = --optimize-db ]; then
    [ -f "$DB_FILE" ] && [ ! -L "$DB_FILE" ] || { echo 'Existing regular database required; no changes made' >&2;exit 1; }
    [ "$(sqlite3 "$DB_FILE" 'PRAGMA quick_check;')" = ok ] || { echo 'Database integrity check failed; no changes made' >&2;exit 1; }
    BACKUP_ROOT="${KT_FW_DB_BACKUPS:-/opt/var/backups/keentool-db}"
    case "$BACKUP_ROOT" in *\"*|*\'*|*$'\n'*|*$'\r'*)echo 'Unsupported backup directory characters; no changes made' >&2;exit 1;;esac
    mkdir -p "$BACKUP_ROOT" || exit 1
    BACKUP_DIR=$(mktemp -d "$BACKUP_ROOT/$(date +%Y%m%d_%H%M%S)-$$.XXXXXX") || exit 1
    chmod 700 "$BACKUP_DIR" || exit 1
    DB_BACKUP="$BACKUP_DIR/firewall_stats.db"
    sqlite3 "$DB_FILE" ".backup \"$DB_BACKUP\"" || { echo 'Online backup failed; no optimization performed' >&2;exit 1; }
    chmod 600 "$DB_BACKUP" || exit 1
    [ "$(sqlite3 "$DB_BACKUP" 'PRAGMA quick_check;')" = ok ] || { echo 'Backup verification failed; no optimization performed' >&2;exit 1; }
    echo "Verified database backup: $DB_BACKUP"
    if [ "$(sqlite3 "$DB_FILE" "SELECT type FROM sqlite_master WHERE name='ip_drops';")" = view ]; then
        sqlite3 "$DB_FILE" 'VACUUM; PRAGMA wal_checkpoint(TRUNCATE);' || exit 1
        echo 'Compact storage retained; database vacuumed. Backup retained.'
        exit 0
    fi
    # Refuse unexpected operator-defined indexes instead of overwriting their definition.
    for INDEX_NAME in idx_list_ts idx_list_ts_ip;do
        INDEX_TABLE=$(sqlite3 "$DB_FILE" "SELECT tbl_name FROM sqlite_master WHERE type='index' AND name='$INDEX_NAME';") || exit 1
        [ -z "$INDEX_TABLE" ] && continue
        INDEX_COLUMNS=$(sqlite3 "$DB_FILE" "SELECT group_concat(name, ',') FROM (SELECT name FROM pragma_index_info('$INDEX_NAME') ORDER BY seqno);") || exit 1
        EXPECTED_COLUMNS='list_type,timestamp';[ "$INDEX_NAME" != idx_list_ts_ip ] || EXPECTED_COLUMNS='list_type,timestamp,ip'
        INDEX_FLAGS=$(sqlite3 "$DB_FILE" "SELECT \"unique\" || '|' || partial FROM pragma_index_list('ip_drops') WHERE name='$INDEX_NAME';") || exit 1
        [ "$INDEX_TABLE" = ip_drops ] && [ "$INDEX_COLUMNS" = "$EXPECTED_COLUMNS" ] && [ "$INDEX_FLAGS" = '0|0' ] || { echo "Unexpected index definition: $INDEX_NAME; no optimization performed" >&2;exit 1; }
    done
    sqlite3 "$DB_FILE" 'BEGIN IMMEDIATE; CREATE INDEX IF NOT EXISTS idx_list_ts ON ip_drops(list_type,timestamp); DROP INDEX IF EXISTS idx_list_ts_ip; COMMIT;' || { echo 'Index transaction failed; database backup retained' >&2;exit 1; }
    sqlite3 "$DB_FILE" 'VACUUM;' || { echo 'Compaction failed or database busy; data retained, retry maintenance later. Backup retained.' >&2;exit 1; }
    CHECKPOINT_RESULT=$(sqlite3 "$DB_FILE" 'PRAGMA wal_checkpoint(TRUNCATE);') || exit 1
    case "$CHECKPOINT_RESULT" in 0\|*) :;;*) echo 'Active readers deferred WAL truncation; logical optimization is complete, disk reclamation may wait for readers to close.' >&2;;esac
    [ "$(sqlite3 "$DB_FILE" 'PRAGMA integrity_check;')" = ok ] || { echo 'Final integrity check failed; retain backup and investigate' >&2;exit 1; }
    echo 'Lossless optimization complete: no rows, timestamps, counters, port histories or report state removed.'
    echo "Database size: $(du -h "$DB_FILE" | awk '{print $1}') (WAL sidecar, if any, is separate)"
    echo 'The database backup is retained separately and still occupies disk space.'
    exit 0
fi
BACKUP_FILE_V4="/opt/etc/firewall_blocklist.save"
BACKUP_FILE_V6="/opt/etc/firewall_blocklist6.save"
BACKUP_GEO_V4="/opt/etc/firewall_geoblock.save"
BACKUP_MANUAL_V4="/opt/etc/Blacklist.backup"
BACKUP_MANUAL_V6="/opt/etc/Blacklist6.backup"
WEB_DIR="${KT_FW_WEB:-/opt/var/www/firewall}"
LIST_DIR="$WEB_DIR/lists"
PUBLISHED_LIST_DIR="$LIST_DIR"
LIST_DIR="$WEB_DIR/.lists.$$"
DATA_FILE="$WEB_DIR/firewall_data.js"
TEMP_DATA_FILE="$WEB_DIR/.fw_data.$$.tmp"
HTML_FILE="$WEB_DIR/index.html"
LOG_TAG="Firewall_Stats"

# Persistence File
AUTOBAN_SAVE_FILE="/opt/etc/firewall_autoban.save"

# Sniffer buffer file
PCAP_BASE="${KT_FW_PCAP:-/opt/var/log/keentool-firewall/fw_syn_ring.pcap}"

# Prepare SQL safe list for Honeypot ports
ALL_TRAP_PORTS="$TCP_SERVICES $UDP_SERVICES"
TRAP_SQL_LIST=$(echo "$ALL_TRAP_PORTS" | tr -s ' ' ',' | sed 's/^,//;s/,$//')

# Define Firewall Targets (IPv4/IPv6)
IPTABLES_CMD="iptables"; IP6TABLES_CMD="ip6tables"
if [ "$ENABLE_IPV6" = "true" ]; then
    TARGETS="FirewallBlock|$IPTABLES_CMD| FirewallBlock6|$IP6TABLES_CMD|6 VPNBlock|$IPTABLES_CMD| GeoBlock|$IPTABLES_CMD| GeoBlock6|$IP6TABLES_CMD|6 Blacklist|$IPTABLES_CMD| Blacklist6|$IP6TABLES_CMD|6 KTManualBan|$IPTABLES_CMD| KTManualBan6|$IP6TABLES_CMD|6 AutoBan|$IPTABLES_CMD| AutoBan6|$IP6TABLES_CMD|6"
else
    TARGETS="FirewallBlock|$IPTABLES_CMD| VPNBlock|$IPTABLES_CMD| GeoBlock|$IPTABLES_CMD| Blacklist|$IPTABLES_CMD| KTManualBan|$IPTABLES_CMD| AutoBan|$IPTABLES_CMD|"
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
# GeoIP state files
DIFF_FILE_GEO="/opt/etc/firewall_geo_diff.dat"
GEO_SIZE_FILE="/opt/etc/firewall_geo_last_size.dat"
DIFF_FILE_GEO6="/opt/etc/firewall_geo6_diff.dat"
GEO6_SIZE_FILE="/opt/etc/firewall_geo6_last_size.dat"
IP_LAST_STATE="/opt/etc/firewall_ip_counters.dat"

#Manual State files
DIFF_FILE_MANUAL="/opt/etc/firewall_manual_diff.dat"
MANUAL_SIZE_FILE="/opt/etc/firewall_manual_last_size.dat"
DIFF_FILE_MANUAL6="/opt/etc/firewall_manual6_diff.dat"
MANUAL6_SIZE_FILE="/opt/etc/firewall_manual6_last_size.dat"

# Load AbuseIPDB Key
KEY_FILE="/opt/etc/AbuseIPDB.key"
if [ -s "$KEY_FILE" ]; then ABUSEIPDB_KEY=$(cat "$KEY_FILE" | tr -d '[:space:]'); else ABUSEIPDB_KEY=""; fi 

# Ensure directories exist and clean old temp lists
mkdir -p "$WEB_DIR"
mkdir -p "$LIST_DIR"
# Remove only the per-run staging directory on failure or normal completion.
trap 'rm -rf "$LIST_DIR"; kt_cleanup' EXIT
rm -f "$LIST_DIR"/*.txt

# Date & Time variables
DATE_CMD="/opt/bin/date"; [ ! -x "$DATE_CMD" ] && DATE_CMD="date"
NOW=${KT_NOW:-$($DATE_CMD +%s)}

# Initialize counters for logging (Added NEW_DROPS_GEO and GEO6)
NEW_DROPS_V4=0; NEW_DROPS_V6=0; NEW_DROPS_VPN=0; NEW_DROPS_TRAP=0; NEW_DROPS_TRAP6=0; NEW_DROPS_GEO=0; NEW_DROPS_GEO6=0; NEW_DROPS_MANUAL=0; NEW_DROPS_MANUAL6=0
NEW_IP_RECORDS=0

echo "=== Firewall Stats Updater v4.0.2 ==="

# ==============================================================================
# 3. DATABASE INITIALIZATION & TUNING
# ==============================================================================
# Enable high-performance SQLite optimizations (WAL mode, memory temp store)
sqlite3 "$DB_FILE" "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA temp_store = MEMORY; PRAGMA cache_size = -4000; PRAGMA busy_timeout = 5000;" >/dev/null

# Verify if the DB has the correct structure (not just if the file exists)
HAS_DROPS=$(sqlite3 "$DB_FILE" "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='drops';" 2>/dev/null)

if [ "$HAS_DROPS" != "1" ]; then
    echo " -> Initializing Database Schema (or fixing corrupted DB)..."
    # Table: drops (Global counters history)
    sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS drops (id INTEGER PRIMARY KEY, timestamp INTEGER, list_name TEXT, count INTEGER); CREATE INDEX IF NOT EXISTS idx_ts ON drops(timestamp);"
    # Table: ip_drops (Individual IP hit events)
    sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS ip_drops (timestamp INTEGER, ip TEXT, count INTEGER, list_type TEXT); CREATE INDEX IF NOT EXISTS idx_ip_ts ON ip_drops(timestamp); CREATE INDEX IF NOT EXISTS idx_list ON ip_drops(list_type); CREATE INDEX IF NOT EXISTS idx_ip ON ip_drops(ip);"
    # Table: ip_info (Geo-data, Risk Score, Domain)
    sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS ip_info (ip TEXT PRIMARY KEY, country TEXT, risk INTEGER, domain TEXT, updated INTEGER, target_port INTEGER, port_history TEXT); CREATE INDEX IF NOT EXISTS idx_port ON ip_info(target_port);"
else
    # --- MIGRATION CHECKS ---
    
    # 1. Check ip_drops for 'list_type' (CRITICAL FIX)
    HAS_LIST=$(sqlite3 "$DB_FILE" "PRAGMA table_info(ip_drops);" | grep list_type)
    if [ -z "$HAS_LIST" ] && [ "$(sqlite3 "$DB_FILE" "SELECT type FROM sqlite_master WHERE name='ip_drops';")" = table ]; then
        echo " -> Migrating DB: Adding list_type column to ip_drops..."
        sqlite3 "$DB_FILE" "ALTER TABLE ip_drops ADD COLUMN list_type TEXT;"
        sqlite3 "$DB_FILE" "CREATE INDEX IF NOT EXISTS idx_list ON ip_drops(list_type);"
    fi

    # 2. Check ip_info for 'target_port'
    HAS_COL=$(sqlite3 "$DB_FILE" "PRAGMA table_info(ip_info);" | grep target_port)
    if [ -z "$HAS_COL" ]; then
        echo " -> Migrating DB: Adding target_port column..."
        sqlite3 "$DB_FILE" "ALTER TABLE ip_info ADD COLUMN target_port INTEGER;"
    fi
    
    # 3. Check ip_info for 'port_history'
    HAS_HIST=$(sqlite3 "$DB_FILE" "PRAGMA table_info(ip_info);" | grep port_history)
    if [ -z "$HAS_HIST" ]; then
        echo " -> Migrating DB: Adding port_history column..."
        sqlite3 "$DB_FILE" "ALTER TABLE ip_info ADD COLUMN port_history TEXT;"
    fi
    
    # 4. Check for Performance Indexes (CPU 100% Fix)
    HAS_IDX_IP=$(sqlite3 "$DB_FILE" "PRAGMA index_list('ip_drops');" | grep "idx_ip")
    if [ -z "$HAS_IDX_IP" ] && [ "$(sqlite3 "$DB_FILE" "SELECT type FROM sqlite_master WHERE name='ip_drops';")" = table ]; then
        echo " -> Migrating DB: Adding performance index idx_ip..."
        sqlite3 "$DB_FILE" "CREATE INDEX IF NOT EXISTS idx_ip ON ip_drops(ip);"
    fi

    HAS_IDX_PORT=$(sqlite3 "$DB_FILE" "PRAGMA index_list('ip_info');" | grep "idx_port")
    if [ -z "$HAS_IDX_PORT" ]; then
        echo " -> Migrating DB: Adding performance index idx_port..."
        sqlite3 "$DB_FILE" "CREATE INDEX IF NOT EXISTS idx_port ON ip_info(target_port);"
    fi
	

fi

    # Keep existing installations unchanged until explicit --optimize-db maintenance.
    # A compact index is sufficient because hit counts already require table access.
    HAS_LIST_TIME=$(sqlite3 "$DB_FILE" "SELECT count(*) FROM sqlite_master WHERE type='index' AND tbl_name='ip_drops' AND name IN ('idx_list_ts','idx_list_ts_ip');")
    if [ "$HAS_LIST_TIME" = 0 ] && [ "$(sqlite3 "$DB_FILE" "SELECT type FROM sqlite_master WHERE name='ip_drops';")" = table ]; then
        echo " -> Adding compact list/time index idx_list_ts..."
        sqlite3 "$DB_FILE" "CREATE INDEX IF NOT EXISTS idx_list_ts ON ip_drops(list_type,timestamp);"
    fi

# ==============================================================================
if [ "${KT_FW_PREVIEW:-false}" != true ]; then
# Snapshot expensive kernel dumps once; replay for all statistics consumers.
ipset() {
    if [ "$1" = list ] && [ "$#" = 2 ]; then
        local snapshot="$KT_WORKDIR/ipset_$2"
        if [ ! -f "$snapshot" ]; then command ipset "$@" > "$snapshot" || { rm -f "$snapshot"; return 1; }; fi
        cat "$snapshot"
    else command ipset "$@"; fi
}
iptables() { fw_chain_dump iptables "$@"; }
ip6tables() { fw_chain_dump ip6tables "$@"; }
fw_chain_dump() {
    local tool=$1; shift
    if [ "$1" = -L ]; then
        local snapshot="$KT_WORKDIR/${tool}_$2"
        if [ ! -f "$snapshot" ]; then command "$tool" "$@" > "$snapshot" || { rm -f "$snapshot"; return 1; }; fi
        cat "$snapshot"
    else command "$tool" "$@"; fi
}
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
    if [[ "$SET_NAME" = Blacklist* ]];then
        # The legacy manual chain is shared by INPUT and FORWARD: count it once.
        C_IN_RAW=$($CMD -L "BLACKLIST${SUFFIX}" -v -x -n 2>/dev/null | grep -w "match-set $SET_NAME" | awk '$3=="DROP"{print $1}' | head -n 1)
        C_FW_RAW=0
    else
        C_IN_RAW=$($CMD -L "BLOCKLIST_IN${SUFFIX}" -v -x -n 2>/dev/null | grep -w "match-set $SET_NAME" | awk '$3=="DROP"{print $1}' | head -n 1)
        C_FW_RAW=$($CMD -L "BLOCKLIST_FWD${SUFFIX}" -v -x -n 2>/dev/null | grep -w "match-set $SET_NAME" | awk '$3=="DROP"{print $1}' | head -n 1)
    fi
    
    C_IN=${C_IN_RAW:-0}; C_FW=${C_FW_RAW:-0}
    CUR=$((C_IN + C_FW))
    
    # Calculate Delta since last run
    if [ -f "$LAST_RUN_FILE" ]; then LAST=$(cat "$LAST_RUN_FILE"); else LAST=0; fi
    LAST=${LAST:-0}
    if [ "$CUR" -lt "$LAST" ]; then DELTA=$CUR; else DELTA=$((CUR - LAST)); fi
    
    # Insert into DB if there are new drops
    if [ "$DELTA" -gt 0 ]; then
        DB_LIST_NAME=$SET_NAME
        [ "$SET_NAME" != KTManualBan ] || DB_LIST_NAME=Blacklist
        [ "$SET_NAME" != KTManualBan6 ] || DB_LIST_NAME=Blacklist6
        sqlite3 "$DB_FILE" "INSERT INTO drops (timestamp, list_name, count) VALUES ($NOW, '$DB_LIST_NAME', $DELTA);" || exit 1
        [ "$SET_NAME" = "FirewallBlock" ] && NEW_DROPS_V4=$DELTA
        [ "$SET_NAME" = "FirewallBlock6" ] && NEW_DROPS_V6=$DELTA
        [ "$SET_NAME" = "VPNBlock" ] && NEW_DROPS_VPN=$DELTA
        # Capture GeoIP drops
        [ "$SET_NAME" = "GeoBlock" ] && NEW_DROPS_GEO=$DELTA
        [ "$SET_NAME" = "GeoBlock6" ] && NEW_DROPS_GEO6=$DELTA
		# Capture Manual drops
        [[ "$SET_NAME" = Blacklist || "$SET_NAME" = KTManualBan ]] && NEW_DROPS_MANUAL=$((NEW_DROPS_MANUAL+DELTA))
        [[ "$SET_NAME" = Blacklist6 || "$SET_NAME" = KTManualBan6 ]] && NEW_DROPS_MANUAL6=$((NEW_DROPS_MANUAL6+DELTA))
        [ "$SET_NAME" != AutoBan ] || NEW_DROPS_TRAP=$((NEW_DROPS_TRAP+DELTA))
        [ "$SET_NAME" != AutoBan6 ] || NEW_DROPS_TRAP6=$((NEW_DROPS_TRAP6+DELTA))
    fi
    echo "$CUR" > "$LAST_RUN_FILE"
    
    # IPv4 + IPv6 Regex fix for correct size counting
    SIZE=$(ipset list "$SET_NAME" 2>/dev/null | grep -cE '^[0-9a-fA-F]')
    eval "SIZE_${SET_NAME}=${SIZE:-0}"
done

# ==============================================================================
# 5. COLLECT TRAP (HONEYPOT) COUNTERS
# ==============================================================================
echo " -> Reading AutoBan Trap..."

collect_trap_counter() {
    local command=$1 suffix=$2 chain
    for chain in "SCAN_TRAP$suffix" "FW_CHK_CONN$suffix" "FW_CHK_BRUTE$suffix";do "$command" -L "$chain" -v -x -n 2>/dev/null || :;done | awk '$3=="DROP"{sum+=$1}END{printf "%.0f\n",sum}'
}

# IPv4 Trap Processing
LAST_RUN_FILE="/tmp/fw_last_trap.dat"
C_TRAP_RAW=$(collect_trap_counter "$IPTABLES_CMD" "")
C_TRAP=${C_TRAP_RAW:-0}
if [ -f "$LAST_RUN_FILE" ]; then LAST=$(cat "$LAST_RUN_FILE"); else LAST=0; fi
LAST=${LAST:-0}
if [ "$C_TRAP" -lt "$LAST" ]; then DELTA=$C_TRAP; else DELTA=$((C_TRAP - LAST)); fi

if [ "$DELTA" -gt 0 ]; then
    sqlite3 "$DB_FILE" "INSERT INTO drops (timestamp, list_name, count) VALUES ($NOW, 'AutoBan', $DELTA);" || exit 1
    NEW_DROPS_TRAP=$((NEW_DROPS_TRAP+DELTA))
fi
echo "$C_TRAP" > "$LAST_RUN_FILE"
SIZE_AutoBan=$(ipset list AutoBan 2>/dev/null | grep -cE '^[0-9]')
SIZE_AutoBan=${SIZE_AutoBan:-0}

# IPv6 Trap Processing
SIZE_AutoBan6=0
if [ "$ENABLE_IPV6" = "true" ]; then
    LAST_RUN_FILE="/tmp/fw_last_trap6.dat"
    C_TRAP6_RAW=$(collect_trap_counter "$IP6TABLES_CMD" 6)
    C_TRAP6=${C_TRAP6_RAW:-0}
    if [ -f "$LAST_RUN_FILE" ]; then LAST=$(cat "$LAST_RUN_FILE"); else LAST=0; fi
    LAST=${LAST:-0}
    if [ "$C_TRAP6" -lt "$LAST" ]; then DELTA=$C_TRAP6; else DELTA=$((C_TRAP6 - LAST)); fi

    if [ "$DELTA" -gt 0 ]; then
        sqlite3 "$DB_FILE" "INSERT INTO drops (timestamp, list_name, count) VALUES ($NOW, 'AutoBan6', $DELTA);" || exit 1
        NEW_DROPS_TRAP6=$((NEW_DROPS_TRAP6+DELTA))
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
# Read diffs for GeoIP sets (Calculated by update_blocklist)
DIFF_GEO=$(read_file "$DIFF_FILE_GEO")
if [ "$ENABLE_IPV6" = "true" ]; then DIFF_GEO6=$(read_file "$DIFF_FILE_GEO6"); else DIFF_GEO6="=0"; fi

SIZE_Blacklist=$(( ${SIZE_Blacklist:-0} + ${SIZE_KTManualBan:-0} ))
SIZE_Blacklist6=$(( ${SIZE_Blacklist6:-0} + ${SIZE_KTManualBan6:-0} ))
# Calculate diffs for all manual blocklists
DIFF_MANUAL=$(calc_diff "$SIZE_Blacklist" "$MANUAL_SIZE_FILE" "$DIFF_FILE_MANUAL")
DIFF_MANUAL6=$(calc_diff "$SIZE_Blacklist6" "$MANUAL6_SIZE_FILE" "$DIFF_FILE_MANUAL6")

# ==============================================================================
# 7. IP PACKET PROCESSING (PER-IP HITS)
# ==============================================================================
echo " -> Processing Per-IP stats..."
CURRENT_DUMP="$KT_WORKDIR/ipset_dump_now.dat"
SQL_IMPORT="$KT_WORKDIR/ip_inserts.sql"
: > "$CURRENT_DUMP"

# Dump active ipsets to temporary file
{
    ipset list FirewallBlock 2>/dev/null | grep "packets" | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2 main/p' | awk '$2 > 0'
    ipset list VPNBlock 2>/dev/null | grep "packets" | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2 main/p' | awk '$2 > 0'
    ipset list AutoBan 2>/dev/null | grep -E '^[0-9]{1,3}\.' | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2 trap/p' | awk '$2 > 0'
    # Extract GeoIP packets and tag them as 'geo'
    ipset list GeoBlock 2>/dev/null | grep "packets" | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2 geo/p' | awk '$2 > 0'
	# Dump Manual IPv4
    ipset list Blacklist 2>/dev/null | grep "packets" | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2 manual/p' | awk '$2 > 0'
    ipset list KTManualBan 2>/dev/null | grep "packets" | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2 manual/p' | awk '$2 > 0'
    if [ "$ENABLE_IPV6" = "true" ]; then
        ipset list FirewallBlock6 2>/dev/null | grep "packets" | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2 main/p' | awk '$2 > 0'
        ipset list AutoBan6 2>/dev/null | grep -E ':' | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2 trap/p' | awk '$2 > 0'
        # Extract GeoBlock6 packets
        ipset list GeoBlock6 2>/dev/null | grep "packets" | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2 geo/p' | awk '$2 > 0'
		# Dump Manual IPv6
        ipset list Blacklist6 2>/dev/null | grep "packets" | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2 manual/p' | awk '$2 > 0'
        ipset list KTManualBan6 2>/dev/null | grep "packets" | sed -n 's/^\([^ ]*\) .*packets \([0-9]*\) .*/\1 \2 manual/p' | awk '$2 > 0'
    fi
} | awk '{key=$1 SUBSEP $3;ips[key]=$1;types[key]=$3;hits[key]+=$2}END{for(key in hits)print ips[key],hits[key],types[key]}' | sort > "$CURRENT_DUMP"

# Calculate deltas for IPs (New Hits = Current Packets - Previous Packets)
DB_IS_EMPTY=$(sqlite3 "$DB_FILE" "SELECT count(*) FROM ip_drops;")
[ -z "$DB_IS_EMPTY" ] && DB_IS_EMPTY=0

if [ ! -f "$IP_LAST_STATE" ] || [ "$DB_IS_EMPTY" -eq 0 ]; then
    awk -v now="$NOW" '{printf "INSERT INTO ip_drops (timestamp, ip, count, list_type) VALUES (%d, \"%s\", %d, \"%s\");\n", now, $1, $2, $3;}' "$CURRENT_DUMP" > "$SQL_IMPORT"
else
    awk -v now="$NOW" 'FNR==NR { old[$1 SUBSEP $3] = $2; next } { key=$1 SUBSEP $3; prev = (old[key] ? old[key] : 0); curr = $2; delta = curr - prev; if (delta < 0) delta = curr; if (delta > 0) printf "INSERT INTO ip_drops (timestamp, ip, count, list_type) VALUES (%d, \"%s\", %d, \"%s\");\n", now, $1, delta, $3; }' "$IP_LAST_STATE" "$CURRENT_DUMP" > "$SQL_IMPORT"
fi
cp "$CURRENT_DUMP" "$KT_WORKDIR/ip_next_state"

# Bulk Insert into DB
if [ -s "$SQL_IMPORT" ]; then
    NEW_IP_RECORDS=$(wc -l < "$SQL_IMPORT")
    (echo "BEGIN TRANSACTION;"; cat "$SQL_IMPORT"; echo "COMMIT;") | sqlite3 "$DB_FILE" || exit 1
fi
mv "$KT_WORKDIR/ip_next_state" "$IP_LAST_STATE"
rm "$CURRENT_DUMP" "$SQL_IMPORT" 2>/dev/null

# ==============================================================================
# 8. SNIFFER PARSER (ULTRA-OPTIMIZED: INCREMENTAL + SELECTIVE DB CACHE)
# ==============================================================================
PCAP_BASE="${KT_FW_PCAP:-/opt/var/log/keentool-firewall/fw_syn_ring.pcap}"
DB_CACHE="$KT_WORKDIR/fw_db_cache.dat"
UNIQUE_TRAFFIC="$KT_WORKDIR/fw_unique_traffic.dat"
LAST_TS_FILE="${KT_FW_PCAP_CURSOR:-/opt/etc/keentool/fw_pcap_last_ts.dat}"
NEXT_TS_FILE="$KT_WORKDIR/pcap_next_ts"
ACTIVE_IPS="$KT_WORKDIR/fw_active_ips.dat"

LOG_BUFFER="$PCAP_BASE" # do not replay already processed rotation segments

if [ -n "$LOG_BUFFER" ] && [ -s "$LOG_BUFFER" ]; then
    echo " -> 🕵️ Processing WAN Sniffer Buffer (Incremental)..."
    
    # 1. Retrieve last analyzed timestamp (Memory State)
    if [ -f "$LAST_TS_FILE" ]; then LAST_TS=$(cat "$LAST_TS_FILE"); else LAST_TS=0; fi
    
    # 2. PHASE 1: Parse PCAP & Deduplicate (Only NEW packets)
    cp "$LOG_BUFFER" "$KT_WORKDIR/capture.pcap" || exit 1
    tcpdump -tt -r "$KT_WORKDIR/capture.pcap" -nn 2>/dev/null | awk -v last_ts="$LAST_TS" '
    BEGIN { 
        max_ts_num = last_ts + 0; 
        max_ts_str = last_ts; 
    }
    {
        current_ts_num = $1 + 0;
        if (current_ts_num <= (last_ts + 0)) next; # SKIP OLD PACKETS!
        
        # Update the timestamp by saving the exact text STRING from tcpdump
        if (current_ts_num > max_ts_num) {
            max_ts_num = current_ts_num;
            max_ts_str = $1; 
        }
        
        # Robust Arrow Detection (SLL/Ethernet safe)
        arrow_idx = 0;
        for (i=1; i<=NF; i++) { if ($i == ">") { arrow_idx = i; break; } }
        
        if (arrow_idx > 0) {
            src_full = $(arrow_idx-1);
            dst_full = $(arrow_idx+1);
            
            # Extract Source IP safely (Fix for both IPv4 and IPv6)
            src_clean = src_full;
            gsub(/:$/, "", src_clean);
            n = split(src_clean, a, ".");
            if (n >= 4) ip = a[1]"."a[2]"."a[3]"."a[4];
            else ip = a[1];

            # Extract Destination Port safely (Prevents IPv6 acting as port)
            dst_clean = dst_full;
            gsub(/:$/, "", dst_clean);
            m = split(dst_clean, b, ".");
            if (m == 5 || m == 2) port_str = b[m];
            else port_str = 0;
            
            gsub(/[^0-9]/, "", port_str); # Ensure it is strictly numeric
            if (port_str == "") port_str = 0;

            # Extract Proto
            proto = "udp"; 
            if ($0 ~ /Flags/ || $0 ~ /seq/ || $0 ~ /ack/) { proto = "tcp" }

            # Print raw tuple for deduplication
            if (length(ip) >= 7 && port_str + 0 > 0) {
                print ip "|" port_str "|" proto
            }
        }
    }
    END { 
        # Print the pure string, bypassing the BusyBox formatting bug
        print max_ts_str > "'"$NEXT_TS_FILE"'" 
    }' | sort -u > "$UNIQUE_TRAFFIC"

    TRAFFIC_COUNT=$(wc -l < "$UNIQUE_TRAFFIC")
    
    if [ "$TRAFFIC_COUNT" -gt 0 ]; then
        echo "    [DEBUG] Found $TRAFFIC_COUNT new unique flows."
        
        # 3. PHASE 2: SELECTIVE DB CACHE (Load only necessary IPs)
        # Extract fresh IPs from the newly parsed traffic
        awk -F"|" '{print $1}' "$UNIQUE_TRAFFIC" | sort -u > "$ACTIVE_IPS"
        
        # Create a temporary table in SQLite to extract ONLY the history of those active IPs
        echo "CREATE TEMP TABLE active_ips (ip TEXT PRIMARY KEY);" > $KT_WORKDIR/query.sql
        awk '{print "INSERT INTO active_ips VALUES (\047" $1 "\047);"}' "$ACTIVE_IPS" >> $KT_WORKDIR/query.sql
        
        # [CPU FIX: Rimosso il JOIN mostruoso con ip_drops, query istantanea]
        echo "SELECT a.ip, IFNULL(i.port_history, '') FROM active_ips a LEFT JOIN ip_info i ON a.ip = i.ip;" >> $KT_WORKDIR/query.sql
        
        sqlite3 -separator "|" "$DB_FILE" < $KT_WORKDIR/query.sql > "$DB_CACHE"
        
        # 4. PHASE 3: Cross-Reference & Generate SQL for the update
        echo "BEGIN TRANSACTION;" > $KT_WORKDIR/port_update.sql
        
        awk -F"|" -v now="$NOW" '
        FNR==NR {
            key = $1; val = $2 "/" $3;
            if (traffic[key] == "") { traffic[key] = val } 
            else { traffic[key] = traffic[key] "," val }
            next
        }
        {
            db_ip = $1; db_hist = $2;
            
            if (db_ip in traffic) {
                new_entries = traffic[db_ip]
                split(new_entries, candidates, ",")
                
                is_modified = 0; final_hist = db_hist; last_port = 0;
                
                for (i in candidates) {
                    cand = candidates[i]
                    split(cand, p, "/")
                    
                    if (index("," final_hist ",", "," cand ",") == 0) {
                        if (final_hist == "") { final_hist = cand }
                        else { final_hist = final_hist "," cand }
                        is_modified = 1; last_port = p[1];
                    } else {
                        last_port = p[1]; is_modified = 1; 
                    }
                }
                
                if (is_modified) {
                    if (last_port !~ /^[0-9]+$/) { last_port = 0; }
                    
                    printf "INSERT OR IGNORE INTO ip_info(ip) VALUES(\047%s\047); UPDATE ip_info SET target_port=%d, port_history=\047%s\047, updated=%d WHERE ip=\047%s\047;\n", db_ip, last_port, final_hist, now, db_ip;
                    updates++
                }
            }
        }
        END { print "    [DEBUG] Updated " (updates+0) " DB records." > "/dev/stderr"; }
        ' "$UNIQUE_TRAFFIC" "$DB_CACHE" >> $KT_WORKDIR/port_update.sql
        
        echo "COMMIT;" >> $KT_WORKDIR/port_update.sql

        # 5. Execute the database update
        sqlite3 "$DB_FILE" < $KT_WORKDIR/port_update.sql
    else
        echo "    [DEBUG] No new traffic since last run."
    fi
    
    [ ! -f "$NEXT_TS_FILE" ] || mv "$NEXT_TS_FILE" "$LAST_TS_FILE"
    # Cleanup temporary files
    rm -f "$KT_WORKDIR/port_update.sql" "$DB_CACHE" "$UNIQUE_TRAFFIC" "$ACTIVE_IPS" "$KT_WORKDIR/query.sql" 2>/dev/null
    
    # --- ULOGD PCAP AUTO-ROTATION (REAL-TIME) ---
    # Check file size (Limit: ~10 MB = 10485760 bytes)
    # Using wc -c is extremely lightweight and prevents CPU overhead
    PCAP_SIZE=$(wc -c < "$LOG_BUFFER" 2>/dev/null)
    if [ -n "$PCAP_SIZE" ] && [ "$PCAP_SIZE" -gt 10485760 ]; then
        echo " -> Rotating oversized PCAP file ($PCAP_SIZE bytes)..."
        mv "$LOG_BUFFER" "${LOG_BUFFER}.processed.$NOW"
        killall -HUP ulogd 2>/dev/null
        # Already processed segment remains available for diagnostics until next run.
        find "$(dirname "$PCAP_BASE")" -name 'fw_syn_ring.pcap.processed.*' -mmin +1440 -delete 2>/dev/null || :
        echo "0" > "$LAST_TS_FILE" # Reset the time bookmark
    fi
    # ---------------------------------
else
    echo " -> 🕵️ Buffer empty or missing."
fi

# ==============================================================================
fi
# 9. GENERATE JSON DATA FOR DASHBOARD (ATOMIC WRITE)
# ==============================================================================
# Aggregate at most once per day before exporting any IP-based tables. Preview never mutates history.
if [ -z "${TZ:-}" ];then
    for timezone_file in /etc/TZ /opt/etc/TZ;do
        if [ -s "$timezone_file" ];then export TZ="$(cat "$timezone_file")";break;fi
    done
fi
HISTORY_JSON='{}'
HISTORY_ENGINE=${KT_HISTORY_ENGINE:-/opt/lib/keentool/history_engine.php}
if [ -f "$HISTORY_ENGINE" ];then
    HISTORY_PHP=${KT_HISTORY_PHP:-}
    if [ -z "$HISTORY_PHP" ];then
        for candidate in /opt/bin/php-cli /opt/bin/php8 /opt/bin/php;do
            if [ -x "$candidate" ] && "$candidate" -r 'exit(PHP_SAPI==="cli"?0:1);' >/dev/null 2>&1;then HISTORY_PHP=$candidate;break;fi
        done
    fi
    if [ -n "$HISTORY_PHP" ];then
        HISTORY_ACTION=(status)
        [ "${KT_FW_PREVIEW:-false}" = true ] || HISTORY_ACTION=(run --due)
        if "$HISTORY_PHP" "$HISTORY_ENGINE" "${HISTORY_ACTION[@]}" > "$KT_WORKDIR/history.json";then
            HISTORY_JSON=$("$HISTORY_PHP" -r '$v=json_decode(file_get_contents($argv[1]),true,512,JSON_THROW_ON_ERROR);unset($v["backup"]);echo json_encode($v,JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_THROW_ON_ERROR);' "$KT_WORKDIR/history.json")
        else
            kt_log 'History aggregation deferred; current statistics remain available. Review the preceding history error.'
            if "$HISTORY_PHP" "$HISTORY_ENGINE" status > "$KT_WORKDIR/history.json";then HISTORY_JSON=$("$HISTORY_PHP" -r '$v=json_decode(file_get_contents($argv[1]),true,512,JSON_THROW_ON_ERROR);unset($v["backup"]);echo json_encode($v,JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_THROW_ON_ERROR);' "$KT_WORKDIR/history.json");fi
        fi
    fi
fi

echo " -> Generating JS Data..."
TOTAL_DROPS_ALL_TIME=$(sqlite3 "$DB_FILE" "SELECT sum(count) FROM drops;")
[ -z "$TOTAL_DROPS_ALL_TIME" ] && TOTAL_DROPS_ALL_TIME="0"

time_cache_name() { case "$1" in *%H:00*)echo hourly;;*%d-%m-%Y*)echo daily;;*%m-%Y*)echo monthly;;*)echo yearly;;esac; }
# Helper to generate Time Series Rows
gen_html_rows() {
    QUERY="SELECT $1, SUM(CASE WHEN list_name='FirewallBlock' THEN count ELSE 0 END), SUM(CASE WHEN list_name='FirewallBlock6' THEN count ELSE 0 END), SUM(CASE WHEN list_name='VPNBlock' THEN count ELSE 0 END), SUM(CASE WHEN list_name='AutoBan' OR list_name='AutoBan6' THEN count ELSE 0 END), SUM(CASE WHEN list_name='GeoBlock' OR list_name='GeoBlock6' THEN count ELSE 0 END), SUM(count) FROM drops $3 GROUP BY $2 ORDER BY MAX(timestamp) DESC;"
    cat "$KT_WORKDIR/render/time_$(time_cache_name "$1").rows" | awk -F'|' '{print "<tr><td>"$1"</td><td class=\"num col-main\">+"$2"</td><td class=\"num col-v6\">+"$3"</td><td class=\"num col-vpn\">+"$4"</td><td class=\"num col-trap\">+"$5"</td><td class=\"num col-geo\">+"$6"</td><td class=\"num\">+"$7"</td></tr>"}'
}

# Helper to get Averages
get_avg() {
    awk -F'|' '{sum+=$7;n++}END{printf "%.0f",(n?sum/n:0)}' "$KT_WORKDIR/render/time_$(time_cache_name "$1").rows"

}


# Function: Generate IP Tables (Pure DB Data)
get_ip_table() {
    WHERE=$1; TYPE=$2
    
    # Aggregate the top 10 before joining metadata; retain the correct d alias.
    QUERY="SELECT sub.ip, sub.total, i.country, i.risk, i.domain, i.target_port, sub.list_type, i.port_history 
           FROM (
               SELECT d.ip, SUM(d.count) as total, d.list_type 
               FROM ip_drops d 
               WHERE $WHERE 
               GROUP BY d.ip 
               ORDER BY total DESC 
               LIMIT 10
           ) sub 
           LEFT JOIN ip_info i ON (
               CASE WHEN INSTR(sub.ip, '/') > 0 THEN SUBSTR(sub.ip, 1, INSTR(sub.ip, '/') - 1) ELSE sub.ip END = i.ip
           ) 
           ORDER BY sub.total DESC;"
    
    while IFS='|' read -r IP COUNT CO SC DO PORT TYPE PHIST; do
        CLEAN_IP=$(echo "$IP" | cut -d'/' -f1)
        CO=${CO:---}; DO=${DO:-Metadata pending}; SC=${SC:-0}
        DO=$(printf '%s' "$DO" | sed 's/\&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
        SC=${SC:-0}; [ "$SC" -ge 50 ] && ST="color:var(--red);font-weight:bold;" || ST="color:var(--green);"
        BADGE_HTML=""; if [ "$2" = "1" ]; then if [ "$TYPE" = "trap" ]; then BADGE_HTML="<span class='list-badge lb-trap'>TRAP</span>"; else BADGE_HTML="<span class='list-badge lb-main'>MAIN</span>"; fi; fi
        
        PORT_KEY=$(printf '%s' "$CLEAN_IP" | sha256sum | awk '{print $1}')
        PORT_CACHE="$KT_WORKDIR/port_html_$PORT_KEY"
        if [ ! -f "$PORT_CACHE" ]; then
            printf '%s|%s\n' "$PORT" "$PHIST" | awk -F'|' -v listdir="$LIST_DIR" -v key="$PORT_KEY" -v ip="$CLEAN_IP" '
            {
              total=split($2,raw,",");n=0;out="";
              for(j=1;j<=total;j++) {
                value=tolower(raw[j]);gsub(/^[ \t]+|[ \t]+$/,"",value);split(value,p,"/");
                if(value ~ /^[0-9]+(\/(tcp|udp))?$/ && p[1]+0>=1 && p[1]+0<=65535)a[++n]=value;
              }
              if(n==0 && $1+0>0)out="<span class=\"list-badge\">:"$1"</span>";
              for(j=1;j<=n && j<=3;j++)out=out "<span class=\"list-badge\" style=\"background:"(a[j]~/\/udp$/?"#0d6efd":"#333")";color:#fff\">:"a[j]"</span>";
              if(n>3) {
                filename="ipports_"key".txt";path=listdir "/" filename;tip="";
                for(j=1;j<=n;j++)print a[j] > path;
                close(path);
                for(j=4;j<=n && j<=103;j++)tip=tip sprintf("%s%s",(j>4?", ":""),a[j]);if(n>103)tip=tip", ...";
                out=out "<button type=\"button\" class=\"list-badge port-more\" data-port-list=\""filename"\" data-ip=\""ip"\" onclick=\"showPorts(this)\" title=\"Other ports: "tip"\" aria-label=\"Show all "n" targeted ports\">(+"(n-3)")</button>";
              }
              print out;
            }' > "$PORT_CACHE" || { rm -f "$PORT_CACHE";return 1; }
        fi
        PORT_HTML=$(cat "$PORT_CACHE")
       echo "<tr><td><span class='badge bg-danger'>$COUNT</span></td><td><a href='https://www.abuseipdb.com/check/$CLEAN_IP' target='_blank'>$IP</a> $BADGE_HTML <a href='#' data-admin-only hidden onclick='unbanIP(\"$CLEAN_IP\"); return false;' title='Quick Unban' style='font-size: 14px; margin-left: 5px; text-decoration: none;'>🔓</a><br> $PORT_HTML</td><td class='meta'><span style='$ST'>Risk: ${SC}%</span> - $CO<br><small>$DO</small></td></tr>"
    done < "$KT_WORKDIR/render/ip_$3.rows"
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
    
    cat "$KT_WORKDIR/render/port_$ID_PREFIX.rows" | awk -F'|' -v listdir="$LIST_DIR" -v prefix="$ID_PREFIX" -v q="'" '
    {
        full_port=$1; ips_raw=$2; count=$3;
        
        # Extract number only for filename (remove /tcp or /udp)
        split(full_port, a, "/"); port_num = a[1];
        
        gsub(/[ \t\r\n]+/, "", ips_raw); 
        proto=a[2]; if(proto=="")proto="unknown"; filename = prefix "_" port_num "_" proto ".txt"; filepath = listdir "/" filename;
        split(ips_raw, ip_array, ","); 
        
        ips_formatted = ips_raw;
        gsub(",", "\n", ips_formatted); 
        print ips_formatted > filepath; 
        close(filepath);
        
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

# Export geography from all recorded IP counters, independently of top-10 tables.
get_geo_data() {
    local period seconds condition
    {
        echo '.bail on'
        echo '.separator |'
        echo 'BEGIN;'
        for period in 24h 30d 1y all; do
            case "$period" in 24h) seconds=86400;;30d) seconds=2592000;;1y) seconds=31536000;;all) seconds=0;;esac
            condition="d.timestamp > $((NOW - seconds))"
            [ "$period" != all ] || condition='1=1'
            echo ".output $KT_WORKDIR/render/map_$period.rows"
            echo "SELECT d.ip, SUM(d.count), UPPER(IFNULL(i.country,'')), COALESCE(NULLIF(i.port_history,''),i.target_port,'') FROM ip_drops d LEFT JOIN ip_info i ON i.ip=CASE WHEN INSTR(d.ip,'/')>0 THEN SUBSTR(d.ip,1,INSTR(d.ip,'/')-1) ELSE d.ip END WHERE $condition GROUP BY d.ip ORDER BY SUM(d.count) DESC,d.ip;"
        done
        echo 'COMMIT;'
    } > "$KT_WORKDIR/map-export.sql"
    sqlite3 "$DB_FILE" < "$KT_WORKDIR/map-export.sql" || return 1
    printf '{'
    local sep=''
    for period in 24h 30d 1y all; do
        printf '%s"%s":' "$sep" "$period"; sep=,
        awk -F'|' '
        BEGIN {total=0}
        $2 ~ /^[0-9]+$/ && $2+0>0 {
            cc=$3; if(cc !~ /^[A-Z][A-Z]$/ || cc=="XX" || cc=="ZZ")cc="unknown";
            hits=$2+0; counts[cc]+=hits; total+=hits; sources[cc]++;
            if(shown[cc]<100 && $1 ~ /^[0-9a-fA-F:.\/]+$/) {
                ports=""; n=split($4,a,","); used=0;
                for(j=1;j<=n && used<12;j++)if(a[j] ~ /^[0-9]+\/(tcp|udp)$/ || a[j] ~ /^[0-9]+$/){ports=ports (used?", ":"") a[j];used++}
                if(n>12)ports=ports ", ...";
                rows[cc]=rows[cc] (shown[cc]?",":"") "{\"ip\":\"" $1 "\",\"hits\":" sprintf("%.0f",hits) ",\"ports\":\"" ports "\"}";
                shown[cc]++;
            }
        }
        END {
            printf "{\"total\":%.0f,\"countries\":{",total; sep="";
            for(cc in counts){printf "%s\"%s\":{\"hits\":%.0f,\"sources\":%d,\"rows\":[%s]}",sep,cc,counts[cc],sources[cc],rows[cc];sep=","}
            printf "}}";
        }' "$KT_WORKDIR/render/map_$period.rows" || return 1
    done
    printf '}'
}

# --- Execute Data Generation ---

# Prepare all 28 raw result sets in one SQLite session (one consistent read snapshot).
. "${KT_RENDER_LIB:-/opt/lib/keentool/render_cache.sh}"
prepare_render_cache "$DB_FILE" "$KT_WORKDIR/render" "$NOW" "$TCP_SERVICES" "$UDP_SERVICES" || exit 1
# Port Tables
PORTS_24H=$(get_port_stats 86400 "" "p24") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
PORTS_30D=$(get_port_stats 2592000 "" "p30") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
PORTS_1Y=$(get_port_stats 31536000 "" "p1y") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
PORTS_ALL=$(get_port_stats "" "" "pall") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }

# Bruteforce Tables (Strict Protocol Filtering)
TCP_CSV=$(echo "$TCP_SERVICES" | tr -s ' ' ',' | sed 's/^,//;s/,$//')
UDP_CSV=$(echo "$UDP_SERVICES" | tr -s ' ' ',' | sed 's/^,//;s/,$//')

CLAUSE_TCP=""
if [ -n "$TCP_CSV" ]; then
    # Match ports in the TCP list whose history contains the corresponding "/tcp" entry.
    CLAUSE_TCP="(i.target_port IN ($TCP_CSV) AND i.port_history LIKE '%' || i.target_port || '/tcp%')"
fi

CLAUSE_UDP=""
if [ -n "$UDP_CSV" ]; then
    # Match ports in the UDP list whose history contains the corresponding "/udp" entry.
    CLAUSE_UDP="(i.target_port IN ($UDP_CSV) AND i.port_history LIKE '%' || i.target_port || '/udp%')"
fi

FULL_CLAUSE=""
if [ -n "$CLAUSE_TCP" ] && [ -n "$CLAUSE_UDP" ]; then
    FULL_CLAUSE="AND ($CLAUSE_TCP OR $CLAUSE_UDP)"
elif [ -n "$CLAUSE_TCP" ]; then
    FULL_CLAUSE="AND $CLAUSE_TCP"
elif [ -n "$CLAUSE_UDP" ]; then
    FULL_CLAUSE="AND $CLAUSE_UDP"
else
    FULL_CLAUSE="AND 0" # No configured service, so no brute-force table
fi

TRAP_PORT_FILTER="AND d.list_type='trap' $FULL_CLAUSE"

BRUTE_24H=$(get_port_stats 86400 "$TRAP_PORT_FILTER" "b24") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
BRUTE_30D=$(get_port_stats 2592000 "$TRAP_PORT_FILTER" "b30") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
BRUTE_1Y=$(get_port_stats 31536000 "$TRAP_PORT_FILTER" "b1y") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
BRUTE_ALL=$(get_port_stats "" "$TRAP_PORT_FILTER" "ball") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }

# IP Tables
IPV6_24H=$(get_ip_table "d.ip LIKE '%:%' AND d.timestamp > $((NOW - 86400))" "1" "ipv6_24h") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
IPV6_30D=$(get_ip_table "d.ip LIKE '%:%' AND d.timestamp > $((NOW - 2592000))" "1" "ipv6_30d") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
IPV6_1Y=$(get_ip_table "d.ip LIKE '%:%' AND d.timestamp > $((NOW - 31536000))" "1" "ipv6_1y") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
IPV6_ALL=$(get_ip_table "d.ip LIKE '%:%'" "1" "ipv6_all") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }

TRAP_24H=$(get_ip_table "d.list_type='trap' AND d.timestamp > $((NOW - 86400))" "" "trap_24h") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
OTHER_24H=$(get_ip_table "d.list_type='main' AND d.ip NOT LIKE '%/%' AND d.timestamp > $((NOW - 86400))" "" "other_24h") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
NETS_24H=$(get_ip_table "d.list_type='main' AND d.ip LIKE '%/%' AND d.timestamp > $((NOW - 86400))" "" "nets_24h") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }

TRAP_30D=$(get_ip_table "d.list_type='trap' AND d.timestamp > $((NOW - 2592000))" "" "trap_30d") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
OTHER_30D=$(get_ip_table "d.list_type='main' AND d.ip NOT LIKE '%/%' AND d.timestamp > $((NOW - 2592000))" "" "other_30d") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
NETS_30D=$(get_ip_table "d.list_type='main' AND d.ip LIKE '%/%' AND d.timestamp > $((NOW - 2592000))" "" "nets_30d") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }

TRAP_1Y=$(get_ip_table "d.list_type='trap' AND d.timestamp > $((NOW - 31536000))" "" "trap_1y") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
OTHER_1Y=$(get_ip_table "d.list_type='main' AND d.ip NOT LIKE '%/%' AND d.timestamp > $((NOW - 31536000))" "" "other_1y") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
NETS_1Y=$(get_ip_table "d.list_type='main' AND d.ip LIKE '%/%' AND d.timestamp > $((NOW - 31536000))" "" "nets_1y") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }

TRAP_ALL=$(get_ip_table "d.list_type='trap'" "" "trap_all") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
OTHER_ALL=$(get_ip_table "d.list_type='main' AND d.ip NOT LIKE '%/%'" "" "other_all") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
NETS_ALL=$(get_ip_table "d.list_type='main' AND d.ip LIKE '%/%'" "" "nets_all") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }

# --- Added GeoIP Tables ---
GEO_24H=$(get_ip_table "d.list_type='geo' AND d.timestamp > $((NOW - 86400))" "" "geo_24h") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
GEO_30D=$(get_ip_table "d.list_type='geo' AND d.timestamp > $((NOW - 2592000))" "" "geo_30d") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
GEO_1Y=$(get_ip_table "d.list_type='geo' AND d.timestamp > $((NOW - 31536000))" "" "geo_1y") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }
GEO_ALL=$(get_ip_table "d.list_type='geo'" "" "geo_all") || { kt_log "Table rendering failed; previous dashboard export retained";exit 1; }

# Time Series Data
ROWS_HOURLY=$(gen_html_rows "strftime('%H:00', timestamp, 'unixepoch', 'localtime')" "1" "WHERE timestamp >= strftime('%s', 'now', '-24 hours')")
ROWS_DAILY=$(gen_html_rows "strftime('%d-%m-%Y', timestamp, 'unixepoch', 'localtime')" "1" "WHERE timestamp >= strftime('%s', 'now', '-30 days')")
ROWS_MONTHLY=$(gen_html_rows "strftime('%m-%Y', timestamp, 'unixepoch', 'localtime')" "1" "WHERE timestamp >= strftime('%s', 'now', '-12 months')")
ROWS_YEARLY=$(gen_html_rows "strftime('%Y', timestamp, 'unixepoch', 'localtime')" "1" "")
QUERY_TOP="SELECT strftime('%d-%m-%Y', timestamp, 'unixepoch', 'localtime') as day, SUM(CASE WHEN list_name='FirewallBlock' THEN count ELSE 0 END), SUM(CASE WHEN list_name='FirewallBlock6' THEN count ELSE 0 END), SUM(CASE WHEN list_name='VPNBlock' THEN count ELSE 0 END), SUM(CASE WHEN list_name='AutoBan' OR list_name='AutoBan6' THEN count ELSE 0 END), SUM(CASE WHEN list_name='GeoBlock' OR list_name='GeoBlock6' THEN count ELSE 0 END), SUM(count) as total FROM drops GROUP BY day ORDER BY total DESC LIMIT 10;"
ROWS_TOP_DAYS=$(sqlite3 -separator "|" "$DB_FILE" "$QUERY_TOP" | awk -F'|' '{print "<tr><td><b>"$1"</b></td><td class=\"num col-main\">+"$2"</td><td class=\"num col-v6\">+"$3"</td><td class=\"num col-vpn\">+"$4"</td><td class=\"num col-trap\">+"$5"</td><td class=\"num col-geo\">+"$6"</td><td class=\"num\">+"$7"</td></tr>"}')

# Averages
AVG_H=$(get_avg "strftime('%H:00', timestamp, 'unixepoch', 'localtime')" "WHERE timestamp >= strftime('%s', 'now', '-24 hours')")
AVG_D=$(get_avg "strftime('%d-%m-%Y', timestamp, 'unixepoch', 'localtime')" "WHERE timestamp >= strftime('%s', 'now', '-30 days')")
AVG_M=$(get_avg "strftime('%m-%Y', timestamp, 'unixepoch', 'localtime')" "WHERE timestamp >= strftime('%s', 'now', '-12 months')")
AVG_Y=$(get_avg "strftime('%Y', timestamp, 'unixepoch', 'localtime')" "")

# Misc Stats (Added S_GEO and S_GEO6)
DATE_UPDATE=$($DATE_CMD "+%d-%m-%Y %H:%M:%S"); UP_SECONDS=$(cut -d. -f1 /proc/uptime)
DAYS=$((UP_SECONDS / 86400)); HOURS=$(( (UP_SECONDS % 86400) / 3600 ))
UPTIME="${DAYS}d ${HOURS}h"
S_MAIN=${SIZE_FirewallBlock:-0}; S_MAIN6=${SIZE_FirewallBlock6:-0}; S_VPN=${SIZE_VPNBlock:-0}; S_TRAP=${SIZE_AutoBan:-0}; S_TRAP6=${SIZE_AutoBan6:-0}; S_GEO=${SIZE_GeoBlock:-0}; S_GEO6=${SIZE_GeoBlock6:-0}

S_MANUAL=${SIZE_Blacklist:-0}; S_MANUAL6=${SIZE_Blacklist6:-0}

# Get file modification times for blocklists
[ -f "$BACKUP_FILE_V4" ] && TIME_MAIN=$($DATE_CMD -r "$BACKUP_FILE_V4" "+%d-%m-%Y %H:%M:%S" 2>/dev/null) || TIME_MAIN="$DATE_UPDATE"
[ -f "$BACKUP_FILE_V6" ] && TIME_V6=$($DATE_CMD -r "$BACKUP_FILE_V6" "+%d-%m-%Y %H:%M:%S" 2>/dev/null) || TIME_V6="$DATE_UPDATE"
[ -f "$BACKUP_GEO_V4" ] && TIME_GEO=$($DATE_CMD -r "$BACKUP_GEO_V4" "+%d-%m-%Y %H:%M:%S" 2>/dev/null) || TIME_GEO="$DATE_UPDATE"
[ -f "$BACKUP_MANUAL_V4" ] && TIME_MANUAL=$($DATE_CMD -r "$BACKUP_MANUAL_V4" "+%d-%m-%Y %H:%M:%S" 2>/dev/null) || TIME_MANUAL="$DATE_UPDATE"

GEO_DATA=$(get_geo_data) || { kt_log "Geographic export failed; previous dashboard export retained";exit 1; }

# Assemble JS File (Atomic Write to Temp File first)
cat <<EOF > "$TEMP_DATA_FILE"
window.FW_DATA = {
    updated: "$DATE_UPDATE", uptime: "$UPTIME", lifetime: "$TOTAL_DROPS_ALL_TIME",
    history: $HISTORY_JSON,
    ipv6_status: "$ENABLE_IPV6",
    lists: { 
      main: "$S_MAIN", diff_v4: "$DIFF_V4", up_main: "$TIME_MAIN",
      main6: "$S_MAIN6", diff_v6: "$DIFF_V6", up_v6: "$TIME_V6",
      manual: "$S_MANUAL", diff_manual: "$DIFF_MANUAL", up_manual: "$TIME_MANUAL",
      manual6: "$S_MANUAL6", diff_manual6: "$DIFF_MANUAL6",
      vpn: "$S_VPN", diff_vpn: "$DIFF_VPN", up_vpn: "$TIME_MAIN",
      trap_ips: "$S_TRAP", diff_trap: "$DIFF_TRAP", up_trap: "$DATE_UPDATE",
      trap6_ips: "$S_TRAP6", diff_trap6: "$DIFF_TRAP6",
      geo: "$S_GEO", diff_geo: "$DIFF_GEO", up_geo: "$TIME_GEO",
      geo6: "$S_GEO6", diff_geo6: "$DIFF_GEO6"
    },
    geography: $GEO_DATA,
    averages: { hourly: "$AVG_H", daily: "$AVG_D", monthly: "$AVG_M", yearly: "$AVG_Y" },
    tables: { 
        hourly: \`$ROWS_HOURLY\`, daily: \`$ROWS_DAILY\`, monthly: \`$ROWS_MONTHLY\`, yearly: \`$ROWS_YEARLY\`, top_days: \`$ROWS_TOP_DAYS\`,
        trap_24h: \`$TRAP_24H\`, other_24h: \`$OTHER_24H\`, nets_24h: \`$NETS_24H\`, ports_24h: \`$PORTS_24H\`, brute_24h: \`$BRUTE_24H\`, ipv6_24h: \`$IPV6_24H\`, geo_24h: \`$GEO_24H\`,
        trap_30d: \`$TRAP_30D\`, other_30d: \`$OTHER_30D\`, nets_30d: \`$NETS_30D\`, ports_30d: \`$PORTS_30D\`, brute_30d: \`$BRUTE_30D\`, ipv6_30d: \`$IPV6_30D\`, geo_30d: \`$GEO_30D\`,
        trap_1y: \`$TRAP_1Y\`, other_1y: \`$OTHER_1Y\`, nets_1y: \`$NETS_1Y\`, ports_1y: \`$PORTS_1Y\`, brute_1y: \`$BRUTE_1Y\`, ipv6_1y: \`$IPV6_1Y\`, geo_1y: \`$GEO_1Y\`,
        trap_all: \`$TRAP_ALL\`, other_all: \`$OTHER_ALL\`, nets_all: \`$NETS_ALL\`, ports_all: \`$PORTS_ALL\`, brute_all: \`$BRUTE_ALL\`, ipv6_all: \`$IPV6_ALL\`, geo_all: \`$GEO_ALL\`
    }
};
EOF

# Move temp file to final location (Atomic update)
mkdir -p "$PUBLISHED_LIST_DIR"
for list in "$LIST_DIR"/*.txt; do [ ! -f "$list" ] || { chmod 644 "$list" && mv "$list" "$PUBLISHED_LIST_DIR/"; }; done
rmdir "$LIST_DIR" 2>/dev/null || :
mv "$TEMP_DATA_FILE" "$DATA_FILE"
chmod 644 "$DATA_FILE"

# ==============================================================================
# 10. SMART MAINTENANCE & PERSISTENCE (LOSSLESS COMPRESSION)
# ==============================================================================
echo " -> IP/list hit totals, global counters, port history and reporting state preserved; history policy is shown on the dashboard."
if [ "${1:-}" = --maintenance ]; then
    [ "$(sqlite3 "$DB_FILE" 'PRAGMA quick_check;')" = ok ] || exit 1
    sqlite3 "$DB_FILE" 'PRAGMA wal_checkpoint(TRUNCATE); VACUUM;' || exit 1
fi
DB_SIZE_H=$(du -h "$DB_FILE" 2>/dev/null | awk '{print $1}')
echo " -> Current DB size: $DB_SIZE_H"

if [ "${KT_FW_PREVIEW:-false}" != true ]; then
# SAVE IPSETS TO DISK (Auto-Save)
echo " -> Saving AutoBan states..."
if [ -f /opt/lib/keentool/firewall_state.sh ];then
 . /opt/lib/keentool/firewall_state.sh
 fw_checkpoint_state || kt_log 'Dynamic state checkpoint failed; previous snapshot retained'
fi
ipset save AutoBan > "$KT_WORKDIR/autoban.save" 2>/dev/null
if [ "$ENABLE_IPV6" = "true" ]; then
    ipset save AutoBan6 >> "$KT_WORKDIR/autoban.save" 2>/dev/null
fi

if [ -s "$KT_WORKDIR/autoban.save" ]; then cp "$KT_WORKDIR/autoban.save" "${AUTOBAN_SAVE_FILE}.tmp" && mv "${AUTOBAN_SAVE_FILE}.tmp" "$AUTOBAN_SAVE_FILE"; fi
kt_log "Statistics generated in $((SECONDS-START_SECONDS)) seconds"
T4_TOT=${SIZE_AutoBan:-0}; T4_DIF=${DIFF_TRAP:-=0}
T6_TOT=${SIZE_AutoBan6:-0}; T6_DIF=${DIFF_TRAP6:-=0}
TOTAL_NEW_DROPS=$((NEW_DROPS_V4 + NEW_DROPS_V6 + NEW_DROPS_VPN + NEW_DROPS_TRAP + NEW_DROPS_TRAP6 + NEW_DROPS_GEO + NEW_DROPS_GEO6 + NEW_DROPS_MANUAL + NEW_DROPS_MANUAL6))

# ==============================================================================
fi
# ADAPTIVE REPORTING MODULE (Daily/Weekly Auto-Detection)
# ==============================================================================
send_report() {
    EMAIL_MOD="/opt/bin/email_sender.mod"
    TIMESTAMP_FILE="/opt/etc/keentool/fw_last_report.ts"
    FORCE_MODE=$1
    
    # 1. Check if Email Module exists
    if [ ! -x "$EMAIL_MOD" ]; then
        echo "Error: Email sender module not found."
        return
    fi

    NOW=$(date +%s)

    # 2. Determine Time Interval
    if [ "$FORCE_MODE" = "weekly" ]; then
        START_TIME=$((NOW - 604800))
        PERIOD_LABEL="Weekly"
        DIFF_HOURS=168
    elif [ "$FORCE_MODE" = "daily" ]; then
        START_TIME=$((NOW - 86400))
        PERIOD_LABEL="Daily"
        DIFF_HOURS=24
    elif [ "$FORCE_MODE" = "monthly" ]; then
        START_TIME=$((NOW - 2592000))
        PERIOD_LABEL="Monthly"
        DIFF_HOURS=720
    else
        # Adaptive logic based on timestamp file
        if [ -f "$TIMESTAMP_FILE" ]; then
            START_TIME=$(cat "$TIMESTAMP_FILE")
        else
            START_TIME=$((NOW - 86400))
        fi

        # Sanity Check: Max 30 days
        if [ $((NOW - START_TIME)) -gt 2592000 ]; then
            START_TIME=$((NOW - 2592000))
        fi

        DIFF_SEC=$((NOW - START_TIME))
        DIFF_HOURS=$((DIFF_SEC / 3600))
        
        if [ "$DIFF_HOURS" -ge 160 ]; then
            PERIOD_LABEL="Weekly"
        elif [ "$DIFF_HOURS" -ge 20 ]; then
            PERIOD_LABEL="Daily"
        else
            PERIOD_LABEL="Periodic (${DIFF_HOURS}h)"
        fi
    fi

    echo " -> Generating $PERIOD_LABEL Report (covering last $DIFF_HOURS hours)..."
    
    # 4. Data Extraction (Querying DB from START_TIME)
    
    # Total Drops count
    DROPS_COUNT=$(sqlite3 "$DB_FILE" "SELECT sum(count) FROM drops WHERE timestamp > $START_TIME;")
    [ -z "$DROPS_COUNT" ] && DROPS_COUNT="0"
    
    # Top 5 Attackers (IPs) - Ordinato correttamente (IP: Count hits)
    TOP_ATTACKERS=$(sqlite3 -separator "|" "$DB_FILE" "SELECT ip, SUM(count) FROM ip_drops WHERE timestamp > $START_TIME GROUP BY ip ORDER BY SUM(count) DESC LIMIT 5;" | awk -F'|' '{print " - " $1 ": " $2 " hits"}')
    [ -z "$TOP_ATTACKERS" ] && TOP_ATTACKERS=" - No attacks recorded"
    
    # Top 5 Targeted Ports
    TOP_PORTS=$(sqlite3 "$DB_FILE" "SELECT i.target_port, sum(d.count) as c FROM ip_drops d JOIN ip_info i ON d.ip=i.ip WHERE d.timestamp > $START_TIME AND i.target_port IS NOT NULL GROUP BY i.target_port ORDER BY c DESC LIMIT 5;" | awk -F'|' '{print " - Port " $1 ": " $2 " hits"}')
    [ -z "$TOP_PORTS" ] && TOP_PORTS=" - No specific ports targeted"

    L_MAIN=${SIZE_FirewallBlock:-0}
    L_TRAP=${SIZE_AutoBan:-0}
    # Calculate total GeoIP subnets (v4 + v6)
    L_GEO=$((${SIZE_GeoBlock:-0} + ${SIZE_GeoBlock6:-0}))
    
    DB_SIZE_H=$(du -h "$DB_FILE" 2>/dev/null | awk '{print $1}')
    [ -z "$DB_SIZE_H" ] && DB_SIZE_H="N/A"
    
    # Format Readable Dates safely
    if date --help 2>&1 | grep -q 'BusyBox'; then
        DATE_FROM=$(date -D %s -d "$START_TIME" +"%d/%m %H:%0M" 2>/dev/null || date +"%d/%m %H:%M" -d "@$START_TIME")
    else
        DATE_FROM=$(date -d "@$START_TIME" "+%d/%m %H:%M")
    fi
    DATE_TO=$(date "+%d/%m %H:%M")
	# Get file modification times for blocklists
	#[ -f "$BACKUP_FILE_V4" ] && TIME_MAIN=$(date -r "$BACKUP_FILE_V4" "+%d-%m-%Y %H:%M:%S" 2>/dev/null) || TIME_MAIN="$UPDATED"
	#[ -f "$BACKUP_FILE_V6" ] && TIME_V6=$(date -r "$BACKUP_FILE_V6" "+%d-%m-%Y %H:%M:%S" 2>/dev/null) || TIME_V6="$UPDATED"
	#[ -f "$BACKUP_GEO_V4" ] && TIME_GEO=$(date -r "$BACKUP_GEO_V4" "+%d-%m-%Y %H:%M:%S" 2>/dev/null) || TIME_GEO="$UPDATED"

    # 5. Construct Email Body (Added GeoIP Blocks line)
    MSG="Firewall $PERIOD_LABEL Report
Period: $DATE_FROM to $DATE_TO
    
🛡️ Total Threats Blocked: $DROPS_COUNT

🏆 Top Attackers:
$TOP_ATTACKERS

🎯 Top Targeted Ports:
$TOP_PORTS

📊 Database Status:
 - Blacklist Size: $L_MAIN IPs
 - AutoBan (Trap): $L_TRAP IPs
 - GeoIP Blocks: $L_GEO Subnets
 - Database Size: $DB_SIZE_H
 
Generated by Keenetic Firewall Stats"

    # 6. Update Timestamp
    mkdir -p "$(dirname "$TIMESTAMP_FILE")"
    echo "$NOW" > "$TIMESTAMP_FILE"

    # 7. Send Email
    "$EMAIL_MOD" "Firewall $PERIOD_LABEL Summary" "$MSG"
}

# Check CLI Arguments
if [ "$1" = "-report" ]; then
    send_report "$2"
    exit 0
fi

# Log summary to Syslog including GeoBlock size
logger -t "$LOG_TAG" "SUMMARY | Drops: +$TOTAL_NEW_DROPS | Trap4: $T4_TOT ($T4_DIF) | Trap6: $T6_TOT ($T6_DIF) | Geo: $SIZE_GeoBlock | Ports: $COUNT_UPDATED | DB: $DB_SIZE_H"
echo "Done."

