#!/bin/sh

# ==============================================================================
# BLOCKLIST UPDATER v2.1.11 (SUBNET FIX)
# Features: 
# - FIX: Fixed aggressive filtering that could remove valid IPs containing "10.".
# - STATS: Explicitly counts and logs how many Subnets (CIDR) are loaded.
# - CORE: Turbo Mode (ipset restore) + Auto-repair TMP sets.
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# --- CONFIGURATION ---
IPSET_NAME="FirewallBlock"
IPSET_TMP_NAME="FirewallBlock_TMP"
IPSET_NAME6="FirewallBlock6"
IPSET_TMP_NAME6="FirewallBlock6_TMP"
IPSET_VPN="VPNBlock"

# SETTINGS
MAX_ELEM=524288  # High capacity required for large lists
ABUSEIPDB_KEY="<PUT YOUR KEY HERE>"
ABUSE_CACHE="/opt/etc/abuseipdb_v6.cache"
CACHE_DURATION=21600 # 6 Hours

# Files
DIFF_FILE_V4="/opt/etc/firewall_v4_diff.dat"
DIFF_FILE_V6="/opt/etc/firewall_v6_diff.dat"
DIFF_FILE_VPN="/opt/etc/firewall_vpn_diff.dat"
BACKUP_FILE="/opt/etc/firewall_blocklist.save"
LOG_TAG="Firewall_Update"

# --- SOURCES ---
# IPv4 Sources (Must include at least one CIDR source like firehol_level1)
BLOCKLIST_URLS="
https://iplists.firehol.org/files/firehol_level1.netset
https://blocklist.greensnow.co/greensnow.txt
http://cinsscore.com/list/ci-badguys.txt
https://lists.blocklist.de/lists/all.txt
https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-30d.ipv4
"

# IPv6 Static Sources
BLOCKLIST_URLS_V6="
https://www.spamhaus.org/drop/dropv6.txt
https://lists.blocklist.de/lists/all.txt
"

# Helper function to calculate numeric difference
calc_diff() {
    old_cnt=$1; new_cnt=$2; file=$3
    diff=$((new_cnt - old_cnt))
    if [ "$diff" -ge 0 ]; then echo "+$diff" > "$file"; else echo "$diff" > "$file"; fi
}

# Helper function for fast loading (Turbo Mode)
load_turbo() {
    SET_NAME=$1
    FILE_CLEAN=$2
    
    LINE_COUNT=$(wc -l < "$FILE_CLEAN")
    SUBNET_COUNT=$(grep -c "/" "$FILE_CLEAN")
    echo " -> Loading $LINE_COUNT entries ($SUBNET_COUNT Subnets) into RAM..."
    
    START_TIME=$(date +%s)
    sed "s/^/add $SET_NAME /" "$FILE_CLEAN" | ipset restore -!
    
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME)); [ "$DURATION" -eq 0 ] && DURATION=1
    RATE=$((LINE_COUNT / DURATION))
    echo " -> Done in ${DURATION}s. (~${RATE} IPs/sec)"
    
    # Return subnet count for logging
    return $SUBNET_COUNT
}

echo "=== Firewall Blocklist Updater v2.1.11 ==="
echo "[$(date '+%H:%M:%S')] Starting update process..."
logger -t "$LOG_TAG" "Starting Blocklist Update..."

# --- 1. INIT IPSETS ---
if ! ipset list -n "$IPSET_NAME" >/dev/null 2>&1; then ipset create "$IPSET_NAME" hash:net hashsize 16384 maxelem $MAX_ELEM counters -exist; fi
if ! ipset list -n "$IPSET_NAME6" >/dev/null 2>&1; then ipset create "$IPSET_NAME6" hash:net family inet6 hashsize 4096 maxelem $MAX_ELEM counters -exist; fi

# --- 2. UPDATE IPv4 LIST ---
echo "------------------------------------------------"
echo "PHASE 1: IPv4 Processing"
CNT_V4_OLD=$(ipset list "$IPSET_NAME" | grep -cE '^[0-9]')
RAW_FILE="/tmp/blocklist_raw.tmp"
CLEAN_FILE="/tmp/blocklist_clean.tmp"
: > "$RAW_FILE"

TOTAL_URLS=$(echo "$BLOCKLIST_URLS" | grep -c "http")
CURR=1
for URL in $BLOCKLIST_URLS; do 
    echo -n " [$CURR/$TOTAL_URLS] Downloading $(basename "$URL")... "
    if wget -q -O - "$URL" >> "$RAW_FILE"; then echo "OK"; else echo "FAIL"; fi
    echo "" >> "$RAW_FILE"
    CURR=$((CURR+1))
done

if [ $(wc -l < "$RAW_FILE") -lt 100 ]; then
    echo " ! ERROR: Download failed (File too small)."
    logger -t "$LOG_TAG" "ERROR: IPv4 Download failed."
    echo "=0" > "$DIFF_FILE_V4"
else
    ipset destroy "$IPSET_TMP_NAME" 2>/dev/null
    ipset create "$IPSET_TMP_NAME" hash:net hashsize 16384 maxelem $MAX_ELEM counters -exist
    ipset flush "$IPSET_TMP_NAME"

    echo -n " -> Normalizing & Whitelisting LAN... "
    # FIX v2.1.11: Added anchors (^) to grep -vE to prevent removing valid public IPs containing "10." etc.
    # Included filtering for loopback, private ranges, and APIPA.
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$RAW_FILE" \
        | awk '{print $1}' \
        | grep -vE "^#|^$|^0.0.0.0|^127\.0\.0\.1|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^169\.254\." \
        | sort -u > "$CLEAN_FILE"
    echo "OK"

    load_turbo "$IPSET_TMP_NAME" "$CLEAN_FILE"
    SUBS_V4=$? # Capture return value from load_turbo

    CNT_V4_NEW=$(ipset list "$IPSET_TMP_NAME" | grep -cE '^[0-9]')
    
    if ipset swap "$IPSET_TMP_NAME" "$IPSET_NAME"; then
        ipset save "$IPSET_NAME" > "$BACKUP_FILE"
        calc_diff "$CNT_V4_OLD" "$CNT_V4_NEW" "$DIFF_FILE_V4"
        CHANGE=$(cat "$DIFF_FILE_V4")
        ipset destroy "$IPSET_TMP_NAME"
        echo " -> Swap Success. Rules: $CNT_V4_NEW (Subnets: $SUBS_V4)"
        logger -t "$LOG_TAG" "IPv4 Updated: $CNT_V4_NEW IPs including $SUBS_V4 Subnets (Change: $CHANGE)"
    else
        echo " ! CRITICAL: IPv4 Swap failed."
        logger -t "$LOG_TAG" "CRITICAL: IPv4 Swap failed."
        ipset destroy "$IPSET_TMP_NAME"
    fi
fi
rm -f "$RAW_FILE" "$CLEAN_FILE"

# --- 3. UPDATE IPv6 LIST ---
echo "------------------------------------------------"
echo "PHASE 2: IPv6 Processing"
CNT_V6_OLD=$(ipset list "$IPSET_NAME6" | grep -cE '^[0-9a-fA-F:]')
RAW_FILE6="/tmp/blocklist_v6.tmp"
CLEAN_FILE6="/tmp/blocklist_clean_v6.tmp"
: > "$RAW_FILE6"

TOTAL_URLS_V6=$(echo "$BLOCKLIST_URLS_V6" | grep -c "http")
TOTAL_OPS=$((TOTAL_URLS_V6 + 1))
CURR=1
for URL in $BLOCKLIST_URLS_V6; do 
    echo -n " [$CURR/$TOTAL_OPS] Downloading $(basename "$URL")... "
    if wget -q -O - "$URL" >> "$RAW_FILE6"; then echo "OK"; else echo "FAIL"; fi
    echo "" >> "$RAW_FILE6"
    CURR=$((CURR+1))
done

# Dynamic Source Logic
echo -n " [$CURR/$TOTAL_OPS] Fetching AbuseIPDB (API Priority)... "
CACHE_VALID=0
if [ -f "$ABUSE_CACHE" ]; then
    AGE=$(( $(date +%s) - $(date +%s -r "$ABUSE_CACHE") ))
    if [ "$AGE" -lt "$CACHE_DURATION" ]; then
        echo "Cache Valid (${AGE}s old)."
        cat "$ABUSE_CACHE" >> "$RAW_FILE6"
        CACHE_VALID=1
    else
        echo -n "Cache Expired. "
    fi
fi

API_SUCCESS=0
if [ "$CACHE_VALID" -eq 0 ]; then
    echo -n "Querying API... "
    curl -s -G https://api.abuseipdb.com/api/v2/blacklist \
        -d confidenceMinimum=100 -d ipVersion=6 -d maxAgeInDays=30 \
        -H "Key: $ABUSEIPDB_KEY" -H "Accept: text/plain" -o "$ABUSE_CACHE.tmp"
    
    if [ -s "$ABUSE_CACHE.tmp" ] && [ $(wc -c < "$ABUSE_CACHE.tmp") -gt 10 ]; then
        echo "Success."
        mv "$ABUSE_CACHE.tmp" "$ABUSE_CACHE"
        cat "$ABUSE_CACHE" >> "$RAW_FILE6"
        API_SUCCESS=1
    else
        echo "FAILED. "
        rm -f "$ABUSE_CACHE.tmp"
    fi
fi

if [ "$CACHE_VALID" -eq 0 ] && [ "$API_SUCCESS" -eq 0 ]; then
    echo -n "Trying GitHub Fallback... "
    DATE_TODAY=$(date +%Y-%m-%d)
    DATE_YESTERDAY=$(date -d @$(( $(date +%s) - 86400 )) +%Y-%m-%d)
    BORESTAD_TMP="/tmp/borestad_v6.tmp"
    
    if wget -q -O "$BORESTAD_TMP" "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/db/${DATE_TODAY}/${DATE_TODAY}.ipv6" && [ -s "$BORESTAD_TMP" ]; then
        echo "GitHub (Today) OK."
        cat "$BORESTAD_TMP" >> "$RAW_FILE6"
    elif wget -q -O "$BORESTAD_TMP" "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/db/${DATE_YESTERDAY}/${DATE_YESTERDAY}.ipv6" && [ -s "$BORESTAD_TMP" ]; then
        echo "GitHub (Yesterday) OK."
        cat "$BORESTAD_TMP" >> "$RAW_FILE6"
    else
        echo "ALL FALLBACKS FAILED."
    fi
    rm -f "$BORESTAD_TMP"
fi
echo "" >> "$RAW_FILE6"

if [ $(wc -l < "$RAW_FILE6") -lt 50 ]; then
    echo " ! WARNING: IPv6 Download failed."
    logger -t "$LOG_TAG" "ERROR: IPv6 Download failed."
    echo "=0" > "$DIFF_FILE_V6"
else
    ipset destroy "$IPSET_TMP_NAME6" 2>/dev/null
    ipset create "$IPSET_TMP_NAME6" hash:net family inet6 hashsize 4096 maxelem $MAX_ELEM counters -exist
    ipset flush "$IPSET_TMP_NAME6"

    echo -n " -> Normalizing IPv6... "
    # FIX v2.1.11: Anchored exclusions for IPv6 local addresses
    grep -E '^[0-9a-fA-F:]+' "$RAW_FILE6" \
        | awk '{print $1}' \
        | grep ":" \
        | grep -vE "^#|^$|^::1|^fe80:" \
        | sort -u > "$CLEAN_FILE6"
    echo "OK"

    load_turbo "$IPSET_TMP_NAME6" "$CLEAN_FILE6"
    SUBS_V6=$?

    CNT_V6_NEW=$(ipset list "$IPSET_TMP_NAME6" | grep -cE '^[0-9a-fA-F:]')

    if ipset swap "$IPSET_TMP_NAME6" "$IPSET_NAME6"; then
        calc_diff "$CNT_V6_OLD" "$CNT_V6_NEW" "$DIFF_FILE_V6"
        CHANGE=$(cat "$DIFF_FILE_V6")
        ipset destroy "$IPSET_TMP_NAME6"
        echo " -> Swap Success. Rules: $CNT_V6_NEW (Subnets: $SUBS_V6)"
        logger -t "$LOG_TAG" "IPv6 Updated: $CNT_V6_NEW IPs including $SUBS_V6 Subnets (Change: $CHANGE)"
    else
        echo " ! CRITICAL: IPv6 Swap failed."
        logger -t "$LOG_TAG" "CRITICAL: IPv6 Swap failed."
        ipset destroy "$IPSET_TMP_NAME6"
    fi
fi
rm -f "$RAW_FILE6" "$CLEAN_FILE6"

# --- 4. OPTIMIZE VPN ---
if ipset list -n "$IPSET_VPN" >/dev/null 2>&1; then
    echo "------------------------------------------------"
    echo "PHASE 3: VPN Optimization"
    VPN_START=$(ipset list "$IPSET_VPN" | grep -cE '^[0-9]')
    CLEAN_COUNT=0
    for ip in $(ipset list "$IPSET_VPN" | grep -E '^[0-9]'); do
        if ipset test "$IPSET_NAME" "$ip" >/dev/null 2>&1; then
            ipset del "$IPSET_VPN" "$ip" 2>/dev/null
            CLEAN_COUNT=$((CLEAN_COUNT + 1))
        fi
    done
    VPN_END=$(ipset list "$IPSET_VPN" | grep -cE '^[0-9]')
    calc_diff "$VPN_START" "$VPN_END" "$DIFF_FILE_VPN"
    if [ "$CLEAN_COUNT" -gt 0 ]; then
        echo " -> Optimized: Removed $CLEAN_COUNT redundant IPs."
        logger -t "$LOG_TAG" "VPN Optimization: Removed $CLEAN_COUNT IPs."
    else
        echo " -> No redundancy found."
    fi
fi

# --- 5. RE-APPLY ---
echo "------------------------------------------------"
echo -n "Finalizing (Reloading Firewall)... "
if [ -x /opt/etc/ndm/netfilter.d/100-firewall.sh ]; then export table=filter; /opt/etc/ndm/netfilter.d/100-firewall.sh >/dev/null 2>&1; fi
echo "Done."
echo "[$(date '+%H:%M:%S')] Update completed."
logger -t "$LOG_TAG" "Update completed."
