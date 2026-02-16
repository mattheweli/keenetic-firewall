#!/bin/sh

# ==============================================================================
# BLOCKLIST UPDATER v2.2.4 (SPLIT SAVE)
# Features: 
# - CONFIG: Reads /opt/etc/firewall.conf for ENABLE_IPV6 and SOURCE URLS.
# - REPORTING: Generates a detailed summary in Syslog and Terminal.
# - LOGIC: Skips Phase 2 (IPv6) completely if disabled.
# - FIX: Saves IPv4 and IPv6 lists to separate files for reliable restore.
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# --- LOAD CONFIG ---
CONF_FILE="/opt/etc/firewall.conf"
if [ -f "$CONF_FILE" ]; then
    . "$CONF_FILE"
else
    # Fallbacks if config missing
    ENABLE_IPV6="true"
    SOURCES_V4="https://iplists.firehol.org/files/firehol_level1.netset https://blocklist.greensnow.co/greensnow.txt"
    SOURCES_V6="https://www.spamhaus.org/drop/dropv6.txt"
fi

# --- INTERNAL VARS ---
IPSET_NAME="FirewallBlock"
IPSET_TMP_NAME="FirewallBlock_TMP"
IPSET_NAME6="FirewallBlock6"
IPSET_TMP_NAME6="FirewallBlock6_TMP"
IPSET_VPN="VPNBlock"

# SETTINGS - CAPACITY
MAX_ELEM_V4=524288
MAX_ELEM_V6=65536

# API Key
# --- SECURE KEY LOADING ---
KEY_FILE="/opt/etc/AbuseIPDB.key"
if [ -s "$KEY_FILE" ]; then
    # Read key and strip any whitespace/newlines
    ABUSEIPDB_KEY=$(cat "$KEY_FILE" | tr -d '[:space:]')
else
    ABUSEIPDB_KEY=""
fi
ABUSE_CACHE="/opt/etc/abuseipdb_v6.cache"
CACHE_DURATION=21600

# Files
DIFF_FILE_V4="/opt/etc/firewall_v4_diff.dat"
DIFF_FILE_V6="/opt/etc/firewall_v6_diff.dat"
DIFF_FILE_VPN="/opt/etc/firewall_vpn_diff.dat"

# [MODIFIED] Separate Backup Files
BACKUP_FILE_V4="/opt/etc/firewall_blocklist.save"
BACKUP_FILE_V6="/opt/etc/firewall_blocklist6.save"

LOG_TAG="Firewall_Update"

# Trackers for Summary
RES_V4="0"; CHG_V4="=0"
RES_V6="0"; CHG_V6="=0"
RES_VPN="0"; CHG_VPN="0"

# Helper: Calc Diff
calc_diff() {
    old_cnt=$1; new_cnt=$2; file=$3
    diff=$((new_cnt - old_cnt))
    if [ "$diff" -ge 0 ]; then echo "+$diff" > "$file"; else echo "$diff" > "$file"; fi
}

# Helper: Optimizer
optimize_list_v4() {
    IN_FILE=$1; OUT_FILE=$2
    if command -v iprange >/dev/null 2>&1; then iprange --optimize "$IN_FILE" > "$OUT_FILE"; return 0; else sort -u "$IN_FILE" > "$OUT_FILE"; return 1; fi
}

# Helper: Turbo Load
load_turbo() {
    SET_NAME=$1; FILE_CLEAN=$2
    LINE_COUNT=$(wc -l < "$FILE_CLEAN")
    echo " -> Loading $LINE_COUNT entries..."
    sed "s/^/add $SET_NAME /" "$FILE_CLEAN" | ipset restore -!
}

echo "=== Firewall Blocklist Updater v2.2.4 ==="
echo "[$(date '+%H:%M:%S')] Starting update. IPv6 Mode: $ENABLE_IPV6"

# --- 1. INIT IPSETS ---
if ! ipset list -n "$IPSET_NAME" >/dev/null 2>&1; then ipset create "$IPSET_NAME" hash:net hashsize 16384 maxelem $MAX_ELEM_V4 counters -exist; fi
if [ "$ENABLE_IPV6" = "true" ]; then
    if ! ipset list -n "$IPSET_NAME6" >/dev/null 2>&1; then ipset create "$IPSET_NAME6" hash:net family inet6 hashsize 4096 maxelem $MAX_ELEM_V6 counters -exist; fi
fi

# --- 2. UPDATE IPv4 ---
echo "------------------------------------------------"
echo "PHASE 1: IPv4 Processing"
CNT_V4_OLD=$(ipset list "$IPSET_NAME" | grep -cE '^[0-9]')
RAW_FILE="/tmp/blocklist_raw.tmp"
: > "$RAW_FILE"

if [ -z "$SOURCES_V4" ]; then echo " ! No IPv4 sources selected."; else
    for URL in $SOURCES_V4; do 
        echo -n " -> Downloading $(basename "$URL")... "
        if wget -q -O - "$URL" >> "$RAW_FILE"; then echo "OK"; else echo "FAIL"; fi
        echo "" >> "$RAW_FILE"
    done
fi

if [ $(wc -l < "$RAW_FILE") -lt 50 ]; then
    echo " ! ERROR: IPv4 Download failed or empty."
    echo "=0" > "$DIFF_FILE_V4"
    RES_V4=$CNT_V4_OLD
else
    ipset destroy "$IPSET_TMP_NAME" 2>/dev/null
    ipset create "$IPSET_TMP_NAME" hash:net hashsize 16384 maxelem $MAX_ELEM_V4 counters -exist
    
    CLEAN_FILE="/tmp/blocklist_clean.tmp"
    FINAL_FILE="/tmp/blocklist_final.tmp"
    
    echo -n " -> Filtering & Optimizing (IPv4)... "
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$RAW_FILE" | awk '{print $1}' | grep -vE "^#|^$|^0.0.0.0|^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^169\.254\." > "$CLEAN_FILE"
    
    if optimize_list_v4 "$CLEAN_FILE" "$FINAL_FILE"; then echo "OK (iprange)"; else echo "OK (sort)"; fi
    
    load_turbo "$IPSET_TMP_NAME" "$FINAL_FILE"
    
    CNT_V4_NEW=$(ipset list "$IPSET_TMP_NAME" | grep -cE '^[0-9]')
    if ipset swap "$IPSET_TMP_NAME" "$IPSET_NAME"; then
        # [MODIFIED] Explicit Save for IPv4
        ipset save "$IPSET_NAME" > "$BACKUP_FILE_V4"
        
        calc_diff "$CNT_V4_OLD" "$CNT_V4_NEW" "$DIFF_FILE_V4"
        CHG_V4=$(cat "$DIFF_FILE_V4")
        RES_V4=$CNT_V4_NEW
        echo " -> Success. Rules: $CNT_V4_NEW ($CHG_V4)"
        ipset destroy "$IPSET_TMP_NAME"
    else
        echo " ! IPv4 Swap Failed."
        RES_V4=$CNT_V4_OLD
        ipset destroy "$IPSET_TMP_NAME"
    fi
    rm -f "$CLEAN_FILE" "$FINAL_FILE"
fi
rm -f "$RAW_FILE"

# --- 3. UPDATE IPv6 ---
if [ "$ENABLE_IPV6" = "true" ]; then
    echo "------------------------------------------------"
    echo "PHASE 2: IPv6 Processing"
    CNT_V6_OLD=$(ipset list "$IPSET_NAME6" | grep -cE '^[0-9a-fA-F:]')
    RAW_FILE6="/tmp/blocklist_v6.tmp"
    : > "$RAW_FILE6"

    if [ -z "$SOURCES_V6" ]; then echo " ! No IPv6 sources selected."; else
        for URL in $SOURCES_V6; do 
            echo -n " -> Downloading $(basename "$URL")... "
            if wget -q -O - "$URL" >> "$RAW_FILE6"; then echo "OK"; else echo "FAIL"; fi
            echo "" >> "$RAW_FILE6"
        done
    fi
    
    if [ -n "$ABUSEIPDB_KEY" ]; then
        echo -n " -> Checking AbuseIPDB API... "
        CACHE_VALID=0
        if [ -f "$ABUSE_CACHE" ]; then
            AGE=$(( $(date +%s) - $(date +%s -r "$ABUSE_CACHE") ))
            if [ "$AGE" -lt "$CACHE_DURATION" ]; then cat "$ABUSE_CACHE" >> "$RAW_FILE6"; CACHE_VALID=1; echo "Cache Valid."; else echo -n "Expired. "; fi
        fi
        if [ "$CACHE_VALID" -eq 0 ]; then
            curl -s -G https://api.abuseipdb.com/api/v2/blacklist \
                -d confidenceMinimum=100 -d ipVersion=6 -d maxAgeInDays=30 \
                -H "Key: $ABUSEIPDB_KEY" -H "Accept: text/plain" -o "$ABUSE_CACHE.tmp"
            if [ -s "$ABUSE_CACHE.tmp" ] && [ $(wc -c < "$ABUSE_CACHE.tmp") -gt 10 ]; then
                mv "$ABUSE_CACHE.tmp" "$ABUSE_CACHE"; cat "$ABUSE_CACHE" >> "$RAW_FILE6"; echo "Downloaded."
            else echo "Failed."; rm -f "$ABUSE_CACHE.tmp"; fi
        fi
        echo "" >> "$RAW_FILE6"
    fi
    
    if [ $(wc -l < "$RAW_FILE6") -lt 10 ]; then
        echo " ! WARNING: IPv6 empty or failed."
        echo "=0" > "$DIFF_FILE_V6"
        RES_V6=$CNT_V6_OLD
    else
        ipset destroy "$IPSET_TMP_NAME6" 2>/dev/null
        ipset create "$IPSET_TMP_NAME6" hash:net family inet6 hashsize 4096 maxelem $MAX_ELEM_V6 counters -exist
        
        CLEAN_FILE6="/tmp/blocklist_clean_v6.tmp"
        echo -n " -> Normalizing & Sorting IPv6... "
        grep -E '^[0-9a-fA-F:]+' "$RAW_FILE6" | awk '{print $1}' | grep ":" | grep -vE "^#|^$|^::1|^fe80:" | sort -u > "$CLEAN_FILE6"
        echo "OK"
        
        load_turbo "$IPSET_TMP_NAME6" "$CLEAN_FILE6"
        CNT_V6_NEW=$(ipset list "$IPSET_TMP_NAME6" | grep -cE '^[0-9a-fA-F:]')

        if ipset swap "$IPSET_TMP_NAME6" "$IPSET_NAME6"; then
            # [MODIFIED] Explicit Save for IPv6
            ipset save "$IPSET_NAME6" > "$BACKUP_FILE_V6"
            
            calc_diff "$CNT_V6_OLD" "$CNT_V6_NEW" "$DIFF_FILE_V6"
            CHG_V6=$(cat "$DIFF_FILE_V6")
            RES_V6=$CNT_V6_NEW
            echo " -> Success. Rules: $CNT_V6_NEW ($CHG_V6)"
            ipset destroy "$IPSET_TMP_NAME6"
        else
            echo " ! IPv6 Swap Failed."
            RES_V6=$CNT_V6_OLD
            ipset destroy "$IPSET_TMP_NAME6"
        fi
        rm -f "$CLEAN_FILE6"
    fi
    rm -f "$RAW_FILE6"
else
    echo "PHASE 2: IPv6 Processing SKIPPED (Disabled in Config)"
    RES_V6="Disabled"
    CHG_V6="-"
fi

# --- 4. OPTIMIZE VPN ---
if ipset list -n "$IPSET_VPN" >/dev/null 2>&1; then
    echo "------------------------------------------------"
    echo "PHASE 3: VPN Optimization"
    VPN_START=$(ipset list "$IPSET_VPN" | grep -cE '^[0-9]')
    CLEAN_COUNT=0
    for ip in $(ipset list "$IPSET_VPN" | grep -E '^[0-9]'); do
        if ipset test "$IPSET_NAME" "$ip" >/dev/null 2>&1; then ipset del "$IPSET_VPN" "$ip" 2>/dev/null; CLEAN_COUNT=$((CLEAN_COUNT + 1)); fi
    done
    VPN_END=$(ipset list "$IPSET_VPN" | grep -cE '^[0-9]')
    calc_diff "$VPN_START" "$VPN_END" "$DIFF_FILE_VPN"
    CHG_VPN=$CLEAN_COUNT
    RES_VPN=$VPN_END
    if [ "$CLEAN_COUNT" -gt 0 ]; then echo " -> Optimized: Removed $CLEAN_COUNT IPs."; else echo " -> No redundancy found."; fi
fi

# --- 5. FINALIZE & LOGGING ---
echo "------------------------------------------------"
echo -n "Reloading Firewall... "
if [ -x /opt/etc/ndm/netfilter.d/100-firewall.sh ]; then export table=filter; /opt/etc/ndm/netfilter.d/100-firewall.sh >/dev/null 2>&1; fi
echo "Done."

# --- SUMMARY REPORT ---
echo ""
echo "================================================"
echo "            BLOCKLIST UPDATE SUMMARY            "
echo "================================================"
echo " IPv4 List: $RES_V4 ($CHG_V4)"
echo " IPv6 List: $RES_V6 ($CHG_V6)"
echo " VPN Optimized: -$CHG_VPN (Total: $RES_VPN)"
echo "================================================"

# Write one-line summary to Syslog
logger -t "$LOG_TAG" "SUMMARY | IPv4: $RES_V4 ($CHG_V4) | IPv6: $RES_V6 ($CHG_V6) | VPN-Opt: -$CHG_VPN"
