#!/bin/sh

# ==============================================================================
# BLOCKLIST UPDATER v1.3.0 (Multi-Source with Packet Counters)
# Description: Downloads blocklists and enables packet tracking for stats.
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# Configuration
IPSET_NAME="FirewallBlock"
IPSET_TMP_NAME="FirewallBlock_TMP"
DIFF_FILE="/opt/etc/firewall_main_diff.dat"

# List of URLs
BLOCKLIST_URLS="
https://iplists.firehol.org/files/firehol_level1.netset
https://blocklist.greensnow.co/greensnow.txt
http://cinsscore.com/list/ci-badguys.txt
"

BACKUP_FILE="/opt/etc/firewall_blocklist.save"
LOG_TAG="Firewall_Update"

# VPN List Config
IPSET_VPN="VPNBlock"
VPN_FILE="/opt/etc/vpn_banned_ips.txt"

# 1. Ensure Main Set Exists with COUNTERS enabled
#    If the set exists but without counters, we might need to destroy it manually once,
#    but usually, the swap handles the upgrade.
if ! ipset list -n "$IPSET_NAME" >/dev/null 2>&1; then
    # 'counters' is crucial for statistics
    ipset create "$IPSET_NAME" hash:net hashsize 16384 maxelem 131072 counters -exist
    logger -t "$LOG_TAG" "Created initial set with counters: $IPSET_NAME"
fi

# 2. Download & Merge Logic
RAW_FILE="/tmp/blocklist_raw.tmp"
: > "$RAW_FILE"

DOWNLOAD_COUNT=0
logger -t "$LOG_TAG" "Starting download from 3 sources..."

for URL in $BLOCKLIST_URLS; do
    if wget -q -O - "$URL" >> "$RAW_FILE"; then
        echo "" >> "$RAW_FILE"
        DOWNLOAD_COUNT=$((DOWNLOAD_COUNT + 1))
    else
        logger -t "$LOG_TAG" "Failed to download: $URL"
    fi
done

# 3. Process & Swap
if [ "$DOWNLOAD_COUNT" -gt 0 ]; then
    
    # Create temp set with COUNTERS
    ipset create "$IPSET_TMP_NAME" hash:net hashsize 16384 maxelem 131072 counters -exist
    ipset flush "$IPSET_TMP_NAME"
    
    # Process IPs
    # Note: We filter private ranges to avoid locking ourselves out
    grep -vE "^#|^$|0.0.0.0|127.0.0.1|10.0.0.0|192.168.|172.16." "$RAW_FILE" | sort -u | while read -r IP; do
        # -exist suppresses errors for duplicates
        ipset -A "$IPSET_TMP_NAME" "$IP" -exist
    done
    
    NEW_COUNT=$(ipset list "$IPSET_TMP_NAME" | grep -cE '^[0-9]')
    OLD_COUNT=$(ipset list "$IPSET_NAME" | grep -cE '^[0-9]')
    
    if [ "$NEW_COUNT" -gt 100 ]; then
        DIFF=$((NEW_COUNT - OLD_COUNT))
        if [ "$DIFF" -gt 0 ]; then DIFF_STR="+$DIFF"; 
        elif [ "$DIFF" -lt 0 ]; then DIFF_STR="$DIFF"; 
        else DIFF_STR="="; fi
        
        echo "$DIFF_STR" > "$DIFF_FILE"

        # Swap sets (This puts the new IPs in place)
        # Note: Swapping resets counters to 0 for the new entries. 
        # This gives you "stats since last update".
        ipset swap "$IPSET_TMP_NAME" "$IPSET_NAME"
        
        ipset save "$IPSET_NAME" > "$BACKUP_FILE"
        
        logger -t "$LOG_TAG" "Success. Total IPs: $NEW_COUNT (Change: $DIFF_STR)"
        
        ipset destroy "$IPSET_TMP_NAME"
        rm "$RAW_FILE"
    else
        logger -t "$LOG_TAG" "Critical Error: Downloaded list too small. Keeping old list."
        ipset destroy "$IPSET_TMP_NAME"
        rm "$RAW_FILE"
        exit 1
    fi

else
    # --- RESTORE FROM BACKUP ---
    CURRENT_COUNT=$(ipset list "$IPSET_NAME" | grep -E '^[0-9]' | wc -l)
    
    if [ "$CURRENT_COUNT" -lt 10 ] && [ -f "$BACKUP_FILE" ]; then
        logger -t "$LOG_TAG" "Restoring from local backup..."
        ipset restore -! < "$BACKUP_FILE"
        echo "+0" > "$DIFF_FILE"
        logger -t "$LOG_TAG" "Backup restored."
    else
        logger -t "$LOG_TAG" "Download failed, keeping existing list."
    fi
    [ -f "$RAW_FILE" ] && rm "$RAW_FILE"
fi

# 4. DEEP DEDUPLICATION (VPN)
if ipset list -n "$IPSET_VPN" >/dev/null 2>&1; then
    CLEAN_COUNT=0
    for ip in $(ipset list "$IPSET_VPN" | grep -E '^[0-9]'); do
        if ipset test "$IPSET_NAME" "$ip" >/dev/null 2>&1; then
            ipset del "$IPSET_VPN" "$ip"
            CLEAN_COUNT=$((CLEAN_COUNT + 1))
        fi
    done
    if [ "$CLEAN_COUNT" -gt 0 ]; then
        logger -t "$LOG_TAG" "Deduplication: Removed $CLEAN_COUNT IPs from VPN list."
    fi
fi
