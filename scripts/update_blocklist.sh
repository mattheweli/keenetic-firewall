#!/bin/sh

# ==============================================================================
# BLOCKLIST UPDATER v1.3.2
# Features: Multi-Source, Deduplication, Persistent Stats (Counters), FW Hook
# Change Log: v1.3.2 - Restored Private IP filtering (Exclude LAN ranges)
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

# 1. Ensure Main Set Exists (WITH COUNTERS)
#    Note: Added 'counters' to enable packet tracking for the dashboard
if ! ipset list -n "$IPSET_NAME" >/dev/null 2>&1; then
    ipset create "$IPSET_NAME" hash:net hashsize 16384 maxelem 131072 counters -exist
    logger -t "$LOG_TAG" "Created initial set with counters: $IPSET_NAME"
fi

# 2. Download & Merge Logic
RAW_FILE="/tmp/blocklist_raw.tmp"
: > "$RAW_FILE"

DOWNLOAD_COUNT=0
logger -t "$LOG_TAG" "Starting download from multiple sources..."

for URL in $BLOCKLIST_URLS; do
    if wget -q -O - "$URL" >> "$RAW_FILE"; then
        DOWNLOAD_COUNT=$((DOWNLOAD_COUNT + 1))
    else
        logger -t "$LOG_TAG" "Failed to download: $URL"
    fi
done

# 3. Logic Branch: UPDATE (Swap) vs RESTORE (Backup)
if [ "$DOWNLOAD_COUNT" -gt 0 ] && [ -s "$RAW_FILE" ]; then
    
    # --- METHOD A: ZERO DOWNTIME UPDATE ---

    # A. Get CURRENT count (Before update)
    if ipset list -n "$IPSET_NAME" >/dev/null 2>&1; then
        OLD_COUNT=$(ipset list "$IPSET_NAME" | grep -E '^[0-9]' | wc -l)
    else
        OLD_COUNT=0
    fi

    # B. Prepare New List (WITH COUNTERS)
    #    Important: The temporary set must also have counters enabled
    ipset create "$IPSET_TMP_NAME" hash:net hashsize 16384 maxelem 131072 counters -exist
    ipset flush "$IPSET_TMP_NAME"

    # Load data into temp set WITH DEDUPLICATION
    # Note: RESTORED FILTER to exclude private ranges (LAN)
    # Filtering: comments, empty lines, 0.0.0.0, localhost, and private classes (10.x, 192.168.x, 172.16.x)
    cat "$RAW_FILE" \
        | grep -vE "^#|^$|0.0.0.0|127.0.0.1|10.0.0.0|192.168.|172.16." \
        | sort -u \
        | while read -r IP; do ipset -A "$IPSET_TMP_NAME" "$IP" -exist; done

    # C. Atomic Swap
    if ipset swap "$IPSET_TMP_NAME" "$IPSET_NAME"; then
        # Save new backup
        ipset save "$IPSET_NAME" > "$BACKUP_FILE"
        
        # D. Get NEW count and Calculate DELTA
        NEW_COUNT=$(ipset list "$IPSET_NAME" | grep -E '^[0-9]' | wc -l)
        DELTA=$((NEW_COUNT - OLD_COUNT))
        
        # Format Delta string (add + sign if positive)
        if [ "$DELTA" -ge 0 ]; then DELTA_STR="+$DELTA"; else DELTA_STR="$DELTA"; fi

        # --- SAVE DELTA FOR DASHBOARD ---
        echo "$DELTA_STR" > "$DIFF_FILE"

        logger -t "$LOG_TAG" "Success. Total IPs: $NEW_COUNT (Change: $DELTA_STR vs previous)"
        
        # Cleanup temp
        ipset destroy "$IPSET_TMP_NAME"
        rm "$RAW_FILE"
    else
        logger -t "$LOG_TAG" "Critical Error: SWAP failed."
        ipset destroy "$IPSET_TMP_NAME"
        rm "$RAW_FILE"
        exit 1
    fi

else
    # --- METHOD B: RESTORE FROM BACKUP ---
    # Useful if the router reboots without internet connectivity
    CURRENT_COUNT=$(ipset list "$IPSET_NAME" | grep -E '^[0-9]' | wc -l)
    
    if [ "$CURRENT_COUNT" -lt 10 ] && [ -f "$BACKUP_FILE" ]; then
        logger -t "$LOG_TAG" "Restoring from local backup..."
        ipset restore -! < "$BACKUP_FILE"
        echo "+0" > "$DIFF_FILE" # Restore = No calculable change
        logger -t "$LOG_TAG" "Backup restored."
    else
        logger -t "$LOG_TAG" "Download failed, keeping existing list."
    fi
    [ -f "$RAW_FILE" ] && rm "$RAW_FILE"
fi

# 4. DEEP DEDUPLICATION (VPN)
# Removes IPs from VPN list if they are already in the Main Blocklist
if ipset list -n "$IPSET_VPN" >/dev/null 2>&1; then
    CLEAN_COUNT=0
    for ip in $(ipset list "$IPSET_VPN" | grep -E '^[0-9]'); do
        if ipset test "$IPSET_NAME" "$ip" >/dev/null 2>&1; then
            ipset del "$IPSET_VPN" "$ip"
            CLEAN_COUNT=$((CLEAN_COUNT + 1))
        fi
    done
    
    if [ "$CLEAN_COUNT" -gt 0 ]; then
        ipset list "$IPSET_VPN" | grep -E '^[0-9]' > "$VPN_FILE"
        logger -t "$LOG_TAG" "Cleaned $CLEAN_COUNT duplicate IPs from VPN list."
    fi
fi

# 5. TRIGGER FIREWALL HOOK
# Reloads Keenetic firewall rules (NDM)
if [ -x /opt/etc/ndm/netfilter.d/100-firewall.sh ]; then
    export table=filter
    /opt/etc/ndm/netfilter.d/100-firewall.sh >/dev/null 2>&1
fi
