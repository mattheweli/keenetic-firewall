#!/bin/sh

# ==============================================================================
# BLOCKLIST UPDATER (MULTI-SOURCE, ZERO DOWNTIME & DEDUPLICATION)
# Description: Downloads IPs from multiple bad-reputation sources.
#              Merges lists and removes duplicates (deduplication).
#              Updates IPSET using atomic SWAP.
#              Performs deep cleanup of VPN list (removes overlaps).
#              Acts as a fallback loader if internet is down.
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# Configuration
IPSET_NAME="FirewallBlock"
IPSET_TMP_NAME="FirewallBlock_TMP"

# List of URLs to download (Space separated)
# 1. Firehol Level 1 (Aggregated high risk)
# 2. GreenSnow (Brute force attacks)
# 3. CINS Army (Bad reputation IPs)
BLOCKLIST_URLS="
https://iplists.firehol.org/files/firehol_level1.netset
https://blocklist.greensnow.co/greensnow.txt
http://cinsscore.com/list/ci-badguys.txt
"

BACKUP_FILE="/opt/etc/firewall_blocklist.save"
LOG_TAG="Firewall_Update"

# VPN List Config (For Cleanup)
IPSET_VPN="VPNBlock"
VPN_FILE="/opt/etc/vpn_banned_ips.txt"

# 1. Ensure Main Set Exists (Boot requirement)
if ! ipset list -n "$IPSET_NAME" >/dev/null 2>&1; then
    # Create empty set if missing
    ipset create "$IPSET_NAME" hash:net hashsize 16384 maxelem 131072 -exist
    logger -t "$LOG_TAG" "Created initial empty set: $IPSET_NAME"
fi

# 2. Download & Merge Logic
RAW_FILE="/tmp/blocklist_raw.tmp"
: > "$RAW_FILE" # Create/Empty the temp file

DOWNLOAD_COUNT=0
logger -t "$LOG_TAG" "Starting download from multiple sources..."

for URL in $BLOCKLIST_URLS; do
    # Append content to RAW_FILE
    if wget -q -O - "$URL" >> "$RAW_FILE"; then
        logger -t "$LOG_TAG" "Downloaded: $URL"
        DOWNLOAD_COUNT=$((DOWNLOAD_COUNT + 1))
    else
        logger -t "$LOG_TAG" "Failed to download: $URL"
    fi
done

# 3. Logic Branch: UPDATE (Swap) vs RESTORE (Backup)
# Proceed only if we downloaded at least one list and file is not empty
if [ "$DOWNLOAD_COUNT" -gt 0 ] && [ -s "$RAW_FILE" ]; then
    # --- METHOD A: ZERO DOWNTIME UPDATE ---
    
    # Create temp set
    ipset create "$IPSET_TMP_NAME" hash:net hashsize 16384 maxelem 131072 -exist
    ipset flush "$IPSET_TMP_NAME"

    # Load data into temp set WITH DEDUPLICATION
    # grep: removes comments, empty lines, and localhost/broadcast
    # sort -u: SORTS and REMOVES DUPLICATES (Merge)
    cat "$RAW_FILE" \
        | grep -vE "^#|^$|0.0.0.0|127.0.0.1" \
        | sort -u \
        | sed "s/^/add $IPSET_TMP_NAME /" \
        | ipset restore -!

    # Atomic Swap
    if ipset swap "$IPSET_TMP_NAME" "$IPSET_NAME"; then
        # Save new backup
        ipset save "$IPSET_NAME" > "$BACKUP_FILE"
        
        # Count entries (Fast method)
        COUNT=$(ipset list "$IPSET_NAME" | grep -E '^[0-9]' | wc -l)
        logger -t "$LOG_TAG" "Success: Merged list updated via SWAP. Total Unique IPs: $COUNT"
        
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
    # --- METHOD B: RESTORE FROM BACKUP (Offline/Boot Mode) ---
    
    # Check if main set is empty
    CURRENT_COUNT=$(ipset list "$IPSET_NAME" | grep -E '^[0-9]' | wc -l)
    
    if [ "$CURRENT_COUNT" -lt 10 ] && [ -f "$BACKUP_FILE" ]; then
        logger -t "$LOG_TAG" "Internet down? Restoring from local backup..."
        ipset restore -! < "$BACKUP_FILE"
        logger -t "$LOG_TAG" "Backup restored."
    else
        logger -t "$LOG_TAG" "Download failed, but keeping existing memory list."
    fi
    
    # Clean up temp file if it exists but failed
    [ -f "$RAW_FILE" ] && rm "$RAW_FILE"
fi

# ==============================================================================
# 4. DEEP DEDUPLICATION (Clean VPN List)
# ==============================================================================
if ipset list -n "$IPSET_VPN" >/dev/null 2>&1; then
    CLEAN_COUNT=0
    # Iterate through VPN IPs
    for ip in $(ipset list "$IPSET_VPN" | grep -E '^[0-9]'); do
        # "test" returns 0 (true) if the IP is inside ANY subnet of the main list
        if ipset test "$IPSET_NAME" "$ip" >/dev/null 2>&1; then
            # Remove from VPN set (it's redundant)
            ipset del "$IPSET_VPN" "$ip"
            CLEAN_COUNT=$((CLEAN_COUNT + 1))
        fi
    done

    if [ "$CLEAN_COUNT" -gt 0 ]; then
        logger -t "$LOG_TAG" "Optimization: Removed $CLEAN_COUNT redundant IPs from $IPSET_VPN."
        ipset list "$IPSET_VPN" | grep -E '^[0-9]' > "$VPN_FILE"
    fi
fi

# ==============================================================================
# 5. TRIGGER FIREWALL HOOK
# ==============================================================================
if [ -x /opt/etc/ndm/netfilter.d/100-firewall.sh ]; then
    export table=filter
    /opt/etc/ndm/netfilter.d/100-firewall.sh >/dev/null 2>&1
fi
