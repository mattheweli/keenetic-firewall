#!/bin/sh

# ==============================================================================
# BLOCKLIST UPDATER (ZERO DOWNTIME & BOOT LOADER)
# Description: Updates IPSET using the atomic SWAP method.
#              Acts as a fallback loader if internet is down (Boot safe).
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# Configuration
IPSET_NAME="FirewallBlock"
IPSET_TMP_NAME="FirewallBlock_TMP"
BLOCKLIST_URL="https://iplists.firehol.org/files/firehol_level1.netset"
BACKUP_FILE="/opt/etc/firewall_blocklist.save"
LOG_TAG="Firewall_Update"

# 1. Ensure Main Set Exists (Boot requirement)
if ! ipset list -n "$IPSET_NAME" >/dev/null 2>&1; then
    # Create empty set if missing
    ipset create "$IPSET_NAME" hash:net hashsize 16384 maxelem 131072 -exist
    logger -t "$LOG_TAG" "Created initial empty set: $IPSET_NAME"
fi

# 2. Download Attempt
DOWNLOAD_SUCCESS=0
if wget -q -O /tmp/blocklist_update.tmp "$BLOCKLIST_URL" && [ -s /tmp/blocklist_update.tmp ]; then
    DOWNLOAD_SUCCESS=1
else
    logger -t "$LOG_TAG" "Download failed or file empty."
fi

# 3. Logic Branch: UPDATE (Swap) vs RESTORE (Backup)
if [ "$DOWNLOAD_SUCCESS" -eq 1 ]; then
    # --- METHOD A: ZERO DOWNTIME UPDATE ---
    
    # Create temp set
    ipset create "$IPSET_TMP_NAME" hash:net hashsize 16384 maxelem 131072 -exist
    ipset flush "$IPSET_TMP_NAME"

    # Load data into temp set
    cat /tmp/blocklist_update.tmp \
        | grep -vE "^#|^$|0.0.0.0" \
        | sed "s/^/add $IPSET_TMP_NAME /" \
        | ipset restore -!

    # Atomic Swap
    if ipset swap "$IPSET_TMP_NAME" "$IPSET_NAME"; then
        # Save new backup
        ipset save "$IPSET_NAME" > "$BACKUP_FILE"
        
        # Count entries (Fast method)
        COUNT=$(ipset list "$IPSET_NAME" | grep -E '^[0-9]' | wc -l)
        logger -t "$LOG_TAG" "Success: List updated via SWAP. Entries: $COUNT"
        
        # Cleanup
        ipset destroy "$IPSET_TMP_NAME"
        rm /tmp/blocklist_update.tmp
    else
        logger -t "$LOG_TAG" "Critical Error: SWAP failed."
        ipset destroy "$IPSET_TMP_NAME"
        rm /tmp/blocklist_update.tmp
        exit 1
    fi

else
    # --- METHOD B: RESTORE FROM BACKUP (Offline/Boot Mode) ---
    
    # Check if main set is empty (meaning we are at boot and download failed)
    CURRENT_COUNT=$(ipset list "$IPSET_NAME" | grep -E '^[0-9]' | wc -l)
    
    if [ "$CURRENT_COUNT" -lt 10 ] && [ -f "$BACKUP_FILE" ]; then
        logger -t "$LOG_TAG" "Internet down? Restoring from local backup..."
        ipset restore -! < "$BACKUP_FILE"
        logger -t "$LOG_TAG" "Backup restored."
    else
        logger -t "$LOG_TAG" "Download failed, but keeping existing memory list."
    fi
fi

# 4. Trigger Firewall Hook (Just in case rules were flushed)
if [ -x /opt/etc/ndm/netfilter.d/100-firewall.sh ]; then
    export table=filter
    /opt/etc/ndm/netfilter.d/100-firewall.sh >/dev/null 2>&1
fi
