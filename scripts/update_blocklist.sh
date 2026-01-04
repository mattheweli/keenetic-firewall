#!/bin/sh

# ==============================================================================
# BLOCKLIST UPDATER (ZERO DOWNTIME)
# Description: Updates IPSET using the atomic SWAP method.
#              No security gaps during the update process.
# Usage: Add to crontab (e.g., daily at 04:00)
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# Configuration
IPSET_NAME="FirewallBlock"
IPSET_TMP_NAME="FirewallBlock_TMP"
BLOCKLIST_URL="https://iplists.firehol.org/files/firehol_level1.netset"
BACKUP_FILE="/opt/etc/firewall_blocklist.save"
LOG_TAG="Firewall_Update"

logger -t "$LOG_TAG" "Starting nightly update..."

# 1. Download the list to a temp file
if ! wget -q -O /tmp/blocklist_update.tmp "$BLOCKLIST_URL"; then
    logger -t "$LOG_TAG" "Error: Download failed. Keeping current list."
    exit 1
fi

# 2. Check if the downloaded file is not empty/corrupted
if [ ! -s /tmp/blocklist_update.tmp ]; then
    logger -t "$LOG_TAG" "Error: Downloaded file is empty."
    rm /tmp/blocklist_update.tmp
    exit 1
fi

# 3. Create a TEMPORARY set in memory
# Must match the main set parameters (hash:net, size, etc.)
ipset create "$IPSET_TMP_NAME" hash:net hashsize 16384 maxelem 131072 -exist
ipset flush "$IPSET_TMP_NAME"

# 4. Load the new list into the TEMPORARY set
cat /tmp/blocklist_update.tmp \
    | grep -vE "^#|^$|0.0.0.0" \
    | sed "s/^/add $IPSET_TMP_NAME /" \
    | ipset restore -!

# 5. ATOMIC SWAP
# This switches the sets instantly. The main name now points to the new data.
if ipset swap "$IPSET_TMP_NAME" "$IPSET_NAME"; then
    
    # 6. Save the new (now active) list to disk for next boot
    ipset save "$IPSET_NAME" > "$BACKUP_FILE"
    
    # 7. Count IPs and Log Success
    # Count lines starting with 'add' in the saved file to get unique IP count
    COUNT=$(grep -c "^add" "$BACKUP_FILE")
    logger -t "$LOG_TAG" "Success: Blocklist updated via SWAP method. Active IPs: $COUNT"
    
    # 8. Cleanup
    ipset destroy "$IPSET_TMP_NAME"
    rm /tmp/blocklist_update.tmp
else
    logger -t "$LOG_TAG" "Critical Error: SWAP failed."
    ipset destroy "$IPSET_TMP_NAME"
    rm /tmp/blocklist_update.tmp
    exit 1
fi
