#!/bin/sh
# VPN LOG ANALYZER -> IPSET
# Integrated Version with Local IPSET

# --- PATHS ---
# Note: Using direct commands, assuming PATH is correct in Entware
LOG_FILE="/opt/var/log/messages"
BANNED_IPS_FILE="/opt/etc/vpn_banned_ips.txt"
IPSET_VPN="VPNBlock"
LOG_TAG="VPN_Blocker"

# Regex to find OpenVPN errors
SEARCH_PATTERN='TLS handshake failed|Bad encapsulated packet length'

# Create file if it doesn't exist
touch "$BANNED_IPS_FILE"

# Check log existence
if [ ! -f "$LOG_FILE" ]; then
    logger -t "${LOG_TAG}" "Error: Log file not found: $LOG_FILE. Exiting."
    exit 1
fi

# Extract unique malicious IPs from log
MALICIOUS_IPS=$(grep -i "openvpn" "$LOG_FILE" | grep -E "$SEARCH_PATTERN" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u)

ip_count=0

if [ -n "$MALICIOUS_IPS" ]; then
    for IP in $MALICIOUS_IPS; do
        # Check if IP is already in text file (persistence)
        if ! grep -qF "$IP" "$BANNED_IPS_FILE"; then
            
            # 1. Add IP to active IPSET (Immediate block)
            # -exist prevents errors if IP is in memory but not in file
            ipset add "$IPSET_VPN" "$IP" -exist 2>/dev/null
            
            # 2. Save IP to file for reboot (Persistence)
            echo "$IP" >> "$BANNED_IPS_FILE"
            
            logger -t "${LOG_TAG}" "New malicious IP detected: $IP. Added to IPSET and File."
            ip_count=$((ip_count + 1))
        fi
        
        # Optional: If IP is in file but somehow not in ipset (e.g., manual flush),
        # uncomment the line below to force memory block
        # ipset add "$IPSET_VPN" "$IP" -exist 2>/dev/null
    done
fi

#if [ "$ip_count" -gt 0 ]; then
    logger -t "${LOG_TAG}" "Check finished. Blocked ${ip_count} NEW IPs."
#fi
# If count is 0, avoid log spam, or use logger if you prefer a heartbeat

exit 0