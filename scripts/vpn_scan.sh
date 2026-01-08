#!/bin/sh
# VPN LOG ANALYZER -> IPSET (SMART DEDUPLICATION)
# Scans logs for OpenVPN errors.
# Adds IPs to VPNBlock ONLY if not present in the Main FirewallBlock.

# --- PATHS ---
LOG_FILE="/opt/var/log/messages"
BANNED_IPS_FILE="/opt/etc/vpn_banned_ips.txt"
IPSET_VPN="VPNBlock"
IPSET_MAIN="FirewallBlock" # Nome della tua lista principale
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

ip_added_count=0
ip_skipped_count=0

if [ -n "$MALICIOUS_IPS" ]; then
    for IP in $MALICIOUS_IPS; do
        
        # 1. CHECK GLOBAL LIST (Ottimizzazione)
        # Se l'IP è già nella lista principale (FirewallBlock), lo ignoriamo.
        # "ipset test" verifica anche se l'IP rientra in una sottorete (CIDR) bloccata.
        if ipset test "$IPSET_MAIN" "$IP" >/dev/null 2>&1; then
            ip_skipped_count=$((ip_skipped_count + 1))
            continue # Salta al prossimo IP
        fi

        # 2. CHECK LOCAL LIST
        # Se non è nella lista globale, controlliamo se lo abbiamo già bannato localmente.
        if ! grep -qF "$IP" "$BANNED_IPS_FILE"; then
            
            # Add IP to active IPSET (Immediate block)
            ipset add "$IPSET_VPN" "$IP" -exist 2>/dev/null
            
            # Save IP to file for reboot (Persistence)
            echo "$IP" >> "$BANNED_IPS_FILE"
            
            logger -t "${LOG_TAG}" "BANNED: $IP (Not in main list). Added to $IPSET_VPN."
            ip_added_count=$((ip_added_count + 1))
        fi
    done
fi

# Log only if there was activity to reduce noise
if [ "$ip_added_count" -gt 0 ] || [ "$ip_skipped_count" -gt 0 ]; then
    logger -t "${LOG_TAG}" "Scan finished. Added: ${ip_added_count}. Skipped (Already in Main Firewall): ${ip_skipped_count}."
fi

exit 0
