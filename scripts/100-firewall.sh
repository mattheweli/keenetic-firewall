#!/bin/sh

# ==============================================================================
# KEENETIC FIREWALL HOOK v2.2.0 (ROBUST EDITION)
# Description: Manages IPv4 & IPv6 blocking.
#              - Removed "Smart Check" to fix "No chain/target" errors.
#              - Forces Chain Reconstruction on every NDM event.
#              - Adds delay (sleep 2) to allow NDM table flush to settle.
# ==============================================================================

[ "$table" != "filter" ] && exit 0

# WAIT FOR NDM: Give the router 2s to finish flushing tables before we rebuild
sleep 2

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# --- LOAD CONFIG ---
CONF_FILE="/opt/etc/firewall.conf"
if [ -f "$CONF_FILE" ]; then
    . "$CONF_FILE"
else
    ENABLE_IPV6="true"
fi

IPSET_MAIN="FirewallBlock"
IPSET_MAIN6="FirewallBlock6"
IPSET_VPN="VPNBlock"
VPN_BANNED_FILE="/opt/etc/vpn_banned_ips.txt"

# SETTINGS - CAPACITY
MAX_ELEM_V4=524288
MAX_ELEM_V6=65536

# --- 1. INITIALIZE IPSETS (Create if missing) ---

if ! ipset list -n "$IPSET_MAIN" >/dev/null 2>&1; then
    ipset create "$IPSET_MAIN" hash:net hashsize 16384 maxelem $MAX_ELEM_V4 counters -exist
    [ -f "/opt/etc/firewall_blocklist.save" ] && ipset restore -! < "/opt/etc/firewall_blocklist.save"
fi

if [ "$ENABLE_IPV6" = "true" ]; then
    if ! ipset list -n "$IPSET_MAIN6" >/dev/null 2>&1; then
        ipset create "$IPSET_MAIN6" hash:net family inet6 hashsize 4096 maxelem $MAX_ELEM_V6 counters -exist
    fi
fi

if ! ipset list -n "$IPSET_VPN" >/dev/null 2>&1; then
    ipset create "$IPSET_VPN" hash:ip hashsize 1024 maxelem 65536 counters -exist
    if [ -f "$VPN_BANNED_FILE" ]; then
        while read -r ip; do [ -n "$ip" ] && ipset add "$IPSET_VPN" "$ip" -exist; done < "$VPN_BANNED_FILE"
    fi
fi

# ==============================================================================
# SECTION A: IPv4 LOGIC (Rebuild Always)
# ==============================================================================

# 1. Create Chains (Force creation, ignore error if exists)
iptables -N BLOCKLIST_IN 2>/dev/null
iptables -N BLOCKLIST_FWD 2>/dev/null

# 2. Flush Chains (Now we are sure they exist)
iptables -F BLOCKLIST_IN
iptables -F BLOCKLIST_FWD

# --- WHITELISTS (ON TOP) ---

# Loopback
iptables -A BLOCKLIST_IN -s 127.0.0.0/8 -j RETURN

# VPN Interfaces (Allow authorized VPN traffic)
iptables -A BLOCKLIST_IN -i tun+ -j RETURN
iptables -A BLOCKLIST_FWD -i tun+ -j RETURN

# Private Networks (RFC 1918) & APIPA
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
    iptables -A BLOCKLIST_IN -s "$net" -j RETURN
    iptables -A BLOCKLIST_FWD -s "$net" -j RETURN
done

# Established Connections
iptables -A BLOCKLIST_IN -m state --state RELATED,ESTABLISHED -j RETURN
iptables -A BLOCKLIST_FWD -m state --state RELATED,ESTABLISHED -j RETURN

# --- BLOCK RULES (BOTTOM) ---
# Check if sets exist before adding rules
if ipset list -n "$IPSET_MAIN" >/dev/null 2>&1; then
    iptables -A BLOCKLIST_IN -m set --match-set "$IPSET_MAIN" src -j DROP
    iptables -A BLOCKLIST_FWD -m set --match-set "$IPSET_MAIN" src -j DROP
fi

if ipset list -n "$IPSET_VPN" >/dev/null 2>&1; then
    iptables -A BLOCKLIST_IN -m set --match-set "$IPSET_VPN" src -j DROP
    iptables -A BLOCKLIST_FWD -m set --match-set "$IPSET_VPN" src -j DROP
fi

# 3. Ensure Linking (Hooks)
# Remove old links first to prevent duplicates, then re-add
# We use check (-C) to avoid errors if the link was already removed by NDM
if iptables -C INPUT -j BLOCKLIST_IN 2>/dev/null; then iptables -D INPUT -j BLOCKLIST_IN; fi
iptables -I INPUT -j BLOCKLIST_IN

if iptables -C FORWARD -j BLOCKLIST_FWD 2>/dev/null; then iptables -D FORWARD -j BLOCKLIST_FWD; fi
iptables -I FORWARD -j BLOCKLIST_FWD

# ==============================================================================
# SECTION B: IPv6 LOGIC
# ==============================================================================

if [ "$ENABLE_IPV6" = "true" ]; then
    # 1. Create & Flush
    ip6tables -N BLOCKLIST_IN6 2>/dev/null
    ip6tables -N BLOCKLIST_FWD6 2>/dev/null
    ip6tables -F BLOCKLIST_IN6
    ip6tables -F BLOCKLIST_FWD6

    # 2. Whitelists
    ip6tables -A BLOCKLIST_IN6 -s ::1/128 -j RETURN
    ip6tables -A BLOCKLIST_IN6 -s fe80::/10 -j RETURN
    ip6tables -A BLOCKLIST_IN6 -i tun+ -j RETURN
    ip6tables -A BLOCKLIST_FWD6 -i tun+ -j RETURN
    ip6tables -A BLOCKLIST_IN6 -m state --state RELATED,ESTABLISHED -j RETURN
    ip6tables -A BLOCKLIST_FWD6 -m state --state RELATED,ESTABLISHED -j RETURN

    # 3. Block Rules
    if ipset list -n "$IPSET_MAIN6" >/dev/null 2>&1; then
        ip6tables -A BLOCKLIST_IN6 -m set --match-set "$IPSET_MAIN6" src -j DROP
        ip6tables -A BLOCKLIST_FWD6 -m set --match-set "$IPSET_MAIN6" src -j DROP
    fi
    
    # 4. Linking
    if ip6tables -C INPUT -j BLOCKLIST_IN6 2>/dev/null; then ip6tables -D INPUT -j BLOCKLIST_IN6; fi
    ip6tables -I INPUT -j BLOCKLIST_IN6

    if ip6tables -C FORWARD -j BLOCKLIST_FWD6 2>/dev/null; then ip6tables -D FORWARD -j BLOCKLIST_FWD6; fi
    ip6tables -I FORWARD -j BLOCKLIST_FWD6

else
    # Cleanup IPv6 if disabled
    ip6tables -D INPUT -j BLOCKLIST_IN6 2>/dev/null
    ip6tables -D FORWARD -j BLOCKLIST_FWD6 2>/dev/null
    ip6tables -F BLOCKLIST_IN6 2>/dev/null
    ip6tables -X BLOCKLIST_IN6 2>/dev/null
    ip6tables -F BLOCKLIST_FWD6 2>/dev/null
    ip6tables -X BLOCKLIST_FWD6 2>/dev/null
fi
