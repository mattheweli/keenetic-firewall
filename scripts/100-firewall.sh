#!/bin/sh

# ==============================================================================
# KEENETIC FIREWALL HOOK v2.0.3 (HIGH CAPACITY)
# Description: Manages IPv4 & IPv6 blocking. 
#              Updated maxelem to 524288 to match large blocklists.
# ==============================================================================

[ "$table" != "filter" ] && exit 0

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

IPSET_MAIN="FirewallBlock"
IPSET_MAIN6="FirewallBlock6"
IPSET_VPN="VPNBlock"
VPN_BANNED_FILE="/opt/etc/vpn_banned_ips.txt"

# SETTINGS
MAX_ELEM=524288 # Increased capacity for 500k+ IPs

# --- 1. INITIALIZE IPSETS ---
# IPv4
if ! ipset list -n "$IPSET_MAIN" >/dev/null 2>&1; then
    ipset create "$IPSET_MAIN" hash:net hashsize 16384 maxelem $MAX_ELEM counters -exist
    [ -f "/opt/etc/firewall_blocklist.save" ] && ipset restore -! < "/opt/etc/firewall_blocklist.save"
fi

# IPv6
if ! ipset list -n "$IPSET_MAIN6" >/dev/null 2>&1; then
    ipset create "$IPSET_MAIN6" hash:net family inet6 hashsize 4096 maxelem $MAX_ELEM counters -exist
fi

# VPN (Smaller list is fine, but kept safe)
if ! ipset list -n "$IPSET_VPN" >/dev/null 2>&1; then
    ipset create "$IPSET_VPN" hash:ip hashsize 1024 maxelem 65536 counters -exist
    if [ -f "$VPN_BANNED_FILE" ]; then
        while read -r ip; do [ -n "$ip" ] && ipset add "$IPSET_VPN" "$ip" -exist; done < "$VPN_BANNED_FILE"
    fi
fi

# ==============================================================================
# SECTION A: IPv4 LOGIC (iptables)
# ==============================================================================

# 1. Ensure Chains Exist (Prevents "No target" errors)
if ! iptables -n -L BLOCKLIST_IN >/dev/null 2>&1; then iptables -N BLOCKLIST_IN 2>/dev/null; fi
if ! iptables -n -L BLOCKLIST_FWD >/dev/null 2>&1; then iptables -N BLOCKLIST_FWD 2>/dev/null; fi

# 2. Check if rules are active (Preserve Counters)
if iptables -C BLOCKLIST_IN -m set --match-set "$IPSET_MAIN" src -j DROP 2>/dev/null; then
    # Double check linking
    if ! iptables -C INPUT -j BLOCKLIST_IN 2>/dev/null; then iptables -I INPUT -j BLOCKLIST_IN; fi
    if ! iptables -C FORWARD -j BLOCKLIST_FWD 2>/dev/null; then iptables -I FORWARD -j BLOCKLIST_FWD; fi
else
    # 3. Rules missing or partial: Flush and Rebuild
    iptables -F BLOCKLIST_IN
    iptables -F BLOCKLIST_FWD

    # Whitelists
    iptables -A BLOCKLIST_IN -s 127.0.0.0/8 -j RETURN
    iptables -A BLOCKLIST_IN -i tun+ -j RETURN
    iptables -A BLOCKLIST_FWD -i tun+ -j RETURN
    iptables -A BLOCKLIST_FWD -s 10.0.0.0/8 -j RETURN
    iptables -A BLOCKLIST_IN -m state --state RELATED,ESTABLISHED -j RETURN
    iptables -A BLOCKLIST_FWD -m state --state RELATED,ESTABLISHED -j RETURN

    # Block Rules
    iptables -A BLOCKLIST_IN -m set --match-set "$IPSET_MAIN" src -j DROP
    iptables -A BLOCKLIST_FWD -m set --match-set "$IPSET_MAIN" src -j DROP
    iptables -A BLOCKLIST_IN -m set --match-set "$IPSET_VPN" src -j DROP
    iptables -A BLOCKLIST_FWD -m set --match-set "$IPSET_VPN" src -j DROP

    # Link Chains
    if ! iptables -C INPUT -j BLOCKLIST_IN 2>/dev/null; then iptables -I INPUT -j BLOCKLIST_IN; fi
    if ! iptables -C FORWARD -j BLOCKLIST_FWD 2>/dev/null; then iptables -I FORWARD -j BLOCKLIST_FWD; fi
fi

# ==============================================================================
# SECTION B: IPv6 LOGIC (ip6tables)
# ==============================================================================

# 1. Ensure IPv6 Chains Exist
if ! ip6tables -n -L BLOCKLIST_IN6 >/dev/null 2>&1; then ip6tables -N BLOCKLIST_IN6 2>/dev/null; fi
if ! ip6tables -n -L BLOCKLIST_FWD6 >/dev/null 2>&1; then ip6tables -N BLOCKLIST_FWD6 2>/dev/null; fi

# 2. Check if rules are active
if ip6tables -C BLOCKLIST_IN6 -m set --match-set "$IPSET_MAIN6" src -j DROP 2>/dev/null; then
    if ! ip6tables -C INPUT -j BLOCKLIST_IN6 2>/dev/null; then ip6tables -I INPUT -j BLOCKLIST_IN6; fi
    if ! ip6tables -C FORWARD -j BLOCKLIST_FWD6 2>/dev/null; then ip6tables -I FORWARD -j BLOCKLIST_FWD6; fi
else
    # 3. Rebuild IPv6 Rules
    ip6tables -F BLOCKLIST_IN6
    ip6tables -F BLOCKLIST_FWD6

    # Whitelists
    ip6tables -A BLOCKLIST_IN6 -s ::1/128 -j RETURN
    ip6tables -A BLOCKLIST_IN6 -s fe80::/10 -j RETURN
    ip6tables -A BLOCKLIST_IN6 -i tun+ -j RETURN
    ip6tables -A BLOCKLIST_FWD6 -i tun+ -j RETURN
    ip6tables -A BLOCKLIST_IN6 -m state --state RELATED,ESTABLISHED -j RETURN
    ip6tables -A BLOCKLIST_FWD6 -m state --state RELATED,ESTABLISHED -j RETURN

    # Block Rules
    ip6tables -A BLOCKLIST_IN6 -m set --match-set "$IPSET_MAIN6" src -j DROP
    ip6tables -A BLOCKLIST_FWD6 -m set --match-set "$IPSET_MAIN6" src -j DROP
    
    # Link Chains
    if ! ip6tables -C INPUT -j BLOCKLIST_IN6 2>/dev/null; then ip6tables -I INPUT -j BLOCKLIST_IN6; fi
    if ! ip6tables -C FORWARD -j BLOCKLIST_FWD6 2>/dev/null; then ip6tables -I FORWARD -j BLOCKLIST_FWD6; fi
fi
