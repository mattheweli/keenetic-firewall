#!/bin/sh

# ==============================================================================
# KEENETIC FIREWALL HOOK
# Description: Integrates IPSET blocklists with Keenetic NDM Netfilter.
#              Protect INPUT and FORWARD chains.
# Note: NAT is handled natively by Keenetic NDM (use "ip nat ..." in CLI).
# ==============================================================================

IPSET_NAME="FirewallBlock"

# --- SECTION: FILTER TABLE ONLY ---
[ "$table" != "filter" ] && exit 0

# Safety check: if IPSET is missing, do nothing.
ipset list -n "$IPSET_NAME" >/dev/null 2>&1 || exit 0

# --- A. CLEANUP (Avoid Duplicates) ---
iptables -D INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null
iptables -D FORWARD -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null

# Remove old whitelists to ensure correct ordering on reload
iptables -D INPUT -s 10.0.0.0/8 -j ACCEPT 2>/dev/null
iptables -D FORWARD -s 10.0.0.0/8 -j ACCEPT 2>/dev/null
iptables -D FORWARD -i tun+ -j ACCEPT 2>/dev/null
iptables -D INPUT -i tun+ -j ACCEPT 2>/dev/null
iptables -D INPUT -i lo -j ACCEPT 2>/dev/null
iptables -D INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null

# --- B. APPLY RULES (Reverse Order for iptables -I) ---

# === FORWARD CHAIN (LAN/VPN -> Internet) ===

# 4. BLOCK: Drop traffic from Blacklist
iptables -I FORWARD -m set --match-set "$IPSET_NAME" src -j DROP

# 3. WHITELIST: VPN Interfaces (Universal)
# Allows traffic from ANY 'tun' interface (OpenVPN/WireGuard)
iptables -I FORWARD -i tun+ -j ACCEPT

# 2. WHITELIST: Private Networks (LAN)
iptables -I FORWARD -s 10.0.0.0/8 -j ACCEPT

# 1. PRIORITY: Established Connections
iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT


# === INPUT CHAIN (Traffic to Router) ===

# 4. BLOCK: Drop traffic from Blacklist
iptables -I INPUT -m set --match-set "$IPSET_NAME" src -j DROP

# 3. WHITELIST: VPN Interfaces
iptables -I INPUT -i tun+ -j ACCEPT

# 2. WHITELIST: LAN & Localhost
iptables -I INPUT -s 10.0.0.0/8 -j ACCEPT
iptables -I INPUT -i lo -j ACCEPT

# 1. PRIORITY: Established Connections
iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT