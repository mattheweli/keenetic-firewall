#!/bin/sh

# ==============================================================================
# KEENETIC FIREWALL HOOK v2.6.0 (MODULAR TRAP)
# Description: Dual-Stack Firewall with Auto-Ban, Connlimit & Port Logging.
# Features:
#   - MODULAR: Conditionally loads Connlimit, BruteForce, and AutoBan rules.
#   - PERSISTENCE: Restores AutoBan lists from disk on startup/restart.
#   - WHITELIST: High-priority IPSet for trusted IPs/Subnets.
#   - XT_RECENT: Anti-BruteForce protection (Configurable).
#   - NAS PROTECTION: Applies AutoBan list to Forwarded traffic (Configurable).
#   - DNS SAFETY: Prevents banning DNS/DoT providers.
#   - ULOGD INTEGRATION: Sends logs to userspace (Group 1) instead of tcpdump.
# ==============================================================================

[ "$table" != "filter" ] && exit 0

sleep 2
export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# --- 0. KERNEL MODULES LOADER ---
load_mod() {
    MOD_NAME=$1
    if ! lsmod | grep -q "$MOD_NAME"; then
        MOD_PATH="/lib/modules/4.9-ndm-5/${MOD_NAME}.ko"
        if [ ! -f "$MOD_PATH" ]; then
            MOD_PATH=$(find /lib/modules/$(uname -r) -name "${MOD_NAME}.ko" 2>/dev/null | head -n 1)
        fi
        if [ -f "$MOD_PATH" ]; then
            if [ "$MOD_NAME" = "xt_recent" ]; then
                insmod "$MOD_PATH" ip_list_tot=2000 ip_pkt_list_tot=20 2>/dev/null
            else
                insmod "$MOD_PATH" 2>/dev/null
            fi
        fi
    fi
}

load_mod "xt_recent"
load_mod "xt_multiport"
load_mod "xt_connlimit"
load_mod "xt_NFLOG"
load_mod "nfnetlink_log"

# --- LOAD CONFIGURATION ---
CONF_FILE="/opt/etc/firewall.conf"
if [ -f "$CONF_FILE" ]; then 
    . "$CONF_FILE"
else 
    # Fallback Defaults
    ENABLE_IPV6="true"
    ENABLE_FWD_PROTECTION="false"
    ENABLE_AUTOBAN="true"
    ENABLE_BRUTEFORCE="true"
    ENABLE_CONNLIMIT="true"
    CONNLIMIT_MAX="15"
    TCP_SERVICES="51515 21"
    UDP_SERVICES=""
    TCP_PASSIVE_RANGE=""
    BAN_TIMEOUT="86400"
    BF_SECONDS="60"
    BF_HITCOUNT="5"
fi

# Fallback defaults if config file exists but variable is missing
: ${ENABLE_AUTOBAN:="true"}
: ${ENABLE_BRUTEFORCE:="true"}
: ${ENABLE_CONNLIMIT:="true"}
: ${CONNLIMIT_MAX:="15"}
: ${ENABLE_FWD_PROTECTION:="false"}
: ${BF_SECONDS:="60"}
: ${BF_HITCOUNT:="5"}

# Settings
IPSET_MAIN="FirewallBlock"; IPSET_MAIN6="FirewallBlock6"
IPSET_VPN="VPNBlock"
IPSET_AUTOBAN="AutoBan"; IPSET_AUTOBAN6="AutoBan6"
IPSET_WHITE="FirewallWhite"; IPSET_WHITE6="FirewallWhite6"

VPN_BANNED_FILE="/opt/etc/vpn_banned_ips.txt"
AUTOBAN_SAVE_FILE="/opt/etc/firewall_autoban.save"
MAX_ELEM_V4=524288; MAX_ELEM_V6=65536

# --- HELPER: CONVERT SPACE TO COMMA ---
to_csv() { echo "$1" | tr ' ' ','; }

TCP_PORTS_CSV=$(to_csv "$TCP_SERVICES")
UDP_PORTS_CSV=$(to_csv "$UDP_SERVICES")

# ==============================================================================
# 1. INITIALIZE IPSETS
# ==============================================================================

# IPv4 Whitelist
if ! ipset list -n "$IPSET_WHITE" >/dev/null 2>&1; then
    ipset create "$IPSET_WHITE" hash:net hashsize 1024 maxelem 65536 counters -exist
fi

# IPv4 Static
if ! ipset list -n "$IPSET_MAIN" >/dev/null 2>&1; then
    ipset create "$IPSET_MAIN" hash:net hashsize 16384 maxelem $MAX_ELEM_V4 counters -exist
    [ -f "/opt/etc/firewall_blocklist.save" ] && ipset restore -! < "/opt/etc/firewall_blocklist.save"
fi

# IPv6 Static & Whitelist
if [ "$ENABLE_IPV6" = "true" ]; then
    if ! ipset list -n "$IPSET_MAIN6" >/dev/null 2>&1; then
        ipset create "$IPSET_MAIN6" hash:net family inet6 hashsize 4096 maxelem $MAX_ELEM_V6 counters -exist
    fi
    if ! ipset list -n "$IPSET_WHITE6" >/dev/null 2>&1; then
        ipset create "$IPSET_WHITE6" hash:net family inet6 hashsize 1024 maxelem 65536 counters -exist
    fi
fi

# VPN Block
if ! ipset list -n "$IPSET_VPN" >/dev/null 2>&1; then
    ipset create "$IPSET_VPN" hash:ip hashsize 1024 maxelem 65536 counters -exist
    if [ -f "$VPN_BANNED_FILE" ]; then
        while read -r ip; do [ -n "$ip" ] && ipset add "$IPSET_VPN" "$ip" -exist; done < "$VPN_BANNED_FILE"
    fi
fi

# IPv4 AutoBan (Modified for Persistence)
if ! ipset list -n "$IPSET_AUTOBAN" >/dev/null 2>&1; then
    # 1. Try restoring from file (Preserves timeouts)
    if [ -f "$AUTOBAN_SAVE_FILE" ]; then
        ipset restore -! < "$AUTOBAN_SAVE_FILE" 2>/dev/null
    fi
    
    # 2. If restore failed or set still missing, create fresh
    if ! ipset list -n "$IPSET_AUTOBAN" >/dev/null 2>&1; then
        if ! ipset create "$IPSET_AUTOBAN" hash:net timeout $BAN_TIMEOUT maxelem $MAX_ELEM_V4 counters -exist 2>/dev/null; then
            ipset create "$IPSET_AUTOBAN" hash:ip maxelem $MAX_ELEM_V4 counters -exist
        fi
    fi
fi

# IPv6 AutoBan (Modified for Persistence)
if [ "$ENABLE_IPV6" = "true" ]; then
    if ! ipset list -n "$IPSET_AUTOBAN6" >/dev/null 2>&1; then
        # 1. Try restoring from file (in case not restored above)
        if [ -f "$AUTOBAN_SAVE_FILE" ]; then
            ipset restore -! < "$AUTOBAN_SAVE_FILE" 2>/dev/null
        fi

        # 2. If still missing, create fresh
        if ! ipset list -n "$IPSET_AUTOBAN6" >/dev/null 2>&1; then
            if ! ipset create "$IPSET_AUTOBAN6" hash:net family inet6 timeout $BAN_TIMEOUT maxelem $MAX_ELEM_V6 counters -exist 2>/dev/null; then
                ipset create "$IPSET_AUTOBAN6" hash:net family inet6 maxelem $MAX_ELEM_V6 counters -exist
            fi
        fi
    fi
fi

# ==============================================================================
# SECTION A: IPv4 LOGIC
# ==============================================================================

iptables -N BLOCKLIST_IN 2>/dev/null; iptables -F BLOCKLIST_IN
iptables -N BLOCKLIST_FWD 2>/dev/null; iptables -F BLOCKLIST_FWD
iptables -N SCAN_TRAP 2>/dev/null;     iptables -F SCAN_TRAP

# --- WHITELISTS (Global & Local) ---
iptables -A BLOCKLIST_IN -s 127.0.0.0/8 -j RETURN
iptables -A BLOCKLIST_IN -i tun+ -j RETURN
iptables -A BLOCKLIST_FWD -i tun+ -j RETURN
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
    iptables -A BLOCKLIST_IN -s "$net" -j RETURN
    iptables -A BLOCKLIST_FWD -s "$net" -j RETURN
done
iptables -A BLOCKLIST_IN -m state --state RELATED,ESTABLISHED -j RETURN
iptables -A BLOCKLIST_FWD -m state --state RELATED,ESTABLISHED -j RETURN

# USER WHITELIST (Highest Priority)
if ipset list -n "$IPSET_WHITE" >/dev/null 2>&1; then
    iptables -A BLOCKLIST_IN -m set --match-set "$IPSET_WHITE" src -j RETURN
    iptables -A BLOCKLIST_FWD -m set --match-set "$IPSET_WHITE" src -j RETURN
fi

# --- STATIC BLACKLISTS (INPUT & FORWARD) ---
if ipset list -n "$IPSET_MAIN" >/dev/null 2>&1; then
    iptables -A BLOCKLIST_IN -m set --match-set "$IPSET_MAIN" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP"
    iptables -A BLOCKLIST_IN -m set --match-set "$IPSET_MAIN" src -j DROP
    iptables -A BLOCKLIST_FWD -m set --match-set "$IPSET_MAIN" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP"
    iptables -A BLOCKLIST_FWD -m set --match-set "$IPSET_MAIN" src -j DROP
fi
if ipset list -n "$IPSET_VPN" >/dev/null 2>&1; then
    iptables -A BLOCKLIST_IN -m set --match-set "$IPSET_VPN" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP"
    iptables -A BLOCKLIST_IN -m set --match-set "$IPSET_VPN" src -j DROP
    iptables -A BLOCKLIST_FWD -m set --match-set "$IPSET_VPN" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP"
    iptables -A BLOCKLIST_FWD -m set --match-set "$IPSET_VPN" src -j DROP
fi

# --- DYNAMIC AUTOBAN BLOCK (Conditionally Active) ---
if [ "$ENABLE_AUTOBAN" = "true" ] && ipset list -n "$IPSET_AUTOBAN" >/dev/null 2>&1; then
    iptables -A BLOCKLIST_IN -m set --match-set "$IPSET_AUTOBAN" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP"
    iptables -A BLOCKLIST_IN -m set --match-set "$IPSET_AUTOBAN" src -j DROP
    iptables -A BLOCKLIST_FWD -m set --match-set "$IPSET_AUTOBAN" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP"
    iptables -A BLOCKLIST_FWD -m set --match-set "$IPSET_AUTOBAN" src -j DROP
fi

# --- THE HONEYPOT TRAP (SCAN_TRAP) ---

# 1. Safety & DNS Fix
iptables -A SCAN_TRAP -i br0 -j RETURN
iptables -A SCAN_TRAP -i tun+ -j RETURN
iptables -A SCAN_TRAP -p icmp -j RETURN
iptables -A SCAN_TRAP -d 255.255.255.255 -j RETURN
iptables -A SCAN_TRAP -d 224.0.0.0/4 -j RETURN
iptables -A SCAN_TRAP -p udp -m multiport --sports 53,853 -j RETURN
iptables -A SCAN_TRAP -p tcp -m multiport --sports 53,853 -j RETURN

# Safety: Whitelist check inside Trap (Double Check)
if ipset list -n "$IPSET_WHITE" >/dev/null 2>&1; then
    iptables -A SCAN_TRAP -m set --match-set "$IPSET_WHITE" src -j RETURN
fi

# 2. TCP SERVICES (With Modular Protections)
if [ -n "$TCP_PORTS_CSV" ]; then
    
    # MODULAR: ConnLimit (DDoS)
    if [ "$ENABLE_CONNLIMIT" = "true" ]; then
        iptables -A SCAN_TRAP -p tcp -m multiport --dports "$TCP_PORTS_CSV" \
            -m connlimit --connlimit-above "$CONNLIMIT_MAX" -j DROP
    fi

    # MODULAR: BruteForce Protection
    if [ "$ENABLE_BRUTEFORCE" = "true" ]; then
        # Check if already over threshold -> Ban (conditionally) or Drop
        iptables -A SCAN_TRAP -p tcp -m multiport --dports "$TCP_PORTS_CSV" -m state --state NEW \
            -m recent --update --seconds $BF_SECONDS --hitcount $BF_HITCOUNT --name BF_PROT --rsource \
            -j SET --add-set "$IPSET_AUTOBAN" src 2>/dev/null

        iptables -A SCAN_TRAP -p tcp -m multiport --dports "$TCP_PORTS_CSV" -m state --state NEW \
            -m recent --update --seconds $BF_SECONDS --hitcount $BF_HITCOUNT --name BF_PROT --rsource \
            -j DROP

        # Create new entry for tracking
        iptables -A SCAN_TRAP -p tcp -m multiport --dports "$TCP_PORTS_CSV" -m state --state NEW \
            -m recent --set --name BF_PROT --rsource
    fi

    # Allow if passed checks
    iptables -A SCAN_TRAP -p tcp -m multiport --dports "$TCP_PORTS_CSV" -j RETURN
fi

# 3. Passive Range
if [ -n "$TCP_PASSIVE_RANGE" ]; then
    iptables -A SCAN_TRAP -p tcp --dport "$TCP_PASSIVE_RANGE" -j RETURN
fi

# 4. UDP Services
if [ -n "$UDP_PORTS_CSV" ]; then
    iptables -A SCAN_TRAP -p udp -m multiport --dports "$UDP_PORTS_CSV" -j RETURN
fi

# 5. Anti-Redundancy
if ipset list -n "$IPSET_MAIN" >/dev/null 2>&1; then
    iptables -A SCAN_TRAP -m set --match-set "$IPSET_MAIN" src -j RETURN
fi

# 6. THE HAMMER (Catch-All & Logger)
# Only add to AutoBan if enabled
if [ "$ENABLE_AUTOBAN" = "true" ] && ipset list -n "$IPSET_AUTOBAN" >/dev/null 2>&1; then
    iptables -A SCAN_TRAP -m set ! --match-set "$IPSET_AUTOBAN" src -j SET --add-set "$IPSET_AUTOBAN" src 2>/dev/null
fi

iptables -A SCAN_TRAP -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "TRAP"
iptables -A SCAN_TRAP -j DROP

# --- LINK CHAINS ---
iptables -A BLOCKLIST_IN -j SCAN_TRAP

# CONDITIONAL FWD PROTECTION
if [ "$ENABLE_FWD_PROTECTION" = "true" ]; then
    iptables -A BLOCKLIST_FWD -j SCAN_TRAP
fi

if iptables -C INPUT -j BLOCKLIST_IN 2>/dev/null; then iptables -D INPUT -j BLOCKLIST_IN; fi
iptables -I INPUT -j BLOCKLIST_IN

if iptables -C FORWARD -j BLOCKLIST_FWD 2>/dev/null; then iptables -D FORWARD -j BLOCKLIST_FWD; fi
iptables -I FORWARD -j BLOCKLIST_FWD

# ==============================================================================
# SECTION B: IPv6 LOGIC
# ==============================================================================

if [ "$ENABLE_IPV6" = "true" ]; then
    ip6tables -N BLOCKLIST_IN6 2>/dev/null; ip6tables -F BLOCKLIST_IN6
    ip6tables -N BLOCKLIST_FWD6 2>/dev/null; ip6tables -F BLOCKLIST_FWD6
    ip6tables -N SCAN_TRAP6 2>/dev/null;     ip6tables -F SCAN_TRAP6
    
    # Whitelists
    ip6tables -A BLOCKLIST_IN6 -s ::1/128 -j RETURN
    ip6tables -A BLOCKLIST_IN6 -s fe80::/10 -j RETURN
    ip6tables -A BLOCKLIST_IN6 -i tun+ -j RETURN
    ip6tables -A BLOCKLIST_FWD6 -i tun+ -j RETURN
    ip6tables -A BLOCKLIST_IN6 -m state --state RELATED,ESTABLISHED -j RETURN
    ip6tables -A BLOCKLIST_FWD6 -m state --state RELATED,ESTABLISHED -j RETURN

    # IPv6 USER WHITELIST
    if ipset list -n "$IPSET_WHITE6" >/dev/null 2>&1; then
        ip6tables -A BLOCKLIST_IN6 -m set --match-set "$IPSET_WHITE6" src -j RETURN
        ip6tables -A BLOCKLIST_FWD6 -m set --match-set "$IPSET_WHITE6" src -j RETURN
    fi

    # Static Blacklists
    if ipset list -n "$IPSET_MAIN6" >/dev/null 2>&1; then
        ip6tables -A BLOCKLIST_IN6 -m set --match-set "$IPSET_MAIN6" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP6"
        ip6tables -A BLOCKLIST_IN6 -m set --match-set "$IPSET_MAIN6" src -j DROP
        ip6tables -A BLOCKLIST_FWD6 -m set --match-set "$IPSET_MAIN6" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP6"
        ip6tables -A BLOCKLIST_FWD6 -m set --match-set "$IPSET_MAIN6" src -j DROP
    fi

    # AutoBan (Conditional)
    if [ "$ENABLE_AUTOBAN" = "true" ] && ipset list -n "$IPSET_AUTOBAN6" >/dev/null 2>&1; then
        ip6tables -A BLOCKLIST_IN6 -m set --match-set "$IPSET_AUTOBAN6" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP6"
        ip6tables -A BLOCKLIST_IN6 -m set --match-set "$IPSET_AUTOBAN6" src -j DROP
        ip6tables -A BLOCKLIST_FWD6 -m set --match-set "$IPSET_AUTOBAN6" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP6"
        ip6tables -A BLOCKLIST_FWD6 -m set --match-set "$IPSET_AUTOBAN6" src -j DROP
    fi

    # Trap Logic
    ip6tables -A SCAN_TRAP6 -i br0 -j RETURN
    ip6tables -A SCAN_TRAP6 -i tun+ -j RETURN
    ip6tables -A SCAN_TRAP6 -p icmpv6 -j RETURN
    ip6tables -A SCAN_TRAP6 -d ff00::/8 -j RETURN
    ip6tables -A SCAN_TRAP6 -p udp -m multiport --sports 53,853 -j RETURN
    ip6tables -A SCAN_TRAP6 -p tcp -m multiport --sports 53,853 -j RETURN

    # Trap Whitelist Check
    if ipset list -n "$IPSET_WHITE6" >/dev/null 2>&1; then
        ip6tables -A SCAN_TRAP6 -m set --match-set "$IPSET_WHITE6" src -j RETURN
    fi

    # IPv6 TCP Services
    if [ -n "$TCP_PORTS_CSV" ]; then
        
        # MODULAR: ConnLimit
        if [ "$ENABLE_CONNLIMIT" = "true" ]; then
            ip6tables -A SCAN_TRAP6 -p tcp -m multiport --dports "$TCP_PORTS_CSV" \
                -m connlimit --connlimit-above "$CONNLIMIT_MAX" -j DROP
        fi

        # MODULAR: BruteForce
        if [ "$ENABLE_BRUTEFORCE" = "true" ]; then
            ip6tables -A SCAN_TRAP6 -p tcp -m multiport --dports "$TCP_PORTS_CSV" -m state --state NEW \
                -m recent --update --seconds $BF_SECONDS --hitcount $BF_HITCOUNT --name BF_PROT6 --rsource \
                -j SET --add-set "$IPSET_AUTOBAN6" src 2>/dev/null

            ip6tables -A SCAN_TRAP6 -p tcp -m multiport --dports "$TCP_PORTS_CSV" -m state --state NEW \
                -m recent --update --seconds $BF_SECONDS --hitcount $BF_HITCOUNT --name BF_PROT6 --rsource \
                -j DROP

            ip6tables -A SCAN_TRAP6 -p tcp -m multiport --dports "$TCP_PORTS_CSV" -m state --state NEW \
                -m recent --set --name BF_PROT6 --rsource
        fi

        ip6tables -A SCAN_TRAP6 -p tcp -m multiport --dports "$TCP_PORTS_CSV" -j RETURN
    fi

    if [ -n "$TCP_PASSIVE_RANGE" ]; then ip6tables -A SCAN_TRAP6 -p tcp --dport "$TCP_PASSIVE_RANGE" -j RETURN; fi
    
    if [ -n "$UDP_PORTS_CSV" ]; then
        ip6tables -A SCAN_TRAP6 -p udp -m multiport --dports "$UDP_PORTS_CSV" -j RETURN
    fi

    if ipset list -n "$IPSET_MAIN6" >/dev/null 2>&1; then ip6tables -A SCAN_TRAP6 -m set --match-set "$IPSET_MAIN6" src -j RETURN; fi

    if [ "$ENABLE_AUTOBAN" = "true" ] && ipset list -n "$IPSET_AUTOBAN6" >/dev/null 2>&1; then
        ip6tables -A SCAN_TRAP6 -m set ! --match-set "$IPSET_AUTOBAN6" src -j SET --add-set "$IPSET_AUTOBAN6" src 2>/dev/null
    fi
    
    ip6tables -A SCAN_TRAP6 -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "TRAP6"
    ip6tables -A SCAN_TRAP6 -j DROP

    # Links
    ip6tables -A BLOCKLIST_IN6 -j SCAN_TRAP6
    
    # CONDITIONAL FWD PROTECTION (IPv6)
    if [ "$ENABLE_FWD_PROTECTION" = "true" ]; then
        ip6tables -A BLOCKLIST_FWD6 -j SCAN_TRAP6
    fi
    
    if ip6tables -C INPUT -j BLOCKLIST_IN6 2>/dev/null; then ip6tables -D INPUT -j BLOCKLIST_IN6; fi
    ip6tables -I INPUT -j BLOCKLIST_IN6

    if ip6tables -C FORWARD -j BLOCKLIST_FWD6 2>/dev/null; then ip6tables -D FORWARD -j BLOCKLIST_FWD6; fi
    ip6tables -I FORWARD -j BLOCKLIST_FWD6

else
    ip6tables -D INPUT -j BLOCKLIST_IN6 2>/dev/null
    ip6tables -D FORWARD -j BLOCKLIST_FWD6 2>/dev/null
    ip6tables -F BLOCKLIST_IN6 2>/dev/null; ip6tables -X BLOCKLIST_IN6 2>/dev/null
    ip6tables -F BLOCKLIST_FWD6 2>/dev/null; ip6tables -X BLOCKLIST_FWD6 2>/dev/null
    ip6tables -F SCAN_TRAP6 2>/dev/null; ip6tables -X SCAN_TRAP6 2>/dev/null
fi

# ==============================================================================
# SECTION C: REMOVED (Replaced by ULOGD)
# ==============================================================================
killall tcpdump 2>/dev/null
exit 0
