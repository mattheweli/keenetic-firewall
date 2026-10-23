#!/opt/bin/bash
# KEENETIC FIREWALL HOOK v3.0.0
# Release: 2026-10-22 | Stable. See CHANGELOG.md for release details.

# ==============================================================================
# KEENETIC FIREWALL HOOK v2.9.3 (MASTER SWITCH & MANUAL BLACKLISTS)
# Description: Dual-Stack Firewall with Auto-Ban, Connlimit & Port Logging.
# Features:
#   - FIX [v2.9.3]: Removed numeric argument from iptables wait flag (-w) to fix "Bad argument '2'" error on v1.4.21.
#   - FIX [v2.9.2]: Corrected Manual Blacklist (BLACKLIST/BLACKLIST6) rule insertion for proper modularity.
#   - FIX [v2.9.2]: Fixed chain jump order (Blacklist before Trap) to ensure correct ULOGD PCAP population.
#   - FIX [v2.9.1]: Resolved "No chain" errors using a safe 'init_chain' function with '-w' (xtables lock wait).
#   - FIX [v2.9.1]: Fixed missing linkage for Manual Blocklists (BLACKLIST/BLACKLIST6) to main firewall chains.
#   - NEW [v2.9.0]: Interactive Manual Blocklists (Blacklist/Blacklist6) via Dashboard.
#   - NEW [v2.9.0]: Instant persistence and restore for Manual Blocklists.
#   - NEW [v2.9.0]: RAM cleanup (flush & destroy) for Manual Blocklists on Switch OFF.
#   - NEW: Restore GeoIP lists from disk if backup files exist.
#   - NEW: Global Kill Switch (ENABLE_FIREWALL) to flush and disable all rules.
#   - NEW: GeoIP Blocking integration (Kernel-level drops for banned countries).
#   - NEW: DDoS Mitigation with Global & Custom Bypass ConnLimits.
#   - NEW: Sub-chain architecture (FW_CHK_CONN, FW_CHK_BRUTE) for granular bypass.
#   - NEW: ConnLimit and BruteForce protections now apply to UDP services.
#   - FIX: load_mod grep mode change.
#   - FIX: IPv6 static list restore.
#   - MODULAR: Conditionally loads Connlimit, BruteForce, and AutoBan rules.
#   - PERSISTENCE: Restores AutoBan lists from disk on startup/restart.
#   - WHITELIST: High-priority IPSet for trusted IPs/Subnets.
#   - XT_RECENT: Anti-BruteForce protection (Configurable).
#   - NAS PROTECTION: Applies AutoBan list to Forwarded traffic (Configurable).
#   - DNS SAFETY: Prevents banning DNS/DoT providers.
#   - ULOGD INTEGRATION: Sends logs to userspace (Group 1) instead of tcpdump.
# ==============================================================================

case "${1:-}" in --disable|--check) ;; *) [ "${table:-}" = filter ] || exit 0;;esac


# Firewall Hook 3.0.0
. "${KT_COMMON:-/opt/lib/keentool/common.sh}" || exit 1
# Wait briefly for the previous hook instead of silently dropping a router event.
initialized=false
for attempt in {1..15};do
    if kt_init firewall-hook;then initialized=true;break;else rc=$?;fi
    [ "$rc" = 75 ] || exit "$rc"
    sleep 1
done
[ "$initialized" = true ] || { kt_log 'Hook still busy after 15 seconds; reapply required';exit 75; }
if [ "${1:-}" = --check ];then /opt/bin/bash "${KT_FW_HEALTH:-/opt/bin/firewall_health}";exit $?;fi

export PATH=${KT_PATH:-/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin}

# --- 0. KERNEL MODULES LOADER (FIXED BROKEN PIPE) ---
load_mod() {
    MOD_NAME=$1
    if ! lsmod | grep "$MOD_NAME" >/dev/null 2>&1; then
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
load_mod "xt_limit"
load_mod "nfnetlink_log"

# --- LOAD CONFIGURATION ---
CONF_FILE="${KT_FW_CONF:-/opt/etc/firewall.conf}"
FW_CONFIG_HASH=$(sha256sum "$CONF_FILE" 2>/dev/null | awk '{print $1}')
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
: ${ENABLE_MANUAL:="true"}
: ${ENABLE_AUTOBAN:="true"}
: ${ENABLE_BRUTEFORCE:="true"}
: ${ENABLE_CONNLIMIT:="true"}
: ${CONNLIMIT_MAX:="15"}
: ${ENABLE_FWD_PROTECTION:="false"}
: ${BF_SECONDS:="60"}
: ${BF_HITCOUNT:="5"}
: ${CONNLIMIT_CUSTOM:="150"}

# Granular Bypass Fallbacks
: ${BYPASS_CONN_TCP:=""}
: ${BYPASS_CONN_UDP:=""}
: ${BYPASS_BRUTE_TCP:=""}
: ${BYPASS_BRUTE_UDP:=""}

# Settings
IPSET_MAIN="FirewallBlock"; IPSET_MAIN6="FirewallBlock6"
IPSET_VPN="VPNBlock"
IPSET_AUTOBAN="AutoBan"; IPSET_AUTOBAN6="AutoBan6"
IPSET_BLACKLIST="Blacklist"
IPSET_BLACKLIST6="Blacklist6"
IPSET_WHITE="FirewallWhite"; IPSET_WHITE6="FirewallWhite6"

VPN_BANNED_FILE="/opt/etc/vpn_banned_ips.txt"
AUTOBAN_SAVE_FILE="/opt/etc/firewall_autoban.save"
BACKUP_BLACKLIST="/opt/etc/Blacklist.backup"
BACKUP_BLACKLIST6="/opt/etc/Blacklist6.backup"
MAX_ELEM_V4=524288; MAX_ELEM_V6=65536

# --- HELPER: CONVERT SPACE TO COMMA (ROBUST) ---
to_csv() { echo "$1" | tr -s ' ' ',' | sed 's/^,//;s/,$//'; }

TCP_PORTS_CSV=$(to_csv "$TCP_SERVICES")
UDP_PORTS_CSV=$(to_csv "$UDP_SERVICES")
BYPASS_CONN_TCP_CSV=$(to_csv "$BYPASS_CONN_TCP")
BYPASS_CONN_UDP_CSV=$(to_csv "$BYPASS_CONN_UDP")
BYPASS_BRUTE_TCP_CSV=$(to_csv "$BYPASS_BRUTE_TCP")
BYPASS_BRUTE_UDP_CSV=$(to_csv "$BYPASS_BRUTE_UDP")

: ${ENABLE_FIREWALL:="true"}
[ "${1:-}" != --disable ] || ENABLE_FIREWALL=false

# Explicit bypass defaults preserve the upstream policy unless changed by the user.
: ${BYPASS_INTERFACES="tun+"}
: ${TRAP_BYPASS_INTERFACES="br0 tun+"}
: ${BYPASS_NETWORKS_V4="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16"}
: ${BYPASS_NETWORKS_V6="::1/128 fe80::/10"}
: ${DNS_BYPASS_PORTS="53 853"}
. "${KT_FW_APPLY:-/opt/lib/keentool/firewall_apply.sh}" || exit 1
fw_stage_begin
# Controlled teardown must remain possible even if an unrelated setting is malformed.
if [ "$ENABLE_FIREWALL" = false ];then fw_apply false false;exit $?;fi
# Validate before touching sets or rules. Shell configuration remains root-owned.
for boolean in ENABLE_FIREWALL ENABLE_IPV6 ENABLE_MANUAL ENABLE_AUTOBAN ENABLE_BRUTEFORCE ENABLE_CONNLIMIT ENABLE_FWD_PROTECTION;do
    [[ "${!boolean:-}" = true || "${!boolean:-}" = false ]] || { kt_log "Invalid boolean: $boolean";exit 1; }
done
for number in CONNLIMIT_MAX CONNLIMIT_CUSTOM BAN_TIMEOUT BF_SECONDS BF_HITCOUNT;do
    [[ "${!number:-}" =~ ^[0-9]+$ ]] && [ "${!number}" -le 2147483647 ] || { kt_log "Invalid number: $number";exit 1; }
done
[ "$CONNLIMIT_MAX" -gt 0 ] && [ "$BF_SECONDS" -gt 0 ] && [ "$BF_HITCOUNT" -gt 0 ] || { kt_log 'Connection/bruteforce thresholds must be positive';exit 1; }
for ports in TCP_SERVICES UDP_SERVICES BYPASS_CONN_TCP BYPASS_CONN_UDP BYPASS_BRUTE_TCP BYPASS_BRUTE_UDP DNS_BYPASS_PORTS;do
    for port in ${!ports};do [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { kt_log "Invalid port in $ports";exit 1; };done
done
[[ "$TCP_PASSIVE_RANGE" = '' || "$TCP_PASSIVE_RANGE" =~ ^[0-9]+:[0-9]+$ ]] || { kt_log 'Invalid passive range';exit 1; }
for list in BYPASS_INTERFACES TRAP_BYPASS_INTERFACES;do
    for iface in ${!list};do [[ "$iface" =~ ^[a-zA-Z0-9_.:+-]+$ ]] || { kt_log "Invalid interface in $list";exit 1; };done
done
for network in $BYPASS_NETWORKS_V4 $BYPASS_NETWORKS_V6;do [[ "$network" =~ ^[a-fA-F0-9.:/]+$ ]] || { kt_log 'Invalid bypass network';exit 1; };done
DNS_BYPASS_CSV=$(to_csv "$DNS_BYPASS_PORTS")

# Once-per-boot restore also handles empty sets created earlier by other startup hooks.
if [ -f /opt/lib/keentool/firewall_state.sh ];then
 . /opt/lib/keentool/firewall_state.sh
 fw_restore_state || { kt_log 'Saved sets restore incomplete; previous filtering retained';exit 1; }
fi

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
    : # State helper owns restoration.
fi

# IPv6 Static & Whitelist
if [ "$ENABLE_IPV6" = "true" ]; then
    if ! ipset list -n "$IPSET_MAIN6" >/dev/null 2>&1; then
        ipset create "$IPSET_MAIN6" hash:net family inet6 hashsize 4096 maxelem $MAX_ELEM_V6 counters -exist
        
        # [FIX] Restore the saved IPv6 set.
        if [ -f "/opt/etc/firewall_blocklist6.save" ]; then
             : # State helper owns restoration.
        fi
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

# GeoIP Block (IPv4 & IPv6)
if ! ipset list -n GeoBlock >/dev/null 2>&1; then
    ipset create GeoBlock hash:net hashsize 1024 maxelem 262144 counters -exist
fi
if [ "$ENABLE_IPV6" = "true" ]; then
    if ! ipset list -n GeoBlock6 >/dev/null 2>&1; then
        ipset create GeoBlock6 hash:net family inet6 hashsize 1024 maxelem 262144 counters -exist
    fi
fi

# [NEW] Restore GeoIP lists from disk if backup files exist
: # GeoIP restoration is once per boot, avoiding repeated full-list imports.
:

# IPv4 AutoBan (Modified for Persistence)
if ! ipset list -n "$IPSET_AUTOBAN" >/dev/null 2>&1; then
    # 1. Try restoring from file (Preserves timeouts)
    if [ -f "$AUTOBAN_SAVE_FILE" ]; then
        : # State helper owns restoration.
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
            : # State helper owns restoration.
        fi

        # 2. If still missing, create fresh
        if ! ipset list -n "$IPSET_AUTOBAN6" >/dev/null 2>&1; then
            if ! ipset create "$IPSET_AUTOBAN6" hash:net family inet6 timeout $BAN_TIMEOUT maxelem $MAX_ELEM_V6 counters -exist 2>/dev/null; then
                ipset create "$IPSET_AUTOBAN6" hash:net family inet6 maxelem $MAX_ELEM_V6 counters -exist
            fi
        fi
    fi
fi

# IPv4 Manual Blacklist (Persistence)
if ! ipset list -n "$IPSET_BLACKLIST" >/dev/null 2>&1; then
    # 1. Try restoring from file
    if [ -f "$BACKUP_BLACKLIST" ]; then
        : # State helper owns restoration.
    fi
    
    # 2. If restore failed or set still missing, create fresh
    if ! ipset list -n "$IPSET_BLACKLIST" >/dev/null 2>&1; then
        ipset create "$IPSET_BLACKLIST" hash:ip maxelem $MAX_ELEM_V4 counters -exist
    fi
fi

# IPv6 Manual Blacklist (Persistence)
if [ "$ENABLE_IPV6" = "true" ]; then
    if ! ipset list -n "$IPSET_BLACKLIST6" >/dev/null 2>&1; then
        # 1. Try restoring from file
        if [ -f "$BACKUP_BLACKLIST6" ]; then
            : # State helper owns restoration.
        fi

        # 2. If still missing, create fresh
        if ! ipset list -n "$IPSET_BLACKLIST6" >/dev/null 2>&1; then
            ipset create "$IPSET_BLACKLIST6" hash:ip family inet6 maxelem $MAX_ELEM_V6 counters -exist
        fi
    fi
fi

# ==============================================================================
# SECTION A: IPv4 LOGIC
# ==============================================================================

# Missing sets must not silently remove a configured protection from the candidate.
required_sets="FirewallWhite FirewallBlock VPNBlock GeoBlock AutoBan Blacklist"
[ "$ENABLE_IPV6" != true ] || required_sets+=" FirewallWhite6 FirewallBlock6 GeoBlock6 AutoBan6 Blacklist6"
for required_set in $required_sets;do
    command ipset list -n "$required_set" >/dev/null 2>&1 || { kt_log "Required set missing: $required_set; previous rules retained";exit 1; }
done
# Limit NFLOG only. The following DROP rules and kernel counters remain unconditional.
: "${FW_LOG_RATE:=2}" "${FW_LOG_BURST:=10}"
[[ "$FW_LOG_RATE" =~ ^[0-9]+$ ]] && [ "$FW_LOG_RATE" -le 1000 ] || { kt_log 'Invalid FW_LOG_RATE';exit 1; }
[[ "$FW_LOG_BURST" =~ ^[0-9]+$ ]] && [ "$FW_LOG_BURST" -ge 1 ] && [ "$FW_LOG_BURST" -le 10000 ] || { kt_log 'Invalid FW_LOG_BURST';exit 1; }
# Dedicated timeout-capable manual sets preserve legacy permanent lists unchanged.
for family in 4 6;do
 [ "$family" = 4 ] || [ "$ENABLE_IPV6" = true ] || continue
 set=KTManualBan;inet=inet;[ "$family" = 4 ] || { set=KTManualBan6;inet=inet6; }
 if ! command ipset list -n "$set" >/dev/null 2>&1;then
  command ipset create "$set" hash:net family "$inet" timeout 0 maxelem 65536 counters || exit 1
 fi
done
fw_policy_stage() {
 local family=$1 i logging=false;shift
 local -a args=("$@")
 for ((i=0;i<${#args[@]};i++));do
  [ "${args[i]}" != NFLOG ] || logging=true
 done
 if [ "$logging" = true ];then
  # Logging must not increment member counters a second time before DROP does.
  for ((i=0;i<${#args[@]};i++));do
   if [ "${args[i]}" = --match-set ];then
    args=("${args[@]:0:i+3}" '!' --update-counters "${args[@]:i+3}");break
   fi
  done
  if [ "$FW_LOG_RATE" -gt 0 ];then
   for ((i=0;i<${#args[@]};i++));do
    if [ "${args[i]}" = -j ] && [ "${args[i+1]:-}" = NFLOG ];then
     args=("${args[@]:0:i}" -m limit --limit "$FW_LOG_RATE/second" --limit-burst "$FW_LOG_BURST" "${args[@]:i}");break
    fi
   done
  fi
 fi
 fw_stage "$family" "${args[@]}"
}
iptables() { fw_policy_stage 4 "$@"; }
ip6tables() { fw_policy_stage 6 "$@"; }
init_chain() {
    $1 -w -N "$2" 2>/dev/null || $1 -w -F "$2" 2>/dev/null
}

init_chain iptables BLOCKLIST_IN
init_chain iptables BLOCKLIST_FWD
init_chain iptables SCAN_TRAP
init_chain iptables BLACKLIST

# Sub-chains for granular checks
init_chain iptables FW_CHK_CONN
init_chain iptables FW_CHK_BRUTE

# --- WHITELISTS (Global & Local) ---
for iface in $BYPASS_INTERFACES;do
    iptables -A BLOCKLIST_IN -i "$iface" -j RETURN
    iptables -A BLOCKLIST_FWD -i "$iface" -j RETURN
done
iptables -A BLOCKLIST_IN -s 127.0.0.0/8 -j RETURN
for net in $BYPASS_NETWORKS_V4; do
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

if [ "$ENABLE_MANUAL" = true ];then
 for chain in BLOCKLIST_IN BLOCKLIST_FWD;do
  iptables -A "$chain" -m set --match-set KTManualBan src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix KT_MANUAL
  iptables -A "$chain" -m set --match-set KTManualBan src -j DROP
 done
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

# GeoIP Blacklist
if ipset list -n GeoBlock >/dev/null 2>&1; then
    iptables -A BLOCKLIST_IN -m set --match-set GeoBlock src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP"
    iptables -A BLOCKLIST_IN -m set --match-set GeoBlock src -j DROP
    iptables -A BLOCKLIST_FWD -m set --match-set GeoBlock src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP"
    iptables -A BLOCKLIST_FWD -m set --match-set GeoBlock src -j DROP
fi

# --- DYNAMIC AUTOBAN BLOCK (Conditionally Active) ---
if [ "$ENABLE_AUTOBAN" = "true" ] && ipset list -n "$IPSET_AUTOBAN" >/dev/null 2>&1; then
    iptables -A BLOCKLIST_IN -m set --match-set "$IPSET_AUTOBAN" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP"
    iptables -A BLOCKLIST_IN -m set --match-set "$IPSET_AUTOBAN" src -j DROP
    iptables -A BLOCKLIST_FWD -m set --match-set "$IPSET_AUTOBAN" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP"
    iptables -A BLOCKLIST_FWD -m set --match-set "$IPSET_AUTOBAN" src -j DROP
fi

# Manual Blacklist IPv4
if [ "$ENABLE_MANUAL" = "true" ] && ipset list -n "$IPSET_BLACKLIST" >/dev/null 2>&1; then
    iptables -w -A BLACKLIST -m set --match-set "$IPSET_BLACKLIST" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP"
    iptables -w -A BLACKLIST -m set --match-set "$IPSET_BLACKLIST" src -j DROP
fi

# --- THE HONEYPOT TRAP (SCAN_TRAP) ---

# 1. Safety & DNS Fix
for iface in $TRAP_BYPASS_INTERFACES;do iptables -A SCAN_TRAP -i "$iface" -j RETURN;done
iptables -A SCAN_TRAP -p icmp -j RETURN
iptables -A SCAN_TRAP -d 255.255.255.255 -j RETURN
iptables -A SCAN_TRAP -d 224.0.0.0/4 -j RETURN
iptables -A SCAN_TRAP -s 127.0.0.0/8 -j DROP
iptables -A SCAN_TRAP -s 224.0.0.0/3 -j DROP
iptables -A SCAN_TRAP -s 255.255.255.255 -j DROP
if [ -n "$DNS_BYPASS_CSV" ];then
    iptables -A SCAN_TRAP -p udp -m multiport --sports "$DNS_BYPASS_CSV" -j RETURN
    iptables -A SCAN_TRAP -p tcp -m multiport --sports "$DNS_BYPASS_CSV" -j RETURN
fi

# Safety: Whitelist check inside Trap (Double Check)
if ipset list -n "$IPSET_WHITE" >/dev/null 2>&1; then
    iptables -A SCAN_TRAP -m set --match-set "$IPSET_WHITE" src -j RETURN
fi

# 2. TCP SERVICES (With Modular Protections)
if [ -n "$TCP_PORTS_CSV" ]; then
    
    # MODULAR: ConnLimit (DDoS)
    if [ "$ENABLE_CONNLIMIT" = "true" ]; then
        iptables -A SCAN_TRAP -p tcp -m multiport --dports "$TCP_PORTS_CSV" -j FW_CHK_CONN
        if [ -n "$BYPASS_CONN_TCP_CSV" ]; then 
            if [ -n "$CONNLIMIT_CUSTOM" ] && [ "$CONNLIMIT_CUSTOM" -gt 0 ]; then
                iptables -A FW_CHK_CONN -p tcp -m multiport --dports "$BYPASS_CONN_TCP_CSV" -m connlimit --connlimit-above "$CONNLIMIT_CUSTOM" -j DROP
            fi
            iptables -A FW_CHK_CONN -p tcp -m multiport --dports "$BYPASS_CONN_TCP_CSV" -j RETURN
        fi
        iptables -A FW_CHK_CONN -p tcp -m connlimit --connlimit-above "$CONNLIMIT_MAX" -j DROP
    fi

    # MODULAR: BruteForce Protection
    if [ "$ENABLE_BRUTEFORCE" = "true" ]; then
        iptables -A SCAN_TRAP -p tcp -m multiport --dports "$TCP_PORTS_CSV" -j FW_CHK_BRUTE
        if [ -n "$BYPASS_BRUTE_TCP_CSV" ]; then 
            iptables -A FW_CHK_BRUTE -p tcp -m multiport --dports "$BYPASS_BRUTE_TCP_CSV" -j RETURN
        fi
        # Check if already over threshold -> Ban (conditionally) or Drop
        if [ "$ENABLE_AUTOBAN" = true ];then iptables -A FW_CHK_BRUTE -p tcp -m state --state NEW -m recent --update --seconds $BF_SECONDS --hitcount $BF_HITCOUNT --name BF_PROT --rsource -j SET --add-set "$IPSET_AUTOBAN" src 2>/dev/null;fi
        iptables -A FW_CHK_BRUTE -p tcp -m state --state NEW -m recent --update --seconds $BF_SECONDS --hitcount $BF_HITCOUNT --name BF_PROT --rsource -j DROP
        # Create new entry for tracking
        iptables -A FW_CHK_BRUTE -p tcp -m state --state NEW -m recent --set --name BF_PROT --rsource
    fi

    # Allow if passed checks
    iptables -A SCAN_TRAP -p tcp -m multiport --dports "$TCP_PORTS_CSV" -j RETURN
fi

# 3. Passive Range
if [ -n "$TCP_PASSIVE_RANGE" ]; then
    iptables -A SCAN_TRAP -p tcp --dport "$TCP_PASSIVE_RANGE" -j RETURN
fi

# 4. UDP Services (With Modular Protections)
if [ -n "$UDP_PORTS_CSV" ]; then
    
    # MODULAR: ConnLimit (DDoS)
    if [ "$ENABLE_CONNLIMIT" = "true" ]; then
        iptables -A SCAN_TRAP -p udp -m multiport --dports "$UDP_PORTS_CSV" -j FW_CHK_CONN
        if [ -n "$BYPASS_CONN_UDP_CSV" ]; then 
            if [ -n "$CONNLIMIT_CUSTOM" ] && [ "$CONNLIMIT_CUSTOM" -gt 0 ]; then
                iptables -A FW_CHK_CONN -p udp -m multiport --dports "$BYPASS_CONN_UDP_CSV" -m connlimit --connlimit-above "$CONNLIMIT_CUSTOM" -j DROP
            fi
            iptables -A FW_CHK_CONN -p udp -m multiport --dports "$BYPASS_CONN_UDP_CSV" -j RETURN
        fi
        iptables -A FW_CHK_CONN -p udp -m connlimit --connlimit-above "$CONNLIMIT_MAX" -j DROP
    fi

    # MODULAR: BruteForce Protection
    if [ "$ENABLE_BRUTEFORCE" = "true" ]; then
        iptables -A SCAN_TRAP -p udp -m multiport --dports "$UDP_PORTS_CSV" -j FW_CHK_BRUTE
        if [ -n "$BYPASS_BRUTE_UDP_CSV" ]; then 
            iptables -A FW_CHK_BRUTE -p udp -m multiport --dports "$BYPASS_BRUTE_UDP_CSV" -j RETURN
        fi
        # Check if already over threshold -> Ban (conditionally) or Drop
        if [ "$ENABLE_AUTOBAN" = true ];then iptables -A FW_CHK_BRUTE -p udp -m state --state NEW -m recent --update --seconds $BF_SECONDS --hitcount $BF_HITCOUNT --name BF_PROT_U --rsource -j SET --add-set "$IPSET_AUTOBAN" src 2>/dev/null;fi
        iptables -A FW_CHK_BRUTE -p udp -m state --state NEW -m recent --update --seconds $BF_SECONDS --hitcount $BF_HITCOUNT --name BF_PROT_U --rsource -j DROP
        # Create new entry for tracking
        iptables -A FW_CHK_BRUTE -p udp -m state --state NEW -m recent --set --name BF_PROT_U --rsource
    fi

    # Allow if passed checks
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
if [ "$ENABLE_MANUAL" = "true" ]; then
    iptables -w -A BLOCKLIST_IN -j BLACKLIST
    iptables -w -A BLOCKLIST_FWD -j BLACKLIST
fi

iptables -w -A BLOCKLIST_IN -j SCAN_TRAP

# CONDITIONAL FWD PROTECTION
if [ "$ENABLE_FWD_PROTECTION" = "true" ]; then
    iptables -w -A BLOCKLIST_FWD -j SCAN_TRAP
fi




# ==============================================================================
# SECTION B: IPv6 LOGIC
# ==============================================================================

if [ "$ENABLE_IPV6" = "true" ]; then
    init_chain ip6tables BLOCKLIST_IN6
    init_chain ip6tables BLOCKLIST_FWD6
    init_chain ip6tables SCAN_TRAP6
    init_chain ip6tables BLACKLIST6
    
    # Sub-chains for granular checks
    init_chain ip6tables FW_CHK_CONN6
    init_chain ip6tables FW_CHK_BRUTE6
    
    # Whitelists
    for net in $BYPASS_NETWORKS_V6;do ip6tables -A BLOCKLIST_IN6 -s "$net" -j RETURN;done
    for iface in $BYPASS_INTERFACES;do
        ip6tables -A BLOCKLIST_IN6 -i "$iface" -j RETURN
        ip6tables -A BLOCKLIST_FWD6 -i "$iface" -j RETURN
    done
    ip6tables -A BLOCKLIST_IN6 -m state --state RELATED,ESTABLISHED -j RETURN
    ip6tables -A BLOCKLIST_FWD6 -m state --state RELATED,ESTABLISHED -j RETURN

    # IPv6 USER WHITELIST
    if ipset list -n "$IPSET_WHITE6" >/dev/null 2>&1; then
        ip6tables -A BLOCKLIST_IN6 -m set --match-set "$IPSET_WHITE6" src -j RETURN
        ip6tables -A BLOCKLIST_FWD6 -m set --match-set "$IPSET_WHITE6" src -j RETURN
    fi

    # Static Blacklists
    if [ "$ENABLE_MANUAL" = true ];then
        for chain in BLOCKLIST_IN6 BLOCKLIST_FWD6;do
            ip6tables -A "$chain" -m set --match-set KTManualBan6 src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix KT_MANUAL6
            ip6tables -A "$chain" -m set --match-set KTManualBan6 src -j DROP
        done
    fi

    if ipset list -n "$IPSET_MAIN6" >/dev/null 2>&1; then
        ip6tables -A BLOCKLIST_IN6 -m set --match-set "$IPSET_MAIN6" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP6"
        ip6tables -A BLOCKLIST_IN6 -m set --match-set "$IPSET_MAIN6" src -j DROP
        ip6tables -A BLOCKLIST_FWD6 -m set --match-set "$IPSET_MAIN6" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP6"
        ip6tables -A BLOCKLIST_FWD6 -m set --match-set "$IPSET_MAIN6" src -j DROP
    fi
	
	# GeoIP Blacklist IPv6
    if ipset list -n GeoBlock6 >/dev/null 2>&1; then
        ip6tables -A BLOCKLIST_IN6 -m set --match-set GeoBlock6 src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP6"
        ip6tables -A BLOCKLIST_IN6 -m set --match-set GeoBlock6 src -j DROP
        ip6tables -A BLOCKLIST_FWD6 -m set --match-set GeoBlock6 src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP6"
        ip6tables -A BLOCKLIST_FWD6 -m set --match-set GeoBlock6 src -j DROP
    fi

    # AutoBan (Conditional)
    if [ "$ENABLE_AUTOBAN" = "true" ] && ipset list -n "$IPSET_AUTOBAN6" >/dev/null 2>&1; then
        ip6tables -A BLOCKLIST_IN6 -m set --match-set "$IPSET_AUTOBAN6" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP6"
        ip6tables -A BLOCKLIST_IN6 -m set --match-set "$IPSET_AUTOBAN6" src -j DROP
        ip6tables -A BLOCKLIST_FWD6 -m set --match-set "$IPSET_AUTOBAN6" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP6"
        ip6tables -A BLOCKLIST_FWD6 -m set --match-set "$IPSET_AUTOBAN6" src -j DROP
    fi
	
	    # Manual Blacklist IPv6
    if [ "$ENABLE_MANUAL" = "true" ] && ipset list -n "$IPSET_BLACKLIST6" >/dev/null 2>&1; then
        ip6tables -w -A BLACKLIST6 -m set --match-set "$IPSET_BLACKLIST6" src -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "FW_DROP6"
        ip6tables -w -A BLACKLIST6 -m set --match-set "$IPSET_BLACKLIST6" src -j DROP
    fi

    # Trap Logic
    for iface in $TRAP_BYPASS_INTERFACES;do ip6tables -A SCAN_TRAP6 -i "$iface" -j RETURN;done
    ip6tables -A SCAN_TRAP6 -p icmpv6 -j RETURN
    ip6tables -A SCAN_TRAP6 -d ff00::/8 -j RETURN
    if [ -n "$DNS_BYPASS_CSV" ];then
        ip6tables -A SCAN_TRAP6 -p udp -m multiport --sports "$DNS_BYPASS_CSV" -j RETURN
        ip6tables -A SCAN_TRAP6 -p tcp -m multiport --sports "$DNS_BYPASS_CSV" -j RETURN
    fi

    # Trap Whitelist Check
    if ipset list -n "$IPSET_WHITE6" >/dev/null 2>&1; then
        ip6tables -A SCAN_TRAP6 -m set --match-set "$IPSET_WHITE6" src -j RETURN
    fi

    # IPv6 TCP Services
    if [ -n "$TCP_PORTS_CSV" ]; then
        
        # MODULAR: ConnLimit
        if [ "$ENABLE_CONNLIMIT" = "true" ]; then
            ip6tables -A SCAN_TRAP6 -p tcp -m multiport --dports "$TCP_PORTS_CSV" -j FW_CHK_CONN6
            if [ -n "$BYPASS_CONN_TCP_CSV" ]; then 
                if [ -n "$CONNLIMIT_CUSTOM" ] && [ "$CONNLIMIT_CUSTOM" -gt 0 ]; then
                    ip6tables -A FW_CHK_CONN6 -p tcp -m multiport --dports "$BYPASS_CONN_TCP_CSV" -m connlimit --connlimit-above "$CONNLIMIT_CUSTOM" -j DROP
                fi
                ip6tables -A FW_CHK_CONN6 -p tcp -m multiport --dports "$BYPASS_CONN_TCP_CSV" -j RETURN
            fi
            ip6tables -A FW_CHK_CONN6 -p tcp -m connlimit --connlimit-above "$CONNLIMIT_MAX" -j DROP
        fi

        # MODULAR: BruteForce
        if [ "$ENABLE_BRUTEFORCE" = "true" ]; then
            ip6tables -A SCAN_TRAP6 -p tcp -m multiport --dports "$TCP_PORTS_CSV" -j FW_CHK_BRUTE6
            if [ -n "$BYPASS_BRUTE_TCP_CSV" ]; then ip6tables -A FW_CHK_BRUTE6 -p tcp -m multiport --dports "$BYPASS_BRUTE_TCP_CSV" -j RETURN; fi
            if [ "$ENABLE_AUTOBAN" = true ];then ip6tables -A FW_CHK_BRUTE6 -p tcp -m state --state NEW -m recent --update --seconds $BF_SECONDS --hitcount $BF_HITCOUNT --name BF_PROT6 --rsource -j SET --add-set "$IPSET_AUTOBAN6" src 2>/dev/null;fi
            ip6tables -A FW_CHK_BRUTE6 -p tcp -m state --state NEW -m recent --update --seconds $BF_SECONDS --hitcount $BF_HITCOUNT --name BF_PROT6 --rsource -j DROP
            ip6tables -A FW_CHK_BRUTE6 -p tcp -m state --state NEW -m recent --set --name BF_PROT6 --rsource
        fi

        ip6tables -A SCAN_TRAP6 -p tcp -m multiport --dports "$TCP_PORTS_CSV" -j RETURN
    fi

    if [ -n "$TCP_PASSIVE_RANGE" ]; then ip6tables -A SCAN_TRAP6 -p tcp --dport "$TCP_PASSIVE_RANGE" -j RETURN; fi
    
    # IPv6 UDP Services
    if [ -n "$UDP_PORTS_CSV" ]; then
        
		# MODULAR: ConnLimit
        if [ "$ENABLE_CONNLIMIT" = "true" ]; then
            ip6tables -A SCAN_TRAP6 -p udp -m multiport --dports "$UDP_PORTS_CSV" -j FW_CHK_CONN6
            if [ -n "$BYPASS_CONN_UDP_CSV" ]; then 
                if [ -n "$CONNLIMIT_CUSTOM" ] && [ "$CONNLIMIT_CUSTOM" -gt 0 ]; then
                    ip6tables -A FW_CHK_CONN6 -p udp -m multiport --dports "$BYPASS_CONN_UDP_CSV" -m connlimit --connlimit-above "$CONNLIMIT_CUSTOM" -j DROP
                fi
                ip6tables -A FW_CHK_CONN6 -p udp -m multiport --dports "$BYPASS_CONN_UDP_CSV" -j RETURN
            fi
            ip6tables -A FW_CHK_CONN6 -p udp -m connlimit --connlimit-above "$CONNLIMIT_MAX" -j DROP
        fi
		
		# MODULAR: BruteForce
        if [ "$ENABLE_BRUTEFORCE" = "true" ]; then
            ip6tables -A SCAN_TRAP6 -p udp -m multiport --dports "$UDP_PORTS_CSV" -j FW_CHK_BRUTE6
            if [ -n "$BYPASS_BRUTE_UDP_CSV" ]; then ip6tables -A FW_CHK_BRUTE6 -p udp -m multiport --dports "$BYPASS_BRUTE_UDP_CSV" -j RETURN; fi
            if [ "$ENABLE_AUTOBAN" = true ];then ip6tables -A FW_CHK_BRUTE6 -p udp -m state --state NEW -m recent --update --seconds $BF_SECONDS --hitcount $BF_HITCOUNT --name BF_PROT6_U --rsource -j SET --add-set "$IPSET_AUTOBAN6" src 2>/dev/null;fi
            ip6tables -A FW_CHK_BRUTE6 -p udp -m state --state NEW -m recent --update --seconds $BF_SECONDS --hitcount $BF_HITCOUNT --name BF_PROT6_U --rsource -j DROP
            ip6tables -A FW_CHK_BRUTE6 -p udp -m state --state NEW -m recent --set --name BF_PROT6_U --rsource
        fi
        ip6tables -A SCAN_TRAP6 -p udp -m multiport --dports "$UDP_PORTS_CSV" -j RETURN
    fi

    if ipset list -n "$IPSET_MAIN6" >/dev/null 2>&1; then ip6tables -A SCAN_TRAP6 -m set --match-set "$IPSET_MAIN6" src -j RETURN; fi

    if [ "$ENABLE_AUTOBAN" = "true" ] && ipset list -n "$IPSET_AUTOBAN6" >/dev/null 2>&1; then
        ip6tables -A SCAN_TRAP6 -m set ! --match-set "$IPSET_AUTOBAN6" src -j SET --add-set "$IPSET_AUTOBAN6" src 2>/dev/null
    fi
    
    ip6tables -A SCAN_TRAP6 -j NFLOG --nflog-group 1 --nflog-range 128 --nflog-prefix "TRAP6"
    ip6tables -A SCAN_TRAP6 -j DROP

            # Links
    if [ "$ENABLE_MANUAL" = "true" ]; then
        ip6tables -w -A BLOCKLIST_IN6 -j BLACKLIST6
        ip6tables -w -A BLOCKLIST_FWD6 -j BLACKLIST6
    fi

    ip6tables -w -A BLOCKLIST_IN6 -j SCAN_TRAP6
    
    # CONDITIONAL FWD PROTECTION (IPv6)
    if [ "$ENABLE_FWD_PROTECTION" = "true" ]; then
        ip6tables -w -A BLOCKLIST_FWD6 -j SCAN_TRAP6
    fi
    


else
    : # Transaction helper removes every owned IPv6 chain, including BLACKLIST6.

fi

# ==============================================================================
# SECTION C: REMOVED (Replaced by ULOGD)
# ==============================================================================
fw_apply "$ENABLE_FIREWALL" "$ENABLE_IPV6"
exit $?

