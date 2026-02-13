#!/bin/sh

# ==============================================================================
# KEENETIC FIREWALL MANAGER v2.3.7 (FWD PROTECTION)
# Changelog:
#   - FWD: Added toggle for Forward Chain Protection (NAS/DMZ).
#   - REPORTER: Added configuration for AbuseIPDB Reporting Cooldown.
#   - UX: Grouped API Key and Cooldown under "AbuseIPDB Settings".
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# --- PATHS ---
SCRIPT_MONITOR="/opt/bin/firewall_monitor"
SCRIPT_UPDATE="/opt/bin/update_blocklist.sh"
SCRIPT_STATS="/opt/bin/firewall_stats.sh"
SCRIPT_VPN="/opt/bin/vpn_scan.sh"
SCRIPT_REPORTER="/opt/bin/abuse_reporter.sh"
SCRIPT_HOOK="/opt/etc/ndm/netfilter.d/100-firewall.sh"
CONF_FILE="/opt/etc/firewall.conf"
WHITELIST_FILE="/opt/etc/firewall_whitelist.txt"
KEY_FILE="/opt/etc/AbuseIPDB.key"

# --- DEFAULTS ---
DEF_IPV6="true"
DEF_FWD_PROT="false" # Default OFF
DEF_BAN_TIME="86400" # 24 Hours
DEF_TCP="447 51515 55422 11872 2121"
DEF_UDP="16257 51515 33252"
DEF_PASSIVE="55536:55541"
DEF_BF_SEC="60"
DEF_BF_HIT="5"
DEF_REP_COOL="604800" # 7 Days

# Default Blocklist URLs
L4_DEFAULTS="https://iplists.firehol.org/files/firehol_level1.netset https://blocklist.greensnow.co/greensnow.txt http://cinsscore.com/list/ci-badguys.txt https://lists.blocklist.de/lists/all.txt https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-30d.ipv4"
L6_DEFAULTS="https://www.spamhaus.org/drop/dropv6.txt https://lists.blocklist.de/lists/all.txt"

# --- TRAP ---
ctrl_c_handler() { return; }
trap ctrl_c_handler INT

# --- COLORS ---
RED='\033[0;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; BLUE='\033[1;34m'; CYAN='\033[1;36m'; WHITE='\033[1;37m'; NC='\033[0m'
BOLD='\033[1m'; DIM='\033[2m'

# --- HELPER: TIME CALCULATOR ---
calculate_seconds() {
    MODE=$1
    # Inviamo i testi descrittivi a stderr (> &2) per vederli a schermo
    echo -e "${YELLOW}--- TIME DURATION CALCULATOR ---${NC}" >&2
    echo -e "${DIM}Leave empty or 0 to skip a unit.${NC}" >&2
    
    M=0; W=0; D=0; H=0; m=0; s=0
    
    if [ "$MODE" = "full" ]; then
        echo -n "  Months:  " >&2; read -r in_M; M=${in_M:-0}
        echo -n "  Weeks:   " >&2; read -r in_W; W=${in_W:-0}
        echo -n "  Days:    " >&2; read -r in_D; D=${in_D:-0}
        echo -n "  Hours:   " >&2; read -r in_H; H=${in_H:-0}
    fi
    
    echo -n "  Minutes: " >&2; read -r in_m; m=${in_m:-0}
    echo -n "  Seconds: " >&2; read -r in_s; s=${in_s:-0}
    
    # Validation
    M=$(echo "$M" | tr -cd '0-9'); [ -z "$M" ] && M=0
    W=$(echo "$W" | tr -cd '0-9'); [ -z "$W" ] && W=0
    D=$(echo "$D" | tr -cd '0-9'); [ -z "$D" ] && D=0
    H=$(echo "$H" | tr -cd '0-9'); [ -z "$H" ] && H=0
    m=$(echo "$m" | tr -cd '0-9'); [ -z "$m" ] && m=0
    s=$(echo "$s" | tr -cd '0-9'); [ -z "$s" ] && s=0
    
    # Calculation
    TOTAL=$(( (M * 2592000) + (W * 604800) + (D * 86400) + (H * 3600) + (m * 60) + s ))
    
    # SOLO il risultato finale va su stdout per essere catturato dalla variabile
    echo "$TOTAL"
}

# --- CONFIG ENGINE ---
load_config() {
    if [ ! -f "$CONF_FILE" ]; then
        echo "ENABLE_IPV6=\"$DEF_IPV6\"" > "$CONF_FILE"
        echo "ENABLE_FWD_PROTECTION=\"$DEF_FWD_PROT\"" >> "$CONF_FILE"
        echo "BAN_TIMEOUT=\"$DEF_BAN_TIME\"" >> "$CONF_FILE"
        echo "TCP_SERVICES=\"$DEF_TCP\"" >> "$CONF_FILE"
        echo "UDP_SERVICES=\"$DEF_UDP\"" >> "$CONF_FILE"
        echo "TCP_PASSIVE_RANGE=\"$DEF_PASSIVE\"" >> "$CONF_FILE"
        echo "BF_SECONDS=\"$DEF_BF_SEC\"" >> "$CONF_FILE"
        echo "BF_HITCOUNT=\"$DEF_BF_HIT\"" >> "$CONF_FILE"
        echo "REPORT_COOLDOWN=\"$DEF_REP_COOL\"" >> "$CONF_FILE"
        echo "SOURCES_V4=\"$L4_DEFAULTS\"" >> "$CONF_FILE"
        echo "SOURCES_V6=\"$L6_DEFAULTS\"" >> "$CONF_FILE"
    fi
    source "$CONF_FILE"
    
    # Defaults / Fallback
    [ -z "$BAN_TIMEOUT" ] && BAN_TIMEOUT="86400"
    [ -z "$SOURCES_V4" ] && SOURCES_V4="$L4_DEFAULTS"
    [ -z "$SOURCES_V6" ] && SOURCES_V6="$L6_DEFAULTS"
    : ${ENABLE_FWD_PROTECTION:="$DEF_FWD_PROT"}
    : ${TCP_SERVICES:="$DEF_TCP"}
    : ${UDP_SERVICES:="$DEF_UDP"}
    : ${TCP_PASSIVE_RANGE:="$DEF_PASSIVE"}
    : ${BF_SECONDS:="$DEF_BF_SEC"}
    : ${BF_HITCOUNT:="$DEF_BF_HIT"}
    : ${REPORT_COOLDOWN:="$DEF_REP_COOL"}
    
    [ ! -f "$WHITELIST_FILE" ] && touch "$WHITELIST_FILE"
}

save_config() {
    echo "ENABLE_IPV6=\"$ENABLE_IPV6\"" > "$CONF_FILE"
    echo "ENABLE_FWD_PROTECTION=\"$ENABLE_FWD_PROTECTION\"" >> "$CONF_FILE"
    echo "BAN_TIMEOUT=\"$BAN_TIMEOUT\"" >> "$CONF_FILE"
    echo "TCP_SERVICES=\"$TCP_SERVICES\"" >> "$CONF_FILE"
    echo "UDP_SERVICES=\"$UDP_SERVICES\"" >> "$CONF_FILE"
    echo "TCP_PASSIVE_RANGE=\"$TCP_PASSIVE_RANGE\"" >> "$CONF_FILE"
    echo "BF_SECONDS=\"$BF_SECONDS\"" >> "$CONF_FILE"
    echo "BF_HITCOUNT=\"$BF_HITCOUNT\"" >> "$CONF_FILE"
    # [NEW] Save Report Cooldown
    echo "REPORT_COOLDOWN=\"$REPORT_COOLDOWN\"" >> "$CONF_FILE"
    echo "SOURCES_V4=\"$SOURCES_V4\"" >> "$CONF_FILE"
    echo "SOURCES_V6=\"$SOURCES_V6\"" >> "$CONF_FILE"
}

# --- MENUS ---
show_header() {
    clear
    echo -e "${CYAN}=================================================${NC}"
    echo -e "${WHITE}      KEENETIC FIREWALL MANAGER v2.3.7      ${NC}"
    echo -e "${CYAN}=================================================${NC}"
}

pause() { echo ""; echo -e "${CYAN}Press [Enter] to continue...${NC}"; read -r; }

# --- WHITELIST MANAGER ---
do_whitelist_menu() {
    while true; do
        show_header
        echo -e "${YELLOW}--- MANAGE WHITELIST (Trust List) ---${NC}"
        echo -e "${DIM}IPs, Subnets, or Domains listed here will bypass ALL blocks.${NC}"
        echo -e "${DIM}Domains are resolved to IPs when you click 'Apply'.${NC}\n"
        
        if [ -s "$WHITELIST_FILE" ]; then
            nl -w2 -s") " "$WHITELIST_FILE"
        else
            echo -e "${DIM}(Whitelist is empty)${NC}"
        fi
        
        echo -e "\n a) Add Entry (IP, CIDR, or Domain)"
        echo -e " r) Remove Entry"
        echo -e " x) ${GREEN}APPLY & RESOLVE${NC} (Load into Firewall)"
        echo -e " 0) Back"
        echo ""
        echo -n "Select option: "
        read -r WOPT
        case $WOPT in
            a)
                echo -e "\nEnter IP (1.2.3.4), Subnet (1.2.3.0/24) or Domain (google.com):"
                read -r NEW_ENTRY
                if [ -n "$NEW_ENTRY" ]; then
                    echo "$NEW_ENTRY" >> "$WHITELIST_FILE"
                    echo -e "${GREEN}Entry added. Remember to APPLY (x).${NC}"
                    sleep 1
                fi
                ;;
            r)
                echo -n "Enter line number to remove: "
                read -r DEL_NUM
                if [ -n "$DEL_NUM" ] && echo "$DEL_NUM" | grep -qE '^[0-9]+$'; then
                    sed -i "${DEL_NUM}d" "$WHITELIST_FILE"
                    echo -e "${RED}Removed.${NC}"
                    sleep 1
                fi
                ;;
            x)
                do_apply_whitelist
                pause
                ;;
            0) return ;;
        esac
    done
}

do_apply_whitelist() {
    echo -e "\n${YELLOW}Applying Whitelist & Resolving Domains...${NC}"
    ipset flush FirewallWhite 2>/dev/null || ipset create FirewallWhite hash:net maxelem 65536
    if [ "$ENABLE_IPV6" = "true" ]; then
        ipset flush FirewallWhite6 2>/dev/null || ipset create FirewallWhite6 hash:net family inet6 maxelem 65536
    fi
    while read -r LINE; do
        [ -z "$LINE" ] && continue
        [[ "$LINE" =~ ^#.* ]] && continue
        if echo "$LINE" | grep -qE '[a-zA-Z]' && ! echo "$LINE" | grep -q ":"; then
            echo -e " -> Resolving Domain: ${CYAN}$LINE${NC}..."
            IPS_V4=$(nslookup "$LINE" 2>/dev/null | awk '/^Address 1: / { print $3 }' | grep -E '^[0-9]')
            if [ -z "$IPS_V4" ]; then IPS_V4=$(nslookup "$LINE" 2>/dev/null | grep "Address:" | grep -v "#53" | awk '{print $2}' | grep -E '^[0-9]'); fi
            for ip in $IPS_V4; do echo "    + IPv4: $ip"; ipset add FirewallWhite "$ip" -exist; done
            if [ "$ENABLE_IPV6" = "true" ]; then
                IPS_V6=$(nslookup -type=AAAA "$LINE" 2>/dev/null | grep "Address:" | grep -v "#53" | awk '{print $3$4}' | grep ":"); 
                for ip in $IPS_V6; do echo "    + IPv6: $ip"; ipset add FirewallWhite6 "$ip" -exist; done
            fi
        else
            if echo "$LINE" | grep -q ":"; then
                if [ "$ENABLE_IPV6" = "true" ]; then echo -e " -> Adding IPv6: ${GREEN}$LINE${NC}"; ipset add FirewallWhite6 "$LINE" -exist; fi
            else
                echo -e " -> Adding IPv4: ${GREEN}$LINE${NC}"; ipset add FirewallWhite "$LINE" -exist
            fi
        fi
    done < "$WHITELIST_FILE"
    echo -e "${GREEN}Whitelist Applied Successfully.${NC}"
}

# --- REPORTER CONFIG (NEW) ---
do_reporter_setup() {
    while true; do
        show_header
        echo -e "${YELLOW}--- ABUSEIPDB SETTINGS ---${NC}"
        
        # KEY STATUS
        if [ -s "$KEY_FILE" ]; then KEY_ST="${GREEN}Configured${NC}"; else KEY_ST="${RED}Missing${NC}"; fi
        
        # COOLDOWN STATUS
        DAYS=$((REPORT_COOLDOWN / 86400)); HOURS=$(( (REPORT_COOLDOWN % 86400) / 3600 ))
        TIME_ST="${CYAN}${REPORT_COOLDOWN}s${NC} (${DAYS}d ${HOURS}h)"

        echo -e " 1) API Key Status:     [$KEY_ST]"
        echo -e " 2) Reporting Cooldown: [$TIME_ST]"
        echo -e "    ${DIM}(Don't report same IP again for this time)${NC}"
        echo -e " 0) Back"
        echo ""
        echo -n "Select option: "
        read -r ROPT
        case $ROPT in
            1)
                echo ""
                echo -n "Enter new AbuseIPDB API Key: "
                read -r NEW_KEY
                if [ -n "$NEW_KEY" ]; then
                    echo "$NEW_KEY" > "$KEY_FILE"
                    chmod 600 "$KEY_FILE"
                    echo -e "${GREEN}Key updated.${NC}"
                    sleep 1
                fi
                ;;
            2)
                echo ""
                echo "Do you want to calculate the duration?"
                echo -e " 1) Yes (Use Calculator)"
                echo -e " 2) No (Enter Total Seconds directly)"
                echo -n "Selection: "
                read -r T_OPT
                NEW_VAL=""
                if [ "$T_OPT" = "1" ]; then
                    NEW_VAL=$(calculate_seconds "full")
                    echo -e "Calculated: ${CYAN}$NEW_VAL seconds${NC}"
                else
                    echo -n "Enter Cooldown in seconds (Default 604800 = 7 days): "
                    read -r IN_VAL
                    NEW_VAL="$IN_VAL"
                fi
                
                if [ -n "$NEW_VAL" ] && echo "$NEW_VAL" | grep -qE '^[0-9]+$'; then
                    REPORT_COOLDOWN="$NEW_VAL"
                    save_config
                    echo -e "${GREEN}Cooldown updated.${NC}"
                    sleep 1
                fi
                ;;
            0) return ;;
        esac
    done
}

# --- PORT EDITOR ---
do_port_editor() {
    while true; do
        show_header
        echo -e "${YELLOW}--- ALLOWED PORTS & SERVICES ---${NC}"
        echo -e "${DIM}Traffic on these ports will NOT trigger the Trap.${NC}"
        echo ""
        echo -e " 1) TCP Ports:         ${GREEN}${TCP_SERVICES:-None}${NC}"
        echo -e " 2) UDP Ports:         ${GREEN}${UDP_SERVICES:-None}${NC}"
        echo -e " 3) TCP Passive Range: ${GREEN}${TCP_PASSIVE_RANGE:-None}${NC}"
        echo -e " 0) Back"
        echo ""
        echo -n "Select option: "
        read -r POPT
        case $POPT in
            1) 
                echo -e "\nEnter TCP ports separated by SPACE (e.g. 22 80 443):"
                read -r NEW_TCP
                if [ -n "$NEW_TCP" ]; then TCP_SERVICES="$NEW_TCP"; save_config; echo -e "${GREEN}Saved.${NC}"; fi
                ;;
            2) 
                echo -e "\nEnter UDP ports separated by SPACE (e.g. 1194 51820):"
                read -r NEW_UDP
                if [ -n "$NEW_UDP" ]; then UDP_SERVICES="$NEW_UDP"; save_config; echo -e "${GREEN}Saved.${NC}"; fi
                ;;
            3)
                echo -e "\nEnter Passive Port Range (e.g. 50000:50100):"
                read -r NEW_RNG
                if [ -n "$NEW_RNG" ]; then TCP_PASSIVE_RANGE="$NEW_RNG"; save_config; echo -e "${GREEN}Saved.${NC}"; fi
                ;;
            0) return ;;
        esac
    done
}

# --- BRUTE FORCE EDITOR ---
do_bf_setup() {
    show_header
    echo -e "${YELLOW}--- BRUTE-FORCE SENSITIVITY ---${NC}"
    echo -e "${DIM}Ban IP if X hits occur within Y seconds on the SAME port.${NC}"
    echo ""
    echo -e "Current: ${GREEN}${BF_HITCOUNT}${NC} hits in ${CYAN}${BF_SECONDS}s${NC}"
    echo ""
    echo "Do you want to calculate the duration?"
    echo -e " 1) Yes (Use Calculator)"
    echo -e " 2) No (Enter Total Seconds directly)"
    echo -n "Selection: "
    read -r BF_OPT

    NEW_SEC=""
    if [ "$BF_OPT" = "1" ]; then
        NEW_SEC=$(calculate_seconds "short")
        echo -e "Calculated: ${CYAN}$NEW_SEC seconds${NC}"
    else
        echo -n "Enter Time Window in seconds (Default 60): "
        read -r IN_SEC
        NEW_SEC="$IN_SEC"
    fi
    
    [ -z "$NEW_SEC" ] && NEW_SEC="$BF_SECONDS"

    echo -n "Enter Max Hit Count (Default 5): "
    read -r NEW_HIT
    [ -z "$NEW_HIT" ] && NEW_HIT="$BF_HITCOUNT"

    if echo "$NEW_SEC" | grep -qE '^[0-9]+$' && echo "$NEW_HIT" | grep -qE '^[0-9]+$'; then
        if [ "$NEW_SEC" -gt 3600 ]; then
            echo -e "${RED}WARNING: Long durations for Bruteforce consume RAM.${NC}"
            echo -n "Are you sure? (y/n): "; read -r CONFIRM
            if [ "$CONFIRM" != "y" ]; then return; fi
        fi
        BF_SECONDS="$NEW_SEC"
        BF_HITCOUNT="$NEW_HIT"
        save_config
        echo -e "${GREEN}Settings updated.${NC}"
    else
        echo -e "${RED}Invalid input. Numbers only.${NC}"
    fi
    pause
}

# --- TIMEOUT SETUP ---
do_timeout_setup() {
    show_header
    echo -e "${YELLOW}--- AUTO-BAN TIMEOUT ---${NC}"
    echo -e "Current Setting: ${CYAN}${BAN_TIMEOUT} seconds${NC}"
    if [ "$BAN_TIMEOUT" -eq 0 ]; then echo -e "Mode: ${RED}UNLIMITED (Permanent Ban)${NC}"; 
    else HRS=$((BAN_TIMEOUT / 3600)); echo -e "Mode: ${GREEN}Temporary ($HRS Hours)${NC}"; fi
    echo ""
    
    echo "Do you want to calculate the duration?"
    echo -e " 1) Yes (Use Calculator)"
    echo -e " 2) No (Enter Total Seconds directly)"
    echo -e " 0) Set to UNLIMITED (0)"
    echo -n "Selection: "
    read -r T_OPT

    NEW_VAL=""
    case $T_OPT in
        1) 
            NEW_VAL=$(calculate_seconds "full")
            echo -e "Calculated: ${CYAN}$NEW_VAL seconds${NC}"
            ;;
        0)
            NEW_VAL="0"
            ;;
        *)
            echo -n "Enter new Timeout in seconds: "
            read -r IN_VAL
            NEW_VAL="$IN_VAL"
            ;;
    esac

    if [ -n "$NEW_VAL" ] && echo "$NEW_VAL" | grep -qE '^[0-9]+$'; then
        BAN_TIMEOUT="$NEW_VAL"
        save_config
        echo -e "${GREEN}Timeout updated. Restart Firewall Hook to apply.${NC}"
    else
        echo -e "${RED}Invalid input.${NC}"
    fi
    pause
}

do_settings() {
    load_config
    while true; do
        show_header
        echo -e "${YELLOW}--- CONFIGURATION SETTINGS ---${NC}"
        if [ "$ENABLE_IPV6" = "true" ]; then ST_V6="${GREEN}ON${NC}"; else ST_V6="${RED}OFF${NC}"; fi
        # [NEW] Forward Status
        if [ "$ENABLE_FWD_PROTECTION" = "true" ]; then ST_FWD="${GREEN}ON${NC}"; else ST_FWD="${RED}OFF${NC}"; fi
        
        CNT_V4=$(echo "$SOURCES_V4" | awk '{print NF}')
        CNT_V6=$(echo "$SOURCES_V6" | awk '{print NF}')
        if [ "$BAN_TIMEOUT" -eq 0 ]; then ST_BAN="${RED}Unlimited${NC}"; else ST_BAN="${GREEN}${BAN_TIMEOUT}s${NC}"; fi
        ST_BF="${WHITE}${BF_HITCOUNT}hits/${BF_SECONDS}s${NC}"

        echo -e " 1) IPv6 Support:            [$ST_V6]"
        echo -e " 2) Manage IPv4 Sources:     [${WHITE}$CNT_V4 Active${NC}]"
        echo -e " 3) Manage IPv6 Sources:     [${WHITE}$CNT_V6 Active${NC}]"
        echo -e " 4) Allowed Ports:           [${WHITE}Edit...${NC}]"
        echo -e " 5) Auto-Ban Timeout:        [$ST_BAN]"
        echo -e " 6) AbuseIPDB Settings:      [${WHITE}Key & Cooldown${NC}]"
        echo -e " 7) Brute-Force Sensitivity: [$ST_BF]"
        echo -e " 8) Forward Protection:      [$ST_FWD]"
        echo -e " 0) Back to Main Menu"
        echo ""
        echo -n "Select option: "
        read -r SOPT
        case $SOPT in
            1) if [ "$ENABLE_IPV6" = "true" ]; then ENABLE_IPV6="false"; else ENABLE_IPV6="true"; fi; save_config ;;
            2) do_manage_sources "V4" ;;
            3) do_manage_sources "V6" ;;
            4) do_port_editor ;;
            5) do_timeout_setup ;;
            6) do_reporter_setup ;;
            7) do_bf_setup ;;
            8) if [ "$ENABLE_FWD_PROTECTION" = "true" ]; then ENABLE_FWD_PROTECTION="false"; else ENABLE_FWD_PROTECTION="true"; fi; save_config ;;
            0) return ;;
        esac
    done
}

do_manage_sources() {
    TYPE=$1
    while true; do
        show_header
        echo -e "${YELLOW}--- IPv$TYPE BLOCKLIST SOURCES ---${NC}"
        eval "CURRENT_SOURCES=\$SOURCES_$TYPE"
        i=1
        for url in $CURRENT_SOURCES; do echo -e " $i) $url"; i=$((i+1)); done
        echo -e "\n a) Add new URL\n r) Remove a URL\n 0) Back"
        echo -n "Select option: "
        read -r MOPT
        case $MOPT in
            a) echo -n "Paste new URL: "; read -r NEW_URL; if [ -n "$NEW_URL" ]; then eval "SOURCES_$TYPE=\"\$SOURCES_$TYPE $NEW_URL\""; save_config; echo -e "${GREEN}Added.${NC}"; sleep 1; fi ;;
            r) echo -n "Enter number to remove: "; read -r REM_NUM; if echo "$REM_NUM" | grep -qE '^[0-9]+$'; then NEW_LIST=""; curr=1; for url in $CURRENT_SOURCES; do [ "$curr" -ne "$REM_NUM" ] && NEW_LIST="$NEW_LIST $url"; curr=$((curr+1)); done; eval "SOURCES_$TYPE=\"$NEW_LIST\""; save_config; echo -e "${RED}Removed.${NC}"; sleep 1; fi ;;
            0) return ;;
        esac
    done
}

do_health_check() {
    clear
    echo -e "${YELLOW}=== FIREWALL DIAGNOSTICS ===${NC}"
    echo -e "\n${BOLD}1. Database Status (IP Sets)${NC}"
    CNT_V4=$(ipset list FirewallBlock 2>/dev/null | grep -cE '^[0-9]')
    if [ "$CNT_V4" -gt 100 ]; then STATUS="${GREEN}OK ($CNT_V4 IPs)${NC}"; else STATUS="${RED}CRITICAL (Empty/Low: $CNT_V4)${NC}"; fi
    echo -e "   IPv4 Blocklist: $STATUS"
    CNT_WHITE=$(ipset list FirewallWhite 2>/dev/null | grep -cE '^[0-9]')
    echo -e "   IPv4 Whitelist: ${CYAN}$CNT_WHITE IPs${NC}"
    CNT_BAN=$(ipset list AutoBan 2>/dev/null | grep -cE '^[0-9]')
    if ipset list AutoBan >/dev/null 2>&1; then echo -e "   Auto-Ban:       ${GREEN}ACTIVE${NC} (${RED}$CNT_BAN IPs${NC})"; else echo -e "   Auto-Ban:       ${RED}MISSING${NC}"; fi
    CNT_VPN=$(ipset list VPNBlock 2>/dev/null | grep -cE '^[0-9]')
    echo -e "   VPN List:       ${CYAN}$CNT_VPN IPs${NC}"
    if [ "$ENABLE_IPV6" = "true" ]; then
        CNT_V6=$(ipset list FirewallBlock6 2>/dev/null | grep -cE '^[0-9a-fA-F:]')
        if [ "$CNT_V6" -gt 10 ]; then STATUS="${GREEN}OK ($CNT_V6 IPs)${NC}"; else STATUS="${RED}CRITICAL (Empty: $CNT_V6)${NC}"; fi
        echo -e "   IPv6 Blocklist: $STATUS"
        CNT_WHITE6=$(ipset list FirewallWhite6 2>/dev/null | grep -cE '^[0-9a-fA-F:]')
        echo -e "   IPv6 Whitelist: ${CYAN}$CNT_WHITE6 IPs${NC}"
        CNT_BAN6=$(ipset list AutoBan6 2>/dev/null | grep -cE '^[0-9a-fA-F:]')
        if ipset list AutoBan6 >/dev/null 2>&1; then echo -e "   Auto-Ban6:      ${GREEN}ACTIVE${NC} (${RED}$CNT_BAN6 IPs${NC})"; else echo -e "   Auto-Ban6:      ${RED}MISSING${NC}"; fi
    else
        echo -e "   IPv6 List:      ${DIM}Disabled${NC}"
    fi
    if pgrep -f "fw_syn_ring.pcap" >/dev/null; then echo -e "   Sniffer:        ${GREEN}RUNNING${NC}"; else echo -e "   Sniffer:        ${RED}STOPPED${NC}"; fi
    echo -e "\n${BOLD}2. Integration (Chain Links)${NC}"
    check_chain() {
        TOOL=$1; CHAIN=$2; PARENT=$3
        if $TOOL -C $PARENT -j $CHAIN 2>/dev/null; then LINK="${GREEN}LINKED${NC}"; else LINK="${RED}UNLINKED${NC}"; fi
        if $TOOL -n -L $CHAIN >/dev/null 2>&1; then EXIST="EXISTS"; else EXIST="MISSING"; LINK="${RED}ERROR${NC}"; fi
        echo -e "   $TOOL $CHAIN: [$EXIST] -> $PARENT: [$LINK]"
    }
    check_chain "iptables" "BLOCKLIST_IN" "INPUT"
    check_chain "iptables" "BLOCKLIST_FWD" "FORWARD"
    check_chain "iptables" "SCAN_TRAP" "BLOCKLIST_IN"
    if [ "$ENABLE_IPV6" = "true" ]; then
        echo -e "   ${DIM}--- IPv6 Chains ---${NC}"
        check_chain "ip6tables" "BLOCKLIST_IN6" "INPUT"
        check_chain "ip6tables" "BLOCKLIST_FWD6" "FORWARD"
        check_chain "ip6tables" "SCAN_TRAP6" "BLOCKLIST_IN6"
    fi
    echo ""
    pause
}

# --- ACTIONS ---
do_update() { echo -e "${YELLOW}Updating Blocklists...${NC}"; if [ -x "$SCRIPT_UPDATE" ]; then "$SCRIPT_UPDATE"; echo -e "${GREEN}Done.${NC}"; fi; pause; }
do_stats() { echo -e "${YELLOW}Generating Stats & Running Sherlock...${NC}"; if [ -x "$SCRIPT_STATS" ]; then "$SCRIPT_STATS" force; echo -e "${GREEN}Done.${NC}"; fi; pause; }
do_monitor() { if [ -x "$SCRIPT_MONITOR" ]; then "$SCRIPT_MONITOR"; else echo -e "${RED}Missing script${NC}"; pause; fi; }
do_vpn() { if [ -x "$SCRIPT_VPN" ]; then "$SCRIPT_VPN"; echo -e "${GREEN}Done.${NC}"; fi; pause; }
do_report() { echo -e "${YELLOW}Sending Reports to AbuseIPDB...${NC}"; if [ -x "$SCRIPT_REPORTER" ]; then "$SCRIPT_REPORTER"; else echo -e "${RED}Reporter script missing${NC}"; fi; pause; }
do_restart() { echo -e "${YELLOW}Restarting Firewall Hook (Applying Config)...${NC}"; if [ -x "$SCRIPT_HOOK" ]; then table=filter "$SCRIPT_HOOK"; echo -e "${GREEN}Done.${NC}"; else echo -e "${RED}Hook script missing${NC}"; fi; pause; }

# --- MAIN MENU ---
load_config
while true; do
    show_header
    echo -e " 1) ${GREEN}📊 Show Live Monitor${NC}"
    echo -e " 2) ${CYAN}🔄 Update Blocklists${NC}"
    echo -e " 3) ${CYAN}📈 Run Stats & Dashboard${NC} "
    echo -e " 4) ${CYAN}🔎 Run VPN Scan${NC}"
    echo -e " 5) ${MAGENTA}📢 Run Abuse Reporter${NC}"
    echo -e " 6) ${YELLOW}🛡️  Run Diagnostics${NC} "
    echo -e " 7) ${RED}⚡ Restart Firewall Hook${NC} (Apply Config)"
    echo -e " 8) ${MAGENTA}⚙️  Configuration & API${NC}"
    echo -e " 9) ${GREEN}✅ Manage Whitelist${NC} (IPs/Domains)"
    echo -e " e) ${RED}❌ Exit${NC}"
    echo -e "${CYAN}-------------------------------------------------${NC}"
    echo -n "Select an option: "
    read -r OPTION

    case $OPTION in
        1) do_monitor ;;
        2) do_update ;;
        3) do_stats ;;
        4) do_vpn ;;
        5) do_report ;;
        6) do_health_check ;;
        7) do_restart ;;
        8) do_settings ;;
        9) do_whitelist_menu ;;
        e|E) exit 0 ;;
        *) sleep 1 ;;
    esac
done
