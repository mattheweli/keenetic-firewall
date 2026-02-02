#!/bin/sh

# ==============================================================================
# KEENETIC FIREWALL MANAGER v2.1.0 (SHERLOCK EDITION)
# Features:
#   - INTELLIGENCE: Manage AbuseIPDB Reporting & Sherlock (Port Detective).
#   - CONFIG: Centralized management of IPv6, Blocklists, and API Keys.
#   - HEALTH CHECK: Deep inspection of Sets, Chains, Rules, and Dependencies.
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# --- PATHS ---
SCRIPT_MONITOR="/opt/bin/firewall_monitor"
SCRIPT_UPDATE="/opt/bin/update_blocklist.sh"
SCRIPT_STATS="/opt/bin/firewall_stats.sh"
SCRIPT_VPN="/opt/bin/vpn_scan.sh"
SCRIPT_REPORTER="/opt/bin/abuse_reporter.sh"
CONF_FILE="/opt/etc/firewall.conf"

# --- DEFAULTS ---
DEF_IPV6="true"
L4_1="https://iplists.firehol.org/files/firehol_level1.netset"
L4_2="https://blocklist.greensnow.co/greensnow.txt"
L4_3="http://cinsscore.com/list/ci-badguys.txt"
L4_4="https://lists.blocklist.de/lists/all.txt"
L4_5="https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-30d.ipv4"
L6_1="https://www.spamhaus.org/drop/dropv6.txt"
L6_2="https://lists.blocklist.de/lists/all.txt"

# --- TRAP ---
ctrl_c_handler() { return; }
trap ctrl_c_handler INT

# --- COLORS ---
RED='\033[0;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; BLUE='\033[1;34m'; CYAN='\033[1;36m'; WHITE='\033[1;37m'; NC='\033[0m'
BOLD='\033[1m'; DIM='\033[2m'

# --- CONFIG ENGINE ---
load_config() {
    if [ ! -f "$CONF_FILE" ]; then
        echo "ENABLE_IPV6=\"$DEF_IPV6\"" > "$CONF_FILE"
        echo "SOURCES_V4=\"$L4_1 $L4_2 $L4_3 $L4_4 $L4_5\"" >> "$CONF_FILE"
        echo "SOURCES_V6=\"$L6_1 $L6_2\"" >> "$CONF_FILE"
    fi
    source "$CONF_FILE"
}

save_config() {
    echo "ENABLE_IPV6=\"$ENABLE_IPV6\"" > "$CONF_FILE"
    echo "SOURCES_V4=\"$SOURCES_V4\"" >> "$CONF_FILE"
    echo "SOURCES_V6=\"$SOURCES_V6\"" >> "$CONF_FILE"
}

# --- MENUS ---
show_header() {
    clear
    echo -e "${CYAN}=================================================${NC}"
    echo -e "${WHITE}      KEENETIC FIREWALL MANAGER v2.1.0     ${NC}"
    echo -e "${CYAN}=================================================${NC}"
}

pause() { echo ""; echo -e "${CYAN}Press [Enter] to continue...${NC}"; read -r; }

# --- API CONFIG ---
do_api_setup() {
    show_header
    echo -e "${YELLOW}--- ABUSEIPDB API KEY ---${NC}"
    CURRENT_KEY=$(grep 'ABUSEIPDB_KEY=' "$SCRIPT_UPDATE" 2>/dev/null | cut -d'"' -f2)
    
    if [ -n "$CURRENT_KEY" ]; then
        echo -e "Current Key: ${GREEN}${CURRENT_KEY:0:10}.......${NC}"
    else
        echo -e "Current Key: ${RED}Not Configured${NC}"
    fi
    echo ""
    echo -n "Enter new API Key (or press Enter to keep current): "
    read -r NEW_KEY
    
    if [ -n "$NEW_KEY" ]; then
        # Update in Updater
        sed -i "s/^ABUSEIPDB_KEY=\".*\"/ABUSEIPDB_KEY=\"$NEW_KEY\"/" "$SCRIPT_UPDATE"
        # Update in Stats (if present, though we centralized reading in scripts)
        if [ -f "$SCRIPT_STATS" ]; then sed -i "s/^ABUSEIPDB_KEY=\".*\"/ABUSEIPDB_KEY=\"$NEW_KEY\"/" "$SCRIPT_STATS"; fi
        echo -e "${GREEN}Key updated successfully.${NC}"
    else
        echo "No change."
    fi
    pause
}

do_settings() {
    load_config
    while true; do
        show_header
        echo -e "${YELLOW}--- CONFIGURATION SETTINGS ---${NC}"
        if [ "$ENABLE_IPV6" = "true" ]; then ST_V6="${GREEN}ON${NC}"; else ST_V6="${RED}OFF${NC}"; fi
        CNT_V4=$(echo "$SOURCES_V4" | awk '{print NF}')
        CNT_V6=$(echo "$SOURCES_V6" | awk '{print NF}')
        
        # Check API Key presence for display
        HAS_KEY=$(grep 'ABUSEIPDB_KEY=' "$SCRIPT_UPDATE" 2>/dev/null | cut -d'"' -f2)
        if [ -n "$HAS_KEY" ]; then ST_API="${GREEN}Configured${NC}"; else ST_API="${RED}Missing${NC}"; fi

        echo -e " 1) IPv6 Support:        [$ST_V6]"
        echo -e " 2) Select IPv4 Lists:   [${WHITE}$CNT_V4 Active${NC}]"
        echo -e " 3) Select IPv6 Lists:   [${WHITE}$CNT_V6 Active${NC}]"
        echo -e " 4) AbuseIPDB API Key:   [$ST_API]"
        echo -e " 0) Back to Main Menu"
        echo ""
        echo -n "Select option: "
        read -r SOPT
        case $SOPT in
            1) if [ "$ENABLE_IPV6" = "true" ]; then ENABLE_IPV6="false"; else ENABLE_IPV6="true"; fi; save_config ;;
            2) do_select_lists_v4 ;;
            3) do_select_lists_v6 ;;
            4) do_api_setup ;;
            0) return ;;
        esac
    done
}

toggle_url() {
    if echo "$1" | grep -q "$2"; then echo "$1" | sed "s| $2||g" | sed "s|$2 ||g" | sed "s|$2||g"; else echo "$1 $2"; fi
}

do_select_lists_v4() {
    while true; do
        show_header
        echo -e "${YELLOW}--- IPv4 BLOCKLIST SOURCES ---${NC}"
        C1=" "; echo "$SOURCES_V4" | grep -q "$L4_1" && C1="X"
        C2=" "; echo "$SOURCES_V4" | grep -q "$L4_2" && C2="X"
        C3=" "; echo "$SOURCES_V4" | grep -q "$L4_3" && C3="X"
        C4=" "; echo "$SOURCES_V4" | grep -q "$L4_4" && C4="X"
        C5=" "; echo "$SOURCES_V4" | grep -q "$L4_5" && C5="X"
        echo -e " 1) [$C1] Firehol Level 1 (Primary)"
        echo -e " 2) [$C2] GreenSnow"
        echo -e " 3) [$C3] CINS Score BadGuys"
        echo -e " 4) [$C4] Blocklist.de (All)"
        echo -e " 5) [$C5] AbuseIPDB (Borestad 100% 30d)"
        echo -e " 0) Done"
        echo ""; echo -n "Toggle Number: "; read -r T
        case $T in
            1) SOURCES_V4=$(toggle_url "$SOURCES_V4" "$L4_1") ;;
            2) SOURCES_V4=$(toggle_url "$SOURCES_V4" "$L4_2") ;;
            3) SOURCES_V4=$(toggle_url "$SOURCES_V4" "$L4_3") ;;
            4) SOURCES_V4=$(toggle_url "$SOURCES_V4" "$L4_4") ;;
            5) SOURCES_V4=$(toggle_url "$SOURCES_V4" "$L4_5") ;;
            0) save_config; return ;;
        esac
    done
}

do_select_lists_v6() {
    while true; do
        show_header
        echo -e "${YELLOW}--- IPv6 BLOCKLIST SOURCES ---${NC}"
        C1=" "; echo "$SOURCES_V6" | grep -q "$L6_1" && C1="X"
        C2=" "; echo "$SOURCES_V6" | grep -q "$L6_2" && C2="X"
        echo -e " 1) [$C1] Spamhaus DROP v6"
        echo -e " 2) [$C2] Blocklist.de (All)"
        echo -e " 0) Done"
        echo ""; echo -n "Toggle Number: "; read -r T
        case $T in
            1) SOURCES_V6=$(toggle_url "$SOURCES_V6" "$L6_1") ;;
            2) SOURCES_V6=$(toggle_url "$SOURCES_V6" "$L6_2") ;;
            0) save_config; return ;;
        esac
    done
}

# --- DIAGNOSTICS ---
do_health_check() {
    clear
    echo -e "${YELLOW}=== FIREWALL DIAGNOSTICS ===${NC}"
    
    # 1. IPSET CHECK
    echo -e "\n${BOLD}1. Database Status (IP Sets)${NC}"
    CNT_V4=$(ipset list FirewallBlock 2>/dev/null | grep -cE '^[0-9]')
    if [ "$CNT_V4" -gt 100 ]; then STATUS="${GREEN}OK ($CNT_V4 IPs)${NC}"; else STATUS="${RED}CRITICAL (Empty/Low: $CNT_V4)${NC}"; fi
    echo -e "   IPv4 List: $STATUS"
    
    if [ "$ENABLE_IPV6" = "true" ]; then
        CNT_V6=$(ipset list FirewallBlock6 2>/dev/null | grep -cE '^[0-9a-fA-F:]')
        if [ "$CNT_V6" -gt 10 ]; then STATUS="${GREEN}OK ($CNT_V6 IPs)${NC}"; else STATUS="${RED}CRITICAL (Empty: $CNT_V6)${NC}"; fi
        echo -e "   IPv6 List: $STATUS"
    else
        echo -e "   IPv6 List: ${DIM}Disabled${NC}"
    fi
    CNT_VPN=$(ipset list VPNBlock 2>/dev/null | grep -cE '^[0-9]')
    echo -e "   VPN List:  ${CYAN}$CNT_VPN IPs${NC}"

    # 2. INTELLIGENCE CHECK (SHERLOCK & API)
    echo -e "\n${BOLD}2. Intelligence & Sherlock${NC}"
    
    # Tcpdump Check
    if command -v tcpdump >/dev/null 2>&1; then 
        echo -e "   Port Detective: ${GREEN}READY${NC} (tcpdump installed)"
    else 
        echo -e "   Port Detective: ${RED}DISABLED${NC} (tcpdump missing)"
    fi
    
    # API Key Check
    KEY=$(grep 'ABUSEIPDB_KEY=' "$SCRIPT_UPDATE" 2>/dev/null | cut -d'"' -f2)
    if [ -n "$KEY" ]; then
        echo -e "   AbuseIPDB API:  ${GREEN}CONFIGURED${NC}"
    else
        echo -e "   AbuseIPDB API:  ${RED}MISSING KEY${NC}"
    fi

    # 3. CHAIN LINK CHECK
    echo -e "\n${BOLD}3. Integration (Chain Links)${NC}"
    check_chain() {
        TOOL=$1; CHAIN=$2; PARENT=$3
        if $TOOL -C $PARENT -j $CHAIN 2>/dev/null; then LINK="${GREEN}LINKED${NC}"; else LINK="${RED}UNLINKED${NC}"; fi
        if $TOOL -n -L $CHAIN >/dev/null 2>&1; then EXIST="EXISTS"; else EXIST="MISSING"; LINK="${RED}ERROR${NC}"; fi
        echo -e "   $TOOL $CHAIN: [$EXIST] -> $PARENT: [$LINK]"
    }
    check_chain "iptables" "BLOCKLIST_IN" "INPUT"
    check_chain "iptables" "BLOCKLIST_FWD" "FORWARD"
    if [ "$ENABLE_IPV6" = "true" ]; then
        check_chain "ip6tables" "BLOCKLIST_IN6" "INPUT"
        check_chain "ip6tables" "BLOCKLIST_FWD6" "FORWARD"
    fi

    # 4. RULE CHECK
    echo -e "\n${BOLD}4. Active Blocking Rules${NC}"
    check_rule() {
        TOOL=$1; CHAIN=$2; SET=$3
        if $TOOL -C $CHAIN -m set --match-set "$SET" src -j DROP 2>/dev/null; then
            echo -e "   $TOOL $CHAIN -> Drop $SET: ${GREEN}ACTIVE${NC}"
        else
            echo -e "   $TOOL $CHAIN -> Drop $SET: ${RED}MISSING${NC}"
        fi
    }
    check_rule "iptables" "BLOCKLIST_IN" "FirewallBlock"
    check_rule "iptables" "BLOCKLIST_FWD" "FirewallBlock"
    if [ "$ENABLE_IPV6" = "true" ]; then
        check_rule "ip6tables" "BLOCKLIST_IN6" "FirewallBlock6"
        check_rule "ip6tables" "BLOCKLIST_FWD6" "FirewallBlock6"
    fi

    echo ""
    pause
}

# --- ACTIONS ---
do_update() { echo -e "${YELLOW}Updating Blocklists...${NC}"; if [ -x "$SCRIPT_UPDATE" ]; then "$SCRIPT_UPDATE"; echo -e "${GREEN}Done.${NC}"; fi; pause; }
do_stats() { 
    echo -e "${YELLOW}Generating Stats & Running Sherlock...${NC}"
    echo -e "${DIM}(This may take up to 60s if scanning ports...)${NC}"
    if [ -x "$SCRIPT_STATS" ]; then "$SCRIPT_STATS" force; echo -e "${GREEN}Done.${NC}"; fi; pause; 
}
do_monitor() { if [ -x "$SCRIPT_MONITOR" ]; then "$SCRIPT_MONITOR"; else echo -e "${RED}Missing script${NC}"; pause; fi; }
do_vpn() { if [ -x "$SCRIPT_VPN" ]; then "$SCRIPT_VPN"; echo -e "${GREEN}Done.${NC}"; fi; pause; }
do_report() {
    echo -e "${YELLOW}Sending Reports to AbuseIPDB...${NC}"
    if [ -x "$SCRIPT_REPORTER" ]; then "$SCRIPT_REPORTER"; else echo -e "${RED}Reporter script missing${NC}"; fi; pause;
}

# --- MAIN MENU ---
load_config
while true; do
    show_header
    echo -e " 1) ${GREEN}📊 Show Live Monitor${NC}"
    echo -e " 2) ${CYAN}🔄 Update Blocklists${NC}"
    echo -e " 3) ${CYAN}📈 Run Stats & Sherlock${NC} "
    echo -e " 4) ${CYAN}🔎 Run VPN Scan${NC}"
    echo -e " 5) ${MAGENTA}📢 Run Abuse Reporter${NC}"
    echo -e " 6) ${YELLOW}⏰ Automation (Cron)${NC}"
    echo -e " 7) ${YELLOW}🛡️  Run Diagnostics${NC} "
    echo -e " 8) ${MAGENTA}⚙️  Configuration & API${NC}"
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
        6) echo "Use Keentool main menu for Cron management."; pause ;;
        7) do_health_check ;;
        8) do_settings ;;
        e|E) exit 0 ;;
        *) sleep 1 ;;
    esac
done
