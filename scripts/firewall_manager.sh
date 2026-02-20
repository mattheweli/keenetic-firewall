#!/bin/sh

# ==============================================================================
# KEENETIC FIREWALL MANAGER v2.5.0 (GRANULAR BYPASS WIZARD)
# Changelog:
#   - FEAT: Introduced Granular Port Whitelisting (Sub-chain Architecture).
#   - FEAT: Interactive Port Wizard to bypass AutoBan, ConnLimit or BruteForce independently.
#   - UX: Settings are automatically applied on exiting the config menu (Option 0).
#   - FIX: Restored missing core UI functions (show_header, pause, whitelist_menu).
#   - FIX: AutoBan list swapped safely when timeout changes (Atomic Swap).
#   - FEAT: Toggle & Config for DDoS Protection (xt_connlimit) extended to UDP.
#   - OPS: Dedicated Menu for Flushing specific IP Sets.
#   - FWD: Toggle for Forward Chain Protection (NAS/DMZ).
#   - REPORTER: Configuration for AbuseIPDB Reporting Cooldown.
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
DEF_ENABLE_AUTOBAN="true"
DEF_ENABLE_BF="true"
DEF_ENABLE_CONN="true"
DEF_CONN_MAX="15"
DEF_BAN_TIME="86400" # 24 Hours
DEF_TCP="80 443"
DEF_UDP=""
DEF_PASSIVE=""
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

# --- UI HELPERS ---
show_header() {
    clear
    echo -e "${BLUE}=================================================${NC}"
    echo -e "${BOLD}🛡️  KEENETIC FIREWALL MANAGER v2.5.0${NC}"
    echo -e "${BLUE}=================================================${NC}"
}

pause() {
    echo -e "\n${DIM}Press [Enter] to continue...${NC}"
    read -r _
}

# --- HELPER: TIME CALCULATOR ---
calculate_seconds() {
    MODE=$1
    # Send descriptive text to stderr so it displays on screen but isn't captured by the variable
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
    
    # Validation (numbers only)
    M=$(echo "$M" | tr -cd '0-9'); [ -z "$M" ] && M=0
    W=$(echo "$W" | tr -cd '0-9'); [ -z "$W" ] && W=0
    D=$(echo "$D" | tr -cd '0-9'); [ -z "$D" ] && D=0
    H=$(echo "$H" | tr -cd '0-9'); [ -z "$H" ] && H=0
    m=$(echo "$m" | tr -cd '0-9'); [ -z "$m" ] && m=0
    s=$(echo "$s" | tr -cd '0-9'); [ -z "$s" ] && s=0
    
    # Calculation
    TOTAL=$(( (M * 2592000) + (W * 604800) + (D * 86400) + (H * 3600) + (m * 60) + s ))
    
    # ONLY the final result goes to stdout to be captured
    echo "$TOTAL"
}

# --- CONFIG ENGINE ---
load_config() {
    if [ ! -f "$CONF_FILE" ]; then
        echo "Generating default configuration file..."
        echo "ENABLE_IPV6=\"$DEF_IPV6\"" > "$CONF_FILE"
        echo "ENABLE_FWD_PROTECTION=\"$DEF_FWD_PROT\"" >> "$CONF_FILE"
        echo "ENABLE_AUTOBAN=\"$DEF_ENABLE_AUTOBAN\"" >> "$CONF_FILE"
        echo "ENABLE_BRUTEFORCE=\"$DEF_ENABLE_BF\"" >> "$CONF_FILE"
        echo "ENABLE_CONNLIMIT=\"$DEF_ENABLE_CONN\"" >> "$CONF_FILE"
        echo "CONNLIMIT_MAX=\"$DEF_CONN_MAX\"" >> "$CONF_FILE"
        echo "BAN_TIMEOUT=\"$DEF_BAN_TIME\"" >> "$CONF_FILE"
        echo "TCP_SERVICES=\"$DEF_TCP\"" >> "$CONF_FILE"
        echo "UDP_SERVICES=\"$DEF_UDP\"" >> "$CONF_FILE"
        
        # Granular Bypass Lists
        echo "BYPASS_CONN_TCP=\"\"" >> "$CONF_FILE"
        echo "BYPASS_CONN_UDP=\"\"" >> "$CONF_FILE"
        echo "BYPASS_BRUTE_TCP=\"\"" >> "$CONF_FILE"
        echo "BYPASS_BRUTE_UDP=\"\"" >> "$CONF_FILE"
        
        echo "TCP_PASSIVE_RANGE=\"$DEF_PASSIVE\"" >> "$CONF_FILE"
        echo "BF_SECONDS=\"$DEF_BF_SEC\"" >> "$CONF_FILE"
        echo "BF_HITCOUNT=\"$DEF_BF_HIT\"" >> "$CONF_FILE"
        echo "REPORT_COOLDOWN=\"$DEF_REP_COOL\"" >> "$CONF_FILE"
        echo "SOURCES_V4=\"$L4_DEFAULTS\"" >> "$CONF_FILE"
        echo "SOURCES_V6=\"$L6_DEFAULTS\"" >> "$CONF_FILE"
    fi
    
    . "$CONF_FILE"
    
    : ${ENABLE_IPV6:=$DEF_IPV6}
    : ${ENABLE_FWD_PROTECTION:=$DEF_FWD_PROT}
    : ${ENABLE_AUTOBAN:=$DEF_ENABLE_AUTOBAN}
    : ${ENABLE_BRUTEFORCE:=$DEF_ENABLE_BF}
    : ${ENABLE_CONNLIMIT:=$DEF_ENABLE_CONN}
    : ${CONNLIMIT_MAX:=$DEF_CONN_MAX}
    : ${BAN_TIMEOUT:=$DEF_BAN_TIME}
    
    # AutoBan Safe Ports
    : ${TCP_SERVICES:=$DEF_TCP}
    : ${UDP_SERVICES:=$DEF_UDP}
    
    # Granular Bypass Fallbacks
    : ${BYPASS_CONN_TCP:=""}
    : ${BYPASS_CONN_UDP:=""}
    : ${BYPASS_BRUTE_TCP:=""}
    : ${BYPASS_BRUTE_UDP:=""}
    
    : ${TCP_PASSIVE_RANGE:=$DEF_PASSIVE}
    : ${BF_SECONDS:=$DEF_BF_SEC}
    : ${BF_HITCOUNT:=$DEF_BF_HIT}
    : ${REPORT_COOLDOWN:=$DEF_REP_COOL}
    : ${SOURCES_V4:=$L4_DEFAULTS}
    : ${SOURCES_V6:=$L6_DEFAULTS}
    
    [ ! -f "$WHITELIST_FILE" ] && touch "$WHITELIST_FILE"
}

save_config() {
    echo "ENABLE_IPV6=\"$ENABLE_IPV6\"" > "$CONF_FILE"
    echo "ENABLE_FWD_PROTECTION=\"$ENABLE_FWD_PROTECTION\"" >> "$CONF_FILE"
    
    # [FIX] Aggiunte le variabili dei moduli di sicurezza e del limite connessioni
    echo "ENABLE_AUTOBAN=\"$ENABLE_AUTOBAN\"" >> "$CONF_FILE"
    echo "ENABLE_BRUTEFORCE=\"$ENABLE_BRUTEFORCE\"" >> "$CONF_FILE"
    echo "ENABLE_CONNLIMIT=\"$ENABLE_CONNLIMIT\"" >> "$CONF_FILE"
    echo "CONNLIMIT_MAX=\"$CONNLIMIT_MAX\"" >> "$CONF_FILE"
    
    echo "BAN_TIMEOUT=\"$BAN_TIMEOUT\"" >> "$CONF_FILE"
    echo "TCP_SERVICES=\"$TCP_SERVICES\"" >> "$CONF_FILE"
    echo "UDP_SERVICES=\"$UDP_SERVICES\"" >> "$CONF_FILE"
    
    echo "BYPASS_CONN_TCP=\"$BYPASS_CONN_TCP\"" >> "$CONF_FILE"
    echo "BYPASS_CONN_UDP=\"$BYPASS_CONN_UDP\"" >> "$CONF_FILE"
    echo "BYPASS_BRUTE_TCP=\"$BYPASS_BRUTE_TCP\"" >> "$CONF_FILE"
    echo "BYPASS_BRUTE_UDP=\"$BYPASS_BRUTE_UDP\"" >> "$CONF_FILE"
    
    echo "TCP_PASSIVE_RANGE=\"$TCP_PASSIVE_RANGE\"" >> "$CONF_FILE"
    echo "BF_SECONDS=\"$BF_SECONDS\"" >> "$CONF_FILE"
    echo "BF_HITCOUNT=\"$BF_HITCOUNT\"" >> "$CONF_FILE"
    echo "REPORT_COOLDOWN=\"$REPORT_COOLDOWN\"" >> "$CONF_FILE"
    echo "SOURCES_V4=\"$SOURCES_V4\"" >> "$CONF_FILE"
    echo "SOURCES_V6=\"$SOURCES_V6\"" >> "$CONF_FILE"
}

# --- PORT EDITOR (GRANULAR BYPASS) ---

# Helper function to toggle a port in a space-separated list safely
toggle_port() {
    local current_list="$1"
    local port="$2"
    local new_list=""
    local found=0
    for p in $current_list; do
        if [ "$p" = "$port" ]; then found=1; else new_list="$new_list $p"; fi
    done
    if [ "$found" -eq 0 ]; then new_list="$current_list $port"; fi
    echo $new_list # Outputs clean space-separated list
}

do_port_wizard() {
    echo -e "\nEnter Port Number (e.g. 32400):"
    read -r W_PORT
    if ! echo "$W_PORT" | grep -qE '^[0-9]+$'; then echo -e "${RED}Invalid port${NC}"; sleep 1; return; fi
    
    echo -e "Protocol (TCP/UDP) [Default TCP]:"
    read -r W_PROTO
    W_PROTO=$(echo "${W_PROTO:-TCP}" | tr 'a-z' 'A-Z')

    while true; do
        ST_AB="${RED}OFF${NC}"; ST_CL="${RED}OFF${NC}"; ST_BF="${RED}OFF${NC}"
        
        # Check current status
        if [ "$W_PROTO" = "TCP" ]; then
            for p in $TCP_SERVICES; do [ "$p" = "$W_PORT" ] && ST_AB="${GREEN}ON${NC}"; done
            for p in $BYPASS_CONN_TCP; do [ "$p" = "$W_PORT" ] && ST_CL="${GREEN}ON${NC}"; done
            for p in $BYPASS_BRUTE_TCP; do [ "$p" = "$W_PORT" ] && ST_BF="${GREEN}ON${NC}"; done
        else
            for p in $UDP_SERVICES; do [ "$p" = "$W_PORT" ] && ST_AB="${GREEN}ON${NC}"; done
            for p in $BYPASS_CONN_UDP; do [ "$p" = "$W_PORT" ] && ST_CL="${GREEN}ON${NC}"; done
            for p in $BYPASS_BRUTE_UDP; do [ "$p" = "$W_PORT" ] && ST_BF="${GREEN}ON${NC}"; done
        fi

        show_header
        echo -e "${YELLOW}--- CONFIGURING PORT $W_PORT/$W_PROTO ---${NC}"
        echo -e "Tick/Untick the protections you want to BYPASS for this specific port."
        echo ""
        echo -e " 1) Bypass AutoBan (Trap) ......... [$ST_AB]"
        echo -e " 2) Bypass DDoS (ConnLimit) ....... [$ST_CL]"
        echo -e " 3) Bypass BruteForce ............. [$ST_BF]"
        echo ""
        echo -e " 0) Save & Return"
        echo ""
        echo -n "Select option: "
        read -r W_OPT

        case $W_OPT in
            1) 
                if [ "$W_PROTO" = "TCP" ]; then TCP_SERVICES=$(toggle_port "$TCP_SERVICES" "$W_PORT"); else UDP_SERVICES=$(toggle_port "$UDP_SERVICES" "$W_PORT"); fi
                ;;
            2)
                if [ "$W_PROTO" = "TCP" ]; then BYPASS_CONN_TCP=$(toggle_port "$BYPASS_CONN_TCP" "$W_PORT"); else BYPASS_CONN_UDP=$(toggle_port "$BYPASS_CONN_UDP" "$W_PORT"); fi
                ;;
            3)
                if [ "$W_PROTO" = "TCP" ]; then BYPASS_BRUTE_TCP=$(toggle_port "$BYPASS_BRUTE_TCP" "$W_PORT"); else BYPASS_BRUTE_UDP=$(toggle_port "$BYPASS_BRUTE_UDP" "$W_PORT"); fi
                ;;
            0) save_config; return ;;
        esac
    done
}

manage_port_list() {
    VAR_NAME=$1
    TITLE=$2
    while true; do
        eval "CURRENT_LIST=\$$VAR_NAME"
        show_header
        echo -e "${YELLOW}--- $TITLE ---${NC}"
        echo -e "Current List: ${GREEN}${CURRENT_LIST:-None}${NC}"
        echo ""
        echo -e " e) Edit Raw String (Manual)"
        echo -e " 0) Back"
        echo ""
        echo -n "Select option: "
        read -r MOPT
        case $MOPT in
            e|E)
                echo -e "\nCurrent Value: ${CYAN}${CURRENT_LIST}${NC}"
                echo -e "Enter NEW string below (space separated) or press Enter to keep current:"
                read -r NEW_VAL
                if [ -n "$NEW_VAL" ]; then
                    eval "$VAR_NAME=\"$NEW_VAL\""
                    save_config
                    echo -e "${GREEN}Saved.${NC}"
                fi
                sleep 1
                ;;
            0) return ;;
            *) echo "Invalid option"; sleep 1 ;;
        esac
    done
}

do_raw_lists_menu() {
    while true; do
        show_header
        echo -e "${YELLOW}--- RAW LIST EDITOR (Advanced) ---${NC}"
        echo -e " 1) AutoBan Bypass TCP   [${CYAN}${TCP_SERVICES:-None}${NC}]"
        echo -e " 2) AutoBan Bypass UDP   [${CYAN}${UDP_SERVICES:-None}${NC}]"
        echo -e " 3) ConnLimit Bypass TCP [${CYAN}${BYPASS_CONN_TCP:-None}${NC}]"
        echo -e " 4) ConnLimit Bypass UDP [${CYAN}${BYPASS_CONN_UDP:-None}${NC}]"
        echo -e " 5) BruteForce Bypass TCP[${CYAN}${BYPASS_BRUTE_TCP:-None}${NC}]"
        echo -e " 6) BruteForce Bypass UDP[${CYAN}${BYPASS_BRUTE_UDP:-None}${NC}]"
        echo ""
        echo -e " 0) Back"
        echo ""
        echo -n "Select option: "
        read -r ROPT
        case $ROPT in
            1) manage_port_list "TCP_SERVICES" "AUTOBAN BYPASS (TCP)" ;;
            2) manage_port_list "UDP_SERVICES" "AUTOBAN BYPASS (UDP)" ;;
            3) manage_port_list "BYPASS_CONN_TCP" "CONNLIMIT BYPASS (TCP)" ;;
            4) manage_port_list "BYPASS_CONN_UDP" "CONNLIMIT BYPASS (UDP)" ;;
            5) manage_port_list "BYPASS_BRUTE_TCP" "BRUTEFORCE BYPASS (TCP)" ;;
            6) manage_port_list "BYPASS_BRUTE_UDP" "BRUTEFORCE BYPASS (UDP)" ;;
            0) return ;;
        esac
    done
}

do_port_editor() {
    while true; do
        show_header
        echo -e "${YELLOW}--- PORT EXCEPTION MANAGER ---${NC}"
        echo -e "Create granular bypass rules for specific ports."
        echo ""
        echo -e " 1) ⚡ ${CYAN}Configure a Port (Wizard)${NC}"
        echo -e "    ${DIM}Select a port and tick which protections to bypass.${NC}"
        echo ""
        echo -e " 2) 📝 Edit Raw Lists (Advanced)"
        echo -e " 3) 🎛️  TCP Passive Range [${GREEN}${TCP_PASSIVE_RANGE:-None}${NC}]"
        echo ""
        echo -e " 0) Back"
        echo ""
        echo -n "Select option: "
        read -r POPT
        case $POPT in
            1) do_port_wizard ;;
            2) do_raw_lists_menu ;;
            3)
                echo -e "\nCurrent Range: ${CYAN}${TCP_PASSIVE_RANGE:-None}${NC}"
                echo -e "Enter Passive Port Range (e.g. 50000:50100) or Enter to keep:"
                read -r NEW_RNG
                if [ -n "$NEW_RNG" ]; then TCP_PASSIVE_RANGE="$NEW_RNG"; save_config; echo -e "${GREEN}Saved.${NC}"; fi
                sleep 1
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
        # 1. Save Configuration
        BAN_TIMEOUT="$NEW_VAL"
        save_config
        
        # 2. HOT SWAP APPLICATION (ATOMIC UPDATE)
        echo -e "\n${YELLOW}Applying new structure to running IPsets...${NC}"
        
        # --- IPv4 Handling ---
        if ipset list -n AutoBan >/dev/null 2>&1; then
            echo " -> Rebuilding AutoBan (v4) with timeout $NEW_VAL..."
            # Create a temporary list with the NEW timeout value
            if [ "$NEW_VAL" -eq "0" ]; then
                ipset create AutoBan_TMP hash:net maxelem 524288 counters -exist
            else
                ipset create AutoBan_TMP hash:net timeout "$NEW_VAL" maxelem 524288 counters -exist
            fi
            
            # Swap the active list with the temporary one (Atomic Swap)
            # The old list (static/wrong) becomes _TMP, the new one becomes AutoBan
            ipset swap AutoBan_TMP AutoBan
            
            # Destroy the old list
            ipset destroy AutoBan_TMP
            echo -e "${GREEN} -> v4 Updated.${NC}"
        fi

        # --- IPv6 Handling ---
        if [ "$ENABLE_IPV6" = "true" ] && ipset list -n AutoBan6 >/dev/null 2>&1; then
            echo " -> Rebuilding AutoBan (v6) with timeout $NEW_VAL..."
            if [ "$NEW_VAL" -eq "0" ]; then
                ipset create AutoBan6_TMP hash:net family inet6 maxelem 65536 counters -exist
            else
                ipset create AutoBan6_TMP hash:net family inet6 timeout "$NEW_VAL" maxelem 65536 counters -exist
            fi
            ipset swap AutoBan6_TMP AutoBan6
            ipset destroy AutoBan6_TMP
            echo -e "${GREEN} -> v6 Updated.${NC}"
        fi

        echo -e "\n${GREEN}Timeout updated successfully without restart.${NC}"
    else
        echo -e "${RED}Invalid input.${NC}"
    fi
    pause
}

# --- WHITELIST MENU ---
do_whitelist_menu() {
    while true; do
        show_header
        echo -e "${YELLOW}--- WHITELIST MANAGER ---${NC}"
        echo -e "Trusted IPs/Subnets bypass ALL firewall blocks."
        echo ""
        echo -e " 1) Add IP/Subnet to Whitelist"
        echo -e " 2) Remove IP/Subnet"
        echo -e " 3) View Current Whitelist"
        echo -e " 0) Back"
        echo ""
        echo -n "Selection: "
        read -r w_opt
        
        case $w_opt in
            1)
                echo -n "Enter IP or Subnet (e.g. 192.168.1.5 or 10.0.0.0/8): "
                read -r new_ip
                if [ -n "$new_ip" ]; then
                    # Basic validation and append
                    echo "$new_ip" >> "$WHITELIST_FILE"
                    if echo "$new_ip" | grep -q ":"; then
                        ipset add FirewallWhite6 "$new_ip" 2>/dev/null
                    else
                        ipset add FirewallWhite "$new_ip" 2>/dev/null
                    fi
                    echo -e "${GREEN}Added to whitelist.${NC}"
                fi
                sleep 1
                ;;
            2)
                echo -n "Enter IP or Subnet to remove: "
                read -r rem_ip
                if [ -n "$rem_ip" ]; then
                    # Remove from file
                    sed -i "\@^$rem_ip\$@d" "$WHITELIST_FILE"
                    # Remove from active sets
                    ipset del FirewallWhite "$rem_ip" 2>/dev/null
                    ipset del FirewallWhite6 "$rem_ip" 2>/dev/null
                    echo -e "${YELLOW}Removed from whitelist.${NC}"
                fi
                sleep 1
                ;;
            3)
                echo -e "\n${CYAN}--- Active Whitelist ($WHITELIST_FILE) ---${NC}"
                if [ -s "$WHITELIST_FILE" ]; then
                    cat "$WHITELIST_FILE"
                else
                    echo "List is empty."
                fi
                pause
                ;;
            0) return ;;
            *) sleep 1 ;;
        esac
    done
}

# --- REPORTER SETUP ---
do_reporter_setup() {
    while true; do
        show_header
        echo -e "${YELLOW}--- AbuseIPDB API Settings ---${NC}"
        
        if [ -s "$KEY_FILE" ]; then
            echo -e "Current API Key: ${GREEN}CONFIGURED${NC} ($(wc -c < "$KEY_FILE") chars)"
        else
            echo -e "Current API Key: ${RED}NOT CONFIGURED${NC}"
        fi
        
        echo -e "\n 1) Enter/Update API Key"
        echo -e " 2) Clear API Key"
        echo -e " 3) Set Reporting Cooldown [Current: ${CYAN}${REPORT_COOLDOWN}s${NC}]"
        echo -e " 0) Back"
        echo ""
        echo -n "Selection: "
        read -r r_opt
        
        case $r_opt in
            1)
                echo -n "Paste your AbuseIPDB API Key: "
                read -r new_key
                if [ -n "$new_key" ]; then
                    echo "$new_key" | tr -d '[:space:]' > "$KEY_FILE"
                    chmod 600 "$KEY_FILE"
                    echo -e "${GREEN}Key saved successfully.${NC}"
                fi
                sleep 1
                ;;
            2)
                > "$KEY_FILE"
                echo -e "${YELLOW}Key cleared.${NC}"
                sleep 1
                ;;
            3)
                echo -n "Enter Cooldown in seconds (Default 604800 for 7 days): "
                read -r new_cool
                if echo "$new_cool" | grep -qE '^[0-9]+$'; then
                    REPORT_COOLDOWN="$new_cool"
                    save_config
                    echo -e "${GREEN}Cooldown updated.${NC}"
                else
                    echo -e "${RED}Invalid input.${NC}"
                fi
                sleep 1
                ;;
            0) return ;;
            *) sleep 1 ;;
        esac
    done
}

# --- FLUSH MENU (MANUAL CLEANUP) ---
do_flush_menu() {
    while true; do
        show_header
        echo -e "${YELLOW}--- FLUSH IP SETS (CLEAR LISTS) ---${NC}"
        echo -e "Select a list to empty immediately:"
        echo ""
        echo -e " 1) AutoBan (Dynamic Bans)     [v4/v6]"
        echo -e " 2) FirewallBlock (Static)     [v4/v6]"
        echo -e " 3) VPNBlock (VPN Bad IPs)     [v4]"
        echo -e " 4) Whitelist (Trusted)        [v4/v6]"
        echo -e " 9) ${RED}FLUSH ALL LISTS${NC}"
        echo -e " 0) Back"
        echo ""
        echo -n "Select option: "
        read -r fopt
        
        case $fopt in
            1) 
                ipset flush AutoBan 2>/dev/null
                ipset flush AutoBan6 2>/dev/null
                echo -e "${GREEN}AutoBan lists flushed.${NC}"
                sleep 1 
                ;;
            2) 
                ipset flush FirewallBlock 2>/dev/null
                ipset flush FirewallBlock6 2>/dev/null
                echo -e "${GREEN}Static Blocklists flushed.${NC}"
                sleep 1 
                ;;
            3) 
                ipset flush VPNBlock 2>/dev/null
                echo -e "${GREEN}VPNBlock flushed.${NC}"
                sleep 1 
                ;;
            4) 
                ipset flush FirewallWhite 2>/dev/null
                ipset flush FirewallWhite6 2>/dev/null
                echo -e "${GREEN}Whitelists flushed.${NC}"
                sleep 1 
                ;;
            9) 
                echo -e "${RED}WARNING: You are about to remove ALL protections.${NC}"
                echo -n "Are you sure? (y/n): "
                read -r confirm
                if [ "$confirm" = "y" ]; then
                    ipset flush
                    echo -e "${RED}ALL IP SETS FLUSHED.${NC}"
                    sleep 1
                fi
                ;;
            0) return ;;
            *) echo "Invalid option"; sleep 1 ;;
        esac
    done
}

do_settings() {
    load_config
    while true; do
        show_header
        echo -e "${YELLOW}--- CONFIGURATION SETTINGS ---${NC}"
        
        # Status Flags & Colors
        if [ "$ENABLE_IPV6" = "true" ]; then ST_V6="${GREEN}ON${NC}"; else ST_V6="${RED}OFF${NC}"; fi
        if [ "$ENABLE_FWD_PROTECTION" = "true" ]; then ST_FWD="${GREEN}ON${NC}"; else ST_FWD="${RED}OFF${NC}"; fi
        
        # New Security Modules Status
        if [ "$ENABLE_AUTOBAN" = "true" ]; then ST_BAN_TOG="${GREEN}ON${NC}"; else ST_BAN_TOG="${RED}OFF${NC}"; fi
        if [ "$ENABLE_BRUTEFORCE" = "true" ]; then ST_BF_TOG="${GREEN}ON${NC}"; else ST_BF_TOG="${RED}OFF${NC}"; fi
        if [ "$ENABLE_CONNLIMIT" = "true" ]; then ST_CONN="${GREEN}ON${NC}"; else ST_CONN="${RED}OFF${NC}"; fi

        # Stats for display
        CNT_V4=$(echo "$SOURCES_V4" | awk '{print NF}')
        CNT_V6=$(echo "$SOURCES_V6" | awk '{print NF}')
        if [ "$BAN_TIMEOUT" -eq 0 ]; then ST_TIMEOUT="${RED}Unlimited${NC}"; else ST_TIMEOUT="${GREEN}${BAN_TIMEOUT}s${NC}"; fi
        ST_BF_SENS="${WHITE}${BF_HITCOUNT}hits/${BF_SECONDS}s${NC}"

        # --- MENU LAYOUT ---
        echo -e " 1) IPv6 Support ....................... [$ST_V6]"
        echo -e " 2) Forward Protection (NAS/DMZ) ....... [$ST_FWD]"
        echo -e "${DIM} ---------------------------------------${NC}"
        echo -e " 3) AutoBan (Dynamic Blacklisting) ..... [$ST_BAN_TOG]"
        echo -e " 4) BruteForce Protection .............. [$ST_BF_TOG]"
        echo -e " 5) DDoS ConnLimit (Max: $CONNLIMIT_MAX) ........... [$ST_CONN]"
        echo -e "${DIM} ---------------------------------------${NC}"
        echo -e " 6) Manage IPv4 Sources ................ [${WHITE}$CNT_V4 Active${NC}]"
        echo -e " 7) Manage IPv6 Sources ................ [${WHITE}$CNT_V6 Active${NC}]"
        echo -e " 8) Allowed Ports (TCP/UDP) ............ [${WHITE}Edit...${NC}]"
        echo -e " 9) Auto-Ban Timeout ................... [$ST_TIMEOUT]"
        echo -e " 10) Brute-Force Sensitivity ........... [$ST_BF_SENS]"
        echo -e " 11) AbuseIPDB Settings ................ [${WHITE}Key & Cooldown${NC}]"
        echo ""
        echo -e " 0) ${GREEN}Apply Changes & Return${NC} (Restarts Hook)"
        echo -e " x) ${RED}Return WITHOUT applying${NC} (Keep current rules)"
        echo ""
        echo -n "Select option: "
        read -r SOPT
        
        case $SOPT in
            1) 
                if [ "$ENABLE_IPV6" = "true" ]; then ENABLE_IPV6="false"; else ENABLE_IPV6="true"; fi
                save_config 
                ;;
            2) 
                if [ "$ENABLE_FWD_PROTECTION" = "true" ]; then 
                    ENABLE_FWD_PROTECTION="false"
                else 
                    echo -e "${YELLOW}WARNING: This blocks traffic to internal servers unless whitelisted!${NC}"
                    read -p "Confirm? (y/n): " c; [ "$c" = "y" ] && ENABLE_FWD_PROTECTION="true"
                fi
                save_config 
                ;;
            3) 
                # AutoBan Logic with Flush Prompt
                if [ "$ENABLE_AUTOBAN" = "true" ]; then 
                    ENABLE_AUTOBAN="false"
                    echo ""
                    echo -e "${YELLOW}AutoBan Disabled.${NC}"
                    read -p "Do you want to FLUSH existing banned IPs? (y/n): " flush_confirm
                    if [ "$flush_confirm" = "y" ]; then
                        ipset flush AutoBan 2>/dev/null
                        ipset flush AutoBan6 2>/dev/null
                        echo -e "${GREEN}AutoBan lists cleared.${NC}"
                        sleep 1
                    fi
                else 
                    ENABLE_AUTOBAN="true"
                fi
                save_config 
                ;;
            4) 
                if [ "$ENABLE_BRUTEFORCE" = "true" ]; then ENABLE_BRUTEFORCE="false"; else ENABLE_BRUTEFORCE="true"; fi
                save_config 
                ;;
            5) 
                # ConnLimit Logic with Config
                if [ "$ENABLE_CONNLIMIT" = "true" ]; then 
                    ENABLE_CONNLIMIT="false"
                else 
                    ENABLE_CONNLIMIT="true"
                    echo ""
                    echo -n "Enter Max Connections per IP [Current: $CONNLIMIT_MAX]: "
                    read -r new_max
                    if [ -n "$new_max" ]; then CONNLIMIT_MAX="$new_max"; fi
                fi
                save_config 
                ;;
            6) do_manage_sources "V4" ;;
            7) do_manage_sources "V6" ;;
            8) do_port_editor ;;
            9) do_timeout_setup ;;
            10) do_bf_setup ;;
            11) do_reporter_setup ;;
            0)
                # Execute hook cleanly in background logic
                echo -e "\n${YELLOW}Applying configuration and restarting Firewall Hook...${NC}"
                if [ -x "$SCRIPT_HOOK" ]; then 
                    table=filter "$SCRIPT_HOOK" >/dev/null 2>&1
                    echo -e "${GREEN}Firewall rules updated successfully.${NC}"
                else 
                    echo -e "${RED}Hook script missing!${NC}"
                fi
                sleep 1
                return 
                ;;
            x|X)
                # Exit without applying
                echo -e "\n${YELLOW}Returning to Main Menu... (Rules not restarted)${NC}"
                sleep 1
                return
                ;;
            *) echo "Invalid option"; sleep 1 ;;
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

    # 1. SYSTEM HEALTH
    echo -e "\n${BOLD}1. System Components${NC}"
    
    # Check Logging Daemon (ULOGD)
    # Robust check with ps
    if ps | grep -v grep | grep -q "ulogd"; then 
        echo -e "   Logger (ULOGD):     ${GREEN}RUNNING${NC}"
    else 
        echo -e "   Logger (ULOGD):     ${RED}STOPPED (No logs will be recorded)${NC}"
    fi

    # Check Scheduler (CRON & JOB) - ROBUST FIX
    # Check both 'crond' and 'cron' using ps
    if ! ps | grep -v grep | grep -qE "crond|cron"; then 
        echo -e "   Scheduler (CRON):   ${RED}STOPPED (Daemon not running)${NC}"
    else 
        # Daemon is running, verify if the job exists
        if crontab -l 2>/dev/null | grep -q "update_blocklist.sh"; then
            echo -e "   Scheduler (CRON):   ${GREEN}ACTIVE (Job scheduled)${NC}"
        else
            echo -e "   Scheduler (CRON):   ${YELLOW}WARNING (Daemon ON, but Job MISSING)${NC}"
        fi
    fi

    # Check Kernel Modules
    if lsmod | grep -q "xt_recent"; then 
        echo -e "   BruteForce Module:  ${GREEN}LOADED${NC}"
    else 
        echo -e "   BruteForce Module:  ${RED}MISSING (xt_recent)${NC}"
    fi

    # 2. IP SETS STATUS
    echo -e "\n${BOLD}2. IP Sets Status${NC}"
    
    # --- IPv4 ---
    CNT_V4=$(ipset list FirewallBlock 2>/dev/null | grep -cE '^[0-9]')
    if [ "$CNT_V4" -gt 100 ]; then STATUS="${GREEN}OK ($CNT_V4 IPs)${NC}"; else STATUS="${RED}CRITICAL (Empty/Low: $CNT_V4)${NC}"; fi
    echo -e "   IPv4 Blocklist:     $STATUS"
    
    CNT_WHITE=$(ipset list FirewallWhite 2>/dev/null | grep -cE '^[0-9]')
    echo -e "   IPv4 Whitelist:     ${CYAN}$CNT_WHITE IPs${NC}"
    
    CNT_BAN=$(ipset list AutoBan 2>/dev/null | grep -cE '^[0-9]')
    if ipset list AutoBan >/dev/null 2>&1; then 
        echo -e "   Auto-Ban (Trap):    ${GREEN}ACTIVE${NC} (${RED}$CNT_BAN IPs${NC})"
    else 
        echo -e "   Auto-Ban (Trap):    ${RED}MISSING${NC}"
    fi
    
    CNT_VPN=$(ipset list VPNBlock 2>/dev/null | grep -cE '^[0-9]')
    echo -e "   VPN Blocklist:      ${CYAN}$CNT_VPN IPs${NC}"
    
    # --- IPv6 ---
    if [ "$ENABLE_IPV6" = "true" ]; then
        CNT_V6=$(ipset list FirewallBlock6 2>/dev/null | grep -cE '^[0-9a-fA-F:]')
        if [ "$CNT_V6" -gt 10 ]; then STATUS="${GREEN}OK ($CNT_V6 IPs)${NC}"; else STATUS="${RED}CRITICAL (Empty: $CNT_V6)${NC}"; fi
        echo -e "   IPv6 Blocklist:     $STATUS"
        
        # IPv6 Whitelist Display
        CNT_WHITE6=$(ipset list FirewallWhite6 2>/dev/null | grep -cE '^[0-9a-fA-F:]')
        echo -e "   IPv6 Whitelist:     ${CYAN}$CNT_WHITE6 IPs${NC}"
        
        CNT_BAN6=$(ipset list AutoBan6 2>/dev/null | grep -cE '^[0-9a-fA-F:]')
        if ipset list AutoBan6 >/dev/null 2>&1; then 
            echo -e "   Auto-Ban6 (Trap):   ${GREEN}ACTIVE${NC} (${RED}$CNT_BAN6 IPs${NC})"
        else 
            echo -e "   Auto-Ban6 (Trap):   ${RED}MISSING${NC}"
        fi
    else
        echo -e "   IPv6 Support:       ${DIM}Disabled${NC}"
    fi
    
    # 3. CHAIN INTEGRATION
    echo -e "\n${BOLD}3. Firewall Integration${NC}"
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
do_stats() { echo -e "${YELLOW}Generating Stats & Dashboard...${NC}"; if [ -x "$SCRIPT_STATS" ]; then "$SCRIPT_STATS" force; echo -e "${GREEN}Done.${NC}"; fi; pause; }
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
    echo -e " 8) ${MAGENTA}⚙️  Configuration & Ports${NC}"
    echo -e " 9) ${GREEN}✅ Manage Whitelist${NC} (IPs/Domains)"
    echo -e " f) ${RED}🗑️  Flush Lists (Manually)${NC}"
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
        f|F) do_flush_menu ;;
        e|E) exit 0 ;;
        *) sleep 1 ;;
    esac
done
