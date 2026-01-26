#!/bin/sh

# ==============================================================================
# KEENETIC FIREWALL MANAGER v1.0
# Central Hub to manage all firewall scripts interactively.
# Changelog: v1.5 - Soft Trap fix (Allows Monitor to handle Ctrl+C correctly)
# ==============================================================================

export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin

# --- CONFIGURATION ---
SCRIPT_MONITOR="/opt/bin/firewall_monitor"
SCRIPT_UPDATE="/opt/bin/update_blocklist.sh"
SCRIPT_STATS="/opt/bin/firewall_stats.sh"
SCRIPT_VPN="/opt/bin/vpn_scan.sh"
CONF_CRON="/opt/etc/crontab"

# --- TRAP CTRL+C (THE FIX v1.5) ---
# We define a function that does nothing. This is a "Soft Trap".
# Unlike "trap '' INT" (Hard Ignore), this allows child processes (like monitor)
# to OVERRIDE the trap and exit correctly when Ctrl+C is pressed.
ctrl_c_handler() {
    return
}
trap ctrl_c_handler INT

# Colors (High Contrast)
RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Helper: Header
show_header() {
    clear
    echo -e "${CYAN}=================================================${NC}"
    echo -e "${WHITE}      KEENETIC FIREWALL MANAGER v1.0      ${NC}"
    echo -e "${CYAN}=================================================${NC}"
}

# Helper: Press Enter
pause() {
    echo ""
    echo -e "${CYAN}Press [Enter] to continue...${NC}"
    read -r
}

# --- ACTIONS ---

do_monitor() {
    if [ -x "$SCRIPT_MONITOR" ]; then 
        # Launch monitor. Thanks to Soft Trap, it can now handle its own Ctrl+C
        "$SCRIPT_MONITOR"
    else 
        echo -e "${RED}Script not found!${NC}"
        pause
    fi
}

do_update() {
    echo -e "${YELLOW}Updating Blocklists...${NC}"
    if [ -x "$SCRIPT_UPDATE" ]; then "$SCRIPT_UPDATE"; echo -e "${GREEN}Done.${NC}"; else echo -e "${RED}Script not found!${NC}"; fi
    pause
}

do_stats() {
    echo -e "${YELLOW}Generating Statistics...${NC}"
    if [ -x "$SCRIPT_STATS" ]; then "$SCRIPT_STATS"; echo -e "${GREEN}Done.${NC}"; else echo -e "${RED}Script not found!${NC}"; fi
    pause
}

do_vpn() {
    echo -e "${YELLOW}Scanning VPN Logs...${NC}"
    if [ -x "$SCRIPT_VPN" ]; then "$SCRIPT_VPN"; echo -e "${GREEN}Done.${NC}"; else echo -e "${RED}Script not found!${NC}"; fi
    pause
}

do_status() {
    echo -e "${YELLOW}Checking Firewall Chains...${NC}"
    CNT_MAIN=$(ipset list FirewallBlock 2>/dev/null | grep -cE '^[0-9]')
    CNT_VPN=$(ipset list VPNBlock 2>/dev/null | grep -cE '^[0-9]')
    echo -e "Blocklists Loaded: Main=${WHITE}$CNT_MAIN${NC}, VPN=${WHITE}$CNT_VPN${NC}"
    echo ""
    echo -e "${CYAN}[BLOCKLIST_IN Top 3]${NC}"
    iptables -L BLOCKLIST_IN -n -v | head -n 5
    echo ""
    echo -e "${CYAN}[BLOCKLIST_FWD Top 3]${NC}"
    iptables -L BLOCKLIST_FWD -n -v | head -n 5
    pause
}

# --- CRON WIZARD ---

apply_cron_change() {
    SCRIPT_PATH=$1
    SCHEDULE=$2
    NAME=$3
    
    grep -v "$SCRIPT_PATH" "$CONF_CRON" > "${CONF_CRON}.tmp"
    echo "$SCHEDULE root $SCRIPT_PATH > /dev/null 2>&1" >> "${CONF_CRON}.tmp"
    mv "${CONF_CRON}.tmp" "$CONF_CRON"
    
    echo -e "${GREEN}Success!${NC} $NAME scheduled: ${WHITE}[$SCHEDULE]${NC}"
    
    if [ -x /opt/etc/init.d/S10cron ]; then
        /opt/etc/init.d/S10cron restart >/dev/null 2>&1
    fi
}

ask_schedule_type() {
    TARGET_SCRIPT=$1
    TARGET_NAME=$2

    echo -e "${YELLOW}Scheduling: $TARGET_NAME${NC}"
    echo " 1) Every Day at a specific time"
    echo " 2) Every N Hours (Interval)"
    echo " 3) Every Hour at minute X"
    echo " 0) Cancel"
    echo -n "Select logic: "
    read -r SCH_OPT
    
    case $SCH_OPT in
        1) # Daily
            echo -n "Enter Hour (0-23): "; read -r HH
            echo -n "Enter Minute (0-59): "; read -r MM
            if [ "$HH" -ge 0 ] && [ "$HH" -le 23 ] && [ "$MM" -ge 0 ] && [ "$MM" -le 59 ]; then
                apply_cron_change "$TARGET_SCRIPT" "$MM $HH * * *" "$TARGET_NAME"
            else
                echo -e "${RED}Invalid time!${NC}"
            fi
            ;;
        2) # Interval
            echo -n "Run every how many hours? (e.g. 4): "; read -r HH
            if [ "$HH" -gt 0 ]; then
                apply_cron_change "$TARGET_SCRIPT" "0 */$HH * * *" "$TARGET_NAME"
            else
                echo -e "${RED}Invalid interval!${NC}"
            fi
            ;;
        3) # Hourly
            echo -n "At which minute? (0-59): "; read -r MM
            if [ "$MM" -ge 0 ] && [ "$MM" -le 59 ]; then
                apply_cron_change "$TARGET_SCRIPT" "$MM * * * *" "$TARGET_NAME"
            else
                echo -e "${RED}Invalid minute!${NC}"
            fi
            ;;
        *) return ;;
    esac
}

do_cron_wizard() {
    while true; do
        show_header
        echo -e "${YELLOW}--- AUTOMATION MANAGER (CRONTAB) ---${NC}"
        echo -e "Current Full Schedule:"
        echo -e "${CYAN}-------------------------------------------------${NC}"
        if [ -f "$CONF_CRON" ]; then
            cat "$CONF_CRON"
        else
            echo -e "${RED}Crontab file not found!${NC}"
        fi
        echo -e "${CYAN}-------------------------------------------------${NC}"
        echo ""
        echo "Select a Firewall task to reschedule:"
        echo " 1) Blocklist Update    (Default: Daily 04:00)"
        echo " 2) Stats Generation    (Default: Hourly :01)"
        echo " 3) VPN Scan            (Default: Every 3h)"
        echo " 0) Back to Main Menu"
        echo ""
        echo -n "Option: "
        read -r SUB_OPT

        case $SUB_OPT in
            1) ask_schedule_type "$SCRIPT_UPDATE" "Blocklist Update" ;;
            2) ask_schedule_type "$SCRIPT_STATS" "Stats Gen" ;;
            3) ask_schedule_type "$SCRIPT_VPN" "VPN Scan" ;;
            0) return ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
        pause
    done
}

# --- MAIN MENU ---

while true; do
    show_header
    echo -e " 1) ${GREEN}📊 Show Live Monitor${NC}"
    echo -e " 2) ${CYAN}🔄 Update Blocklists${NC}"
    echo -e " 3) ${CYAN}📈 Generate Statistics${NC}"
    echo -e " 4) ${CYAN}🔎 Run VPN Scan${NC}"
    echo -e " 5) ${YELLOW}⏰ Check/Edit Automation (Cron)${NC}"
    echo -e " 6) ${YELLOW}🛡️ Check Firewall Status${NC}"
    echo -e " e) ${RED}❌ Exit${NC}"
    echo -e "${CYAN}-------------------------------------------------${NC}"
    echo -n "Select an option: "
    read -r OPTION

    case $OPTION in
        1) do_monitor ;;
        2) do_update ;;
        3) do_stats ;;
        4) do_vpn ;;
        5) do_cron_wizard ;;
        6) do_status ;;
        e|E) echo "Goodbye!"; exit 0 ;;
        *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
    esac
done
