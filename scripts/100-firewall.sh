#!/bin/sh

# ==============================================================================
# KEENETIC FIREWALL HOOK (DUAL LIST)
# Description: Integrates IPSET blocklists with Keenetic NDM Netfilter.
#              Manages both downloaded lists and local VPN bans.
# ==============================================================================

# 1. LISTA ESTERNA (Quella da 20k+ IP, gestita da script esterno)
IPSET_MAIN="FirewallBlock"

# 2. LISTA LOCALE (Quella generata dallo scan dei log VPN)
IPSET_VPN="VPNBlock"
VPN_BANNED_FILE="/opt/etc/vpn_banned_ips.txt"

# --- SECTION: FILTER TABLE ONLY ---
[ "$table" != "filter" ] && exit 0

# --- INIZIALIZZAZIONE IPSET LOCALE ---
# Creiamo il set per la VPN se non esiste (hash:ip perché sono IP singoli)
ipset create "$IPSET_VPN" hash:ip hashsize 1024 maxelem 65536 -exist 2>/dev/null

# --- RIPRISTINO PERSISTENZA (Fondamentale al riavvio) ---
# Se il set è vuoto ma abbiamo un file di salvataggio, ricarichiamo gli IP
if [ -f "$VPN_BANNED_FILE" ]; then
    # Leggiamo il file e aggiungiamo silenziosamente gli IP al set
    while read -r ip; do
        [ -n "$ip" ] && ipset add "$IPSET_VPN" "$ip" -exist 2>/dev/null
    done < "$VPN_BANNED_FILE"
fi

# Verifica di sicurezza: se il set Main non esiste, non applicare le sue regole (ma applica VPNBlock)
MAIN_EXISTS=0
ipset list -n "$IPSET_MAIN" >/dev/null 2>&1 && MAIN_EXISTS=1

# --- A. CLEANUP (Pulizia vecchie regole) ---
iptables -D INPUT -m set --match-set "$IPSET_MAIN" src -j DROP 2>/dev/null
iptables -D FORWARD -m set --match-set "$IPSET_MAIN" src -j DROP 2>/dev/null
iptables -D INPUT -m set --match-set "$IPSET_VPN" src -j DROP 2>/dev/null
iptables -D FORWARD -m set --match-set "$IPSET_VPN" src -j DROP 2>/dev/null

# Pulizia whitelist
iptables -D INPUT -s 10.0.0.0/8 -j ACCEPT 2>/dev/null
iptables -D FORWARD -s 10.0.0.0/8 -j ACCEPT 2>/dev/null
iptables -D FORWARD -i tun+ -j ACCEPT 2>/dev/null
iptables -D INPUT -i tun+ -j ACCEPT 2>/dev/null
iptables -D INPUT -i lo -j ACCEPT 2>/dev/null
iptables -D INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null

# --- B. APPLICAZIONE REGOLE (Ordine Inverso - LIFO) ---

# === FORWARD CHAIN (LAN/VPN -> Internet) ===

# 5. BLOCK: Traffico dalla lista principale (Internet)
[ "$MAIN_EXISTS" -eq 1 ] && iptables -I FORWARD -m set --match-set "$IPSET_MAIN" src -j DROP

# 4. BLOCK: Traffico dalla lista VPN (Attaccanti specifici)
iptables -I FORWARD -m set --match-set "$IPSET_VPN" src -j DROP

# 3. WHITELIST: Interfacce VPN (Permetti traffico legittimo attraverso il tunnel)
iptables -I FORWARD -i tun+ -j ACCEPT

# 2. WHITELIST: Reti Private (LAN)
iptables -I FORWARD -s 10.0.0.0/8 -j ACCEPT

# 1. PRIORITY: Connessioni Stabilite
iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT


# === INPUT CHAIN (Verso il Router) ===

# 5. BLOCK: Traffico dalla lista principale
[ "$MAIN_EXISTS" -eq 1 ] && iptables -I INPUT -m set --match-set "$IPSET_MAIN" src -j DROP

# 4. BLOCK: Traffico dalla lista VPN
iptables -I INPUT -m set --match-set "$IPSET_VPN" src -j DROP

# 3. WHITELIST: Interfacce VPN
iptables -I INPUT -i tun+ -j ACCEPT

# 2. WHITELIST: LAN & Localhost
iptables -I INPUT -s 10.0.0.0/8 -j ACCEPT
iptables -I INPUT -i lo -j ACCEPT

# 1. PRIORITY: Connessioni Stabilite
iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
