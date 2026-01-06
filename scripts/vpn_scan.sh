#!/bin/sh
# ANALIZZATORE LOG VPN -> IPSET
# Versione Integrata con IPSET Locale

# --- PERCORSI ---
# Nota: Usiamo i comandi diretti, assumendo che il PATH sia corretto in Entware
LOG_FILE="/opt/var/log/messages"
BANNED_IPS_FILE="/opt/etc/vpn_banned_ips.txt"
IPSET_VPN="VPNBlock"
LOG_TAG="VPN_Blocker"

# Regex per trovare gli errori OpenVPN
SEARCH_PATTERN='TLS handshake failed|Bad encapsulated packet length'

# Crea il file se non esiste
touch "$BANNED_IPS_FILE"

# Verifica esistenza log
if [ ! -f "$LOG_FILE" ]; then
    logger -t "${LOG_TAG}" "Errore: File di log non trovato: $LOG_FILE. Uscita."
    exit 1
fi

# Estrae gli IP unici malevoli dal log
MALICIOUS_IPS=$(grep -i "openvpn" "$LOG_FILE" | grep -E "$SEARCH_PATTERN" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u)

ip_count=0

if [ -n "$MALICIOUS_IPS" ]; then
    for IP in $MALICIOUS_IPS; do
        # Verifica se l'IP è già nel file di testo (persistenza)
        if ! grep -qF "$IP" "$BANNED_IPS_FILE"; then
            
            # 1. Aggiunge l'IP al set IPSET attivo (Blocco immediato)
            # -exist evita errori se l'IP è già in memoria ma non nel file
            ipset add "$IPSET_VPN" "$IP" -exist 2>/dev/null
            
            # 2. Salva l'IP nel file per il riavvio (Persistenza)
            echo "$IP" >> "$BANNED_IPS_FILE"
            
            logger -t "${LOG_TAG}" "Nuovo IP malevolo rilevato: $IP. Aggiunto a IPSET e File."
            ip_count=$((ip_count + 1))
        fi
        
        # Opzionale: Se l'IP è nel file ma per qualche motivo non nell'ipset (es. flush manuale),
        # decommenta la riga sotto per forzare il blocco in memoria
        # ipset add "$IPSET_VPN" "$IP" -exist 2>/dev/null
    done
fi

#if [ "$ip_count" -gt 0 ]; then
    logger -t "${LOG_TAG}" "Controllo terminato. Bloccati ${ip_count} NUOVI IP."
#fi
# Se count è 0, evitiamo di spammare il log, oppure usa logger se preferisci vedere l'heartbeat

exit 0
