#!/opt/bin/bash
# VPN LOG ANALYZER v2.0.0
# Release: 2026-10-22 | Stable. See CHANGELOG.md for release details.

# VPN LOG ANALYZER v1.3.3 - threshold, whitelist, incremental cursor and expiry
export PATH=${KT_PATH:-/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin}
. "${KT_COMMON:-/opt/lib/keentool/common.sh}" || exit 1
kt_init vpn-scan || exit $?
CONF=${KT_FW_CONF:-/opt/etc/firewall.conf};[ ! -f "$CONF" ] || . "$CONF"
: "${VPN_FAILURE_THRESHOLD:=5}" "${VPN_FAILURE_WINDOW:=900}" "${VPN_BAN_TIMEOUT:=86400}"
for value in "$VPN_FAILURE_THRESHOLD" "$VPN_FAILURE_WINDOW" "$VPN_BAN_TIMEOUT"; do [[ "$value" =~ ^[0-9]+$ ]] || exit 1; done
LOG_FILE=${KT_VPN_LOG:-/opt/var/log/messages};[ -n "${KT_VPN_LOG:-}" ] || { [ ! -f /opt/var/log/vpn.log ] || LOG_FILE=/opt/var/log/vpn.log; }
[ -f "$LOG_FILE" ] || exit 1
STATE_DIR=${KT_VPN_STATE:-/opt/etc/keentool/vpn};VPN_SAVE=${KT_VPN_SAVE:-/opt/etc/vpn_banned_ips.txt};export LC_ALL=C; mkdir -p "$STATE_DIR"
now=${KT_NOW:-$(date +%s)}; inode=$(kt_stat %i "$LOG_FILE"); size=$(wc -c < "$LOG_FILE")
read -r old_inode offset < "$STATE_DIR/cursor" 2>/dev/null || offset=0
if [ "${old_inode:-}" != "$inode" ] || [ "$size" -lt "${offset:-0}" ]; then offset=0; fi
# Copy only the bytes present at this snapshot; last incomplete line is retried.
if [ "$size" -gt "$offset" ]; then
    tail -c +$((offset+1)) "$LOG_FILE" | head -c $((size-offset)) > "$KT_WORKDIR/newlog"
    if [ -s "$KT_WORKDIR/newlog" ] && [ "$(tail -c 1 "$KT_WORKDIR/newlog" | wc -l)" = 0 ];then
        trailing=$(tail -n 1 "$KT_WORKDIR/newlog")
        complete=$((size-offset-${#trailing}))
        head -c "$complete" "$KT_WORKDIR/newlog" > "$KT_WORKDIR/complete"
        mv "$KT_WORKDIR/complete" "$KT_WORKDIR/newlog"
        size=$((offset+complete))
    fi
    # Do not backfill old logs on first installation; establish cursor only.
    if [ -f "$STATE_DIR/cursor" ]; then
        awk '/TLS handshake failed|Bad encapsulated packet length/{for(i=1;i<=NF;i++){x=$i;gsub(/[^0-9.:]/,"",x);if(x~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?$/){sub(/:[0-9]+$/, "",x);print x;break}}}' "$KT_WORKDIR/newlog" |
        while read -r ip; do printf '%s %s\n' "$now" "$ip"; done >> "$STATE_DIR/failures"
    fi
fi
printf '%s %s\n' "$inode" "$size" > "$STATE_DIR/cursor"
[ -f "$STATE_DIR/failures" ] || touch "$STATE_DIR/failures"
awk -v cutoff="$((now-VPN_FAILURE_WINDOW))" '$1>=cutoff' "$STATE_DIR/failures" > "$KT_WORKDIR/recent"
mv "$KT_WORKDIR/recent" "$STATE_DIR/failures"
awk -v n="$VPN_FAILURE_THRESHOLD" '{c[$2]++}END{for(ip in c)if(c[ip]>=n)print ip}' "$STATE_DIR/failures" > "$KT_WORKDIR/candidates"
[ -f "$STATE_DIR/bans" ] || touch "$STATE_DIR/bans"
# expire only scanner-owned bans; legacy persistent list is preserved independently
while read -r expiry ip; do
    if [ "$expiry" -gt "$now" ]; then printf '%s %s\n' "$expiry" "$ip" >> "$KT_WORKDIR/kept"
    else ipset del VPNBlock "$ip" 2>/dev/null || :; fi
done < "$STATE_DIR/bans"
: >> "$KT_WORKDIR/kept"
while read -r ip; do
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    if ipset test FirewallWhite "$ip" >/dev/null 2>&1 || ipset test FirewallBlock "$ip" >/dev/null 2>&1 || ipset test VPNBlock "$ip" >/dev/null 2>&1; then continue; fi
    case "$ip" in 10.*|127.*|192.168.*|169.254.*|172.1[6-9].*|172.2?.*|172.3[01].*) continue;;esac
    if ipset add VPNBlock "$ip"; then printf '%s %s\n' "$((now+VPN_BAN_TIMEOUT))" "$ip" >> "$KT_WORKDIR/kept"; logger -t VPN_Blocker "Banned $ip after repeated VPN failures"; fi
done < "$KT_WORKDIR/candidates"
mv "$KT_WORKDIR/kept" "$STATE_DIR/bans"
# Only these current scanner bans are persisted in the legacy file consumed by the hook.
# Preserve original entries in a separate immutable legacy file on first run.
if [ ! -f "$STATE_DIR/legacy" ]; then cp "$VPN_SAVE" "$STATE_DIR/legacy" 2>/dev/null || touch "$STATE_DIR/legacy"; fi
{ cat "$STATE_DIR/legacy"; awk '{print $2}' "$STATE_DIR/bans"; } | sort -u > "$VPN_SAVE.tmp"
mv "$VPN_SAVE.tmp" "$VPN_SAVE"
