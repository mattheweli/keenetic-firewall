#!/opt/bin/bash
# BLOCKLIST UPDATER v3.0.0
# Release: 2026-10-22 | Stable. See CHANGELOG.md for release details.

set -o pipefail
export PATH=${KT_PATH:-/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin}
. "${KT_COMMON:-/opt/lib/keentool/common.sh}" || exit 1
kt_init firewall-update || exit $?
CONF_FILE=/opt/etc/firewall.conf
[ ! -f "$CONF_FILE" ] || . "$CONF_FILE"
: "${ENABLE_IPV6:=true}" "${UPDATE_INTERFACE:=}" "${BANNED_COUNTRIES:=}"
: "${SOURCES_V4=https://iplists.firehol.org/files/firehol_level1.netset https://blocklist.greensnow.co/greensnow.txt}"
: "${SOURCES_V6=https://www.spamhaus.org/drop/dropv6.txt}"
CACHE_DIR=/opt/etc/keentool/blocklist-cache; mkdir -p "$CACHE_DIR"
FAILED=0
valid_list() {
    local family=$1 input=$2
    if [ "$family" = inet ]; then
        awk '{sub(/;.*/,"");if($1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/){split($1,a,"/");n=split(a[1],b,".");ok=n==4;for(i=1;i<=4;i++)if(b[i]>255)ok=0;if(a[2]!="" && a[2]>32)ok=0;if(ok && b[1]!=0 && b[1]!=127 && b[1]<224 && b[1]!=10 && !(b[1]==192 && b[2]==168) && !(b[1]==172 && b[2]>=16 && b[2]<=31) && !(b[1]==169 && b[2]==254))print $1}}' "$input"
    else
        awk '{sub(/;.*/,"");if($1 ~ /^[0-9a-fA-F:]+(\/[0-9]+)?$/ && index($1,":") && $1 !~ /^::1(\/|$)/ && $1 !~ /^[fF][eE]80:/)print $1}' "$input"
    fi
}
source_label() {
    case "$1" in
        https://www.ipdeny.com/*) local name=${1##*/};printf 'ipdeny.com (%s)' "${name%-aggregated.zone}";;
        https://www.spamhaus.org/*) printf 'spamhaus.org';;
        https://api.abuseipdb.com/*) printf 'AbuseIPDB';;
        *) printf 'configured source';;
    esac
}
fetch_source() {
    local family=$1 url=$2 destination=$3 key raw clean cache label status rc code message family_label=IPv4
    key=$(printf '%s|%s' "$family" "$url" | sha256sum);key=${key%% *}
    cache="$CACHE_DIR/$key.list";raw="$KT_WORKDIR/raw_$key";clean="$KT_WORKDIR/clean_$key";label=$(source_label "$url")
    [ "$family" != inet6 ] || family_label=IPv6
    local -a opts=(-fsSL --connect-timeout 15 --max-time 60 --retry 1 --retry-connrefused --retry-delay 2 --retry-max-time 45)
    if [[ "$url" = https://api.abuseipdb.com/* ]];then
        local api_key;api_key=$(cat /opt/etc/AbuseIPDB.key 2>/dev/null) || { LIST_FAILURE_CODE=source_credentials;LIST_FAILURE_DETAIL='AbuseIPDB key could not be read.';return 1; }
        opts+=(-H "Key: $api_key" -H 'Accept: text/plain')
    fi
    [ -z "$UPDATE_INTERFACE" ] || opts+=(--interface "$UPDATE_INTERFACE")
    local -a transport=()
    [[ "$url" != https://www.ipdeny.com/* ]] || transport=(--ipv4)
    status=$(curl "${transport[@]}" "${opts[@]}" -w '%{http_code}' "$url" -o "$raw" 2>"$KT_WORKDIR/curl_$key.err");rc=$?
    if [ "${#transport[@]}" -gt 0 ] && [[ "$rc" = 6 || "$rc" = 7 || "$rc" = 28 || "$rc" = 35 ]];then
        # Address-family fallback affects HTTP transport only, never prefix validation.
        status=$(curl "${opts[@]}" -w '%{http_code}' "$url" -o "$raw" 2>"$KT_WORKDIR/curl_$key.err");rc=$?
    fi
    [[ "$status" =~ ^[0-9]{3}$ ]] || status=unknown
    if [ "$rc" = 0 ];then
        if ! valid_list "$family" "$raw" | sort -u > "$clean";then
            code=source_validation;message="$label: source validation failed."
        elif [ ! -s "$clean" ];then
            code=source_empty;message="$label: downloaded file contains no usable $family_label prefixes."
        elif ! cp "$clean" "${cache}.tmp" || ! mv "${cache}.tmp" "$cache";then
            code=cache_write;message="$label: validated source could not be saved to the cache."
        else
            cat "$cache" >> "$destination" || { LIST_FAILURE_CODE=merge_write;LIST_FAILURE_DETAIL='Source lists could not be merged (check storage).';return 1; }
            return 0
        fi
    else
        case "$rc" in
            6)code=download_dns;message="$label: DNS resolution failed.";;
            7)code=download_connect;message="$label: connection failed.";;
            28)code=download_timeout;message="$label: download timed out.";;
            35|51|60)code=download_tls;message="$label: TLS connection or certificate verification failed.";;
            22)code=download_http;message="$label: HTTP $status returned by the source.";;
            *)code=download_failed;message="$label: download failed (curl exit $rc, HTTP $status).";;
        esac
    fi
    if [ -s "$cache" ] && valid_list "$family" "$cache" | sort -u > "$clean" && [ -s "$clean" ];then
        LIST_SOURCE_WARNINGS="${LIST_SOURCE_WARNINGS:+$LIST_SOURCE_WARNINGS }$message Previous cached source used."
        kt_log "$message Previous cached source used."
        cat "$clean" >> "$destination" || { LIST_FAILURE_CODE=merge_write;LIST_FAILURE_DETAIL='Cached lists could not be merged (check storage).';return 1; }
        return 0
    fi
    LIST_FAILURE_CODE=$code;LIST_FAILURE_DETAIL="${LIST_FAILURE_DETAIL:+$LIST_FAILURE_DETAIL }$message No valid cache is available; installed list retained."
    kt_log "$LIST_FAILURE_DETAIL";return 1
}
list_security_event() {
    LIST_EVENT_WRITTEN=true
    [ ! -x /opt/bin/firewall_security ] || /opt/bin/bash /opt/bin/firewall_security list-event "$@" || kt_log 'Security list event could not be saved'
}
reject_list() {
    local set=$1 code=$2 detail=$3 old=${4:-0} new=${5:-0} expected=${6:-normal}
    kt_log "$set: $detail"
    list_security_event "$set" "$old" "$new" "$expected" rejected "$code" "$detail" "${LIST_SOURCE_WARNINGS:-}"
    return 1
}
staging_hint() {
    local file=$1 line
    if grep -qiE 'hash is full|maxelem|maximum.*entries' "$file";then printf 'Staging set capacity was exceeded.'
    elif grep -qiE 'cannot allocate memory|out of memory' "$file";then printf 'Kernel memory allocation failed.'
    else
        line=$(sed -nE 's/.*[Ee]rror in line ([0-9]+).*/\1/p' "$file" | head -n 1)
        printf 'ipset rejected the staged prefixes%s; check address syntax, IPv6 support and set compatibility.' "${line:+ at line $line}"
    fi
}
swap_list() {
    local set=$1 family=$2 input=$3 backup=$4 diff_file=$5 tmp old new expected=normal policy_sha policy_file error
    [ -s "$input" ] || { reject_list "$set" merged_empty 'Merged list is empty; installed list retained.';return 1; }
    sort -u "$input" > "$KT_WORKDIR/sorted_$set" || { reject_list "$set" sort_failed 'List sorting failed; installed list retained.';return 1; }
    if [ "$family" = inet ] && command -v iprange >/dev/null;then
        iprange --optimize "$KT_WORKDIR/sorted_$set" > "$KT_WORKDIR/optimized_$set" || { reject_list "$set" optimize_failed 'IPv4 prefix optimization failed; installed list retained.';return 1; }
        input="$KT_WORKDIR/optimized_$set"
    else input="$KT_WORKDIR/sorted_$set";fi
    tmp="${set}_TMP";error="$KT_WORKDIR/ipset_$set.err";ipset destroy "$tmp" 2>/dev/null || :
    if ! ipset list -n "$set" >/dev/null 2>&1;then
        ipset create "$set" hash:net family "$family" hashsize 16384 maxelem 524288 counters 2>"$error" || { reject_list "$set" set_create 'Installed set could not be created; check kernel support and memory.';return 1; }
    fi
    old=$(ipset save "$set" | awk '$1=="add"{n++}END{print n+0}') || { reject_list "$set" installed_read 'Installed prefix count could not be read; no swap performed.';return 1; }
    ipset create "$tmp" hash:net family "$family" hashsize 16384 maxelem 524288 counters 2>"$error" || { reject_list "$set" staging_create 'Staging set could not be created; check kernel support, memory or stale staging references.' "$old";return 1; }
    sed "s/^/add $tmp /" "$input" > "$KT_WORKDIR/load_$set" || { reject_list "$set" staging_file 'Staging input could not be written; installed list retained.' "$old";ipset destroy "$tmp";return 1; }
    if ! ipset restore -! < "$KT_WORKDIR/load_$set" 2>"$error";then
        reject_list "$set" staging_load "$(staging_hint "$error") Installed list retained." "$old";ipset destroy "$tmp";return 1
    fi
    new=$(ipset save "$tmp" | awk '$1=="add"{n++}END{print n+0}') || { reject_list "$set" staging_read 'Staging prefix count could not be read; installed list retained.' "$old";ipset destroy "$tmp";return 1; }
    [[ "$new" =~ ^[0-9]+$ ]] && [ "$new" -gt 0 ] || { reject_list "$set" staging_empty 'Staging set is empty; installed list retained.' "$old";ipset destroy "$tmp";return 1; }
    policy_file="$CACHE_DIR/policy_$set.sha"
    policy_sha=$(printf '%s' "$set|${BANNED_COUNTRIES:-}|${SOURCES_V4:-}|${SOURCES_V6:-}|${GEOIP_V6_EXCLUDE_COUNTRIES:-}" | sha256sum);policy_sha=${policy_sha%% *}
    if [ ! -f "$policy_file" ] || [ "$(cat "$policy_file")" != "$policy_sha" ];then expected=baseline;fi
    # GeoIP size changes are warning-only; invalid/empty/staging failures still stop publication.
    if [[ "$set" != GeoBlock* ]] && [ "${ALLOW_LARGE_LIST_SHRINK:-false}" != true ] && [ "$old" -gt 100 ] && [ "$new" -lt "$((old/4))" ];then
        reject_list "$set" shrink_rejected 'Main list shrank by more than 75%; installed list retained.' "$old" "$new" "$expected";ipset destroy "$tmp";return 1
    fi
    ipset swap "$tmp" "$set" 2>"$error" || { reject_list "$set" swap_failed 'Kernel set swap failed (check set compatibility); installed list retained.' "$old" "$new" "$expected";ipset destroy "$tmp";return 1; }
    if ! kt_atomic_save_set "$set" "$backup";then
        if ipset swap "$tmp" "$set";then
            reject_list "$set" persistence_failed 'Saving the set failed; previous kernel set restored. Check storage and file permissions.' "$old" "$new" "$expected";ipset destroy "$tmp"
        else
            reject_list "$set" rollback_failed 'Saving the set and kernel rollback both failed. Staging set retained for recovery; kernel and saved state may differ.' "$old" "$new" "$expected"
        fi
        return 1
    fi
    ipset destroy "$tmp" || :
    printf '%+d\n' "$((new-old))" > "$diff_file"
    printf '%s\n' "$policy_sha" > "$policy_file"
    local installed_detail='Validated prefixes installed and saved successfully.'
    if [ "$set" = GeoBlock6 ] && [ -n "${GEOIP_V6_EXCLUDE_COUNTRIES:-}" ];then installed_detail+=" Explicit IPv6 country exclusions: $GEOIP_V6_EXCLUDE_COUNTRIES.";fi
    list_security_event "$set" "$old" "$new" "$expected" installed installed "$installed_detail" "${LIST_SOURCE_WARNINGS:-}"
    kt_log "$set installed: $new entries"
}
update_sources() {
    local family=$1 set=$2 urls=$3 backup=$4 diff=$5 url raw="$KT_WORKDIR/merged_$2" ok=true old=0
    LIST_EVENT_WRITTEN=false;LIST_FAILURE_CODE='';LIST_FAILURE_DETAIL='';LIST_SOURCE_WARNINGS=''
    : > "$raw" || { reject_list "$set" merge_write 'Merged list file could not be created; check storage.';return 1; }
    [ -n "$urls" ] || { kt_log "No sources selected for $set; keeping installed list";return 0; }
    for url in $urls;do fetch_source "$family" "$url" "$raw" || ok=false;done
    if [ "$ok" != true ];then
        old=$(ipset save "$set" 2>/dev/null | awk '$1=="add"{n++}END{print n+0}') || old=0
        reject_list "$set" "${LIST_FAILURE_CODE:-source_failed}" "${LIST_FAILURE_DETAIL:-Source unavailable; installed list retained.}" "$old";return 1
    fi
    swap_list "$set" "$family" "$raw" "$backup" "$diff"
}
update_sources inet FirewallBlock "$SOURCES_V4" /opt/etc/firewall_blocklist.save /opt/etc/firewall_v4_diff.dat || FAILED=1
if [ "$ENABLE_IPV6" = true ]; then
    if [ -s /opt/etc/AbuseIPDB.key ]; then
        SOURCES_V6+=" https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=100&ipVersion=6&maxAgeInDays=30"
    fi
    update_sources inet6 FirewallBlock6 "$SOURCES_V6" /opt/etc/firewall_blocklist6.save /opt/etc/firewall_v6_diff.dat || FAILED=1
fi
# GeoIP uses the same validated cache engine; missing allocations are not published as an empty set.
if [ -n "$BANNED_COUNTRIES" ]; then
    urls4=""; urls6=""
    for country in $BANNED_COUNTRIES; do
        [[ "$country" =~ ^[a-z]{2}$ ]] || { kt_log "Invalid country: $country"; exit 1; }
        urls4+=" https://www.ipdeny.com/ipblocks/data/aggregated/${country}-aggregated.zone"
        case " ${GEOIP_V6_EXCLUDE_COUNTRIES:-} " in
            *" $country "*)kt_log "GeoBlock6: country $country explicitly excluded by the administrator";;
            *)urls6+=" https://www.ipdeny.com/ipv6/ipaddresses/aggregated/${country}-aggregated.zone";;
        esac
    done
    update_sources inet GeoBlock "$urls4" /opt/etc/firewall_geoblock.save /opt/etc/firewall_geo_diff.dat || FAILED=1
    [ "$ENABLE_IPV6" != true ] || update_sources inet6 GeoBlock6 "$urls6" /opt/etc/firewall_geoblock6.save /opt/etc/firewall_geo6_diff.dat || FAILED=1
else
    for set in GeoBlock GeoBlock6; do ipset flush "$set" 2>/dev/null || :; done
    : > /opt/etc/firewall_geoblock.save; : > /opt/etc/firewall_geoblock6.save
fi
# Source overlap is retained in VPNBlock: deleting it would weaken protection when a static source later removes an IP.
if [ -x /opt/etc/ndm/netfilter.d/100-firewall.sh ]; then
    table=filter /opt/etc/ndm/netfilter.d/100-firewall.sh || FAILED=1
fi
exit "$FAILED"
