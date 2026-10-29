<?php
// KEENTOOL WEB SETTINGS v1.0.4 — 2026-10-23, stable.
// Typed fixed-file configuration only; never evaluate shell input or return unrelated secrets.
if(PHP_SAPI!=='cli'||!function_exists('kdispatch')){http_response_code(403);exit(1);}
function ksettingsspec() {
    $f=[];
    $add=function(&$fields,$key,$label,$type,$default,$extra=[]) {$fields[$key]=array_merge(['label'=>$label,'type'=>$type,'default'=>$default],$extra);};
    foreach(['ENABLE_FIREWALL'=>'Firewall enabled','ENABLE_IPV6'=>'IPv6 firewall','ENABLE_FWD_PROTECTION'=>'Forwarded traffic protection','ENABLE_AUTOBAN'=>'AutoBan','ENABLE_MANUAL'=>'Manual bans','ENABLE_BRUTEFORCE'=>'Brute-force protection','ENABLE_CONNLIMIT'=>'Connection limits'] as $k=>$label)$add($f,$k,$label,'bool',$k!=='ENABLE_FWD_PROTECTION');
    foreach(['CONNLIMIT_MAX'=>['Connection limit',15,1,65535],'CONNLIMIT_CUSTOM'=>['Custom bypass connection limit',150,1,65535],'BAN_TIMEOUT'=>['Ban duration (seconds; 0 = permanent)',86400,0,31536000],'BF_SECONDS'=>['Brute-force window (seconds)',60,1,86400],'BF_HITCOUNT'=>['Brute-force hit threshold',5,1,10000],'REPORT_COOLDOWN'=>['Report cooldown (seconds)',604800,0,31536000],'FW_LOG_RATE'=>['NFLOG packets per second (0 = off)',2,0,1000],'FW_LOG_BURST'=>['NFLOG burst',10,1,10000]] as $k=>$d)$add($f,$k,$d[0],'int',$d[1],['min'=>$d[2],'max'=>$d[3]]);
    foreach(['TCP_SERVICES'=>'TCP services','UDP_SERVICES'=>'UDP services','TCP_PASSIVE_RANGE'=>'Passive TCP range','BYPASS_CONN_TCP'=>'Connection-limit TCP bypass ports','BYPASS_CONN_UDP'=>'Connection-limit UDP bypass ports','BYPASS_BRUTE_TCP'=>'Brute-force TCP bypass ports','BYPASS_BRUTE_UDP'=>'Brute-force UDP bypass ports','DNS_BYPASS_PORTS'=>'DNS bypass ports'] as $k=>$label)$add($f,$k,$label,'ports',$k==='TCP_SERVICES'?'80 443':($k==='DNS_BYPASS_PORTS'?'53 853':''));
    foreach(['BYPASS_INTERFACES'=>'General bypass interfaces','TRAP_BYPASS_INTERFACES'=>'Trap bypass interfaces','UPDATE_INTERFACE'=>'Blocklist download interface'] as $k=>$label)$add($f,$k,$label,'interfaces',$k==='BYPASS_INTERFACES'?'tun+':($k==='TRAP_BYPASS_INTERFACES'?'br0 tun+':''));
    $add($f,'BYPASS_NETWORKS_V4','IPv4 bypass networks','networks','10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16',['family'=>4]);
    $add($f,'BYPASS_NETWORKS_V6','IPv6 bypass networks','networks','::1/128 fe80::/10',['family'=>6]);
    $add($f,'BANNED_COUNTRIES','GeoIP blocked country codes','countries','',['help'=>'Space-separated two-letter codes. Changes take effect at the next blocklist update.']);
    $add($f,'GEOIP_V6_EXCLUDE_COUNTRIES','Explicit IPv6-only country exclusions','countries','',['help'=>'Optional. IPdeny does not publish an IPv6 feed for every country. Excluding a code omits its GeoIP IPv6 source only; IPv4 remains selected. No country is excluded automatically.']);
    $add($f,'SOURCES_V4','IPv4 blocklist sources','urls','https://iplists.firehol.org/files/firehol_level1.netset https://blocklist.greensnow.co/greensnow.txt');
    $add($f,'SOURCES_V6','IPv6 blocklist sources','urls','https://www.spamhaus.org/drop/dropv6.txt');
    $p=[];
    $add($p,'ENABLE_IPV6','IPv6 probes','bool',true);$add($p,'EMAIL_ALERTS','Connection email alerts','bool',true);
    $add($p,'PING_TARGET','IPv4 probe target','target','8.8.8.8',['family'=>4]);$add($p,'PING_TARGET_V6','IPv6 probe target','target','2001:4860:4860::8888',['family'=>6]);
    foreach(['PING_DURATION'=>['Probe duration (seconds)',30,1,50],'TRIGGER_LATENCY'=>['Latency alert threshold (ms)',30,1,10000],'RETENTION_DAYS'=>['History retention (days)',45,1,3650],'MAX_DISPLAY_POINTS'=>['Maximum chart points',2000,100,10000],'WAN_MONITOR_INTERVAL'=>['PPP syslog check interval (seconds)',5,1,60]] as $k=>$d)$add($p,$k,$d[0],'int',$d[1],['min'=>$d[2],'max'=>$d[3]]);
    $p['RETENTION_DAYS']['help']='Increasing is allowed. Lowering retention can delete stored samples and remains a CLI operation.';
    $add($p,'WAN_LABEL','WAN notification label','interfaces','');$add($p,'WAN_SYSLOG_ENABLED','PPP syslog monitoring','bool',true);
    $h=[];$add($h,'HISTORY_ENABLED','Aggregate older IP history','bool',true,['section'=>'History precision']);
    $add($h,'HISTORY_RAW_DAYS','Original sample detail (days)','int',7,['min'=>1,'max'=>3650,'presets'=>[['value'=>2],['value'=>7],['value'=>14],['value'=>30],['value'=>90]],'unit'=>'days','section'=>'History precision']);
    $add($h,'HISTORY_HOURLY_DAYS','Hourly detail through (days)','int',30,['min'=>1,'max'=>3650,'presets'=>[['value'=>7],['value'=>30],['value'=>60],['value'=>90],['value'=>365]],'unit'=>'days','section'=>'History precision','help'=>'Must be at least the original-sample days. Older records become daily buckets. No IP/list hit totals, global counters or port histories are removed.']);
    $add($h,'HISTORY_DAILY_DAYS','Daily detail through (days; 0 disables monthly rollup)','int',0,['min'=>0,'max'=>3650,'presets'=>[['value'=>0],['value'=>365],['value'=>730]],'unit'=>'days','section'=>'History precision','help'=>'Use 0 to keep daily buckets indefinitely, or at least the hourly days. Older complete calendar months become monthly IP/list totals. Global counters and port history remain unchanged.']);
    $add($h,'HISTORY_COMPACT','Enable compact IP storage','bool',false,['section'=>'History precision','help'=>'Conversion runs at the next due statistics maintenance, after a verified backup. Turning this off does not expand already compact storage. Fresh installations use the Balanced 2/7/365 profile with this enabled; existing settings are preserved.']);
    $t=[];$add($t,'MONTHLY_QUOTA_GB','Monthly traffic quota (GB; 0 = off)','decimal',0,['min'=>0,'max'=>1000000000]);$add($t,'VNSTAT_ALIASES','Interface aliases (in configured interface order)','interfaces','',['help'=>'One space-separated alias per interface. Interface selection and job schedules remain in KeenTool.']);
    $sec=[];$securityDefaults=['monitor_interval'=>60,'email_enabled'=>true,'immediate_alerts'=>true,'digest_enabled'=>true,'digest_hour'=>7,'timezone'=>'Europe/Rome','guard_seconds'=>120,'management_networks'=>[],'list_shrink_percent'=>50,'list_growth_percent'=>100,'geo_shrink_percent'=>90,'geo_growth_percent'=>300];foreach($securityDefaults as $k=>$v){
        $label=ucfirst(str_replace('_',' ',$k));
        if(is_bool($v))$add($sec,$k,$label,'bool',$v);
        elseif($k==='timezone')$add($sec,$k,'Summary timezone','timezone','Europe/Rome');
        elseif($k==='management_networks')$add($sec,$k,'Protected management networks','networks','');
        else {$range=$k==='monitor_interval'?[30,3600]:($k==='guard_seconds'?[30,300]:($k==='digest_hour'?[0,23]:(str_contains($k,'shrink')?[1,100]:[1,1000])));$add($sec,$k,$label,'int',$v,['min'=>$range[0],'max'=>$range[1]]);}
    }
    // UI hints do not change server-side validation or silently alter configured values.
    $preset=function(&$fields,$key,$values,$unit=''){
        $fields[$key]['presets']=array_map(fn($value)=>['value'=>$value],$values);
        if($unit!=='')$fields[$key]['unit']=$unit;
    };
    foreach($f as $key=>&$field){
        $field['section']=str_starts_with($key,'ENABLE_')?'Protection':(str_starts_with($key,'CONNLIMIT_')?'Connection limits':(str_starts_with($key,'BF_')?'Brute-force detection':(str_starts_with($key,'FW_LOG_')?'Logging':(str_contains($key,'BYPASS')?'Bypasses':(in_array($key,['BAN_TIMEOUT','REPORT_COOLDOWN'],true)?'Ban and report timers':(in_array($key,['BANNED_COUNTRIES','GEOIP_V6_EXCLUDE_COUNTRIES','SOURCES_V4','SOURCES_V6'],true)?'Blocklists and GeoIP':'Services and ports'))))));
        if($field['type']==='ports')$field['help']='Ports 1–65535, separated by spaces. Use a colon for a range, for example 50000:51000.';
        elseif($field['type']==='interfaces')$field['help']=$key==='UPDATE_INTERFACE'?'One interface, or leave empty for automatic routing.':'Space-separated interface names; a trailing + matches a prefix.';
        elseif($field['type']==='networks')$field['help']='Space-separated IP addresses or CIDR networks. At most 32 networks.';
        elseif($field['type']==='urls')$field['help']='One HTTP(S) blocklist URL per line. Credentials and fragments are not allowed.';
    }unset($field);
    $preset($f,'BAN_TIMEOUT',[0,900,3600,86400,604800,2592000],'seconds');
    $preset($f,'REPORT_COOLDOWN',[0,3600,86400,604800],'seconds');
    $preset($f,'BF_SECONDS',[30,60,300,600,3600],'seconds');
    $preset($f,'FW_LOG_RATE',[0,1,2,5,10,20],'packets/s');
    $f['BAN_TIMEOUT']['presets'][0]['label']='Permanent';$f['REPORT_COOLDOWN']['presets'][0]['label']='No cooldown';$f['FW_LOG_RATE']['presets'][0]['label']='Off';
    foreach($p as $key=>&$field)$field['section']=in_array($key,['RETENTION_DAYS','MAX_DISPLAY_POINTS'],true)?'History and charts':(str_starts_with($key,'WAN_')&&$key!=='WAN_LABEL'?'PPP syslog':(in_array($key,['EMAIL_ALERTS','TRIGGER_LATENCY'],true)?'Alerts':'Probe checks'));unset($field);
    $preset($p,'PING_DURATION',[10,20,30,50],'seconds');$preset($p,'TRIGGER_LATENCY',[20,30,50,100,200],'ms');
    $preset($p,'RETENTION_DAYS',[30,45,90,180,365],'days');$preset($p,'MAX_DISPLAY_POINTS',[500,1000,2000,5000,10000],'points');
    $preset($p,'WAN_MONITOR_INTERVAL',[5,15,30,60],'seconds');
    $p['PING_TARGET']['presets']=[['value'=>'8.8.8.8','label'=>'Google DNS — 8.8.8.8'],['value'=>'1.1.1.1','label'=>'Cloudflare — 1.1.1.1'],['value'=>'9.9.9.9','label'=>'Quad9 — 9.9.9.9']];
    $p['PING_TARGET_V6']['presets']=[['value'=>'2001:4860:4860::8888','label'=>'Google DNS — IPv6'],['value'=>'2606:4700:4700::1111','label'=>'Cloudflare — IPv6'],['value'=>'2620:fe::fe','label'=>'Quad9 — IPv6']];
    $t['MONTHLY_QUOTA_GB']['section']='Monthly quota';$t['MONTHLY_QUOTA_GB']['unit']='GB';$t['VNSTAT_ALIASES']['section']='Interface names';
    foreach($sec as $key=>&$field){$field['section']=str_contains($key,'percent')?'List-change warnings':($key==='management_networks'?'Management access':'Monitoring and notifications');if(str_contains($key,'percent'))$field['unit']='%';}unset($field);
    $preset($sec,'monitor_interval',[30,60,120,300,600,1800,3600],'seconds');$preset($sec,'guard_seconds',[30,60,120,180,300],'seconds');
    $sec['digest_hour']['choices']=array_map(fn($hour)=>['value'=>$hour,'label'=>sprintf('%02d:00',$hour)],range(0,23));
    $sec['timezone']['presets']=array_map(fn($zone)=>['value'=>$zone,'label'=>$zone],['Europe/Rome','Europe/London','Europe/Paris','Europe/Berlin','UTC','America/New_York','Asia/Tokyo']);
    $sec['guard_seconds']['label']='Firewall confirmation window';$sec['monitor_interval']['label']='Health check interval';$sec['digest_hour']['label']='Daily summary time';$sec['digest_enabled']['label']='Daily summary email';$sec['digest_enabled']['help']='Disable the daily Security & Health summary while keeping immediate health/blocklist alerts enabled. The master email setting still controls all Security & Health email.';
    $sec['management_networks']['help']='Space-separated IP addresses or CIDR networks that manual bans must never overlap. At most 32 networks.';
    return ['firewall'=>['title'=>'Firewall and blocklists','path'=>'/opt/etc/firewall.conf','fields'=>$f,'note'=>'Saving applies the hook with timed rollback. Confirm the new policy before the deadline. GeoIP/source changes are used at the next scheduled list update; lists are not downloaded by this form.'],
        'firewall_history'=>['title'=>'Firewall history','path'=>'/opt/etc/keentool/firewall-history.conf','fields'=>$h,'note'=>'Once daily at the next firewall statistics run: keep recent samples, then hourly, then daily buckets. A verified backup precedes the first aggregation. Reduced time precision cannot be restored by increasing thresholds or disabling this policy. Period boundaries crossing a bucket are approximate. Firewall rules are not reapplied.'],
        'ping'=>['title'=>'Connection Monitor','path'=>'/opt/etc/pingtool.conf','fields'=>$p,'note'=>'Probe and chart changes take effect at the next scheduled run. PPP settings are read by the WAN monitor.'],
        'traffic'=>['title'=>'Traffic Monitor','path'=>'/opt/etc/keentool/dashboard.conf','fields'=>$t,'note'=>'Changes appear at the next scheduled traffic export. Existing interfaces, databases and schedules are preserved.'],
        'security'=>['title'=>'Security monitoring','path'=>'/opt/etc/keentool/security/settings.json','fields'=>$sec,'note'=>'Changes are read by the security service at its next cycle. Existing schedules and mail credentials are preserved.']];
}
function ksettingsliteral($path) {
    $out=[];foreach(@file($path,FILE_IGNORE_NEW_LINES)?:[] as $line){
        if(!preg_match('/^\s*([A-Z][A-Z0-9_]*)=(.*)$/D',$line,$m))continue;
        $raw=trim($m[2]);
        if(preg_match('/^"([^"\\\\$`\r\n]*)"\s*(?:#.*)?$/D',$raw,$v)||preg_match("/^'([^'\r\n]*)'\\s*(?:#.*)?$/D",$raw,$v)||preg_match('/^([A-Za-z0-9_.:+\/-]+)\s*(?:#.*)?$/D',$raw,$v))$out[$m[1]]=$v[1];
        else $out[$m[1]]=null;
    }return $out;
}
function ksettingsread($name,$group) {
    $path=kp($group['path']);if(is_link($path)||!is_file($path))throw new RuntimeException('Existing configuration unavailable: '.$name);
    $raw=file_get_contents($path);if($raw===false)throw new RuntimeException('Cannot read configuration');
    $data=$name==='security'?kconfig():ksettingsliteral($path);$values=[];
    foreach($group['fields'] as $key=>$field){
        $value=array_key_exists($key,$data)?$data[$key]:$field['default'];
        if($value===null)throw new RuntimeException('Use literal values in '.$name.' configuration before editing it here: '.$key);
        if(is_string($value)&&strlen($value)>2048)throw new RuntimeException('Configuration value is too long for web editing: '.$key);
        if($field['type']==='bool'){if(!is_bool($value)&&!in_array($value,['true','false'],true))throw new RuntimeException('Literal boolean required: '.$key);$value=is_bool($value)?$value:$value==='true';}
        elseif($field['type']==='int')$value=(int)$value;
        elseif($field['type']==='decimal')$value=(float)$value;
        elseif(is_array($value))$value=implode(' ',$value);
        $values[$key]=$value;
    }return ['values'=>$values,'revision'=>hash('sha256',$raw),'raw'=>$raw];
}
function ksettingsget() {
    $out=[];foreach(ksettingsspec() as $name=>$group){
        try{$data=ksettingsread($name,$group);$out[$name]=['title'=>$group['title'],'note'=>$group['note'],'fields'=>$group['fields'],'values'=>$data['values'],'revision'=>$data['revision']];}
        catch(Throwable $e){$out[$name]=['title'=>$group['title'],'error'=>$e->getMessage()];}
    }$reply=['status'=>'success','groups'=>$out,'pending'=>kpending()];if(strlen(json_encode($reply))>48000)throw new RuntimeException('Settings response is too large; review the configuration from the CLI');return $reply;
}
function ksettingsvalue($value,$field) {
    $type=$field['type'];
    if($type==='bool'){if(!is_bool($value))throw new InvalidArgumentException('Boolean required');return $value;}
    if($type==='int'){if(!is_int($value)||$value<$field['min']||$value>$field['max'])throw new InvalidArgumentException('Integer outside allowed range');return $value;}
    if($type==='decimal'){if(!is_numeric($value)||!is_finite((float)$value)||$value<$field['min']||$value>$field['max'])throw new InvalidArgumentException('Number outside allowed range');return round((float)$value,3);}
    if(is_string($value))$value=preg_replace('/[\r\n\t]+/',' ',$value);
    if(!is_string($value)||strlen($value)>2048||preg_match('/[\x00-\x1f\x7f$`"\x27\\\\<>]/',$value))throw new InvalidArgumentException('Invalid configuration text');
    $value=trim(preg_replace('/[ ,]+/',' ',$value));$tokens=preg_split('/\s+/',$value,-1,PREG_SPLIT_NO_EMPTY);
    if($type==='ports')foreach($tokens as $port){if(!preg_match('/^([0-9]{1,5})(?::([0-9]{1,5}))?$/D',$port,$m)||(int)$m[1]<1||(int)$m[1]>65535||(isset($m[2])&&((int)$m[2]<(int)$m[1]||(int)$m[2]>65535)))throw new InvalidArgumentException('Invalid port or port range');}
    elseif($type==='countries'){$tokens=array_map('strtolower',$tokens);foreach($tokens as $t)if(!preg_match('/^[a-z]{2}$/D',$t))throw new InvalidArgumentException('Two-letter country codes required');}
    elseif($type==='interfaces'){foreach($tokens as $t)if(!preg_match('/^[A-Za-z0-9_.:+-]{1,32}$/D',$t))throw new InvalidArgumentException('Invalid interface or alias');}
    elseif($type==='networks'){if(count($tokens)>32)throw new InvalidArgumentException('At most 32 networks');foreach($tokens as &$t){$n=knetwork($t);if(isset($field['family'])&&(strpos($n['text'],':')!==false?6:4)!==$field['family'])throw new InvalidArgumentException('Address family mismatch');$t=$n['text'];}unset($t);}
    elseif($type==='urls'){foreach($tokens as $url){$u=parse_url($url);if(!$u||!in_array($u['scheme']??'',['http','https'],true)||empty($u['host'])||isset($u['user'])||isset($u['pass'])||isset($u['fragment'])||!preg_match('/^[A-Za-z0-9.-]+$/D',$u['host']))throw new InvalidArgumentException('HTTP(S) source URLs without credentials required');}}
    elseif($type==='target'){if(strlen($value)>253||!$value||preg_match('/\s/',$value))throw new InvalidArgumentException('Valid probe target required');if(strpos($value,':')!==false||preg_match('/^[0-9.]+$/D',$value)){$packed=@inet_pton($value);if($packed===false||strlen($packed)!==($field['family']===4?4:16))throw new InvalidArgumentException('Probe address family mismatch');}elseif(!preg_match('/^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/D',$value))throw new InvalidArgumentException('Valid probe hostname required');return $value;}
    elseif($type==='timezone'){if(!in_array($value,timezone_identifiers_list(),true))throw new InvalidArgumentException('Valid IANA timezone required');return $value;}
    return implode(' ',array_values(array_unique($tokens)));
}
function ksettingssave($input,$actor) {
    $name=$input['group']??'';$groups=ksettingsspec();if(!is_string($name)||!isset($groups[$name]))throw new InvalidArgumentException('Unknown settings group');
    if(kpending())throw new RuntimeException('Confirm or roll back the pending firewall policy first');
    $group=$groups[$name];$data=ksettingsread($name,$group);$revision=$input['revision']??'';
    if(!is_string($revision)||!hash_equals($data['revision'],$revision))throw new RuntimeException('Configuration changed. Reload Settings before saving.');
    $changes=$input['values']??null;if(!is_array($changes)||!$changes||strlen(json_encode($changes))>6000)throw new InvalidArgumentException('Bounded settings object required');
    $values=[];foreach($changes as $key=>$value){if(!isset($group['fields'][$key]))throw new InvalidArgumentException('Unknown setting: '.$key);try{$values[$key]=ksettingsvalue($value,$group['fields'][$key]);}catch(Throwable $e){throw new InvalidArgumentException($key.': '.$e->getMessage());}}
    if($name==='firewall_history'){$merged=array_merge($data['values'],$values);if($merged['HISTORY_DAILY_DAYS']!==0&&$merged['HISTORY_DAILY_DAYS']<$merged['HISTORY_HOURLY_DAYS'])throw new InvalidArgumentException('Daily detail days must be zero or at least the hourly days');if($merged['HISTORY_HOURLY_DAYS']<$merged['HISTORY_RAW_DAYS'])throw new InvalidArgumentException('Hourly detail days must be at least the original-sample days');}
    if($name==='ping'&&isset($values['RETENTION_DAYS'])&&$values['RETENTION_DAYS']<$data['values']['RETENTION_DAYS'])throw new InvalidArgumentException('Lowering history retention can delete data; use the CLI explicitly.');
    if($name==='firewall'){
        $merged=array_merge($data['values'],$values);
        foreach(explode(' ',$merged['GEOIP_V6_EXCLUDE_COUNTRIES']) as $code)if($code!==''&&!in_array($code,explode(' ',$merged['BANNED_COUNTRIES']),true))throw new InvalidArgumentException('IPv6 exclusions must also be selected GeoIP countries');
        if($merged['ENABLE_IPV6']&&$merged['BANNED_COUNTRIES']!==''&&!array_diff(explode(' ',$merged['BANNED_COUNTRIES']),explode(' ',$merged['GEOIP_V6_EXCLUDE_COUNTRIES'])))throw new InvalidArgumentException('Keep at least one IPv6 GeoIP country selected; empty publication is not applied.');
        if(count(preg_split('/\s+/',trim($merged['UPDATE_INTERFACE']),-1,PREG_SPLIT_NO_EMPTY))>1)throw new InvalidArgumentException('Select at most one download interface');
    }
    if($name==='ping'&&isset($values['WAN_LABEL'])&&str_contains($values['WAN_LABEL'],' '))throw new InvalidArgumentException('Use a single WAN label');
    $path=kp($group['path']);
    if($name==='security'){
        $new=array_merge(kconfig(),$values);if(isset($values['management_networks']))$new['management_networks']=preg_split('/\s+/',trim($values['management_networks']),-1,PREG_SPLIT_NO_EMPTY);
        $text=json_encode($new,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n";
    }else{
        $lines=preg_split('/\r?\n/',$data['raw']);$out=[];
        foreach($lines as $line){if(preg_match('/^\s*([A-Z][A-Z0-9_]*)=/',$line,$m)&&array_key_exists($m[1],$values))continue;$out[]=$line;}
        foreach($values as $key=>$value)$out[]=$key.'="'.(is_bool($value)?($value?'true':'false'):$value).'"';$text=implode("\n",$out)."\n";
    }
    $backup=kp('/opt/var/backups/keentool-settings/'.gmdate('Ymd_His').'-'.bin2hex(random_bytes(4)));if(!mkdir($backup,0700,true))throw new RuntimeException('Cannot create settings backup');
    ktext($backup.'/'.basename($path),$data['raw']);
    if(!hash_equals($data['revision'],hash_file('sha256',$path)))throw new RuntimeException('Configuration changed while saving; reload Settings.');
    if($name==='firewall')$result=kpolicy($merged['ENABLE_FIREWALL'],$actor,$text);
    else {
        ktext($path,$text);
        if($name==='ping'&&!empty($values['WAN_SYSLOG_ENABLED'])&&!$data['values']['WAN_SYSLOG_ENABLED']){
            [$rc]=krun([kp('/opt/bin/bash'),kp('/opt/bin/wan_syslog_service'),'start'],15);
            if($rc!==0){ktext($path,$data['raw']);throw new RuntimeException('WAN service could not be started; previous settings restored');}
        }
        $result=['status'=>'success','message'=>$group['note']];
    }
    kaudit('admin','settings updated','ok',$actor,$name,'Changed keys: '.implode(', ',array_keys($values)));
    return array_merge($result,['backup'=>$backup,'revision'=>hash_file('sha256',$path)]);
}
