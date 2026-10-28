<?php
// KEENTOOL SECURITY ENGINE v1.0.3 — 2026-10-23, stable.
// Root-only local command broker, audit, guarded policy changes and monitoring.
if (PHP_SAPI !== 'cli') { http_response_code(403); exit(1); }
umask(0077);
function kdigits($value) { return is_string($value) && preg_match('/^[0-9]+$/D',$value)===1; }
function kp($path) { return (getenv('KT_SECURITY_ROOT') ?: '') . $path; }
function kread($path, $fallback=[]) { if(!is_file($path))return $fallback;$v=json_decode((string)file_get_contents($path),true);if(!is_array($v))throw new RuntimeException('Invalid JSON state: '.basename($path));return $v; }
function ktext($path,$text,$mode=0600) {
    $dir=dirname($path);if(!is_dir($dir)&&!mkdir($dir,0700,true))throw new RuntimeException('Cannot create state directory');
    $tmp=tempnam($dir,'.kt_');if(!$tmp)throw new RuntimeException('Cannot create state file');
    if(file_put_contents($tmp,$text)!==strlen($text)||!chmod($tmp,$mode)||!rename($tmp,$path)){@unlink($tmp);throw new RuntimeException('Cannot save state');}
}
function kwrite($path,$value,$mode=0600) {
    $dir=dirname($path);if(!is_dir($dir)&&!mkdir($dir,0700,true))throw new RuntimeException('Cannot create private state directory');
    $json=json_encode($value,JSON_UNESCAPED_SLASHES|JSON_INVALID_UTF8_SUBSTITUTE|JSON_THROW_ON_ERROR);
    $tmp=tempnam($dir,'.kt_');if(!$tmp)throw new RuntimeException('Cannot create state file');
    if(file_put_contents($tmp,$json)!==strlen($json)||!chmod($tmp,$mode)||!rename($tmp,$path)){@unlink($tmp);throw new RuntimeException('Cannot save state');}
}
function krun($argv,$limit=15,$max=4194304) {
    // Argument arrays bypass the shell. There is no arbitrary-command broker action.
    $env=null;$p=proc_open($argv,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,null,$env);
    if(!is_resource($p))return [127,'Cannot start command'];fclose($pipes[0]);
    stream_set_blocking($pipes[1],false);stream_set_blocking($pipes[2],false);$out='';$err='';$end=microtime(true)+$limit;$code=-1;
    do {
        $out.=stream_get_contents($pipes[1]);$err.=stream_get_contents($pipes[2]);$s=proc_get_status($p);
        if(strlen($out)+strlen($err)>$max||microtime(true)>$end){proc_terminate($p);usleep(100000);proc_terminate($p,9);$code=124;break;}
        if(!$s['running']){$code=$s['exitcode'];break;}usleep(10000);
    }while(true);
    $out.=stream_get_contents($pipes[1]);$err.=stream_get_contents($pipes[2]);if(strlen($out)+strlen($err)>$max){$code=124;$out='';$err='Output limit exceeded';}fclose($pipes[1]);fclose($pipes[2]);$last=proc_close($p);
    if($code<0)$code=$last;return [$code,$out,$err];
}
function kconfig() {
    $defaults=['monitor_interval'=>60,'email_enabled'=>true,'immediate_alerts'=>true,'digest_hour'=>7,'timezone'=>'Europe/Rome','guard_seconds'=>120,'management_networks'=>[], 'list_shrink_percent'=>50,'list_growth_percent'=>100,'geo_shrink_percent'=>90,'geo_growth_percent'=>300];
    return array_merge($defaults,kread(kp('/opt/etc/keentool/security/settings.json')));
}
function kconf() {
    $out=['BYPASS_INTERFACES'=>'tun+','TRAP_BYPASS_INTERFACES'=>'br0 tun+','BYPASS_NETWORKS_V4'=>'10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16','BYPASS_NETWORKS_V6'=>'::1/128 fe80::/10','DNS_BYPASS_PORTS'=>'53 853'];foreach(@file(kp('/opt/etc/firewall.conf'),FILE_IGNORE_NEW_LINES)?:[] as $line)if(preg_match('/^([A-Z0-9_]+)=["\x27]?(.*?)["\x27]?$/',$line,$m))$out[$m[1]]=$m[2];return $out;
}
function kmono() { return hrtime(true)/1000000000; }
function kboot() { return trim((string)@file_get_contents(kp('/proc/sys/kernel/random/boot_id'))) ?: 'unknown'; }
function klock($name) {
    $dir=kp('/opt/etc/keentool/security');if(!is_dir($dir))mkdir($dir,0700,true);
    $f=fopen($dir.'/'.$name.'.lock','c');if(!$f||!flock($f,LOCK_EX))throw new RuntimeException('Security lock unavailable');return $f;
}
function kunlock($f) { flock($f,LOCK_UN);fclose($f); }
function kaudit($category,$event,$outcome='ok',$actor='local',$target='',$note='',$eventTime=null,$publicDetail=null) {
    $f=klock('audit');try {
        $path=kp('/opt/var/log/keentool-security/audit.jsonl');$dir=dirname($path);if(!is_dir($dir))mkdir($dir,0700,true);chmod($dir,0700);
        if(is_file($path)&&filesize($path)>2097152){for($i=4;$i>=1;$i--)if(is_file($path.'.'.$i))rename($path.'.'.$i,$path.'.'.($i+1));rename($path,$path.'.1');}
        $row=['time'=>$eventTime??time(),'recorded_at'=>time(),'category'=>substr($category,0,32),'event'=>substr($event,0,120),'outcome'=>substr($outcome,0,24),'actor'=>substr($actor,0,64),'target'=>substr($target,0,80),'note'=>substr(preg_replace('/[\x00-\x1f]/',' ',(string)$note),0,400)];
        if($publicDetail!==null&&$category==='blocklist')$row['detail']=substr(preg_replace('/[\x00-\x1f]/',' ',(string)$publicDetail),0,600);
        $line=json_encode($row,JSON_INVALID_UTF8_SUBSTITUTE)."\n";
        if(file_put_contents($path,$line,FILE_APPEND)!==strlen($line))throw new RuntimeException('Audit write failed');chmod($path,0600);
    }finally{kunlock($f);}
}
function kevents($private=false,$limit=200) {
    $rows=[];foreach([kp('/opt/var/log/keentool-security/audit.jsonl.1'),kp('/opt/var/log/keentool-security/audit.jsonl')] as $path){$f=@fopen($path,'r');if(!$f)continue;while(($line=fgets($f))!==false){$r=json_decode($line,true);if(!is_array($r))continue;if(!$private)unset($r['actor'],$r['note']);$rows[]=$r;if(count($rows)>$limit)array_shift($rows);}fclose($f);}usort($rows,fn($a,$b)=>$b['time']<=>$a['time']);return $rows;
}
function kip($value) { return is_string($value) && @inet_pton($value)!==false; }
function knetwork($value) {
    if(!is_string($value)||strlen($value)>80)throw new InvalidArgumentException('Invalid IP or subnet');$a=explode('/',$value);
    if(count($a)>2||!kip($a[0]))throw new InvalidArgumentException('Invalid IP or subnet');
    $packed=inet_pton($a[0]);$bits=strlen($packed)*8;$prefix=$a[1]??(string)$bits;
    if(!kdigits((string)$prefix)||(int)$prefix>$bits)throw new InvalidArgumentException('Invalid prefix');$prefix=(int)$prefix;
    $mask='';for($i=0;$i<strlen($packed);$i++)$mask.=chr($prefix>=$i*8+8?255:($prefix<=$i*8?0:(255<<(8-($prefix-$i*8)))&255));
    $net=$packed & $mask;return ['text'=>inet_ntop($net).($prefix===$bits?'':'/'.$prefix),'bytes'=>$net,'mask'=>$mask,'prefix'=>$prefix,'bits'=>$bits];
}
function koverlap($a,$b) { $a=knetwork($a);$b=knetwork($b);if($a['bits']!==$b['bits'])return false;$mask=$a['prefix']<$b['prefix']?$a['mask']:$b['mask'];return ($a['bytes']&$mask)===($b['bytes']&$mask); }
function kprotected($target,$actor) {
    $nets=array_merge(['0.0.0.0/8','127.0.0.0/8','169.254.0.0/16','224.0.0.0/3','::/128','::1/128','fe80::/10','ff00::/8'],kconfig()['management_networks']);
    if(kip($actor)){$nets[]=$actor;$packed=inet_pton($actor);if(strlen($packed)===16&&substr($packed,0,12)===str_repeat(chr(0),10).chr(255).chr(255))$nets[]=inet_ntop(substr($packed,12));}
    [$rc,$addresses]=krun(['ip','-o','addr','show']);
    if($rc===0&&preg_match_all('/\binet6?\s+([0-9a-fA-F:.]+)\/(\d+)/',$addresses,$matches,PREG_SET_ORDER))foreach($matches as $m){$nets[]=$m[1];}
    // Protect the actual connected management bridge networks, not guessed RFC1918 ranges.
    foreach([['ip','-4','route','show','dev','br0'],['ip','-6','route','show','dev','br0']] as $argv){[$rc,$routes]=krun($argv);if($rc===0)foreach(explode("\n",$routes) as $line){$net=strtok($line,' ');try{if($net&&strpos($net,'/')!==false)$nets[]=$net;}catch(Throwable $e){}}}
    foreach($nets as $net){try{if(koverlap($target,$net))return $net;}catch(Throwable $e){}}return '';
}
function kmembers($ip) {
    $v6=strpos($ip,':')!==false;$sets=$v6?['FirewallWhite6','KTManualBan6','Blacklist6','AutoBan6','GeoBlock6','FirewallBlock6']:['FirewallWhite','KTManualBan','Blacklist','AutoBan','GeoBlock','FirewallBlock','VPNBlock'];$rows=[];
    foreach($sets as $set){[$rc]=krun(['ipset','test',$set,$ip]);if($rc!==0)continue;$row=['set'=>$set,'member'=>null,'timeout_remaining'=>str_starts_with($set,'Blacklist')?0:null,'packets'=>null,'bytes'=>null];
        if(in_array($set,['AutoBan','AutoBan6','KTManualBan','KTManualBan6','Blacklist','Blacklist6'],true)){
            [$rc,$save]=krun(['ipset','save',$set],10,8388608);if($rc===0)foreach(explode("\n",$save) as $line){$tokens=preg_split('/\s+/',trim($line));if(($tokens[0]??'')!=='add')continue;try{$match=koverlap($ip,$tokens[2]??'');}catch(Throwable $e){$match=false;}if(!$match)continue;
                $row['member']=$tokens[2];foreach(['timeout'=>'timeout_remaining','packets'=>'packets','bytes'=>'bytes'] as $tag=>$key){$index=array_search($tag,$tokens,true);if($index!==false)$row[$key]=(int)($tokens[$index+1]??0);}break;
            }
        }$rows[]=$row;
    }return $rows;
}
function ksql($sql) {
    $db=kp('/opt/etc/firewall_stats.db');if(!is_file($db))return [];
    [$rc,$json]=krun(['sqlite3','-readonly','-json',$db,$sql],20,2097152);if($rc!==0)throw new RuntimeException('Statistics query failed');$rows=json_decode($json,true);return is_array($rows)?$rows:[];
}
function khealth() {
    [$rc,$json]=krun([kp('/opt/bin/bash'),kp('/opt/bin/firewall_health')],20);$data=json_decode($json,true);
    if($rc!==0||!is_array($data))return ['enabled'=>null,'applied'=>false,'healthy'=>false,'error'=>'Health verification unavailable'];
    if(!empty($data['enabled'])&&(kconf()['ENABLE_MANUAL']??'true')==='true'){
        foreach(['iptables'=>['BLOCKLIST_IN','BLOCKLIST_FWD','KTManualBan'],'ip6tables'=>['BLOCKLIST_IN6','BLOCKLIST_FWD6','KTManualBan6']] as $tool=>$chains){
            if($tool==='ip6tables'&&(kconf()['ENABLE_IPV6']??'true')!=='true')continue;
            [$status,$rules]=krun([$tool.'-save','-t','filter'],10);
            foreach(array_slice($chains,0,2) as $chain)if($status!==0||strpos($rules,'-A '.$chain.' -m set --match-set '.$chains[2].' src -j DROP')===false){$data['healthy']=false;$data['applied']=false;$data['error']='Apply the current hook to link persistent manual bans';}
        }
    }return $data;
}
function kensureSets() {
    foreach(['KTManualBan'=>'inet','KTManualBan6'=>'inet6'] as $set=>$family){if($family==='inet6'&&(kconf()['ENABLE_IPV6']??'true')!=='true')continue;[$rc]=krun(['ipset','list','-n',$set]);if($rc!==0){[$rc,$out]=krun(['ipset','create',$set,'hash:net','family',$family,'timeout','0','maxelem','65536','counters']);if($rc!==0)throw new RuntimeException('Cannot create manual-ban set');}}
}
function ksaveLegacy($v6) {
    $set=$v6?'Blacklist6':'Blacklist';[$rc,$save]=krun(['ipset','save',$set],15,16777216);
    if($rc===0)ktext(kp('/opt/etc/'.$set.'.backup'),$save);
    else{[$exists]=krun(['ipset','list','-n',$set]);if($exists===0)throw new RuntimeException('Manual persistence failed');}
    $save='';foreach(['AutoBan','AutoBan6'] as $set){[$rc,$text]=krun(['ipset','save',$set],15,16777216);if($rc===0)$save.=$text;else{[$exists]=krun(['ipset','list','-n',$set]);if($exists===0)throw new RuntimeException('AutoBan persistence failed');}}
    if($save!=='')ktext(kp('/opt/etc/firewall_autoban.save'),$save);
}
function kban($input,$actor) {
    $target=knetwork($input['ip']??'')['text'];$ttl=$input['duration']??0;
    if(!is_int($ttl)||!in_array($ttl,[0,900,3600,86400],true))throw new InvalidArgumentException('Choose permanent, 15 minutes, 1 hour or 24 hours');
    $note=$input['note']??'';if(!is_string($note)||strlen($note)>200)throw new InvalidArgumentException('Note must be at most 200 bytes');
    if(kprotected($target,$actor)!=='')throw new InvalidArgumentException('Protected management address or overlapping subnet');
    $conf=kconf();if(($conf['ENABLE_MANUAL']??'true')!=='true')throw new RuntimeException('Manual blocking is disabled in firewall.conf');
    if(strpos($target,':')!==false&&($conf['ENABLE_IPV6']??'true')!=='true')throw new RuntimeException('IPv6 firewall is disabled');
    $health=khealth();if(empty($health['healthy'])||empty($health['enabled']))throw new RuntimeException('Apply and verify the firewall before adding a ban');
    foreach(kmembers($target) as $row)if(strpos($row['set'],'FirewallWhite')===0)throw new InvalidArgumentException('Target overlaps a whitelist entry');
    // Also reject a broad subnet containing any whitelisted host/network.
    foreach(['FirewallWhite','FirewallWhite6'] as $set){[$rc,$save]=krun(['ipset','save',$set],10,8388608);if($rc===0)foreach(explode("\n",$save) as $line){$a=explode(' ',trim($line));if(($a[0]??'')==='add'&&koverlap($target,$a[2]))throw new InvalidArgumentException('Target contains a whitelisted address');}}
    kensureSets();$path=kp('/opt/etc/keentool/security/manual-bans.json');$bans=kread($path);
    if(isset($bans[$target])&&$bans[$target]['expires']===0&&$ttl>0)throw new InvalidArgumentException('Unban the permanent entry before shortening it');
    $entry=['expires'=>$ttl?time()+$ttl:0,'duration'=>$ttl,'mono_deadline'=>$ttl?kmono()+$ttl:0,'boot'=>kboot(),'note'=>$note,'created'=>time(),'actor'=>$actor];$old=$bans;
    $bans[$target]=$entry;kwrite($path,$bans);$set=strpos($target,':')!==false?'KTManualBan6':'KTManualBan';
    [$rc]=krun(['ipset','add',$set,$target,'timeout',(string)$ttl,'-exist']);if($rc!==0){kwrite($path,$old);throw new RuntimeException('Kernel rejected the ban');}
    kaudit('firewall','ban','ok',$actor,$target,$note);return ['status'=>'success','ip'=>$target,'expires'=>$entry['expires'],'remaining'=>array_column(kmembers($target),'set')];
}
function kunban($input,$actor) {
    $target=knetwork($input['ip']??'')['text'];$v6=strpos($target,':')!==false;
    foreach($v6?['KTManualBan6','AutoBan6','Blacklist6']:['KTManualBan','AutoBan','Blacklist'] as $set){[$rc]=krun(['ipset','test',$set,$target]);if($rc===0){[$rc]=krun(['ipset','del',$set,$target]);if($rc!==0)throw new RuntimeException('Unban failed; inspect remaining lists');}}
    $path=kp('/opt/etc/keentool/security/manual-bans.json');$bans=kread($path);unset($bans[$target]);kwrite($path,$bans);ksaveLegacy($v6);
    kaudit('firewall','unban','ok',$actor,$target);return ['status'=>'success','ip'=>$target,'remaining'=>array_column(kmembers($target),'set')];
}
function kreconcile($restore=false) {
    $path=kp('/opt/etc/keentool/security/manual-bans.json');$bans=kread($path);$changed=false;
    foreach($bans as $target=>$entry){$remaining=$entry['expires']?(int)$entry['expires']-time():0;if($entry['expires']&&($entry['boot']??'')===kboot()&&isset($entry['mono_deadline']))$remaining=(int)ceil($entry['mono_deadline']-kmono());if($entry['expires'])$remaining=min($remaining,(int)($entry['duration']??86400));$set=strpos($target,':')!==false?'KTManualBan6':'KTManualBan';
        if($entry['expires']&&$remaining<=0){krun(['ipset','del',$set,$target]);unset($bans[$target]);$changed=true;kaudit('firewall','temporary ban expired','ok','local',$target);}
        elseif($restore){if(str_ends_with($set,'6')&&(kconf()['ENABLE_IPV6']??'true')!=='true')continue;[$rc]=krun(['ipset','add',$set,$target,'timeout',(string)max(0,$remaining),'-exist']);if($rc!==0)throw new RuntimeException('Cannot restore a persisted manual ban');}
    }if($changed)kwrite($path,$bans);
}
function kpolicy($enabled,$actor,$replacement=null) {
    $path=kp('/opt/etc/keentool/security/pending.json');if(is_file($path))throw new RuntimeException('Confirm or roll back the pending policy first');
    $conf=kp('/opt/etc/firewall.conf');$old=file_get_contents($conf);if($old===false)throw new RuntimeException('Configuration unavailable');
    $line='ENABLE_FIREWALL="'.($enabled?'true':'false').'"';$new=preg_replace('/^ENABLE_FIREWALL=.*$/m',$line,$old,-1,$n);if(!$n)$new.="\n".$line."\n";if($replacement!==null)$new=$replacement;
    $seconds=max(30,min(300,(int)kconfig()['guard_seconds']));$id=bin2hex(random_bytes(24));$pending=['id'=>$id,'expires'=>time()+$seconds,'mono_deadline'=>kmono()+$seconds,'boot'=>kboot(),'old_config'=>base64_encode($old),'new_sha'=>hash('sha256',$new),'actor'=>$actor];kwrite($path,$pending);
    try{ktext($conf,$new);}catch(Throwable $e){@unlink($path);throw $e;}
    // A separate HUP-safe guardian survives a stopped monitoring/broker process.
    [$rc]=krun([kp('/opt/bin/bash'),kp('/opt/lib/keentool/firewall_guard'),'launch',$id]);
    if($rc!==0){krollback($id,'guardian launch failed');throw new RuntimeException('Guardian unavailable; previous policy restored');}
    [$rc]=krun(['env','table=filter',kp('/opt/bin/bash'),kp('/opt/etc/ndm/netfilter.d/100-firewall.sh')],45);
    $health=khealth();if($rc!==0||empty($health['healthy'])||$health['enabled']!==$enabled){krollback($id,'policy verification failed');throw new RuntimeException('New policy failed; rollback attempted');}
    kaudit('firewall','policy awaiting confirmation','ok',$actor,$enabled?'enabled':'disabled');return array_merge(['status'=>'success','pending_id'=>$id,'confirm_before'=>$pending['expires']],$health);
}
function krollback($id,$reason) {
    $path=kp('/opt/etc/keentool/security/pending.json');$pending=kread($path);if(!$pending||!hash_equals($pending['id'],$id))return;
    $conf=kp('/opt/etc/firewall.conf');
    if(!hash_equals($pending['new_sha'],hash_file('sha256',$conf))){kaudit('firewall','policy rollback conflict','error','local','',$reason);throw new RuntimeException('Configuration changed externally; automatic rollback cannot overwrite it');}
    $old=base64_decode($pending['old_config'],true);if($old===false)throw new RuntimeException('Invalid rollback state');ktext($conf,$old);
    [$rc]=krun(['env','table=filter',kp('/opt/bin/bash'),kp('/opt/etc/ndm/netfilter.d/100-firewall.sh')],45);
    if($rc!==0||empty(khealth()['healthy'])){kaudit('firewall','policy rollback failed','error','local','',$reason);throw new RuntimeException('Previous policy could not be verified');}
    unlink($path);kaudit('firewall','policy rolled back','ok','local','',$reason);
}
function kpending() {$p=kread(kp('/opt/etc/keentool/security/pending.json'));return $p?['pending_id'=>$p['id'],'confirm_before'=>$p['expires']]:null;}
function khistorynote() {
    $rows=ksql("SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name='kt_history_meta';");
    return !empty($rows[0]['n'])?' Older IP history uses hourly/daily and optionally monthly buckets; hit totals per IP/list are exact, but first/last timestamps and period boundaries crossing a bucket are approximate.':'';
}
function klookup($input) {
    $ip=knetwork($input['ip']??'')['text'];$members=kmembers($ip);$q="'".str_replace("'","''",$ip)."'";$base=explode('/',$ip)[0];
    $metadata=ksql("SELECT country,risk,domain,target_port,substr(port_history,1,4000) AS port_history FROM ip_info WHERE ip='".$base."' LIMIT 1;");
    $counters=ksql("SELECT list_type,SUM(count) AS hits,MIN(timestamp) AS first_seen,MAX(timestamp) AS last_seen FROM ip_drops WHERE ip=$q GROUP BY list_type;");
    $rules=[];$tool=strpos($ip,':')!==false?'ip6tables-save':'iptables-save';[$rc,$saved]=krun([$tool,'-t','filter'],10);
    if($rc===0)foreach(explode("\n",$saved) as $line)foreach($members as $member)if(strpos($line,'--match-set '.$member['set'].' ')!==false)$rules[]=$line;
    $conf=kconf();$bypassed=[];foreach(preg_split('/\s+/',trim($conf[strpos($ip,':')!==false?'BYPASS_NETWORKS_V6':'BYPASS_NETWORKS_V4']??'')) as $net){try{if($net&&koverlap($ip,$net))$bypassed[]=$net;}catch(Throwable $e){}}
    $white=array_filter($members,fn($v)=>strpos($v['set'],'FirewallWhite')===0);$blocking=array_values(array_filter($members,fn($v)=>strpos($v['set'],'FirewallWhite')!==0));
    return ['status'=>'success','ip'=>$ip,'blocked'=>count($blocking)>0,'lists'=>array_column($blocking,'set'),'matches'=>$members,'rules'=>array_values(array_unique($rules)),'whitelisted'=>(bool)$white,'bypass_networks'=>$bypassed,'health'=>khealth(),'metadata'=>$metadata[0]??null,'counters'=>$counters,'manual_note'=>null,'explanation'=>'List membership is not proof of a dropped packet. Interface/network bypasses, established connections, enabled list settings and rule order also apply. Counters are historical, not a live packet trace.'.khistorynote()];
}
function kqueue($key,$subject,$body,$html=null) {
    $path=kp('/opt/etc/keentool/security/notifications.json');$lock=klock('notifications');try{$q=kread($path);$q[$key]=['subject'=>$subject,'body'=>$body,'created'=>time()];if($html!==null)$q[$key]['html']=$html;if(count($q)>50)$q=array_slice($q,-50,null,true);kwrite($path,$q);}finally{kunlock($lock);}
}
function klistEvent($args) {
    [$set,$old,$new,$expected,$reason,$code,$detail,$sourceWarning]=array_pad($args,8,'');
    if(!in_array($set,['FirewallBlock','FirewallBlock6','GeoBlock','GeoBlock6'],true)||!kdigits($old)||!kdigits($new)||!in_array($reason,['installed','rejected'],true))throw new InvalidArgumentException('Invalid list event');
    $clean=fn($v)=>substr(preg_replace('/[\x00-\x1f]/',' ',(string)$v),0,600);$detail=$clean($detail);$sourceWarning=$clean($sourceWarning);
    if($code!==''&&!preg_match('/^[a-z_]{1,48}$/D',$code))throw new InvalidArgumentException('Invalid list diagnostic code');
    $geo=strpos($set,'Geo')===0;$settings=kconfig();$old=(int)$old;$new=(int)$new;$delta=$old?($new-$old)*100/$old:0;
    $sizeWarn=$expected!=='baseline'&&$old>0&&($delta<=-(int)$settings[$geo?'geo_shrink_percent':'list_shrink_percent']||$delta>=(int)$settings[$geo?'geo_growth_percent':'list_growth_percent']);
    $warn=$reason==='installed'&&($sizeWarn||$sourceWarning!=='');$outcome=$reason==='rejected'?'error':($warn?'warning':'ok');
    $publicDetail=trim($detail.' '.$sourceWarning);$event=$set.($reason==='rejected'?' update rejected':($sourceWarning!==''?' updated using cached source':' updated'));
    kaudit('blocklist',$event,$outcome,'local',$set,"$old -> $new prefixes; ".round($delta,1)."%; $expected; $reason",null,$publicDetail);
    if($reason==='rejected'&&!empty($settings['immediate_alerts']))kqueue('feed-'.$set,'KeenTool: blocklist update failed',"$set update rejected. ".$publicDetail);
    $path=kp('/opt/etc/keentool/security/lists.json');$lock=klock('lists');try{
        $rows=kread($path);$prior=$rows[$set]??[];$installed=$reason==='rejected'?($prior['installed']??($old?:null)):$new;
        if($code==='rollback_failed')$installed=null;
        $rows[$set]=['installed'=>$installed,'old'=>$old,'new'=>$new,'delta_percent'=>round($delta,1),'time'=>time(),'last_success'=>$reason==='installed'?time():($prior['last_success']??(($prior['result']??'')==='installed'?($prior['time']??null):null)),'warning'=>$warn,'size_warning'=>$reason==='installed'&&$sizeWarn,'result'=>$reason,'baseline'=>$expected==='baseline','geo'=>$geo,'error_code'=>$code,'detail'=>$detail,'source_warning'=>$sourceWarning];kwrite($path,$rows);
    }finally{kunlock($lock);}
}
function kcomparison() {
    $now=time();$sets=[];foreach([['day',86400],['week',604800]] as [$name,$span]){
        $start=$now-$span;$previous=$now-2*$span;
        $summary=ksql("SELECT SUM(CASE WHEN timestamp>$start THEN count ELSE 0 END) AS current,SUM(CASE WHEN timestamp<=$start AND timestamp>$previous THEN count ELSE 0 END) AS previous FROM ip_drops WHERE timestamp>$previous AND timestamp<=$now;");
        $countries=ksql("SELECT country_key AS country,SUM(CASE WHEN timestamp>$start THEN count ELSE 0 END) AS current,SUM(CASE WHEN timestamp<=$start THEN count ELSE 0 END) AS previous FROM (SELECT CASE WHEN length(trim(i.country))=2 AND upper(trim(i.country)) GLOB '[A-Z][A-Z]' THEN upper(trim(i.country)) ELSE 'XX' END AS country_key,d.timestamp,d.count FROM ip_drops d LEFT JOIN ip_info i ON i.ip=CASE WHEN INSTR(d.ip,'/')>0 THEN SUBSTR(d.ip,1,INSTR(d.ip,'/')-1) ELSE d.ip END WHERE d.timestamp>$previous AND d.timestamp<=$now) AS normalized GROUP BY country_key ORDER BY (current+previous) DESC,country_key LIMIT 10;");
        $ports=ksql("SELECT COALESCE(NULLIF(i.target_port,''),'unknown') AS port,SUM(CASE WHEN d.timestamp>$start THEN d.count ELSE 0 END) AS current,SUM(CASE WHEN d.timestamp<=$start THEN d.count ELSE 0 END) AS previous FROM ip_drops d LEFT JOIN ip_info i ON i.ip=CASE WHEN INSTR(d.ip,'/')>0 THEN SUBSTR(d.ip,1,INSTR(d.ip,'/')-1) ELSE d.ip END WHERE d.timestamp>$previous AND d.timestamp<=$now GROUP BY port ORDER BY (current+previous) DESC LIMIT 10;");
        $sets[$name]=['seconds'=>$span,'current_start'=>$start,'current_end'=>$now,'previous_start'=>$previous,'previous_end'=>$start,'summary'=>$summary[0]??['current'=>0,'previous'=>0],'countries'=>$countries,'ports'=>$ports];
    }return $sets;
}
function ksystem() {
    $root=kp('/opt');$db=kp('/opt/etc/firewall_stats.db');$health=khealth();$services=[];
    foreach(['ulogd','lighttpd','syslog-ng','vnstatd','wan_syslog_service'] as $service){[$rc,$out]=krun(['pidof',$service],3);$services[$service]=$rc===0;}
    [$cronRc]=krun(['pidof','crond','cron'],3);$services['cron']=$cronRc===0;
    $sizes=[];foreach([kp('/opt/etc/firewall_stats.db'),kp('/opt/etc/pingtool/pingtool.db')] as $file)if(is_file($file))$sizes[basename($file)]=filesize($file);
    $backups=array_merge(glob(kp('/opt/var/backups/keentool-alpha/*/INSTALL.tsv'))?:[],glob(kp('/opt/var/backups/keentool-release/*/INSTALL.tsv'))?:[]);$last=0;$verified=0;
    usort($backups,fn($a,$b)=>filemtime($b)<=>filemtime($a));
    foreach($backups as $path){$last=max($last,filemtime($path));$ledger=dirname($path).'/checksums.json';if(!$verified&&is_file($ledger)){
        $hashes=kread($ledger);$valid=count($hashes)>0;foreach($hashes as $rel=>$sha){if(strpos($rel,'files/')!==0||strpos($rel,'..')!==false||!is_file(dirname($path).'/'.$rel)||!hash_equals($sha,hash_file('sha256',dirname($path).'/'.$rel))){$valid=false;break;}}
        if($valid)$verified=filemtime($path);
    }}
    $verifiedSmb=kread(kp('/opt/etc/keentool/security/backups.json'));$lastSmb=$verifiedSmb?end($verifiedSmb):null;
    $conf=kconf();$review=[];foreach(['BYPASS_INTERFACES','TRAP_BYPASS_INTERFACES','BYPASS_NETWORKS_V4','BYPASS_NETWORKS_V6','DNS_BYPASS_PORTS'] as $key)$review[$key]=$conf[$key]??'(hook default)';
    $webRoot=false;$webSeen=false;foreach(glob(kp('/proc/[0-9]*/comm'))?:[] as $path){
        $name=trim((string)@file_get_contents($path));if(!in_array($name,['php-cgi','php8-cgi','lighttpd'],true))continue;$webSeen=true;
        if(preg_match('/^Uid:\s*(\d+)/m',(string)@file_get_contents(dirname($path).'/status'),$m)&&(int)$m[1]===0)$webRoot=true;
    }
    $wanPid=trim((string)@file_get_contents(kp('/tmp/keentool-wan-service.pid')));$services['wan_syslog_service']=kdigits($wanPid)&&strpos((string)@file_get_contents(kp('/proc/'.$wanPid.'/cmdline')),'wan_syslog_service')!==false;
    $setHealth=[];foreach(['FirewallBlock','FirewallBlock6','GeoBlock','GeoBlock6','AutoBan','AutoBan6','KTManualBan','KTManualBan6'] as $set){[$rc,$text]=krun(['ipset','list',$set,'-terse'],5);$row=['present'=>$rc===0,'boot_restore_complete'=>trim((string)@file_get_contents(kp('/tmp/fw-restored-'.$set)))==='complete-v2'];if(preg_match('/Number of entries:\s*(\d+)/',$text,$m))$row['entries']=(int)$m[1];if(preg_match('/References:\s*(\d+)/',$text,$m))$row['references']=(int)$m[1];$setHealth[$set]=$row;}
    return ['time'=>time(),'monitor_interval'=>max(30,min(3600,(int)kconfig()['monitor_interval'])),'firewall'=>$health,'disk'=>['free'=>@disk_free_space($root),'total'=>@disk_total_space($root)],'databases'=>$sizes,'services'=>$services,'latest_verified_smb_backup'=>$lastSmb,'latest_source_backup'=>$last?:null,'latest_verified_source_backup'=>$verified?:null,'backup_note'=>$verified?'Backup file checksums verified; database recovery is not included.':'Source-backup presence only; legacy backup has no checksum ledger.','web_privileges'=>$webSeen?($webRoot?'root detected':'unprivileged detected'):'not verified','isolation_configured'=>is_file(kp('/opt/etc/keentool/security/web-hardened')),'sets'=>$setHealth,'bypasses'=>$review,'management_networks'=>kconfig()['management_networks'],'pending'=>kpending(),'lists'=>kread(kp('/opt/etc/keentool/security/lists.json')),'manual_bans'=>array_map(fn($r)=>['expires'=>$r['expires'],'created'=>$r['created']],kread(kp('/opt/etc/keentool/security/manual-bans.json')))];
}
// Decimal units keep the public dashboard and digest consistent.
function kstorageSize($bytes) {
    if((!is_int($bytes)&&!is_float($bytes))||!is_finite((float)$bytes)||$bytes<0)return 'Unavailable';
    $units=['B','KB','MB','GB','TB','PB'];$unit=0;$value=(float)$bytes;
    while($value>=1000&&$unit<count($units)-1){$value/=1000;$unit++;}
    if(round($value,1)>=1000&&$unit<count($units)-1){$value/=1000;$unit++;}
    return rtrim(rtrim(number_format($value,1,',','.'),'0'),',').' '.$units[$unit];
}
function kdigest($system,$events) {
    $healthy=$system['firewall']['healthy']??null;
    $rows=[['Firewall healthy',$healthy===true?'yes':($healthy===false?'no':'Not verified'),$healthy===true?'ok':($healthy===false?'error':'unknown')]];
    $web=$system['web_privileges']??'not verified';
    $rows[]=['Web privileges',$web,$web==='unprivileged detected'?'ok':($web==='root detected'?'error':'unknown')];
    $free=$system['disk']['free']??null;$total=$system['disk']['total']??null;
    $known=(is_int($free)||is_float($free))&&$free>=0&&(is_int($total)||is_float($total))&&$total>0;
    $rows[]=['Free storage',kstorageSize($free),$known?($free/$total>=.05?'ok':'error'):'unknown'];
    foreach($system['lists']??[] as $set=>$row){
        $rejected=($row['result']??'')==='rejected';
        if(!$rejected&&empty($row['warning']))continue;
        $cached=trim((string)($row['source_warning']??''));
        $lines=[$rejected?(isset($row['installed'])?'Update rejected; previous installed list retained.':'Update rejected; installed state unverified.'):($cached!==''?'Installed with cached source data.':'Installed with a prefix-count warning.')];
        $count=$row['installed']??null;
        $lines[]='Installed prefixes: '.(is_numeric($count)&&$count>=0?number_format((float)$count,0,',','.'):'Not verified');
        // A rejected candidate is not an installed change, even when new=0 and delta=-100.
        $delta=$row['delta_percent']??null;
        if(!$rejected&&is_numeric($delta)&&is_finite((float)$delta)){
            $change=rtrim(rtrim(number_format((float)$delta,1,',','.'),'0'),',');
            $lines[]='Installed prefix-count change: '.($delta>0?'+':'').$change.'% (not address coverage).';
        }
        if(!empty($row['size_warning']))$lines[]='Prefix-count variation exceeded the configured warning threshold.';
        $detail=trim((string)($row['detail']??''));
        $lines[]='Update details: '.($detail!==''?$detail:'Not recorded.');
        if($cached!=='')$lines[]='Source warning: '.$cached;
        $attempt=$row['time']??null;$success=$row['last_success']??null;
        $lines[]='Last update attempt: '.(is_numeric($attempt)&&$attempt>0?date('d/m/Y H:i:s T',(int)$attempt):'Not recorded.');
        $lines[]='Last successful installation: '.(is_numeric($success)&&$success>0?date('d/m/Y H:i:s T',(int)$success):'Not recorded; list age unknown.');
        if($cached!=='')$lines[]='Cached source age is not recorded; installation time does not confirm source freshness.';
        $rows[]=[$set,implode("\n",$lines),$rejected?'error':'unknown'];
    }
    $escape=fn($text)=>htmlspecialchars((string)$text,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');
    $colors=['ok'=>'#00843d','unknown'=>'#966000','error'=>'#bd3030'];$plain=[];
    $html='<!doctype html><html lang="en"><head><meta charset="utf-8"></head><body style="margin:0;padding:20px;background:#ffffff;color:#17202b;font-family:Arial,sans-serif;font-size:15px;line-height:1.5"><h2 style="font-size:20px;margin:0 0 16px">KeenTool security summary</h2><table role="presentation" style="border-collapse:collapse">';
    foreach($rows as [$label,$value,$state]){
        $plain[]=$label.': '.$value;
        $html.="\r\n".'<tr><td style="padding:6px 18px 6px 0;vertical-align:top">'.$escape($label).':</td><td style="padding:6px 0;vertical-align:top;font-weight:700;color:'.$colors[$state].'">'.nl2br($escape($value),false).'</td></tr>';
    }
    $recent='Recent events: '.count($events);$plain[]=$recent;
    $html.="\r\n".'</table><p style="margin:16px 0 0">'.$escape($recent).'</p></body></html>';
    return ['body'=>implode("\n",$plain),'html'=>$html];
}
function ktick() {
    $lock=klock('monitor');try {
        $system=ksystem();$events=kevents();try{$comparisons=kcomparison();}catch(Throwable $e){$comparisons=['error'=>$e->getMessage()];}$settings=kconfig();$statePath=kp('/opt/etc/keentool/security/monitor.json');$old=kread($statePath);$now=time();if(!$old)$old['digest_date']=date('Y-m-d');
        $issues=[];if($system['isolation_configured']&&$system['web_privileges']!=='unprivileged detected')$issues[]='Configured web isolation cannot be verified';if(empty($system['firewall']['healthy']))$issues[]='Firewall rules do not match the expected configuration';
        $free=$system['disk']['free'];$total=$system['disk']['total'];if(is_numeric($free)&&is_numeric($total)&&$total>0&&$free/$total<.05)$issues[]='Entware storage has less than 5% free space';
        if($system['firewall']['enabled']??false){
            $required=['FirewallBlock'];if((kconf()['ENABLE_IPV6']??'true')==='true')$required[]='FirewallBlock6';
            foreach($required as $set)if(!($system['sets'][$set]['present']??false))$issues[]='Required set missing: '.$set;
            foreach(['FirewallBlock'=>'firewall_blocklist.save','FirewallBlock6'=>'firewall_blocklist6.save','GeoBlock'=>'firewall_geoblock.save','GeoBlock6'=>'firewall_geoblock6.save'] as $set=>$file){
                if(str_ends_with($set,'6')&&(kconf()['ENABLE_IPV6']??'true')!=='true')continue;
                if(is_file(kp('/opt/etc/'.$file))&&filesize(kp('/opt/etc/'.$file))>0&&empty($system['sets'][$set]['boot_restore_complete']))$issues[]='Saved-set import not marked complete: '.$set;
            }
        }
        $key=hash('sha256',json_encode($issues));$consecutive=$key===($old['issue_key']??'')?($old['consecutive']??0)+1:1;
        if($issues&&$consecutive>=2&&$key!==($old['notified_key']??'')&&!empty($settings['immediate_alerts'])&&$now-($old['started']??$now)>=180){kqueue('health','KeenTool: security health warning',implode("\n",$issues));$old['notified_key']=$key;kaudit('health','health warning','warning','local','',implode('; ',$issues));}
        if(!$issues&&!empty($old['had_issues'])){kaudit('health','health recovered');$old['notified_key']='';}
        $date=date('Y-m-d');if((int)date('G')>=(int)$settings['digest_hour']&&($old['digest_date']??'')!==$date){
            $digest=kdigest($system,$events);kqueue('digest-'.$date,'KeenTool: daily security summary',$digest['body'],$digest['html']);$old['digest_date']=$date;
        }
        $state=array_merge($old,['started'=>$old['started']??$now,'issue_key'=>$key,'consecutive'=>$consecutive,'had_issues'=>(bool)$issues,'last_check'=>$now]);kwrite($statePath,$state);
        $public=kp('/opt/var/www/firewall/security-data.json');$dir=dirname($public);if(!is_dir($dir))mkdir($dir,0755,true);kwrite($public,['system'=>$system,'events'=>$events,'comparisons'=>$comparisons,'coverage_note'=>'Counters describe recorded IP hits. Port comparisons attribute each IP to its latest target_port metadata; they are not per-port packet measurements. Country metadata is current, including for historical periods.'.khistorynote()],0644);
    }finally{kunlock($lock);}
    if(!empty($settings['email_enabled'])&&is_file(kp('/opt/etc/keentool/mail/email.conf'))&&is_file(kp('/opt/etc/keentool/mail/emailpw.enc'))){
        $lock=klock('mail');try{$qPath=kp('/opt/etc/keentool/security/notifications.json');$q=kread($qPath);if($q){$id=array_key_first($q);$mail=$q[$id];$argv=[kp('/opt/bin/email_sender.mod'),$mail['subject'],$mail['body']];if(isset($mail['html']))$argv[]=$mail['html'];[$rc]=krun($argv,50);if($rc===0){$qlock=klock('notifications');try{$current=kread($qPath);if(($current[$id]??null)===$mail)unset($current[$id]);kwrite($qPath,$current);}finally{kunlock($qlock);}}}}finally{kunlock($lock);}
    }
}
function kcapture($file,$limit=1000) {
    $p=proc_open(['tcpdump','-tttt','-nn','-r',$file],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    if(!is_resource($p))throw new RuntimeException('Cannot decode capture');fclose($pipes[0]);stream_set_blocking($pipes[1],false);stream_set_blocking($pipes[2],false);
    $ring=[];$count=0;$buffer='';$deadline=kmono()+15;$partial=false;$exit=-1;
    do{
        $buffer.=stream_get_contents($pipes[1],65536);stream_get_contents($pipes[2],65536);
        while(($position=strpos($buffer,"\n"))!==false){$line=substr($buffer,0,$position);$buffer=substr($buffer,$position+1);$ring[$count%$limit]=substr($line,0,1024);if(strlen($line)>1024)$partial=true;$count++;}
        if(strlen($buffer)>65536){$buffer=substr($buffer,-16384);$partial=true;}
        $status=proc_get_status($p);if(!$status['running']){$exit=$status['exitcode'];break;}
        if(kmono()>$deadline){proc_terminate($p);usleep(100000);proc_terminate($p,9);$partial=true;break;}usleep(1000);
    }while(true);
    // Drain the final pipe chunk after process exit, still keeping only a bounded ring.
    $buffer.=stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);foreach(explode("\n",$buffer) as $line)if($line!==''){$ring[$count%$limit]=substr($line,0,1024);if(strlen($line)>1024)$partial=true;$count++;}
    fclose($pipes[1]);fclose($pipes[2]);proc_close($p);$rows=[];for($i=max(0,$count-$limit);$i<$count;$i++)$rows[]=$ring[$i%$limit];
    if(!$rows&&$exit!==0)throw new RuntimeException('Capture decode failed');return ['rows'=>$rows,'partial'=>$partial];
}
function kthrottle($action,$actor,$interval=null) {
    static $rates=[];$now=kmono();foreach($rates as $key=>$until)if($until<$now-60)unset($rates[$key]);
    if(count($rates)>512)throw new RuntimeException('Diagnostic rate limit reached',429);
    $key=$action.'|'.$actor;if(($rates[$key]??0)>$now)throw new RuntimeException('Diagnostic rate limit reached',429);
    $rates[$key]=$now+($interval??($action==='livelog'?5:($action==='lookup'?.5:1)));
}
function ksystemlogs() {
    return ['main'=>'messages','ulogd'=>'ulogd.log','vpn'=>'vpn.log','proxy'=>'nginx_proxy.log','scripts'=>'keentool.log','wifi'=>'wifi_monitor.log','dhcp'=>'ndhcps.log','dns'=>'dns_proxy.log'];
}
function klogsizes($actor) {
    kthrottle('log_sizes',$actor);$sizes=[];
    foreach(ksystemlogs() as $id=>$name){
        $path=kp('/opt/var/log/'.$name);clearstatcache(true,$path);
        $stat=is_link($path)?false:@stat($path);
        $sizes[$id]=$stat&&($stat['mode']&0170000)===0100000?$stat['size']:null;
    }
    return ['status'=>'success','sizes'=>$sizes];
}
function kloganchor($file,$size) {
    $start=max(0,$size-64);
    if(fseek($file,$start)!==0)throw new RuntimeException('Cannot seek system log');
    $text=stream_get_contents($file,$size-$start);
    if($text===false||strlen($text)!==$size-$start)throw new RuntimeException('System log changed during read; refresh latest entries');
    return hash('sha256',$text);
}
function ksystemlog($input) {
    $logs=ksystemlogs();
    $id=$input['log_id']??'';$cursor=$input['cursor']??null;$page=null;
    if(!is_string($id)||!isset($logs[$id]))throw new InvalidArgumentException('Unknown system log');
    if($cursor!==null){
        if(!is_string($cursor)||strlen($cursor)>1024||!preg_match('/^[A-Za-z0-9_-]+$/D',$cursor))throw new InvalidArgumentException('Invalid log cursor');
        $decoded=base64_decode(strtr($cursor,'-_','+/'),true);$page=$decoded===false?null:json_decode($decoded,true);
        if(!is_array($page)||($page['v']??null)!==1||($page['id']??null)!==$id||!kdigits($page['dev']??null)||!kdigits($page['ino']??null)||!is_int($page['end']??null)||!is_int($page['size']??null)||$page['end']<0||$page['end']>$page['size']||!is_string($page['anchor']??null)||!preg_match('/^[a-f0-9]{64}$/D',$page['anchor']))throw new InvalidArgumentException('Invalid log cursor');
    }
    kthrottle('systemlog_'.$id.($cursor===null?'_latest':'_page'),$input['actor']??'local',$cursor===null?1:.02);
    $path=kp('/opt/var/log/'.$logs[$id]);
    if(is_link($path)||!is_file($path))throw new RuntimeException('System log is unavailable');
    $file=@fopen($path,'rb');if(!$file)throw new RuntimeException('System log cannot be read');
    try {
        $stat=fstat($file);if(!$stat||($stat['mode']&0170000)!==0100000)throw new RuntimeException('Regular system log required');
        $reset=['status'=>'success','reset_required'=>true,'message'=>'Log rotated or truncated. Refresh latest entries to start a new view.'];
        if($page&&($page['dev']!==(string)$stat['dev']||$page['ino']!==(string)$stat['ino']||$stat['size']<$page['size']))return $reset;
        if(!$page)$page=['v'=>1,'id'=>$id,'dev'=>(string)$stat['dev'],'ino'=>(string)$stat['ino'],'size'=>$stat['size'],'end'=>$stat['size'],'anchor'=>kloganchor($file,$stat['size'])];
        if(!hash_equals($page['anchor'],kloganchor($file,$page['size'])))return $reset;
        $end=$page['end'];$limit=32768;$offset=max(0,$end-$limit);
        if(fseek($file,$offset)!==0)throw new RuntimeException('Cannot seek system log');
        $text=stream_get_contents($file,$end-$offset);if($text===false||strlen($text)!==$end-$offset)return $reset;
        if($offset>0){
            $newline=strpos($text,"\n");
            if($newline!==false&&$newline+1<strlen($text)){$cut=$newline+1;$offset+=$cut;$text=substr($text,$cut);}
            else {
                // A very long line may span pages; keep UTF-8 boundaries when possible.
                $cut=0;while($cut<strlen($text)&&(ord($text[$cut])&0xc0)===0x80)$cut++;
                $offset+=$cut;$text=substr($text,$cut);
            }
        }
        $rows=explode("\n",$text);$drop=count($rows)-1000-(str_ends_with($text,"\n")?1:0);
        if($drop>0){$cut=strlen(implode("\n",array_slice($rows,0,$drop)))+1;$offset+=$cut;$text=substr($text,$cut);}
        if(!hash_equals($page['anchor'],kloganchor($file,$page['size'])))return $reset;
        while(true){
            $page['end']=$offset;$more=$offset>0;
            $next=$more?rtrim(strtr(base64_encode(json_encode($page)),'+/','-_'),'='):null;
            $reply=['status'=>'success','log'=>$text,'partial_preview'=>$more,'has_more'=>$more,'next_cursor'=>$next,'size_bytes'=>$page['size'],'loaded_bytes'=>strlen($text),'note'=>'Internal transfer block; the dashboard loads the complete current log.'];
            // Bound encoded bytes as escaping may expand raw log content substantially.
            if(strlen(json_encode($reply,JSON_INVALID_UTF8_SUBSTITUTE))<=48000)return $reply;
            $cut=max(1,intdiv(strlen($text),4));$newline=strpos($text,"\n",$cut);
            if($newline!==false&&$newline+1<strlen($text))$cut=$newline+1;
            else while($cut<strlen($text)&&(ord($text[$cut])&0xc0)===0x80)$cut++;
            $offset+=$cut;$text=substr($text,$cut);
        }
    } finally {fclose($file);}
}
function kdispatch($input) {
    static $statusCache=null;
    $action=$input['action']??'';$actor=$input['actor']??'local';if(!is_string($action)||!is_string($actor)||($actor!=='local'&&!kip($actor)))throw new InvalidArgumentException('Invalid action context');
    if(in_array($action,['settings_get','settings_save'],true)){require_once kp('/opt/lib/keentool-security/settings_engine.php');}
    if($action==='settings_get')return ksettingsget();
    if($action==='log_sizes')return klogsizes($actor);
    if($action==='systemlog')return ksystemlog($input);
    if($action==='lookup')kthrottle($action,$actor);
    if($action==='status'){if(!$statusCache||kmono()-$statusCache['at']>1)$statusCache=['at'=>kmono(),'data'=>array_merge(['status'=>'success','pending'=>kpending()],khealth())];return $statusCache['data'];}
    if($action==='lookup')return klookup($input);
    if($action==='snapshot')return ['status'=>'success','data'=>kread(kp('/opt/var/www/firewall/security-data.json'))];
    if($action==='audit')return ['status'=>'success','events'=>kevents(true)];
    if($action==='audit_auth'){if(!in_array($input['event']??'',['login success','login failed','login throttled','logout','CSRF rejected','authorization rejected'],true))throw new InvalidArgumentException('Invalid auth event');kaudit('admin',$input['event'],'info',$actor);return ['status'=>'success'];}
    if($action==='livelog'){
        $lines=max(1,min(1000,(int)($input['lines']??500)));static $cache=null;
        if(!$cache||kmono()-$cache['at']>10){
            $base=kp('/opt/var/log/keentool-firewall/fw_syn_ring.pcap');$paths=glob($base.'.processed.*')?:[];rsort($paths,SORT_NATURAL);$paths=array_slice($paths,0,1);if(is_file($base))$paths[]=$base;
            $rows=[];$partial=false;foreach($paths as $file){$capture=kcapture($file);$rows=array_slice(array_merge($rows,$capture['rows']),-1000);$partial=$partial||$capture['partial'];}
            $cache=['at'=>kmono(),'rows'=>array_values(array_unique($rows)),'partial'=>$partial];
        }
        return ['status'=>'success','log'=>$cache['rows']?implode("\n",array_slice($cache['rows'],-$lines)):'No captured packets available.','partial_preview'=>$cache['partial'],'sampled'=>(int)(kconf()['FW_LOG_RATE']??2)>0,'note'=>'Preview cached for 10 seconds. NFLOG may be rate-limited; kernel drop counters remain the authoritative totals.'];
    }
    $statusCache=null;
    if(is_file(kp('/opt/etc/keentool/maintenance')))throw new RuntimeException('Entware maintenance active; retry after completion');
    $lock=klock('commands');try {
        if($action==='settings_save')return ksettingssave($input,$actor);
        if($action==='ban')return kban($input,$actor);
        if($action==='unban')return kunban($input,$actor);
        if($action==='enable'||$action==='disable')return kpolicy($action==='enable',$actor);
        if($action==='confirm_policy'){
            $p=kread(kp('/opt/etc/keentool/security/pending.json'));$id=$input['pending_id']??'';
            if(!$p||!is_string($id)||!hash_equals($p['id'],$id)||time()>=$p['expires']||kmono()>=($p['mono_deadline']??PHP_FLOAT_MAX)||$p['boot']!==kboot())throw new InvalidArgumentException('Confirmation expired or invalid');
            if(!hash_equals($p['new_sha'],hash_file('sha256',kp('/opt/etc/firewall.conf')))||empty(khealth()['healthy']))throw new RuntimeException('Policy changed or is unhealthy');
            unlink(kp('/opt/etc/keentool/security/pending.json'));kaudit('firewall','policy confirmed','ok',$actor);return ['status'=>'success'];
        }
        if($action==='rollback_policy'){$p=kpending();if(!$p)throw new InvalidArgumentException('No pending policy');krollback($p['pending_id'],'user requested');return ['status'=>'success'];}
        throw new InvalidArgumentException('Unknown action');
    }catch(Throwable $e){kaudit('firewall',$action,'error',$actor,is_string($input['ip']??null)?$input['ip']:'',$e->getMessage());throw $e;}finally{kunlock($lock);}
}
function kmain($args) {
    $mode=$args[1]??'status';
    if($mode==='path-mtime'){ $path=$args[2]??'';if($path!==kp('/opt/var/run/keentool-security-service.pid.lock'))throw new InvalidArgumentException('Unsupported metadata path');$at=@filemtime($path);if($at===false)throw new RuntimeException('Metadata unavailable');echo $at;return;}
    if($mode==='init'){
        $dir=kp('/opt/etc/keentool/security');if(!is_dir($dir))mkdir($dir,0700,true);if(!is_file($dir.'/settings.json'))kwrite($dir.'/settings.json',kconfig());
        $lock=klock('commands');try{$p=kpending();if($p)krollback($p['pending_id'],'service initialization');kensureSets();kreconcile(true);}finally{kunlock($lock);}echo "Security state ready\n";return;
    }
    if($mode==='guard'){
        $id=$args[2]??'';while(true){$p=kread(kp('/opt/etc/keentool/security/pending.json'));if(!$p||!hash_equals($p['id'],$id))return;
            if(time()>=$p['expires']||kmono()>=($p['mono_deadline']??PHP_FLOAT_MAX)||$p['boot']!==kboot()){$lock=klock('commands');try{krollback($id,'confirmation deadline elapsed');}finally{kunlock($lock);}return;}sleep(1);}
    }
    if($mode==='tick'){ktick();return;}
    if($mode==='reconcile'){$lock=klock('commands');try{kreconcile(false);}finally{kunlock($lock);}return;}
    if($mode==='backup-event'){
        $folder=$args[2]??'';if(!preg_match('/^[0-9]{8}_[0-9]{6}$/D',$folder))throw new InvalidArgumentException('Invalid verified backup id');
        $manifest=stream_get_contents(STDIN,4097);if(strlen($manifest)>4096)throw new InvalidArgumentException('Manifest too large');$files=[];
        foreach(explode("\n",trim($manifest)) as $line){if(!preg_match('/^([a-f0-9]{64})\s+([a-zA-Z0-9_.-]+)$/D',$line,$m))throw new InvalidArgumentException('Invalid verified manifest');$files[$m[2]]=$m[1];}
        if(count($files)!==3)throw new InvalidArgumentException('Three verified archives required');
        $lock=klock('backups');try{$path=kp('/opt/etc/keentool/security/backups.json');$rows=kread($path);$rows[$folder]=['time'=>time(),'folder'=>$folder,'verified_at_upload'=>true,'files'=>$files];kwrite($path,array_slice($rows,-10,null,true));}finally{kunlock($lock);}
        kaudit('backup','SMB backup read-back verified','ok','local',$folder);return;
    }
    if($mode==='list-event'){klistEvent(array_slice($args,2));return;}
    if($mode==='event'){$category=$args[2]??'';if(!in_array($category,['wan','ping','entware','blocklist','health'],true))throw new InvalidArgumentException('Invalid event category');$at=$args[5]??null;if($at!==null&&(!kdigits($at)||(int)$at<1514764800||(int)$at>time()+60))throw new InvalidArgumentException('Invalid event timestamp');kaudit($category,substr($args[3]??'event',0,120),preg_match('/failed|error/i',$args[3]??'')?'error':'info','local','',substr($args[4]??'',0,400),$at===null?null:(int)$at);return;}
    if($mode==='settings'){
        $data=json_decode(stream_get_contents(STDIN,8192),true);if(!is_array($data))throw new InvalidArgumentException('JSON settings required');$old=kconfig();
        foreach($data as $key=>$value){if(!array_key_exists($key,$old))throw new InvalidArgumentException('Unknown setting');if($key==='management_networks'){if(!is_array($value)||count($value)>32)throw new InvalidArgumentException('At most 32 management networks');$value=array_map(fn($net)=>knetwork($net)['text'],$value);}elseif($key==='timezone'){if(!is_string($value)||!in_array($value,timezone_identifiers_list(),true))throw new InvalidArgumentException('Valid IANA timezone required');}elseif(in_array($key,['email_enabled','immediate_alerts'],true)){if(!is_bool($value))throw new InvalidArgumentException('Boolean required');}else{if(!is_int($value))throw new InvalidArgumentException('Integer required');$range=$key==='monitor_interval'?[30,3600]:($key==='guard_seconds'?[30,300]:($key==='digest_hour'?[0,23]:(str_contains($key,'shrink')?[1,100]:[1,1000])));if($value<$range[0]||$value>$range[1])throw new InvalidArgumentException('Setting outside allowed range');}$old[$key]=$value;}
        kwrite(kp('/opt/etc/keentool/security/settings.json'),$old);kaudit('admin','security settings updated');echo "Settings saved\n";return;
    }
    if($mode==='clear-manual'){
        $lock=klock('commands');try{
            foreach(['KTManualBan','KTManualBan6','Blacklist','Blacklist6'] as $set){[$exists]=krun(['ipset','list','-n',$set]);if($exists!==0)continue;[$rc]=krun(['ipset','flush',$set]);if($rc!==0)throw new RuntimeException('Cannot clear manual set');}
            kwrite(kp('/opt/etc/keentool/security/manual-bans.json'),[]);ksaveLegacy(false);ksaveLegacy(true);kaudit('firewall','all manual bans cleared');
        }finally{kunlock($lock);}return;
    }
    if($mode==='interval'){echo max(30,min(3600,(int)kconfig()['monitor_interval']));return;}
    if($mode==='broker'){
        if(!function_exists('proc_open')||!function_exists('stream_socket_server'))throw new RuntimeException('PHP process/socket functions unavailable');
        $lock=klock('broker');$dir=kp('/opt/var/run/keentool-security');if(!is_dir($dir))mkdir($dir,0710,true);$socket=$dir.'/broker.sock';@unlink($socket);
        $server=stream_socket_server('unix://'.$socket,$errno,$error);if(!$server)throw new RuntimeException('Cannot start privileged broker');
        [$groupRc,$groupId]=krun(['id','-g','ktweb'],3);if($groupRc===0&&is_file(kp('/opt/etc/keentool/security/web-hardened'))){chgrp($dir,(int)trim($groupId));chgrp($socket,(int)trim($groupId));}chmod($dir,0710);chmod($socket,0660);
        while(true){$client=@stream_socket_accept($server,1);if(!$client)continue;stream_set_timeout($client,3);$line=fgets($client,8193);$input=json_decode($line?:'',true);
            try{if(!$line||strlen($line)>8192||substr($line,-1)!=="\n"||!is_array($input))throw new InvalidArgumentException('Invalid local request');$reply=kdispatch($input);}catch(Throwable $e){$reply=['status'=>'error','message'=>$e->getMessage(),'http_status'=>$e->getCode()===429?429:400];}
            $json=json_encode($reply,JSON_INVALID_UTF8_SUBSTITUTE)."\n";stream_set_timeout($client,3);$offset=0;while($offset<strlen($json)){ $n=@fwrite($client,substr($json,$offset));if(!$n)break;$offset+=$n;}fclose($client);
        }kunlock($lock);return;
    }
    if($mode==='request'){$input=json_decode(stream_get_contents(STDIN,8192),true);if(!is_array($input))throw new InvalidArgumentException('JSON required');echo json_encode(kdispatch($input),JSON_PRETTY_PRINT|JSON_INVALID_UTF8_SUBSTITUTE)."\n";return;}
    if($mode==='status'){echo json_encode(ksystem(),JSON_PRETTY_PRINT|JSON_INVALID_UTF8_SUBSTITUTE)."\n";return;}
    throw new InvalidArgumentException('Unknown engine mode');
}
if(!defined('KT_ENGINE_TEST')){try{date_default_timezone_set(kconfig()['timezone']);$tz=@file_get_contents(kp('/etc/TZ'));if($tz===false)$tz=@file_get_contents(kp('/opt/etc/TZ'));if($tz!==false)putenv('TZ='.trim($tz));kmain($argv);}catch(Throwable $e){fwrite(STDERR,$e->getMessage()."\n");exit(1);}}
