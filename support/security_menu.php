<?php
// KEENTOOL SECURITY MENU v1.0.0 — 2026-10-29. Read-only terminal presentation.
if(PHP_SAPI!=='cli'||!function_exists('kconfig')){http_response_code(403);exit(1);}
function kmtext($value,$limit=240){return substr(preg_replace('/[\x00-\x1f\x7f]/',' ',(string)$value),0,$limit);}
function kmrow($label,$value){printf("  %-30s %s\n",kmtext($label),kmtext($value));}
function kmheading($title){echo "\n".kmtext($title)."\n".str_repeat('-',72)."\n";}
function kmdate($value){return is_numeric($value)&&(int)$value>0?date('d/m/Y H:i:s',(int)$value):'Not checked yet';}
function kmoptional($path){try{return kread($path);}catch(Throwable $e){return [];}}
function kmdata(){
 $settings=kconfig();$conf=kconf();$monitor=kmoptional(kp('/opt/etc/keentool/security/monitor.json'));$snapshot=kmoptional(kp('/opt/var/www/firewall/security-data.json'));$system=$snapshot['system']??[];
 $pid=trim((string)@file_get_contents(kp('/opt/var/run/keentool-security-service.pid')));$cmd=kdigits($pid)?str_replace("\0",' ',(string)@file_get_contents(kp('/proc/'.$pid.'/cmdline'))):'';
 $alive=$cmd!==''&&str_contains($cmd,kp('/opt/bin/keentool_security_service').' run');
 $socket=kp('/opt/var/run/keentool-security/broker.sock');$broker=!is_link($socket)&&@filetype($socket)==='socket';$service=$alive?($broker?'RUNNING':'NOT READY'):'STOPPED';
 $mail=kp('/opt/etc/keentool/mail/');$transport=is_file($mail.'email.conf')&&is_file($mail.'emailpw.enc')&&is_executable(kp('/opt/bin/email_sender.mod'));
 $at=(int)($system['time']??0);$fresh=$service==='RUNNING'&&(int)($monitor['last_check']??0)>0&&$at>0&&time()>=$at&&time()-$at<=max(90,2*(int)$settings['monitor_interval']);
 if(is_file(kp('/opt/etc/firewall.conf'))&&filemtime(kp('/opt/etc/firewall.conf'))>$at)$fresh=false;
 $fw='NOT VERIFIED';if(($conf['ENABLE_FIREWALL']??null)==='false')$fw=$fresh&&($system['firewall']['enabled']??null)===false?'DISABLED (snapshot)':'DISABLED (configured; not verified)';elseif($fresh&&($system['firewall']['enabled']??null)===true){$fw=($system['firewall']['healthy']??false)?'OK (snapshot)':'ISSUE (snapshot)';}
 $pending=kread(kp('/opt/etc/keentool/security/pending.json'));
 return ['settings'=>$settings,'conf'=>$conf,'service'=>$service,'transport_ready'=>$transport,'last_check'=>(int)($monitor['last_check']??0),'snapshot_time'=>$at,'snapshot_fresh'=>$fresh,'firewall'=>$fw,'web_isolated'=>is_file(kp('/opt/etc/keentool/security/web-hardened')),'web_observed'=>$fresh?($system['web_privileges']??'not verified'):'not verified','pending'=>!empty($pending),'system'=>$system];
}
function kmnotification($data,$key,$short=false){
 if(empty($data['settings'][$key]))return 'OFF';$why='';
 if(empty($data['settings']['email_enabled']))$why='email OFF';elseif(!$data['transport_ready'])$why='mail not configured';elseif($data['service']!=='RUNNING')$why='monitor not ready';
 return $why!==''?($short?'PAUSED':'ON / PAUSED ('.$why.')'):'ON';
}
function kmsummary(){
 $d=kmdata();echo $d['service'].'; warnings '.kmnotification($d,'immediate_alerts',true).'; daily '.kmnotification($d,'digest_enabled',true);
}
function kmmenu(){
 $d=kmdata();$s=$d['settings'];$c=$d['conf'];
 kmheading('Security Monitoring');kmrow('Monitor service',$d['service']);kmrow('Last completed check',kmdate($d['last_check']));kmrow('Firewall rules',$d['firewall']);
 echo "\nOverview\n  1. System health details\n  2. Recent events\n  3. Policy bypass review\n";
 echo "\nMonitoring\n";kmrow('5. Check interval',(int)$s['monitor_interval'].' seconds');
 echo "\nNotifications\n";kmrow('7. All security email',!empty($s['email_enabled'])?'ON':'OFF');kmrow('Mail transport',$d['transport_ready']?'Configured':'Not configured');
 kmrow('W. Immediate warning email',kmnotification($d,'immediate_alerts'));kmrow('D. Daily summary email',kmnotification($d,'digest_enabled'));
 kmrow('6. Daily summary time',sprintf('%02d:00',(int)$s['digest_hour']).(empty($s['digest_enabled'])?' (summary OFF)':''));kmrow('T. Notification timezone',$s['timezone']);
 echo "\nAccess and protection\n";kmrow('4. Protected management nets',count($s['management_networks']).' configured');kmrow('Web isolation / last check',$d['web_isolated']?'Configured; '.$d['web_observed']:'Not configured');kmrow('Policy confirmation window',(int)$s['guard_seconds'].' seconds');kmrow('Pending policy change',$d['pending']?'YES - confirm or roll back':'None');
 echo "  8. Review web isolation\n  9. Apply web isolation\n  R. Roll back web isolation\n";
 echo "\nBlocklist warnings and logging\n";kmrow('G. GeoIP change thresholds','shrink '.$s['geo_shrink_percent'].'% / growth '.$s['geo_growth_percent'].'%');kmrow('B. Other list thresholds','shrink '.$s['list_shrink_percent'].'% / growth '.$s['list_growth_percent'].'%');
 $rate=$c['FW_LOG_RATE']??'2';$burst=$c['FW_LOG_BURST']??'10';kmrow('L. NFLOG capture rate',preg_match('/^[0-9]+$/D',(string)$rate)?((int)$rate===0?'All packets (no sampling)':number_format((int)$rate,0,',','.').' packets/s per rule; burst '.kmtext($burst)):'Unavailable');
 echo "\n  0. Back\n";if(!$d['snapshot_fresh'])echo "Health snapshot is unavailable/stale; option 1 performs a live check.\n";
}
function kmhealth(){
 $system=ksystem();kmheading('System health - live check');kmrow('Checked at',kmdate($system['time']));$fw=$system['firewall'];kmrow('Firewall',($fw['enabled']??null)===false?'DISABLED':(!empty($fw['healthy'])?'OK':(($fw['enabled']??null)===true?'VERIFICATION FAILED':'NOT VERIFIED')));kmrow('Web privileges',$system['web_privileges']);kmrow('Free storage',kstorageSize($system['disk']['free']));
 foreach($system['databases'] as $name=>$size)kmrow($name,kstorageSize($size));
 kmheading('Services');foreach($system['services'] as $name=>$on)kmrow($name,$on?'RUNNING':'STOPPED');
 kmheading('Firewall sets');foreach($system['sets'] as $name=>$row)kmrow($name,empty($row['present'])?'Not available':(isset($row['entries'])?number_format((int)$row['entries'],0,',','.').' entries':'Entry count unavailable').'; '.(int)($row['references']??0).' references');
 kmheading('Blocklist updates');if(empty($system['lists']))echo "  No list update status recorded.\n";
 foreach($system['lists'] as $name=>$row){kmrow($name,($row['result']??'unknown').(!empty($row['warning'])?' / warning':''));if(!empty($row['detail']))echo '    '.kmtext($row['detail'],400)."\n";if(!empty($row['source_warning']))echo '    '.kmtext($row['source_warning'],400)."\n";}
 echo "\nLive checks do not change rules or settings.\n";
}
function kmevents(){
 kmheading('Recent security events - newest first');$events=kevents(true,20);if(!$events)echo "  No recent events.\n";
 foreach($events as $e){printf("  %s  %-10s %s\n",kmdate($e['time']??0),kmtext($e['outcome']??'unknown',10),kmtext(($e['category']??'').': '.($e['event']??''),160));$detail=trim(($e['target']??'').' '.(!empty($e['note'])?$e['note']:($e['detail']??'')));if($detail!=='')echo '    '.kmtext($detail,400)."\n";}
}
function kmbypasses(){
 $c=kconf();kmheading('Configured policy bypasses');foreach(['BYPASS_INTERFACES'=>'Interface bypass','TRAP_BYPASS_INTERFACES'=>'AutoBan bypass interfaces','BYPASS_NETWORKS_V4'=>'IPv4 bypass networks','BYPASS_NETWORKS_V6'=>'IPv6 bypass networks','DNS_BYPASS_PORTS'=>'DNS bypass ports'] as $key=>$label)kmrow($label,$c[$key]??'(hook default)');
 kmheading('Protected management networks');$nets=kconfig()['management_networks'];if(!$nets)echo "  No additional management networks configured.\n";foreach($nets as $net)echo '  '.kmtext($net)."\n";
 echo "\nThis is configuration, not a live packet trace. Existing bypasses and established connections affect rule matching.\n";
}
