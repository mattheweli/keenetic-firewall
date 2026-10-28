<?php
// KEENTOOL DATABASE MAINTENANCE v1.0.1 — private, backup-first CLI only.
if(PHP_SAPI!=='cli'){http_response_code(403);exit(1);}umask(0077);
define('KT_HISTORY_LIBRARY',true);require __DIR__.'/history_engine.php';
try{
 $kind=$argv[1]??'';$action=$argv[2]??'status';
 if(!in_array($kind,['firewall','ping','traffic'],true)||!in_array($action,['status','compact','balanced','expand'],true))throw new InvalidArgumentException('Use firewall|ping|traffic status|compact; firewall also supports balanced|expand');
 $db=$kind==='traffic'?(getenv('KT_VNSTAT_DB')?:hp('/opt/var/lib/vnstat/vnstat.db')):($kind==='firewall'?(getenv('KT_FW_DB')?:hp('/opt/etc/firewall_stats.db')):(getenv('KT_PING_DB')?:hp('/opt/etc/pingtool/pingtool.db')));
 if(!is_file($db)||is_link($db))throw new RuntimeException('Existing regular database required');
 $before=(int)hsql($db,'SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size();',true);
 if($action==='status')$result=['kind'=>$kind,'bytes'=>$before,'free_pages'=>(int)hsql($db,'PRAGMA freelist_count;',true),'storage'=>$kind==='firewall'?(ds_compact($db)?'compact':'legacy'):'original'];
 elseif($kind==='ping'||$kind==='traffic'){
  if($action!=='compact')throw new InvalidArgumentException('This database supports lossless compact only');
  if($kind==='ping')foreach(['stats','stats_v6'] as $table){$cols=hsql($db,"SELECT group_concat(name,'|') FROM pragma_table_info('$table');",true);if($cols!=='id|timestamp|ping|jitter|loss')throw new RuntimeException('Custom ping schema requires manual review');}
  $backup=ds_backup($db,$kind);hsql($db,'VACUUM; PRAGMA wal_checkpoint(TRUNCATE);');if(hsql($db,'PRAGMA integrity_check;',true)!=='ok')throw new RuntimeException('Post-compaction check failed; retain backup: '.$backup);
  $result=['kind'=>$kind,'backup'=>$backup,'samples_changed'=>false];
 }else{
  if($action==='expand')$result=ds_expand($db);else $result=ds_normalize($db);
  if($action==='balanced'){
   if(empty($result['backup']))$result['backup']=ds_backup($db,'balanced');
   hconfigure(['HISTORY_ENABLED'=>'true','HISTORY_RAW_DAYS'=>2,'HISTORY_HOURLY_DAYS'=>7,'HISTORY_DAILY_DAYS'=>365]);
   $result['history']=hrun($db,hconfig(),false);
  }
 }
 $result['before_bytes']=$before;$result['after_bytes']=(int)hsql($db,'SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size();',true);
 echo json_encode($result,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n";
}catch(Throwable $e){fwrite(STDERR,'Database maintenance: '.$e->getMessage()."\n");exit(1);}
