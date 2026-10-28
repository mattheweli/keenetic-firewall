<?php
// FIREWALL HISTORY v1.0.2 — progressive, transactional temporal aggregation.
// Requires PHP core and sqlite3 CLI; no PHP SQLite extension or shell evaluation.
if(PHP_SAPI!=='cli'){http_response_code(403);exit(1);}umask(0077);
function hp($path){return (getenv('KT_HISTORY_ROOT')?:'').$path;}
function hq($value){return "'".str_replace("'","''",(string)$value)."'";}
function hsql($db,$sql,$readonly=false){
    $cmd=['sqlite3','-bail','-cmd','.timeout 5000'];if($readonly)$cmd[]='-readonly';$cmd[]=$db;
    putenv('SQLITE_TMPDIR='.dirname($db));
    $p=proc_open($cmd,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p))throw new RuntimeException('Cannot start sqlite3');
    // SQL is bounded and output is small; feed the full script through stdin, never argv or a shell.
    $offset=0;while($offset<strlen($sql)){$n=fwrite($pipes[0],substr($sql,$offset));if(!$n)break;$offset+=$n;}fclose($pipes[0]);
    $out=stream_get_contents($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$rc=proc_close($p);
    if($rc!==0||$offset!==strlen($sql))throw new RuntimeException('History database operation failed: '.trim($err));return trim($out);
}
require_once __DIR__.'/db_storage.php';
function hconfig(){
    $values=['HISTORY_ENABLED'=>'true','HISTORY_RAW_DAYS'=>'7','HISTORY_HOURLY_DAYS'=>'30','HISTORY_DAILY_DAYS'=>'0','HISTORY_COMPACT'=>'false'];$path=hp('/opt/etc/keentool/firewall-history.conf');
    if(is_link($path))throw new RuntimeException('History configuration must not be a symbolic link');
    if(is_file($path))foreach(file($path,FILE_IGNORE_NEW_LINES) as $line){if(trim($line)===''||str_starts_with(ltrim($line),'#'))continue;
        if(!preg_match('/^([A-Z_]+)="?(true|false|[0-9]+)"?$/D',trim($line),$m)||!array_key_exists($m[1],$values))throw new RuntimeException('Invalid literal history configuration');$values[$m[1]]=$m[2];}
    if(!in_array($values['HISTORY_COMPACT'],['true','false'],true)||!in_array($values['HISTORY_ENABLED'],['true','false'],true)||!preg_match('/^[0-9]+$/D',$values['HISTORY_RAW_DAYS'])||!preg_match('/^[0-9]+$/D',$values['HISTORY_HOURLY_DAYS']))throw new RuntimeException('Invalid history settings');
    $raw=(int)$values['HISTORY_RAW_DAYS'];$hourly=(int)$values['HISTORY_HOURLY_DAYS'];if($raw<1||$raw>3650||$hourly<$raw||$hourly>3650)throw new RuntimeException('History days must satisfy 1 <= raw <= hourly <= 3650');$daily=(int)$values['HISTORY_DAILY_DAYS'];if(!preg_match('/^[0-9]+$/D',$values['HISTORY_DAILY_DAYS'])||($daily!==0&&($daily<$hourly||$daily>3650)))throw new RuntimeException('Invalid daily history days');return $values;
}
function hzone(){
    if(!getenv('TZ'))foreach([hp('/etc/TZ'),hp('/opt/etc/TZ')] as $file)if(is_file($file)){$tz=trim(file_get_contents($file));if($tz!=='')putenv('TZ='.$tz);break;}
    return getenv('TZ')?:('system:'.(is_file('/etc/localtime')?hash_file('sha256','/etc/localtime'):'libc-default')); 
}
function hmeta($db){
    if(hsql($db,"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='kt_history_meta';",true)!=='1')return [];
    $rows=json_decode(hsql($db,".mode json\nSELECT key,value FROM kt_history_meta;",true),true,512,JSON_THROW_ON_ERROR);$meta=[];foreach($rows as $r)$meta[$r['key']]=$r['value'];if(($meta['format']??null)!=='1'||!isset($meta['first_run'],$meta['last_run'],$meta['timezone'],$meta['backup']))throw new RuntimeException('Unexpected history metadata; manual review required');return $meta;
}
function hstatus($db,$conf,$meta=null){
    $meta=$meta??hmeta($db);$raw=(int)$conf['HISTORY_RAW_DAYS'];$hourly=(int)$conf['HISTORY_HOURLY_DAYS'];$daily=(int)$conf['HISTORY_DAILY_DAYS'];
    $monthly=$daily?"After $daily days, older complete calendar months use monthly IP buckets. Calendar-day/rolling-window boundaries inside them are approximate.":'Monthly aggregation is disabled; existing monthly buckets, if any, keep their reduced precision.';
    $note=($conf['HISTORY_ENABLED']==='true'?'':'Further aggregation is disabled. ')."Configured IP history: samples for $raw days, hourly through $hourly days, then daily. Total hits per IP/list are preserved. Time windows crossing a bucket boundary and historical first/last timestamps are approximate. Increasing thresholds or disabling aggregation cannot restore earlier detail. Global counters and port history are unchanged. ".$monthly;
    return ['enabled'=>$conf['HISTORY_ENABLED']==='true','raw_days'=>$raw,'hourly_days'=>$hourly,'daily_days'=>$daily,'storage'=>ds_compact($db)?'compact':'legacy','compact_requested'=>$conf['HISTORY_COMPACT']==='true','aggregated'=>isset($meta['first_run']),
        'last_run'=>(int)($meta['last_run']??0),'backup'=>$meta['backup']??null,'monthly_note'=>$monthly,'note'=>$note];
}
function hatomic($path,$text){
    if(is_link($path))throw new RuntimeException('Refusing symbolic-link state');$dir=dirname($path);if(!is_dir($dir)&&!mkdir($dir,0700,true))throw new RuntimeException('Cannot create history directory');
    $tmp=tempnam($dir,'.history-');if(!$tmp)throw new RuntimeException('Cannot create private state');try{if(file_put_contents($tmp,$text)!==strlen($text)||!chmod($tmp,0600)||!rename($tmp,$path))throw new RuntimeException('Cannot save history state');}finally{if(is_file($tmp))unlink($tmp);}
}
function hconfigure($input=null){
    $input=$input??json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);if(!is_array($input)||array_diff(array_keys($input),['HISTORY_ENABLED','HISTORY_RAW_DAYS','HISTORY_HOURLY_DAYS','HISTORY_DAILY_DAYS','HISTORY_COMPACT']))throw new InvalidArgumentException('Invalid history settings');
    $old=hconfig();$new=array_merge($old,$input);if(!in_array($new['HISTORY_COMPACT'],['true','false'],true)||!in_array($new['HISTORY_ENABLED'],['true','false'],true))throw new InvalidArgumentException('Use true or false');
    foreach(['HISTORY_RAW_DAYS','HISTORY_HOURLY_DAYS','HISTORY_DAILY_DAYS'] as $key)if(!is_int($new[$key])&&!preg_match('/^[0-9]+$/D',(string)$new[$key]))throw new InvalidArgumentException('Integer days required');
    $raw=(int)$new['HISTORY_RAW_DAYS'];$hourly=(int)$new['HISTORY_HOURLY_DAYS'];if($raw<1||$raw>3650||$hourly<$raw||$hourly>3650)throw new InvalidArgumentException('History days must satisfy 1 <= raw <= hourly <= 3650');
    $daily=(int)$new['HISTORY_DAILY_DAYS'];if($daily!==0&&($daily<$hourly||$daily>3650))throw new InvalidArgumentException('Daily days must be zero (no monthly rollup), or hourly through 3650');
    $path=hp('/opt/etc/keentool/firewall-history.conf');if(is_file($path))hatomic(hp('/opt/var/backups/keentool-history-config/'.gmdate('Ymd_His').'-'.bin2hex(random_bytes(4)).'.conf'),file_get_contents($path));
    hatomic($path,'# Firewall IP history; time precision is reduced, hit totals are preserved.'."\nHISTORY_ENABLED=\"".$new['HISTORY_ENABLED']."\"\nHISTORY_RAW_DAYS=\"$raw\"\nHISTORY_HOURLY_DAYS=\"$hourly\"\nHISTORY_DAILY_DAYS=\"$daily\"\nHISTORY_COMPACT=\"".$new['HISTORY_COMPACT']."\"\n");return ['saved'=>true,'raw_days'=>$raw,'hourly_days'=>$hourly];
}
function hrun($db,$conf,$due){
    $zone=hzone();$meta=hmeta($db);$now=(int)(getenv('KT_HISTORY_NOW')?:time());
    if($conf['HISTORY_ENABLED']!=='true')return hstatus($db,$conf,$meta)+['skipped'=>'disabled'];
    if($due&&isset($meta['last_run'])&&$now-(int)$meta['last_run']<86400)return hstatus($db,$conf,$meta)+['skipped'=>'not due'];
    if(isset($meta['timezone'])&&$meta['timezone']!==$zone)throw new RuntimeException('History timezone changed; restore the previous router timezone before aggregating existing buckets');
    if($conf['HISTORY_COMPACT']==='true'&&!ds_compact($db))ds_normalize($db);
    if(hsql($db,'PRAGMA quick_check;',true)!=='ok')throw new RuntimeException('Database integrity check failed; no aggregation performed');
    $columns=explode('|',hsql($db,"SELECT group_concat(name,'|') FROM pragma_table_info('ip_drops');",true));
    if($columns!==['timestamp','ip','count','list_type']&&$columns!==['timestamp','ip','count','list_type','resolution'])throw new RuntimeException('Unexpected ip_drops schema; no aggregation performed');
    if(!ds_compact($db)&&hsql($db,"SELECT count(*) FROM sqlite_master WHERE type='trigger' AND tbl_name='ip_drops';",true)!=='0')throw new RuntimeException('Custom IP history triggers require manual review');
    if(hsql($db,"SELECT count(*) FROM ip_drops WHERE typeof(timestamp)<>'integer' OR typeof(count)<>'integer' OR count<0;",true)!=='0')throw new RuntimeException('Invalid sample timestamps or counts; no aggregation performed');
    $compact=ds_compact($db);$newSchema=count($columns)===4;$raw=(int)$conf['HISTORY_RAW_DAYS'];$hourly=(int)$conf['HISTORY_HOURLY_DAYS'];
    // Start-of-local-day cutoffs keep at least the requested elapsed days intact, including DST.
    $rawCut=(int)hsql($db,"SELECT strftime('%s',date(($now-$raw*86400),'unixepoch','localtime'),'utc');",true);
    $dayCut=(int)hsql($db,"SELECT strftime('%s',date(($now-$hourly*86400),'unixepoch','localtime'),'utc');",true);
    $daily=(int)$conf['HISTORY_DAILY_DAYS'];$monthCut=$daily?(int)hsql($db,"SELECT strftime('%s',date(($now-$daily*86400),'unixepoch','localtime','start of month'),'utc');",true):0;
    $hasOld=(int)hsql($db,"SELECT count(*) FROM ip_drops WHERE timestamp<$rawCut;",true);
    if(!$hasOld)return hstatus($db,$conf,$meta)+['skipped'=>'no old samples'];
    $size=(int)hsql($db,'SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size();',true);
    $free=disk_free_space(dirname($db));if($free===false||$free<$size*(isset($meta['first_run'])?2:3)+16777216)throw new RuntimeException('Insufficient free space for a verified backup and SQLite compaction');
    $backup=$meta['backup']??null;
    if(!isset($meta['first_run'])){
        $base=getenv('KT_FW_DB_BACKUPS')?:hp('/opt/var/backups/keentool-db');
        if(preg_match('/[\x00-\x1f"\x27]/',$base))throw new RuntimeException('Unsupported backup directory characters');
        for($check=$base;$check!==dirname($check);$check=dirname($check))if(is_link($check))throw new RuntimeException('Refusing symbolic-link backup directory');
        $dir=$base.'/history-'.gmdate('Ymd_His').'-'.bin2hex(random_bytes(6));if(!mkdir($dir,0700,true))throw new RuntimeException('Cannot create private history backup');
        $backup=$dir.'/firewall_stats.db';hsql($db,'.backup "'.$backup.'"'."\n");chmod($backup,0600);
        if(hsql($backup,'PRAGMA integrity_check;',true)!=='ok')throw new RuntimeException('Backup integrity check failed; no aggregation performed');
    }
    $schema=$newSchema?'ALTER TABLE ip_drops ADD COLUMN resolution INTEGER NOT NULL DEFAULT 0;':'';
    // Each repeated local hour has its own epoch key; a local calendar day spans 23/24/25 hours.
    $hour="timestamp-CAST(strftime('%M',timestamp,'unixepoch','localtime') AS INTEGER)*60-CAST(strftime('%S',timestamp,'unixepoch','localtime') AS INTEGER)";
    $month="CAST(strftime('%s',date(timestamp,'unixepoch','localtime','start of month'),'utc') AS INTEGER)";
    $day="CAST(strftime('%s',date(timestamp,'unixepoch','localtime'),'utc') AS INTEGER)";
    $sql="PRAGMA temp_store=FILE; PRAGMA cache_size=-4000; BEGIN IMMEDIATE; $schema
CREATE TABLE IF NOT EXISTS kt_history_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TEMP TABLE kt_guard(ok INTEGER CHECK(ok=1));
INSERT INTO kt_guard SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM ip_drops WHERE resolution NOT IN (0,3600,86400,2592000)) THEN 1 ELSE 0 END;
CREATE TEMP TABLE kt_totals AS SELECT ip,list_type,SUM(count) AS hits FROM ip_drops GROUP BY ip,list_type;
CREATE TEMP TABLE kt_days AS SELECT date(timestamp,'unixepoch','localtime') AS day,ip,list_type,SUM(count) AS hits FROM ip_drops WHERE timestamp>=$monthCut AND resolution<>2592000 GROUP BY day,ip,list_type;
CREATE TEMP TABLE kt_months AS SELECT strftime('%Y-%m',timestamp,'unixepoch','localtime') AS month,ip,list_type,SUM(count) AS hits FROM ip_drops GROUP BY 1,2,3;
CREATE TEMP TABLE kt_raw AS SELECT timestamp,ip,count,list_type,resolution FROM ip_drops WHERE resolution=0 AND timestamp>=$rawCut;
CREATE TEMP TABLE kt_rollup AS
SELECT CASE WHEN level=2592000 THEN $month WHEN level=86400 THEN $day ELSE $hour END AS bucket,ip,SUM(count) AS count,list_type,level
FROM (SELECT *,CASE WHEN resolution=2592000 OR ($monthCut>0 AND timestamp<$monthCut) THEN 2592000 WHEN resolution=86400 OR timestamp<$dayCut THEN 86400 ELSE 3600 END AS level FROM ip_drops WHERE resolution>0 OR timestamp<$rawCut)
GROUP BY bucket,ip,list_type,level;
DELETE FROM ip_drops WHERE resolution>0 OR timestamp<$rawCut;
INSERT INTO ip_drops(timestamp,ip,count,list_type,resolution) SELECT bucket,ip,count,list_type,level FROM kt_rollup;
INSERT INTO kt_guard SELECT CASE WHEN NOT EXISTS(SELECT * FROM kt_totals EXCEPT SELECT ip,list_type,SUM(count) FROM ip_drops GROUP BY ip,list_type) AND NOT EXISTS(SELECT ip,list_type,SUM(count) FROM ip_drops GROUP BY ip,list_type EXCEPT SELECT * FROM kt_totals) THEN 1 ELSE 0 END;
INSERT INTO kt_guard SELECT CASE WHEN NOT EXISTS(SELECT * FROM kt_days EXCEPT SELECT date(timestamp,'unixepoch','localtime'),ip,list_type,SUM(count) FROM ip_drops WHERE timestamp>=$monthCut AND resolution<>2592000 GROUP BY 1,2,3) AND NOT EXISTS(SELECT date(timestamp,'unixepoch','localtime'),ip,list_type,SUM(count) FROM ip_drops WHERE timestamp>=$monthCut AND resolution<>2592000 GROUP BY 1,2,3 EXCEPT SELECT * FROM kt_days) THEN 1 ELSE 0 END;
INSERT INTO kt_guard SELECT CASE WHEN NOT EXISTS(SELECT * FROM kt_months EXCEPT SELECT strftime('%Y-%m',timestamp,'unixepoch','localtime'),ip,list_type,SUM(count) FROM ip_drops GROUP BY 1,2,3) AND NOT EXISTS(SELECT strftime('%Y-%m',timestamp,'unixepoch','localtime'),ip,list_type,SUM(count) FROM ip_drops GROUP BY 1,2,3 EXCEPT SELECT * FROM kt_months) THEN 1 ELSE 0 END;
INSERT INTO kt_guard SELECT CASE WHEN NOT EXISTS(SELECT * FROM kt_raw EXCEPT SELECT timestamp,ip,count,list_type,resolution FROM ip_drops WHERE resolution=0 AND timestamp>=$rawCut) AND NOT EXISTS(SELECT timestamp,ip,count,list_type,resolution FROM ip_drops WHERE resolution=0 AND timestamp>=$rawCut EXCEPT SELECT * FROM kt_raw) THEN 1 ELSE 0 END;\n";
    foreach(['format'=>'1','first_run'=>$meta['first_run']??(string)$now,'last_run'=>(string)$now,'backup'=>$backup,'timezone'=>$zone] as $key=>$value)$sql.='INSERT OR REPLACE INTO kt_history_meta VALUES('.hq($key).','.hq($value).");\n";
    $sql.="COMMIT;\n";if($compact){$sql=str_replace('ip_drops','kt_ip_hits',$sql);$sql=preg_replace('/\\bip\\b/','ip_id',$sql);}hsql($db,$sql);
    // Committed data remains valid if readers delay space reclamation; retry at the next due run.
    try{$checkpoint=hsql($db,'VACUUM; PRAGMA wal_checkpoint(TRUNCATE);');$compacted=str_starts_with($checkpoint,'0|');}catch(Throwable $e){$compacted=false;}
    if(hsql($db,'PRAGMA integrity_check;',true)!=='ok')throw new RuntimeException('Post-aggregation integrity check failed; retain the verified backup');
    return hstatus($db,$conf)+['compacted'=>$compacted,'before_bytes'=>$size,'after_bytes'=>(int)hsql($db,'SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size();',true)];
}
if(!defined('KT_HISTORY_LIBRARY'))try{
    $action=$argv[1]??'status';if($action==='configure')$result=hconfigure();else{
        $db=getenv('KT_FW_DB')?:hp('/opt/etc/firewall_stats.db');if(!is_file($db)||is_link($db))throw new RuntimeException('Existing regular firewall statistics database required');$conf=hconfig();
        if($action==='status')$result=hstatus($db,$conf);elseif($action==='run')$result=hrun($db,$conf,in_array('--due',$argv,true));else throw new InvalidArgumentException('Use status, run [--due], or configure');
    }echo json_encode($result,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n";
}catch(Throwable $e){fwrite(STDERR,'Firewall history: '.$e->getMessage()."\n");exit(1);}
