<?php
// KEENTOOL SQLITE STORAGE v1.0.0. Loaded only by private CLI engines.
function ds_schema(){return [
 'kt_ips'=>"CREATE TABLE kt_ips(id INTEGER PRIMARY KEY,ip TEXT NOT NULL UNIQUE)",
 'kt_ip_hits'=>"CREATE TABLE kt_ip_hits(timestamp INTEGER NOT NULL,ip_id INTEGER NOT NULL,count INTEGER NOT NULL CHECK(count>=0),list_type TEXT,resolution INTEGER NOT NULL DEFAULT 0)",
 'kt_hits_ip'=>"CREATE INDEX kt_hits_ip ON kt_ip_hits(ip_id)",
 'kt_hits_ts'=>"CREATE INDEX kt_hits_ts ON kt_ip_hits(timestamp)",
 'kt_hits_list_ts'=>"CREATE INDEX kt_hits_list_ts ON kt_ip_hits(list_type,timestamp)",
 'ip_drops'=>"CREATE VIEW ip_drops AS SELECT h.timestamp,i.ip,h.count,h.list_type,h.resolution FROM kt_ip_hits h JOIN kt_ips i ON i.id=h.ip_id",
 'kt_ip_drops_insert'=>"CREATE TRIGGER kt_ip_drops_insert INSTEAD OF INSERT ON ip_drops BEGIN INSERT OR IGNORE INTO kt_ips(ip) VALUES(NEW.ip); INSERT INTO kt_ip_hits(timestamp,ip_id,count,list_type,resolution) VALUES(NEW.timestamp,(SELECT id FROM kt_ips WHERE ip=NEW.ip),NEW.count,NEW.list_type,COALESCE(NEW.resolution,0)); END",
 'kt_ip_drops_delete'=>"CREATE TRIGGER kt_ip_drops_delete INSTEAD OF DELETE ON ip_drops BEGIN DELETE FROM kt_ip_hits WHERE timestamp IS OLD.timestamp AND ip_id=(SELECT id FROM kt_ips WHERE ip=OLD.ip) AND count IS OLD.count AND list_type IS OLD.list_type AND resolution IS OLD.resolution; END"
];}
function ds_compact($db){
 $type=hsql($db,"SELECT type FROM sqlite_master WHERE name='ip_drops';",true);if($type==='table')return false;
 if($type!=='view')throw new RuntimeException('Unsupported IP history object');
 $schema=ds_schema();foreach($schema as $name=>$sql){$actual=hsql($db,'SELECT sql FROM sqlite_master WHERE name='.hq($name).';',true);if($actual!==$sql)throw new RuntimeException('Unexpected compact storage schema: '.$name);}
 if(hsql($db,"SELECT count(*) FROM sqlite_master WHERE type='trigger' AND tbl_name IN('kt_ips','kt_ip_hits','ip_drops') AND name NOT IN('kt_ip_drops_insert','kt_ip_drops_delete');",true)!=='0')throw new RuntimeException('Custom compact storage triggers require manual review');
 if(hsql($db,'SELECT count(*) FROM kt_ip_hits h LEFT JOIN kt_ips i ON i.id=h.ip_id WHERE i.id IS NULL;',true)!=='0')throw new RuntimeException('Compact history has an invalid IP reference');return true;
}
function ds_backup($db,$label){
 if(hsql($db,'PRAGMA integrity_check;',true)!=='ok')throw new RuntimeException('Database integrity failed; no changes made');
 $size=(int)hsql($db,'SELECT page_count*page_size FROM pragma_page_count(),pragma_page_size();',true);
 $free=disk_free_space(dirname($db));if($free===false||$free<$size*3+16777216)throw new RuntimeException('Insufficient free space for backup and compaction');
 $base=getenv('KT_FW_DB_BACKUPS')?:hp('/opt/var/backups/keentool-db');
 if(preg_match('/[\x00-\x1f"\x27]/',$base))throw new RuntimeException('Unsupported backup path');
 for($p=$base;$p!==dirname($p);$p=dirname($p))if(is_link($p))throw new RuntimeException('Refusing symbolic-link backup directory');
 $dir=$base.'/'.$label.'-'.gmdate('Ymd_His').'-'.bin2hex(random_bytes(6));if(!mkdir($dir,0700,true))throw new RuntimeException('Cannot create backup directory');
 $backup=$dir.'/'.basename($db);hsql($db,'.backup "'.$backup.'"'."\n");if(!chmod($backup,0600)||hsql($backup,'PRAGMA integrity_check;',true)!=='ok')throw new RuntimeException('Backup verification failed; no changes made');fwrite(STDERR,'Verified database backup: '.$backup."\n");return $backup;
}
function ds_normalize($db){
 if(ds_compact($db))return ['storage'=>'compact','changed'=>false];
 $cols=explode('|',hsql($db,"SELECT group_concat(name,'|') FROM pragma_table_info('ip_drops');",true));
 if($cols!==['timestamp','ip','count','list_type']&&$cols!==['timestamp','ip','count','list_type','resolution'])throw new RuntimeException('Custom IP schema requires manual review');
 if(hsql($db,"SELECT count(*) FROM sqlite_master WHERE (name GLOB 'kt_ips*' OR name GLOB 'kt_ip_hits*' OR name GLOB 'kt_hits*' OR name GLOB 'kt_ip_drops*') OR (type='trigger' AND tbl_name='ip_drops');",true)!=='0')throw new RuntimeException('Custom storage objects require manual review');
 $allowed=['idx_ip'=>'ip','idx_ip_ts'=>'timestamp','idx_list'=>'list_type','idx_list_ts'=>'list_type,timestamp','idx_list_ts_ip'=>'list_type,timestamp,ip'];
 $indexes=json_decode(hsql($db,".mode json\nSELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name='ip_drops';",true)?:'[]',true,512,JSON_THROW_ON_ERROR);
 foreach($indexes as $index){$name=$index['name'];if(!isset($allowed[$name])||hsql($db,"SELECT group_concat(name,',') FROM pragma_index_info(".hq($name).');',true)!==$allowed[$name]||stripos($index['sql'],'UNIQUE')!==false||stripos($index['sql'],' WHERE ')!==false)throw new RuntimeException('Custom IP index requires manual review: '.$name);}
 if(hsql($db,"SELECT count(*) FROM ip_drops WHERE typeof(timestamp)<>'integer' OR typeof(ip)<>'text' OR typeof(count)<>'integer' OR count<0;",true)!=='0')throw new RuntimeException('Invalid IP history; no migration performed');
 $backup=ds_backup($db,'compact');$schema=ds_schema();$resolution=count($cols)===5?'resolution':'0';
 $sql="PRAGMA temp_store=FILE; PRAGMA cache_size=-4000; BEGIN IMMEDIATE; CREATE TEMP TABLE kt_storage_guard(ok INTEGER CHECK(ok=1));\n";
 foreach(['kt_ips','kt_ip_hits'] as $name)$sql.=$schema[$name].";\n";
 $sql.="INSERT INTO kt_ips(ip) SELECT DISTINCT ip FROM ip_drops ORDER BY ip;
 INSERT INTO kt_ip_hits SELECT d.timestamp,i.id,d.count,d.list_type,$resolution FROM ip_drops d JOIN kt_ips i ON i.ip=d.ip;
 CREATE TEMP TABLE kt_original AS SELECT timestamp,ip,count,list_type,$resolution AS resolution,COUNT(*) AS copies FROM ip_drops GROUP BY 1,2,3,4,5;
 CREATE TEMP TABLE kt_converted AS SELECT h.timestamp,i.ip,h.count,h.list_type,h.resolution,COUNT(*) AS copies FROM kt_ip_hits h JOIN kt_ips i ON i.id=h.ip_id GROUP BY 1,2,3,4,5;
 INSERT INTO kt_storage_guard SELECT CASE WHEN NOT EXISTS(SELECT * FROM kt_original EXCEPT SELECT * FROM kt_converted) AND NOT EXISTS(SELECT * FROM kt_converted EXCEPT SELECT * FROM kt_original) THEN 1 ELSE 0 END;
 DROP TABLE ip_drops;\n";
 foreach($schema as $name=>$definition)if(!in_array($name,['kt_ips','kt_ip_hits'],true))$sql.=$definition.";\n";
 $sql.="COMMIT;";hsql($db,$sql);ds_compact($db);
 // VACUUM is independent of the committed, verified schema transaction.
 $compacted=true;try{hsql($db,'VACUUM; PRAGMA wal_checkpoint(TRUNCATE);');}catch(Throwable $e){$compacted=false;}
 if(hsql($db,'PRAGMA integrity_check;',true)!=='ok')throw new RuntimeException('Post-migration integrity failed; retain backup: '.$backup);
 return ['storage'=>'compact','changed'=>true,'compacted'=>$compacted,'backup'=>$backup];
}
function ds_expand($db){
 if(!ds_compact($db))return ['storage'=>'legacy','changed'=>false];
 $backup=ds_backup($db,'expand');
 hsql($db,"BEGIN IMMEDIATE;
 CREATE TABLE kt_expanded(timestamp INTEGER,ip TEXT,count INTEGER,list_type TEXT,resolution INTEGER NOT NULL DEFAULT 0);
 INSERT INTO kt_expanded SELECT * FROM ip_drops;
 CREATE TEMP TABLE kt_expand_guard(ok INTEGER CHECK(ok=1));
 INSERT INTO kt_expand_guard SELECT CASE WHEN (SELECT count(*) FROM kt_expanded)=(SELECT count(*) FROM kt_ip_hits) THEN 1 ELSE 0 END;
 DROP TRIGGER kt_ip_drops_insert;DROP TRIGGER kt_ip_drops_delete;DROP VIEW ip_drops;
 DROP TABLE kt_ip_hits;DROP TABLE kt_ips;ALTER TABLE kt_expanded RENAME TO ip_drops;
 CREATE INDEX idx_ip ON ip_drops(ip);CREATE INDEX idx_ip_ts ON ip_drops(timestamp);CREATE INDEX idx_list_ts ON ip_drops(list_type,timestamp);COMMIT;");
 hsql($db,'VACUUM; PRAGMA wal_checkpoint(TRUNCATE);');if(hsql($db,'PRAGMA integrity_check;',true)!=='ok')throw new RuntimeException('Post-expansion integrity failed; retain backup: '.$backup);return ['storage'=>'legacy','changed'=>true,'backup'=>$backup,'note'=>'Text storage restored; already reduced historical time precision is unchanged.'];
}
