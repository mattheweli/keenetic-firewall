<?php
// ==============================================================================
// FIREWALL API v2.0.0
// Release date: 2026-10-22 | Status: stable
// Previous upstream version: unversioned
// Changelog v2.0.0:
//   - Require admin for Settings reads and POST/CSRF for typed Settings writes.
// Changelog v2.0.0:
//   - Expose fixed-list read-only log size metadata independently of log downloads.
// Changelog v2.0.0:
//   - Forward bounded log pagination cursors to the existing read-only broker operation.
// Changelog v2.0.0:
//   - Public read-only system-log previews through the existing bounded broker.
// Changelog v2.0.0:
//   - Delegate fixed operations to the private Unix-socket broker; retain HTTPS/session/CSRF, add guarded policy confirmation, audit and typed temporary bans.
// Changelog v2.0.0:
//   - STATUS: read-only verification of all expected rules and both families.
// Changelog v2.0.0:
//   - READ: live PCAP log is public/read-only; admin/CSRF retained for mutations.
//   - LOG: router-local date/time and persistent PCAP with latest rotation fallback.
// Changelog v2.0.0:
//   - UX: password-only admin login; no username field or username dependency.
// Changelog v2.0.0:
//   - NEW: HTTPS-only admin login/logout, server-side session and automatic CSRF validation.
//   - NEW: admin password hash outside web root; throttling and session expiry/revocation.
//   - ACCESS: lookup/status public, mutations and live log protected; token retained for automation.
// Changelog v2.0.0:
//   - SECURITY: authenticated reads/writes using X-KT-Token and constant-time comparison.
//   - SECURITY: writes require POST JSON; same-origin check when Origin is supplied.
//   - VALIDATION: inet_pton validation; reject subnet input for host actions.
//   - FIX: check command outcomes; use installed netfilter hook path.
//   - NEW: lookup reports matching block sets; ban/unban persists manual sets.
//   - HTTP: JSON errors/status codes, no-store and nosniff headers.
//   - LIMIT: PHP runtime, token access and command privileges require router validation.
// ==============================================================================
// Historical upstream header / changelog follows.

// HTTPS session/CSRF authorization stays in the unprivileged web process.
// Privileged work is delegated to a bounded local Unix-socket protocol.
putenv('PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
function reply($data,$code=200){http_response_code($code);echo json_encode($data,JSON_INVALID_UTF8_SUBSTITUTE);exit;}
function kt_broker($input,$quiet=false){
    $input['actor']=$_SERVER['REMOTE_ADDR']??'local';
    $socket=@stream_socket_client('unix:///opt/var/run/keentool-security/broker.sock',$errno,$error,2);
    if(!$socket){if($quiet)return null;reply(['status'=>'error','message'=>'Security service unavailable'],503);}
    stream_set_timeout($socket,55);$line=json_encode($input,JSON_INVALID_UTF8_SUBSTITUTE)."\n";
    if(strlen($line)>8192||fwrite($socket,$line)!==strlen($line)){fclose($socket);if($quiet)return null;reply(['status'=>'error','message'=>'Security request failed'],503);}
    $line=fgets($socket,2097153);fclose($socket);$data=json_decode($line?:'',true);
    if(!is_array($data)){if($quiet)return null;reply(['status'=>'error','message'=>'Invalid security response'],503);}return $data;
}
function kt_auth_event($event){kt_broker(['action'=>'audit_auth','event'=>$event],true);}
function fail($message,$code=400){
    global $action;
    if(($action??'')==='login')kt_auth_event($code===429?'login throttled':'login failed');
    elseif($code===401)kt_auth_event('authorization rejected');
    elseif(stripos($message,'CSRF')!==false)kt_auth_event('CSRF rejected');
    reply(['status'=>'error','message'=>$message],$code);
}
$tokenFile='/opt/etc/keentool/firewall-api.token';$expected=is_readable($tokenFile)?trim(file_get_contents($tokenFile)):'';
$provided=$_SERVER['HTTP_X_KT_TOKEN']??'';if(!is_string($provided))fail('Invalid token',401);
$tokenAuth=strlen($expected)>=32&&$provided!==''&&hash_equals($expected,$provided);
require '/opt/lib/keentool-admin/admin_auth.php';
if(!kt_secure_request())fail('HTTPS required',403);
if(isset($_SERVER['HTTP_ORIGIN'])){
    $origin=parse_url($_SERVER['HTTP_ORIGIN']);$scheme=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http';
    $authority=($origin['host']??'').(isset($origin['port'])?':'.$origin['port']:'');
    if(($origin['scheme']??'')!==$scheme||strcasecmp($authority,$_SERVER['HTTP_HOST']??'')!==0)fail('Origin rejected',403);
}
$method=$_SERVER['REQUEST_METHOD']??'GET';$input=$_GET;
if($method==='POST'){
    if(stripos($_SERVER['CONTENT_TYPE']??'','application/json')!==0)fail('JSON required',415);
    $body=file_get_contents('php://input',false,null,0,8193);if($body===false||strlen($body)>8192)fail('Request too large',413);
    $input=json_decode($body,true);if(!is_array($input))fail('Invalid JSON');
}
$action=$input['action']??'';
if(!is_string($action)||!is_string($input['ip']??''))fail('Invalid input');
$writes=['ban','unban','enable','disable','confirm_policy','rollback_policy','settings_save'];
if(in_array($action,$writes,true)&&$method!=='POST')fail('POST required',405);
$admin=in_array($action,$writes,true)||in_array($action,['audit','settings_get'],true);
if(in_array($action,['auth_status','login','logout'],true)||(!$tokenAuth&&$admin)){
    kt_boot_session();
    if($action==='auth_status')reply(['status'=>'success','authenticated'=>kt_admin_active(),'configured'=>kt_credentials()!==null,'csrf'=>$_SESSION['csrf']]);
    if($action==='login'||$action==='logout'){
        if($method!=='POST')fail('POST required',405);kt_require_csrf();
        if($action==='login'){kt_admin_login($input);kt_auth_event('login success');reply(['status'=>'success','authenticated'=>true,'csrf'=>$_SESSION['csrf']]);}
        kt_admin_logout();kt_auth_event('logout');reply(['status'=>'success','authenticated'=>false]);
    }
    if(!kt_admin_active())fail('Admin login required',401);
    if(in_array($action,$writes,true))kt_require_csrf();
    $_SESSION['seen']=time();session_write_close();
}
if(!in_array($action,array_merge($writes,['status','lookup','livelog','systemlog','log_sizes','snapshot','audit','settings_get']),true))fail('Unknown action');
$request=['action'=>$action];
foreach(['ip','duration','note','pending_id','lines','log_id','cursor','group','revision','values'] as $key)if(isset($input[$key]))$request[$key]=$input[$key];
$result=kt_broker($request);reply($result,($result['status']??'error')==='success'?200:((int)($result['http_status']??400)===429?429:400));
