<?php
// FIREWALL ADMIN AUTH v1.0.0 — 2026-10-22
// Changelog: a2: password-only login, preserve revocation and session checks; a1: HTTPS sessions, CSRF, expiry and rate limits.
// New: HTTPS-only admin sessions, CSRF, password revision revocation and login throttling.
if (!defined('KT_ADMIN_DIR')) define('KT_ADMIN_DIR', '/opt/etc/keentool/admin');
function kt_secure_request() {
    return (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off')
        || (($_SERVER['REQUEST_SCHEME'] ?? '') === 'https');
}
function kt_credentials() {
    $data = json_decode((string)@file_get_contents(KT_ADMIN_DIR . '/credentials.json'), true);
    return is_array($data) && isset($data['hash'], $data['revision']) ? $data : null;
}
function kt_boot_session() {
    if (!function_exists('session_start')) fail('Install php8-mod-session', 503);
    $dir = KT_ADMIN_DIR . '/sessions';
    if (!is_dir($dir) || !is_writable($dir)) fail('Admin session directory unavailable', 503);
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_trans_sid', '0');
    ini_set('session.gc_maxlifetime', '28800');
    session_save_path($dir);
    session_name('KT_FW_ADMIN');
    session_set_cookie_params(['lifetime'=>0, 'path'=>'/firewall/', 'secure'=>true, 'httponly'=>true, 'samesite'=>'Strict']);
    if (!session_start()) fail('Cannot start admin session', 503);
    if (!isset($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
}
function kt_admin_boot() { return trim((string)@file_get_contents('/proc/sys/kernel/random/boot_id')); }
function kt_admin_active() {
    $c = kt_credentials(); $now = time();
    $valid = $c && isset($_SESSION['revision'], $_SESSION['born'], $_SESSION['seen'])
        && hash_equals((string)$c['revision'], (string)$_SESSION['revision'])
        && $now >= $_SESSION['seen'] && $now >= $_SESSION['born']
        && kt_admin_boot() !== '' && hash_equals(kt_admin_boot(), (string)($_SESSION['boot'] ?? ''))
        && $now - $_SESSION['seen'] < 1800 && $now - $_SESSION['born'] < 28800;
    if (!$valid) unset($_SESSION['revision'], $_SESSION['born'], $_SESSION['seen']);
    return (bool)$valid;
}
function kt_require_csrf() {
    $value = $_SERVER['HTTP_X_KT_CSRF'] ?? '';
    if (!is_string($value) || !hash_equals($_SESSION['csrf'], $value)) fail('Invalid CSRF token', 403);
}
function kt_admin_login($input) {
    $c = kt_credentials();
    if (!$c) fail('Admin password not configured', 503);
    if (kt_admin_boot() === '') fail('Kernel boot identity unavailable', 503);
    $password = $input['password'] ?? null;
    if (!is_string($password) || strlen($password) > 72) fail('Invalid credentials', 401);
    // Shared file lock prevents concurrent requests bypassing the limit.
    $f = @fopen(KT_ADMIN_DIR . '/attempts.json', 'c+');
    if (!$f || !flock($f, LOCK_EX)) fail('Login limiter unavailable', 503);
    $data = json_decode(stream_get_contents($f), true); if (!is_array($data)) $data = [];
    $now = time();
    foreach ($data as $key=>$row) if (!is_array($row) || ($row['until'] ?? 0) <= $now) unset($data[$key]);
    $key = hash('sha256', $_SERVER['REMOTE_ADDR'] ?? 'unknown');
    $global = $data['global'] ?? ['count'=>0,'until'=>$now+900];
    $row = $data[$key] ?? ['count'=>0,'until'=>$now+900];
    if ($row['count'] >= 5 || $global['count'] >= 30) { fclose($f); fail('Too many login attempts; retry within 15 minutes', 429); }
    $ok = password_verify($password, $c['hash']);
    if ($ok) unset($data[$key]);
    else {
        $row['count']++; $global['count']++;
        if (count($data) > 128 && !isset($data[$key])) { fclose($f); fail('Too many login attempts; retry within 15 minutes', 429); }
        $data[$key]=$row; $data['global']=$global;
    }
    rewind($f); $json = json_encode($data);
    if (!ftruncate($f, 0) || fwrite($f, $json) !== strlen($json) || !fflush($f)) { fclose($f); fail('Cannot update login limiter', 503); }
    fclose($f);
    if (!$ok) fail('Invalid credentials', 401);
    if (!session_regenerate_id(true)) fail('Cannot renew session', 503);
    $_SESSION = ['csrf'=>bin2hex(random_bytes(32)), 'revision'=>$c['revision'], 'born'=>$now, 'seen'=>$now, 'boot'=>kt_admin_boot()];
}
function kt_admin_logout() {
    $_SESSION = [];
    session_destroy();
    setcookie(session_name(), '', ['expires'=>time()-3600, 'path'=>'/firewall/', 'secure'=>true, 'httponly'=>true, 'samesite'=>'Strict']);
}
