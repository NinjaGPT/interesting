<?php
// FILEPATH: Untitled-1
function isIpv6Address($ip) {
    if (empty($ip)) {
        return false;
    }
    $chunks = explode(':', $ip);
    if (count($chunks) > 8 || count($chunks) < 3) {
        return false;
    }
    foreach ($chunks as $chunk) {
        if ($chunk !== '' && preg_match('/([a-fA-F0-9]*)/', $chunk) === 0 && hexdec($chunk) <= 65535) {
            return false;
        }
    }
    return true;
}

if ($x === 1) {
    return $x;
} elseif ($source === 'local') {
    validateSnortRequest($snortTable);
    $copymode = $snortTable['copymode'];
    $ipaddress = $snortTable['ipaddress'];
    $filePath = $snortTable['filePath'];
    $destination = $snortTable['destination'];
    $ddestFilename = $snortTable['destFilename'];
    if ($destFilename === '' || $destFilename === null) {
        if (strpos($filePath, '/') !== false) {
            $path = explode('/', $filePath);
            $destFilename = end($path);
        } else {
            $destFilename = $filePath;
        }
    }
    if ($copymode === 'ftp') {
        $ftpUsername = $snortTable['ftpUsername'];
        $ftpPassword = base64_decode($snortTable['ftpPassword']);
        $url = 'ftp://' . $ftpUsername . ':' . $ftpPassword . '@' . $ipaddress . '/' . $filePath;
    } elseif ($copymode === 'sftp') {
        $sftpUsername = $snortTable['ftpUsername'];
        $sftpPassword = base64_decode($snortTable['ftpPassword']);
        $url = 'sftp://' . $sftpUsername . ':' . $sftpPassword . '@' . $ipaddress . '/' . $filePath;
    } else {
        $url = 'tftp://' . $ipaddress . '/' . $filePath;
    }
    $destinationFile = $destination . $destFilename;
    exec('setsid ' . $cleanup_script . ' copyova ' . $url . ' ' . escapeshellarg($destinationFile) . ' &');
    return true;
}
?>
