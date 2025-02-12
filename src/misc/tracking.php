<?php
// Configuration
$logFile = '/var/www/html/data/tracking.log'; // Log file for tracking data

// Ensure log file directory exists
if (!is_file($logFile)) {
    file_put_contents($logFile, "");
}

// Function to sanitize input for logging
function sanitize($data) {
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}


// Collect visitor details
// $ip = sanitize($_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_CLIENT_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? 'Unknown IP');
$ip = "Testing";
$userAgent = sanitize($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown User Agent');
$referrer = sanitize($_SERVER['HTTP_REFERER'] ?? 'Direct Access');
$timestamp = date('Y-m-d H:i:s');
$request = sanitize($_SERVER['REQUEST_URI'] ?? 'Unknown Request');

// Build the log entry
$logEntry = "[$timestamp] IP: $ip, Referrer: $referrer, User-Agent: $userAgent, Request: $request" . PHP_EOL;

// Save log entry to the file
file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
?>