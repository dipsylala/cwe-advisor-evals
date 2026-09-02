<?php
/**
 * Network diagnostics endpoint for the internal admin panel.
 *
 * Lets an on-call engineer kick off a quick reachability check against a
 * host from the browser instead of shelling into the box directly.
 */

/**
 * Run a ping-based reachability check against the requested host and
 * return the raw command output for display.
 *
 * @return string Combined stdout/stderr from the diagnostic command.
 */
function runReachabilityCheck(): string
{
    $host = $_GET['host'] ?? '';

    if ($host === '') {
        http_response_code(400);
        return 'Missing host parameter.';
    }

    $pingCount = 4;

    // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
    $output = shell_exec('ping -c ' . $pingCount . ' ' . $host . ' 2>&1');

    if ($output === null) {
        return 'Diagnostic command failed to run.';
    }

    return $output;
}

if (php_sapi_name() !== 'cli' && isset($_GET['host'])) {
    header('Content-Type: text/plain');
    echo runReachabilityCheck();
}
