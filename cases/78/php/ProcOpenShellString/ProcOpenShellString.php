<?php

/**
 * Streams matching lines from the daily application log back to an
 * operator so they can search for a request ID or error string without
 * shelling into the box.
 */
function searchApplicationLog(string $term): array
{
    $logPath = '/var/log/app/access.log';
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];

    // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
    $process = proc_open('grep -F -- "' . $term . '" ' . $logPath, $descriptors, $pipes);

    if (!is_resource($process)) {
        return ['matches' => [], 'error' => 'unable to start search'];
    }

    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]);
    $errors = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exitCode = proc_close($process);

    if ($exitCode > 1) {
        return ['matches' => [], 'error' => trim($errors)];
    }

    $lines = $output === '' ? [] : explode("\n", trim($output));

    return ['matches' => $lines, 'error' => null];
}

// Example endpoint wiring: GET /admin/log-search?term=...
$searchTerm = $_GET['term'] ?? '';
$result = searchApplicationLog($searchTerm);

header('Content-Type: application/json');
echo json_encode($result);
