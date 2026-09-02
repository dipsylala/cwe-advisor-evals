<?php

function check_host_reachability(string $host): array
{
    $resultCode = 0;

    // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
    system('ping -c 2 -W 2 ' . $host, $resultCode);

    return [
        'host' => $host,
        'reachable' => $resultCode === 0,
    ];
}

header('Content-Type: application/json');
$status = check_host_reachability($_GET['host'] ?? '');
echo json_encode($status);
