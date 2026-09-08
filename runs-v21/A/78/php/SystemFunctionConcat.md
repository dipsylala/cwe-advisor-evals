## Verdict
CONFIRMED

## Source
Line 8 in SystemFunctionConcat.php receives the `$host` parameter from untrusted user input (`$_GET['host']`), which is then concatenated directly into an OS command passed to `system()`.

## Fix

### File: SystemFunctionConcat.php
```php
<?php

function check_host_reachability(string $host): array
{
    $resultCode = 0;

    // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
    system('ping -c 2 -W 2 ' . escapeshellarg($host), $resultCode);

    return [
        'host' => $host,
        'reachable' => $resultCode === 0,
    ];
}

header('Content-Type: application/json');
$status = check_host_reachability($_GET['host'] ?? '');
echo json_encode($status);
```

## Explanation
The vulnerability exists because user-supplied input is concatenated directly into a shell command without escaping. An attacker can inject arbitrary shell metacharacters and commands—for example, `host; rm -rf /`.

The fix uses `escapeshellarg()`, which wraps the argument in single quotes and escapes any single quotes within the value, ensuring it is treated as a single literal argument to the `ping` command. This prevents shell metacharacter interpretation while preserving the intended hostname value.
