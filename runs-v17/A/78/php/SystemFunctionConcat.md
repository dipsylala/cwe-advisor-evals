## Verdict
CONFIRMED

## Source
Line 8 in SystemFunctionConcat.php:
```
system('ping -c 2 -W 2 ' . $host, $resultCode);
```

The `$host` parameter originates from unsanitized user input via `$_GET['host']` at line 17 and is concatenated directly into a command string passed to `system()`. This allows an attacker to inject arbitrary shell metacharacters and commands.

Example attack payload: `127.0.0.1; rm -rf /` would execute both ping and a destructive command in sequence.

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
The fix applies `escapeshellarg()` to the user-controlled `$host` parameter. This function wraps the argument in single quotes and escapes any single quotes within the value, ensuring the shell treats it as a single literal argument rather than interpreting metacharacters like `;`, `|`, `&`, or backticks as shell operators.

With this change, a payload like `127.0.0.1; whoami` is passed to ping as a literal hostname rather than two separate commands, preventing command injection while preserving the intended functionality for legitimate hostnames.
