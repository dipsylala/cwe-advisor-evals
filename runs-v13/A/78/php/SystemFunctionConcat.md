## Verdict
The vulnerability is real. User-supplied input from `$_GET['host']` flows unsanitized into the `system()` function on line 8, allowing arbitrary OS command injection.

## Source
```php
function check_host_reachability(string $host): array
{
    $resultCode = 0;
    system('ping -c 2 -W 2 ' . $host, $resultCode);
    return [
        'host' => $host,
        'reachable' => $resultCode === 0,
    ];
}

header('Content-Type: application/json');
$status = check_host_reachability($_GET['host'] ?? '');
```

The `$host` parameter receives untrusted input from `$_GET['host']` and is directly concatenated into a shell command string passed to `system()`. An attacker can inject shell metacharacters and commands, for example `127.0.0.1; rm -rf /` or `127.0.0.1 || malicious_command`.

## Fix
```php
<?php

function check_host_reachability(string $host): array
{
    $resultCode = 0;

    // Validate that $host is a valid hostname or IP address
    if (!preg_match('/^[a-zA-Z0-9\.\-_]+$/', $host)) {
        return [
            'host' => $host,
            'reachable' => false,
        ];
    }

    // Use escapeshellarg to neutralize shell metacharacters as secondary defense
    $escaped_host = escapeshellarg($host);
    system('ping -c 2 -W 2 ' . $escaped_host, $resultCode);

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
The fix combines two defenses:

1. **Input validation**: A `preg_match()` check enforces that `$host` contains only alphanumeric characters, dots, hyphens, and underscores—the characters valid in hostnames and IPv4 addresses. This rejects shell metacharacters (`|`, `;`, `&`, `$`, backticks, etc.) at the boundary before they reach the command. Invalid input returns early with `reachable` set to `false`.

2. **Shell escaping**: The `escapeshellarg()` function wraps the input in single quotes and escapes any single quotes within the value, preventing shell interpretation of special characters. This serves as a secondary defense for any input that passes validation.

Combined, these defenses prevent command injection: the validation blocks the most dangerous patterns structurally, and `escapeshellarg()` ensures that even if validation were somehow bypassed, shell metacharacters cannot be interpreted as command separators or operators.
