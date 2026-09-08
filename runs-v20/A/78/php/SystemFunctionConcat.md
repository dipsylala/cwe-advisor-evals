## Verdict

Confirmed. `check_host_reachability()` passes `$host` — sourced directly from `$_GET['host']` with no validation — into `system()` by string concatenation. An attacker can append shell metacharacters (e.g. `; rm -rf /`, `` `whoami` ``, `$(...)`, `&&`, `|`) to the `host` query parameter to execute arbitrary commands with the privileges of the web server process.

## Source

`$_GET['host']` in the top-level script code (line 17), passed straight into `check_host_reachability()` and concatenated into the `system()` argument at line 8 with no validation or escaping in between.

## Fix

### File: SystemFunctionConcat.php

```php
<?php

function is_valid_ping_target(string $host): bool
{
    if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
        return true;
    }

    // RFC 1123 hostname: dot-separated labels, alphanumeric plus hyphen,
    // no leading/trailing hyphen per label, max 253 chars overall.
    if (strlen($host) > 253) {
        return false;
    }

    $label = '[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?';
    return preg_match('/^' . $label . '(\.' . $label . ')*$/', $host) === 1;
}

function check_host_reachability(string $host): array
{
    if (!is_valid_ping_target($host)) {
        return [
            'host' => $host,
            'reachable' => false,
        ];
    }

    $resultCode = 0;

    // Host is now confirmed to be a well-formed IP address or hostname
    // (no shell metacharacters possible), and escapeshellarg() gives a
    // second, defense-in-depth layer around the system() call.
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

The original code builds the `system()` command line by directly concatenating an untrusted, attacker-controlled string, which lets any shell metacharacter in `host` be interpreted by the shell that `system()` invokes.

The fix addresses this in two layers:

1. **Primary defence — format validation.** `ping` only ever needs a literal IPv4/IPv6 address or an RFC 1123 hostname as its target. `is_valid_ping_target()` accepts a value only if it parses as a valid IP (`filter_var(..., FILTER_VALIDATE_IP)`) or matches the standard hostname grammar (dot-separated alphanumeric-and-hyphen labels, no leading/trailing hyphen, no consecutive dots, max 253 characters). This is a format constraint the target program itself imposes — not a security-only denylist — so it rejects malformed/injected input while accepting every legitimate hostname or IP a caller would ever supply. Invalid input short-circuits before the command ever runs, so no shell invocation happens on tainted data at all.
2. **Defense-in-depth — proper escaping.** Even though validation already excludes shell metacharacters, `escapeshellarg($host)` wraps the value as a single, safely quoted shell argument rather than relying solely on the regex to be airtight against every edge case (e.g. locale-dependent regex behavior, future refactors that loosen the check). `escapeshellarg()` is the correct API for building a `system()`/`exec()` command string; it quotes the value and neutralizes anything inside it, whereas manual string concatenation is exactly the anti-pattern that caused this finding.

Together, these mean an attacker cannot get shell-metacharacter payloads past validation, and even if a payload did slip through, `escapeshellarg()` prevents it from being interpreted by the shell.
