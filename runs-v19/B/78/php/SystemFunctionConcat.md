## Verdict

CONFIRMED - Real exploitable OS command injection vulnerability. The `$host` parameter from `$_GET['host']` flows directly into a shell command string passed to `system()`, allowing attackers to inject arbitrary shell commands.

## Source

`$_GET['host']` (line 17) → parameter `$host` in `check_host_reachability()` (line 3) → concatenated into command string (line 8).

## Fix

### File: SystemFunctionConcat.php

```php
<?php

function check_host_reachability(string $host): array
{
    // Use proc_open() with argument array to safely execute ping
    // The host parameter is passed as a separate array element, preventing shell injection
    $descriptorspec = array();  // Inherit parent's file descriptors
    $pipes = array();
    $process = proc_open(['ping', '-c', '2', '-W', '2', $host], $descriptorspec, $pipes);
    
    $resultCode = 0;
    if (is_resource($process)) {
        $resultCode = proc_close($process);
    }

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

The vulnerability stems from concatenating untrusted input directly into an OS command string passed to `system()`. The original code executes `'ping -c 2 -W 2 ' . $host` as a shell command, where an attacker can inject shell metacharacters (e.g., `;`, `|`, `$()`) via the host parameter to execute arbitrary commands.

The fix replaces `system()` with `proc_open()` using an argument array `['ping', '-c', '2', '-W', '2', $host]`. In array form, each element is passed as a separate argument to the `ping` binary without shell interpretation, eliminating the injection vector. The host parameter becomes a distinct argument element that cannot be split or reinterpreted by a shell.

The function's return value and behavior are preserved: it still returns the host and reachability status (based on exit code 0), and ping's output continues to stream to stdout via inherited file descriptors (the empty `descriptorspec`).

This approach is required because PHP has no native equivalent for ICMP ping—that capability requires raw sockets and elevated privileges. By using parameterized execution with an argument array, the code retains the intended functionality while closing the injection point.

Requires PHP 7.4 or later. For versions prior to PHP 8.1.29/8.2.20/8.3.8, Windows batch-file targets have a known bypass, but `ping` is a native binary executable, not a batch file, so this is not a concern for this fix.

## Behaviour changes

- `system()` is replaced with `proc_open()` and `proc_close()`, maintaining the same exit code logic and output streaming behavior.
- No functional change to the caller's perspective: the function still returns the host and reachability status in the same structure, and ping output is printed as before.
- The host value can now safely contain shell metacharacters without triggering command injection.
