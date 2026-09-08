## Verdict

exploitable

- cwe_id: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'))
- location: SystemFunctionConcat.php, line 8, inside `check_host_reachability()`
- confidence: high

## Source

`$_GET['host']` (line 17), passed unvalidated and unescaped into `check_host_reachability($host)` as the `$host` parameter.

## Fix

The command is concatenated directly into a shell string: `system('ping -c 2 -W 2 ' . $host, $resultCode)` at line 8. `$host` comes straight from `$_GET['host']` with no validation or escaping, so a value such as `127.0.0.1; cat /etc/passwd` or `` `id` `` reaches a real shell (`system()` always invokes one) and executes as additional commands.

`ping` has no PHP library equivalent (it requires raw/ICMP sockets and reproduces timing/echo behavior a rewrite would have to duplicate), so this is a keep-and-execute-safely case, not a remove-the-call case. The fix keeps `ping` but invokes it through `proc_open()` with an argument array, which never invokes a shell, so shell metacharacters in `$host` can no longer terminate or extend the command. A literal `--` is inserted before the host argument so a value like `-R` (a `ping` flag) cannot be interpreted as an option (CWE-88, argument injection) instead of the host operand. A secondary hostname/IP format check is added ahead of the `proc_open()` call, since the host is a value whose format the application owns (a network hostname or address) — it rejects clearly malformed input early without acting as the primary defence.

The sink's original contract is preserved: it returns an array with `host` and a `reachable` boolean derived from the process exit code being `0`; `ping`'s stdout/stderr are read and discarded, never surfaced to the caller, matching the original code's behavior of never capturing that output.

### File: SystemFunctionConcat.php

```php
<?php

function check_host_reachability(string $host): array
{
    $resultCode = 0;

    // Reject anything that is not a well-formed IP address or hostname before it
    // ever reaches the ping invocation. This is a secondary check only: the
    // primary defence is the argument-array proc_open() call below, which never
    // invokes a shell.
    $isValidIp = filter_var($host, FILTER_VALIDATE_IP) !== false;
    $isValidHostname = strlen($host) <= 253
        && preg_match('/\A[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\z/', $host) === 1;

    if (!$isValidIp && !$isValidHostname) {
        return [
            'host' => $host,
            'reachable' => false,
        ];
    }

    // SAST FINDING (fixed): ping is invoked as an argument array with no shell,
    // so the host cannot be split into extra shell commands. The literal '--'
    // marks the end of options so the host also cannot be read as a ping flag.
    $descriptorSpec = [
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $process = proc_open(['ping', '-c', '2', '-W', '2', '--', $host], $descriptorSpec, $pipes);

    if (!is_resource($process)) {
        return [
            'host' => $host,
            'reachable' => false,
        ];
    }

    // Drain and discard ping's output, matching the original code, which never
    // surfaced it to the caller.
    stream_get_contents($pipes[1]);
    stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);

    $resultCode = proc_close($process);

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

The vulnerable code built a shell command string by concatenating unvalidated user input (`$host`) and ran it via `system()`, which always executes through `/bin/sh`, letting shell metacharacters in the input run arbitrary additional commands. The fix keeps `ping` (there is no PHP-native replacement for ICMP echo) but calls it through `proc_open()` with the command given as an argument array; PHP passes each array element to the target program directly with no shell in between, so metacharacters in `$host` are inert. A literal `--` before the host argument closes the separate argument-injection gap (a host value starting with `-` being read as a `ping` option). A secondary format check (valid IP or RFC-1123-shaped hostname) rejects structurally invalid input before the process is even spawned. `proc_close()`'s exit status replaces `system()`'s by-reference `$resultCode`, preserving the original `reachable === ($resultCode === 0)` semantics, and `ping`'s stdout/stderr are read and discarded rather than returned, so no information leak is introduced.

## Behaviour changes

- Requests where `$host` is not a valid IP address or RFC-1123-shaped hostname now return `{"reachable": false}` immediately without invoking `ping` at all. Previously such a value (including any injection payload) was passed straight to the shell. This is the intended effect of closing the vulnerability, not a side effect.
- `$resultCode` is now set from `proc_close()`'s return value instead of `system()`'s by-reference output parameter; the value and its use in `$resultCode === 0` are unchanged.
- No other differences: the function signature, return shape (`['host' => ..., 'reachable' => ...]`), `ping` flags (`-c 2 -W 2`), and discarding of `ping`'s output are all preserved.

**Verification**: `php -l` (PHP 8.5.8 CLI) against the fixed file reported "No syntax errors detected." `proc_open()`'s array-argument form and `FILTER_VALIDATE_IP` are core PHP (no version floor beyond PHP 7.4, already implied by the array-form requirement noted in the loaded PHP guidance); no new third-party dependency was introduced.

**Assumptions**: The finding names no explicit call chain beyond this single file, so the trace source (`$_GET['host']`) and sink (`system()` at line 8) were read directly from the file rather than from a supplied SAST call-graph.
