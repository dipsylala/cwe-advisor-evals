## Verdict

Confirmed. `runReachabilityCheck()` builds a shell command by concatenating an unvalidated `$_GET['host']` value directly into a string passed to `shell_exec()`. An attacker can supply a host value such as `127.0.0.1; cat /etc/passwd` or `$(id)` to execute arbitrary commands on the host, since `shell_exec()` runs its argument through `/bin/sh -c` (or `cmd.exe` on Windows).

## Source

`$_GET['host']` (line 17), read directly from the HTTP request with no validation before use.

## Fix

Running a diagnostic ping is the purpose of this endpoint, not an incidental wrapper around something PHP can do natively (no PHP function or library performs an ICMP echo), so the command execution is kept and made safe rather than removed. Three changes close the finding:

1. The host value is validated against a hostname/IP allowlist format before it is used anywhere, since a reachability-check target is a value the application owns the format of. This also structurally prevents a leading `-` from being read as a flag (CWE-88).
2. `shell_exec()` (which invokes `/bin/sh -c '...'`) is replaced with `proc_open()` using an argument array, so the host is passed as a discrete process argument and never parsed by a shell.
3. The binary is invoked by an absolute path from a fixed candidate list, so a writable `PATH` entry cannot substitute a different program.

### File: ShellExecConcat.php

```php
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

    // The application only needs a hostname or IP address here, so that is
    // the format we own and can enforce. This also rules out a value that
    // begins with '-', which would otherwise be read as a flag by ping
    // (CWE-88) even once shell injection is closed below.
    $isValidTarget = filter_var($host, FILTER_VALIDATE_IP) !== false
        || preg_match(
            '/\A(?=.{1,253}\z)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\z/',
            $host
        ) === 1;

    if (!$isValidTarget) {
        http_response_code(400);
        return 'Invalid host parameter.';
    }

    $pingCount = 4;

    $pingBinary = null;
    foreach (['/usr/bin/ping', '/bin/ping'] as $candidate) {
        if (is_executable($candidate)) {
            $pingBinary = $candidate;
            break;
        }
    }

    if ($pingBinary === null) {
        return 'Diagnostic command failed to run.';
    }

    // proc_open() with an argument array never invokes a shell, so the host
    // value cannot be used to inject additional shell commands. Descriptor 2
    // is redirected onto descriptor 1 to keep the original combined
    // stdout/stderr behaviour of the "2>&1" shell_exec() call.
    $descriptorSpec = [
        1 => ['pipe', 'w'],
        2 => ['redirect', 1],
    ];

    $process = proc_open(
        [$pingBinary, '-c', (string) $pingCount, $host],
        $descriptorSpec,
        $pipes
    );

    if (!is_resource($process)) {
        return 'Diagnostic command failed to run.';
    }

    $output = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $exitCode = proc_close($process);

    if ($output === false || $exitCode < 0) {
        return 'Diagnostic command failed to run.';
    }

    return $output;
}

if (php_sapi_name() !== 'cli' && isset($_GET['host'])) {
    header('Content-Type: text/plain');
    echo runReachabilityCheck();
}
```

## Explanation

The vulnerable line concatenated `$host` into a string handed to `shell_exec()`, which runs its argument through a shell; any shell metacharacter in the host value (`;`, `&&`, `` ` ``, `$()`) let an attacker append arbitrary commands. The fix addresses this in two layers, per the loaded CWE-78 PHP guidance: `ping` has no PHP-native equivalent (an ICMP echo requires a raw/ICMP socket and reimplementing timing and output formatting, which is a rewrite, not a replacement), so the command is kept but executed through `proc_open()` with the command supplied as an array (`[$pingBinary, '-c', '4', $host]`). PHP never builds a shell string from an array-form `proc_open()` call, so shell metacharacters in `$host` are inert - they are passed as literal bytes of one argument, not parsed for control characters. Second, because an argument array only closes shell-metacharacter injection and not argument/flag injection (CWE-88), the host is validated against a hostname/IP format before use; a valid hostname or IP cannot begin with `-`, so the value cannot be read as an option flag by `ping` either. The binary path is resolved from a fixed absolute-path candidate list rather than trusting `PATH`. `2 => ['redirect', 1]` preserves the original "2>&1" combined stdout/stderr behavior that the caller displays as plain text.

## Behaviour changes

- Requests with a host that is not a syntactically valid hostname or IP address (including anything containing shell metacharacters, whitespace, or a leading `-`) now receive HTTP 400 and `"Invalid host parameter."` instead of having that value run through `ping`. This is intended: it is the closing of the injection, not a side effect.
- `shell_exec()` returns `null` (mapped to `"Diagnostic command failed to run."`) both on a real execution failure and, per PHP's documented behaviour, whenever the command produces no output at all. The `proc_open()` replacement distinguishes these cases: a successful run that happens to produce empty output now returns an empty string rather than the failure message. In practice `ping` always writes a header line on success, so this only differs for an ping binary that produces truly no output.
- If neither `/usr/bin/ping` nor `/bin/ping` exists and is executable on the host running this code, the endpoint now returns `"Diagnostic command failed to run."` unconditionally; the original code relied on `PATH` resolution and would have worked with `ping` installed anywhere on `PATH`. This trade-off is the direct consequence of invoking by absolute path to prevent `PATH`-substitution attacks; if the deployment target keeps `ping` at a different fixed location, add that path to the candidate list.

Verification performed: `php -l` on the fixed file reported no syntax errors. The hostname/IP validation regex was exercised against `127.0.0.1`, `example.com`, `host-1.internal`, and `2001:db8::1` (all accepted), and against `127.0.0.1; touch pwned`, `-oProxyCommand=touch pwned`, `host && rm -rf /`, an empty string, and a trailing-newline payload `"host\n"` (all rejected), confirming both the injection payloads and the CWE-88 leading-dash case are closed. `is_executable()`, `proc_open()`, `stream_get_contents()`, `proc_close()`, and the `['redirect', 1]` descriptor form are documented PHP standard-library behaviour (the `redirect` descriptor type has been available since PHP 7.4, matching the array-form `proc_open()` floor the loaded guidance already assumes).
