## Verdict
exploitable

## Source
Line 17: `$_GET['host']` (untrusted user input from query parameter)

## Fix

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

    $pingCount = 4;

    // Use proc_open with argument array instead of shell_exec with concatenation
    // This prevents OS command injection by passing the host as a separate argument
    $descriptorspec = [
        1 => ['pipe', 'w'],  // stdout
        2 => ['pipe', 'w'],  // stderr
    ];
    
    $process = proc_open(
        ['ping', '-c', (string)$pingCount, $host],
        $descriptorspec,
        $pipes
    );

    if ($process === false) {
        return 'Diagnostic command failed to run.';
    }

    $output = '';
    $output .= stream_get_contents($pipes[1]);
    $output .= stream_get_contents($pipes[2]);
    
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);

    return $output;
}

if (php_sapi_name() !== 'cli' && isset($_GET['host'])) {
    header('Content-Type: text/plain');
    echo runReachabilityCheck();
}
```

## Explanation
The original code concatenates the untrusted `$_GET['host']` parameter directly into a shell command string passed to `shell_exec()`, enabling OS command injection. An attacker could inject shell metacharacters or arbitrary commands (e.g., `?host=localhost;id;`) to execute unintended operations.

The fix replaces `shell_exec()` with `proc_open()` using an argument array (PHP 7.4+). The command and its arguments are passed as separate array elements, preventing the shell from interpreting any part of the host parameter as commands or metacharacters. The `$descriptorspec` array captures both stdout and stderr into separate pipes, which are then combined using `stream_get_contents()` to match the original behavior of `shell_exec()` with `2>&1` redirection. All pipes are properly closed and the process is reaped with `proc_close()` to prevent resource leaks.

## Behaviour changes
- **Return value preservation**: The function still returns a string combining stdout and stderr, matching the original's contract
- **Error handling**: Returns the same error message on command failure (`'Diagnostic command failed to run.'`)
- **Output format**: Combined stdout/stderr via explicit pipe handling instead of shell redirection (functionally identical)
- **Process cleanup**: Added explicit pipe closure and process reaping with `proc_close()` to prevent resource leaks (improvement, not a regression)

