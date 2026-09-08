## Verdict
exploitable

## Source
`$_GET['host']` (line 17) - untrusted user input

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

    // Use proc_open with argument array to prevent shell injection.
    // The -- separator prevents the host from being interpreted as an option.
    $descriptorspec = [
        1 => ['pipe', 'w'],  // stdout
        2 => ['pipe', 'w'],  // stderr
    ];

    $process = proc_open(
        ['ping', '-c', (string)$pingCount, '--', $host],
        $descriptorspec,
        $pipes
    );

    if (!is_resource($process)) {
        return 'Diagnostic command failed to run.';
    }

    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);

    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);

    if ($stdout === false || $stderr === false) {
        return 'Diagnostic command failed to run.';
    }

    return $stdout . $stderr;
}

if (php_sapi_name() !== 'cli' && isset($_GET['host'])) {
    header('Content-Type: text/plain');
    echo runReachabilityCheck();
}
```

## Explanation
The vulnerability was eliminated by replacing `shell_exec()` with `proc_open()` using an argument array form. In `shell_exec()`, the host parameter was concatenated directly into a shell command string, allowing attackers to inject shell metacharacters and execute arbitrary commands. The fixed code passes the host as a separate array element to `proc_open()`, preventing shell interpretation. The `--` argument marks the end of options, preventing the host value from being misinterpreted as a flag if it starts with a dash. The fix preserves the original behavior: it returns combined stdout and stderr as a string, and returns the same error message on failure. PHP versions 7.4 and later are required for `proc_open()` argument array support.

## Behaviour changes
- `proc_open()` with array form is used instead of shell string concatenation, closing the injection vector
- The `--` separator is added before the host argument to prevent argument injection (CWE-88), rejecting no legitimate values
- Stream reading is performed explicitly instead of relying on shell output redirection
- Process resources (`$pipes`, `$process`) are properly freed after execution, improving resource management
- Output combines stdout and stderr in the same order as the original (stdout first, then stderr), preserving the caller's expectation of combined error reporting

## Verification
`php -l` on the fixed code returned "No syntax errors detected", confirming valid PHP 7.4+ syntax. All new APIs used (`proc_open()`, `stream_get_contents()`, `fclose()`, `is_resource()`) are part of PHP's standard library.
