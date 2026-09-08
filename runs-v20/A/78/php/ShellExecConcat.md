## Verdict

Confirmed. `runReachabilityCheck()` builds the `ping` command line by directly concatenating the unvalidated `$_GET['host']` value into a string passed to `shell_exec()`. Because the value reaches a shell interpreter as raw text, an attacker can supply shell metacharacters (e.g. `; rm -rf /`, `` `id` ``, `$(...)`, `&&`, `|`) to run arbitrary commands with the privileges of the web server process.

## Source

`$_GET['host']` at line 17, read into `$host` with no validation beyond an empty-string check, then concatenated unescaped into the command string built at line 27 and executed by `shell_exec()`.

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

    $output = shell_exec('ping -c ' . $pingCount . ' ' . escapeshellarg($host) . ' 2>&1');

    if ($output === null) {
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

`escapeshellarg()` wraps `$host` in single quotes and escapes any single quote it contains, so the value is passed to the shell as one inert argument no matter what characters it holds. This closes the injection at the sink itself rather than relying on a hostname pattern that could reject legitimate values (e.g. IPv6 literals) or be bypassed by an encoding the pattern didn't anticipate. `$pingCount` stays a literal integer, so it needs no escaping. The rest of the control flow, response handling, and output are unchanged.
