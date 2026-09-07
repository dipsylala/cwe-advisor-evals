## Verdict

OS Command Injection confirmed. The vulnerable code concatenates user-supplied input (`$_GET['term']`) into a shell command string passed to `proc_open()`, allowing arbitrary grep arguments or shell metacharacters to be injected. The `grep -F` option and `--` separator provide some defence against regex and flag injection but do not eliminate shell command string interpretation. The fix uses an argument array to bypass the shell entirely.

## Source

`$_GET['term']` (line 41, endpoint parameter) flows through `searchApplicationLog($term)` parameter (line 8) and is concatenated into the proc_open command string (line 18).

## Fix

### File: ProcOpenShellString.php

```php
<?php

/**
 * Streams matching lines from the daily application log back to an
 * operator so they can search for a request ID or error string without
 * shelling into the box.
 */
function searchApplicationLog(string $term): array
{
    $logPath = '/var/log/app/access.log';
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];

    // Use proc_open() with an argument array to prevent command injection.
    // Arguments are passed directly to grep without shell interpretation.
    $process = proc_open(
        ['grep', '-F', '--', $term, $logPath],
        $descriptors,
        $pipes
    );

    if (!is_resource($process)) {
        return ['matches' => [], 'error' => 'unable to start search'];
    }

    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]);
    $errors = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exitCode = proc_close($process);

    if ($exitCode > 1) {
        return ['matches' => [], 'error' => trim($errors)];
    }

    $lines = $output === '' ? [] : explode("\n", trim($output));

    return ['matches' => $lines, 'error' => null];
}

// Example endpoint wiring: GET /admin/log-search?term=...
$searchTerm = $_GET['term'] ?? '';
$result = searchApplicationLog($searchTerm);

header('Content-Type: application/json');
echo json_encode($result);
```

## Explanation

The fix replaces the shell command string with an argument array passed to `proc_open()`. When an array is provided (PHP 7.4+), `proc_open()` invokes the program directly without spawning a shell, eliminating shell metacharacter interpretation. The `$term` value is now a single argument element that cannot be split or interpreted as shell syntax. The `--` literal between flags and operands prevents the target program from misinterpreting a leading hyphen in `$term` as a flag (CWE-88 mitigation), and the `-F` flag in the array ensures grep treats the argument as a fixed string rather than a regex pattern. The log file path remains a separate array element, preventing any injection there as well. The function's return type and error handling are preserved.

## Behaviour changes

No behaviour changes. The grep invocation produces identical output:
- Same `-F` (fixed string matching) and `--` (end of options) semantics
- Same process output handling via pipes
- Same exit code interpretation (0 or 1 for success, >1 for error)
- Same return shape for the caller
- Same JSON encoding of results
