## Verdict

Real. The `proc_open()` call on line 18 uses a shell string with untrusted user input concatenated directly into the command. Although the code employs `-F` (fixed-string matching) and `--` (end-of-options) as defensive measures, these do not prevent shell metacharacter injection because the shell parses the entire command before grep receives arguments. An attacker can supply input containing shell metacharacters to inject additional commands or break out of the quoted argument context.

## Source

- **Taint source**: `$_GET['term']` on line 41, user-supplied query parameter
- **Taint sink**: `proc_open()` on line 18, where `$term` is concatenated into a shell command string
- **Data flow**: `$_GET['term']` → `searchApplicationLog($searchTerm)` (line 42) → `$term` parameter (line 8) → shell command concatenation (line 18)

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

    // Fixed: Use proc_open() with an argument array instead of shell string
    // This prevents shell interpretation of special characters in $term
    $process = proc_open(
        ['/bin/grep', '-F', '--', $term, $logPath],
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

The vulnerability existed because untrusted user input (`$term` from `$_GET['term']`) was concatenated directly into a shell command string passed to `proc_open()`. Even with `-F` (fixed-string matching) and `--` (end-of-options) as defensive layers, the shell still parses the entire command line before grep receives its arguments, allowing special characters to break out of the quoted context and inject additional commands.

The fix converts `proc_open()` from shell string form to argument array form (available in PHP 7.4+). When the first argument is an array, PHP passes arguments directly to the process without shell interpretation. The array `['/bin/grep', '-F', '--', $term, $logPath]` is constructed by the PHP interpreter and passed to the operating system directly, bypassing shell parsing entirely. The use of an absolute path to grep (`/bin/grep`) prevents PATH injection attacks per CWE-78 guidance.

For PHP versions 8.1.29+, 8.2.20+, or 8.3.8+, the fix also benefits from CVE-2024-1874 hardening that strengthened the array form implementation and CVE-2024-5585 closure of a trailing-space bypass. For older PHP versions (7.4 through 8.1.28 / 8.2.0-18 / 8.3.0-5), the array form is still significantly safer than the shell string form and is the recommended pattern.

## Behaviour changes

- **Shell interpretation**: Eliminated. Arguments are no longer subject to shell parsing; special characters in `$term` are treated as literal characters, not shell metacharacters.
- **Return value**: Unchanged. The function still returns the same structure: `['matches' => [...], 'error' => ...]` with exit codes handled identically.
- **Error handling**: Preserved. Process resource checks via `is_resource()` and error detection via exit codes remain the same.
- **Process execution**: The grep utility is still invoked directly; the command execution semantics are unchanged. Only the argument passing mechanism changes from shell-constructed string to direct argument vector.
- **Input validation**: No additional input validation is needed. The array form provides protection at the operating system call level, not the language level.
- **Portability note**: The absolute path `/bin/grep` is appropriate for POSIX systems (Linux, BSD, macOS). On systems where grep is installed elsewhere, adjust the path accordingly or use `which grep` to discover the location at configuration time.
