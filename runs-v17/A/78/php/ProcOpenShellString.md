## Verdict
CONFIRMED - Command injection vulnerability via unescaped string interpolation in proc_open shell command.

## Source
User-controlled input from `$_GET['term']` flows to `searchApplicationLog()` as parameter `$term`, then directly into the shell command string at line 18 without proper escaping.

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

    // Use proc_open with an argument array to prevent command injection.
    // The array form passes arguments directly to the command without shell parsing.
    $process = proc_open(['grep', '-F', '--', $term, $logPath], $descriptors, $pipes);

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
The vulnerability exists because `proc_open()` with a shell command string is forced to parse the command through the shell, which interprets special characters and metacharacters. Even with `grep -F` (fixed-string mode), an attacker can inject characters like double quotes and backslashes to break out of the quoted context and execute arbitrary shell commands.

The fix passes an argument array to `proc_open()` instead of a shell command string. When given an array, `proc_open()` bypasses shell parsing entirely and passes arguments directly to the `grep` executable. The elements of the array become literal arguments:
- `'grep'` - the command to execute
- `'-F'` - fixed-string mode flag
- `'--'` - option terminator (prevents `$term` from being interpreted as an option if it starts with `-`)
- `$term` - the search term, treated as a literal string regardless of content
- `$logPath` - the file path, treated as a literal argument

This eliminates the injection vector because the shell never sees or interprets the user-controlled `$term` value.
