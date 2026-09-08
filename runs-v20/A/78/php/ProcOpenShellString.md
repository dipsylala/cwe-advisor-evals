## Verdict

Confirmed. `$term` (from `$_GET['term']`) is concatenated directly into a shell command string passed to `proc_open()`. When `proc_open()` receives a string command it runs it via `/bin/sh -c` (or `cmd.exe` on Windows), so shell metacharacters in `$term` are interpreted by the shell rather than treated as literal data. Although the value is wrapped in double quotes, an attacker can close the quote (`"; id; echo "`) or use `` ` `` / `$()` inside the quoted string to run arbitrary commands with the web server's privileges.

## Source

`$_GET['term']` at line 41, passed as `$searchTerm` into `searchApplicationLog()` and used unmodified as `$term` in the shell string built at line 18.

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

`proc_open()` (and `exec()`, `shell_exec()`, `system()`, `passthru()`, backtick execution) invoke a shell whenever given a single command string, so any special character in interpolated user data is subject to shell parsing regardless of surrounding quotes. Passing the command as an array (`['grep', '-F', '--', $term, $logPath]`) instead of a string tells `proc_open()` to execute the binary directly via `execve()`-style invocation with no shell in between, so each array element reaches `grep` as one literal argument — quotes, `;`, backticks, `$()`, and `|` in `$term` are just search text, not shell syntax.

The `-F` flag keeps the match literal (no regex metacharacter interpretation inside `grep` itself), and the pre-existing `--` before `$term` stops `grep` from treating a value that happens to start with `-` as an option flag, so a search term like `-r` or `--help` is still searched for literally rather than changing `grep`'s behavior.

A test with `$term` containing `"; id; echo "` (or backticks/`$()`) previously executed the injected command and returned its output; against the fixed code that string is grepped for literally in the log file (returning no matches) and no injected command runs, which is the correct before/after signal.
