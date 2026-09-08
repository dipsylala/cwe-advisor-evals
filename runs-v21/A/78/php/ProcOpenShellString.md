## Verdict
Confirmed. Line 18 contains an OS command injection vulnerability due to shell string concatenation of unsanitized user input.

## Source
The vulnerability is in line 18 of `ProcOpenShellString.php`:

```php
$process = proc_open('grep -F -- "' . $term . '" ' . $logPath, $descriptors, $pipes);
```

The `$term` parameter originates from user-controlled input (`$_GET['term']`) and is directly concatenated into a shell command string passed to `proc_open()`. Although `grep -F` treats the pattern as a fixed string (not a regex), embedding an attacker-controlled value in double quotes still allows shell metacharacter escape via `"`, `$`, backticks, or other shell operators. An attacker can inject shell commands by crafting input like `"; malicious_command; echo "`.

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

    // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
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
The fix replaces the shell-string concatenation with an argument array. `proc_open()` accepts either a string (which invokes the shell) or an array of arguments (which invokes the program directly without shell interpretation). By passing `['grep', '-F', '--', $term, $logPath]`, the program is executed with these as separate arguments:

- The shell is never invoked, eliminating shell metacharacter interpretation.
- `$term` is passed literally as the search pattern, regardless of what special characters it contains.
- The `--` separator ensures `grep` treats `$term` as the pattern, not as an option flag, even if it begins with `-`.

This is the primary defence mechanism for command injection via `proc_open()` in PHP: use argument arrays instead of concatenated strings.
