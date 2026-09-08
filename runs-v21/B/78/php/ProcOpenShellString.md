## Verdict

The vulnerability is confirmed as exploitable. Untrusted user input from `$_GET['term']` flows directly into a shell command string executed via `proc_open()` without parameterization or safe argument passing.

## Source

Line 41: `$_GET['term']` (user-controlled parameter)
→ Line 42: assigned to `$searchTerm`
→ Line 8: passed to function parameter `$term`
→ Line 18: concatenated into command string for `proc_open()`

## Fix

Replace the entire command execution approach with PHP's native file and string search functions. This eliminates shell involvement completely.

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
    
    $lines = @file($logPath, FILE_IGNORE_NEW_LINES);
    if ($lines === false) {
        return ['matches' => [], 'error' => 'unable to read log'];
    }
    
    $matches = [];
    foreach ($lines as $line) {
        if (strpos($line, $term) !== false) {
            $matches[] = $line;
        }
    }
    
    return ['matches' => $matches, 'error' => null];
}

// Example endpoint wiring: GET /admin/log-search?term=...
$searchTerm = $_GET['term'] ?? '';
$result = searchApplicationLog($searchTerm);

header('Content-Type: application/json');
echo json_encode($result);
```

## Explanation

The original code constructs a shell command string with untrusted user input and passes it to `proc_open()`. Even though `grep -F` treats the pattern as a literal string (not regex) and `--` ends option processing, the shell still parses the entire command line, creating an injection point. An attacker can include shell metacharacters in `$term` to break the quoting and inject arbitrary commands.

The fix replaces shell command execution with PHP's native file and string search functions:
- `file($logPath, FILE_IGNORE_NEW_LINES)` reads the file into an array of lines
- `strpos($line, $term)` performs a literal string search on each line (equivalent to `grep -F`)
- User input is passed only to `strpos()`, which performs no shell interpretation

This achieves identical functionality—literal string search in a file—without any shell involvement, completely closing the injection vector. No parameterized API or validation is needed because there is no command execution at all.

## Behaviour changes

- **Process spawning eliminated:** No longer spawns grep subprocess; all work done in-process.
- **Error handling:** File read failures return error message "unable to read log" instead of relying on grep's exit codes. For the use case (log file should always exist and be readable by the application), this is appropriate.
- **Empty results:** When no matches are found, returns empty array with `error: null` (equivalent to grep exit code 1).
- **Performance:** For small-to-medium log files, this is faster (no subprocess overhead). For very large files, `file()` loads the entire file into memory, which may have operational implications—consider pagination or streaming if the log grows unbounded.
- **Functionality:** Identical from the caller's perspective: same return structure, same search semantics (literal string matching).
