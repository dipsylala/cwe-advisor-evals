## Verdict

Exploitable. The `$_GET['term']` parameter flows unsanitized into an OS command string passed to `proc_open()`, allowing arbitrary shell command injection despite the use of `grep -F` and `--`.

## Source

`$_GET['term']` (line 41 of the case file) is passed unsanitized to `searchApplicationLog()` as `$term`. It is then concatenated directly into the OS command string at line 18: `'grep -F -- "' . $term . '" ' . $logPath`.

An attacker can inject shell metacharacters such as `"$(malicious_command)"`, `` `command` ``, `; command;`, or `| command` to execute arbitrary OS commands.

## Fix

The purpose of this code is to search a log file for matching lines. This is not a case where OS command execution is the feature; it is incidental. Replace `proc_open() + grep` with PHP's native file I/O functions (`file()` and `strpos()`). This eliminates the attack surface entirely.

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

    // Use PHP's file functions instead of grep command to eliminate OS command injection
    $lines = @file($logPath, FILE_IGNORE_NEW_LINES);
    
    if ($lines === false) {
        return ['matches' => [], 'error' => 'unable to read log file'];
    }
    
    // Filter lines containing the search term (literal string match, equivalent to grep -F)
    $matches = array_filter($lines, function($line) use ($term) {
        return strpos($line, $term) !== false;
    });
    
    return ['matches' => array_values($matches), 'error' => null];
}

// Example endpoint wiring: GET /admin/log-search?term=...
$searchTerm = $_GET['term'] ?? '';
$result = searchApplicationLog($searchTerm);

header('Content-Type: application/json');
echo json_encode($result);
```

## Explanation

The fix replaces OS command execution with native PHP file I/O, eliminating the injection vector entirely. `file($logPath, FILE_IGNORE_NEW_LINES)` reads all lines from the log file (equivalent to grep reading the file), and `array_filter()` with `strpos()` performs literal string matching (equivalent to `grep -F`). The `$term` parameter is now used only in a string search operation, not in command construction, so injection is no longer possible. The return structure is preserved: an array of matching lines or an error message.

## Behaviour changes

1. **Error handling**: Original returns `proc_open()` errors and grep's stderr via the error field; fixed version returns a generic "unable to read log file" message if file reading fails. This is acceptable because it maintains the error-reporting contract (returns error or matches, never both) while eliminating the complexity of capturing and returning grep's output.

2. **Exit codes**: Original distinguishes between `grep` exit codes (0 = matches found, 1 = no matches, > 1 = error). Fixed version treats "no matches" and "read success with zero matches" identically (both return empty matches array with no error). This is acceptable because the caller cannot distinguish between these states, and both result in an empty result set.

3. **Performance**: For very large log files, the fixed version reads the entire file into memory via `file()`, whereas `grep` streams results. For typical application logs, this is acceptable. If memory becomes a constraint, this could be refactored to use `fopen()` and read line-by-line, but that is a separate optimization not required for the security fix.

4. **Search semantics**: Both the original (grep -F) and fixed (strpos) perform literal substring matching, so search semantics are unchanged. Empty search terms match all lines in both versions.
