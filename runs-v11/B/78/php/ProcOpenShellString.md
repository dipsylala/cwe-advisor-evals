## Verdict

Confirmed. The finding is exploitable. Line 18 concatenates user input from `$_GET['term']` directly into a shell command string passed to `proc_open()`, allowing OS command injection.

## Source

Input flows from `$_GET['term']` (line 41) through the function parameter `$term` to the `proc_open()` call at line 18.

```php
$searchTerm = $_GET['term'] ?? '';
$result = searchApplicationLog($searchTerm);  // line 42

// Vulnerability is in searchApplicationLog():
$process = proc_open('grep -F -- "' . $term . '" ' . $logPath, $descriptors, $pipes);  // line 18
```

An attacker can break the quoted string—for example, `foo" && whoami && echo "` becomes `grep -F -- "foo" && whoami && echo "" /var/log/app/access.log`, executing `whoami` as an injected command.

## Fix

Replace the `proc_open()` call with PHP's native file I/O and string search functions. The code's purpose is to search a log file for matching lines; this is not a command-execution task, so elimination of `proc_open()` is the primary defence.

```php
function searchApplicationLog(string $term): array
{
    $logPath = '/var/log/app/access.log';
    
    if (!is_readable($logPath)) {
        return ['matches' => [], 'error' => 'unable to access log file'];
    }
    
    $lines = file($logPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        return ['matches' => [], 'error' => 'unable to read log file'];
    }
    
    $matches = [];
    foreach ($lines as $line) {
        if (strpos($line, $term) !== false) {
            $matches[] = $line;
        }
    }
    
    return ['matches' => $matches, 'error' => null];
}
```

Remove the `$descriptors` and `$pipes` variables and all associated pipe management code (lines 11–28) that is no longer needed.

## Explanation

The fixed code eliminates the OS command execution entirely by using PHP's `file()` function to read the log file and `strpos()` to search for the term within each line. This achieves the same functionality—returning an array of matching lines—without invoking a shell or external command. No user input is ever interpreted as code or shell syntax; `$term` is treated as plain data in a string comparison. The fix preserves the original return contract: `['matches' => [...], 'error' => ...]` on success and error state on failure.

The guidance for CWE-78 in PHP states that where the command is incidental—a wrapper around something the language does natively—elimination of process execution is the primary defence and is strongly preferred over parameterized execution APIs. File searching is a native PHP capability, so replacement with `file()` and `strpos()` is the correct fix, not `proc_open()` with an argument array.

## Behaviour changes

- **Removed:** Invocation of `grep` subprocess; all pipe handling and process lifecycle management.
- **Added:** Pre-flight check that the log file is readable (`is_readable()`), with error return if not.
- **Changed:** Search algorithm now performs in-process substring matching instead of delegating to `grep -F`. Semantics are equivalent (literal substring search, case-sensitive) and correctness is preserved.
- **Unchanged:** Return type and structure (`['matches' => [...], 'error' => ...]`), error handling flow, and functionality visible to the caller.
