## Verdict

Confirmed. The finding is exploitable. Untrusted user input (`$_GET['term']`) is concatenated directly into a shell command string passed to `proc_open()`, allowing OS command injection.

## Source

User input flows from `$_GET['term']` (line 41) as `$searchTerm` into the function parameter `$term` (line 8), then is concatenated into the shell command at line 18.

## Fix

Replace line 18 to use `proc_open()` with an argument array instead of a shell command string:

```php
// Original (vulnerable)
$process = proc_open('grep -F -- "' . $term . '" ' . $logPath, $descriptors, $pipes);

// Fixed
$process = proc_open(['grep', '-F', '--', $term, $logPath], $descriptors, $pipes);
```

This fix requires PHP 7.4 or later for array-form `proc_open()` support.

## Explanation

The array form of `proc_open()` passes each argument directly to the target process without shell interpretation. Each element of the array becomes a separate argv entry; the shell is not invoked. The `--` argument tells grep to stop processing options and treat all remaining arguments as filenames/search terms. Even if `$term` starts with `-`, it cannot be misinterpreted as a flag because it arrives as a complete argument after `--`, not as a string the shell can parse.

This eliminates the injection point entirely: the shell command string is no longer constructed, so shell metacharacters in `$term` (semicolons, pipes, command substitution, etc.) are treated as literal characters in the search term, not as shell syntax.

## Behaviour changes

- The command no longer invokes a shell; arguments are passed directly to grep
- The search term is no longer embedded in shell-escaped quotes; it arrives as a raw string argument
- Functionality is preserved: grep still searches the log file identically
- Input validation improvement: the `--` separator ensures even a search term starting with `-` is not misinterpreted as an option flag
