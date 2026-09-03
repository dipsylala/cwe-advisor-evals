## Verdict
Confirmed OS Command Injection (CWE-78).

## Source
Line 41: `$_GET['term']` is user-controlled input from an HTTP request parameter.

Line 42: The unsanitized `$searchTerm` is passed to `searchApplicationLog()`.

## Fix
Replace the shell string with an argument array:

```php
// Before (line 18):
$process = proc_open('grep -F -- "' . $term . '" ' . $logPath, $descriptors, $pipes);

// After:
$process = proc_open(['grep', '-F', '--', $term, $logPath], $descriptors, $pipes);
```

The argument array form passes each argument separately to the `grep` executable without invoking a shell, preventing command injection entirely. Shell metacharacters like backticks, dollar signs, semicolons, and pipes in `$term` are treated as literal argument content, not interpreted as shell syntax.

## Explanation
The original code constructs a shell command string by concatenating user input into a `grep` invocation, then passes it to `proc_open()`. Although the command uses `grep -F` (literal pattern matching, not regex) and `--` (option terminator), these do not prevent shell injection. A quote character in `$_GET['term']` can break out of the surrounding quotes and enable arbitrary command execution—for example, `term=""; whoami; echo "` becomes `grep -F -- ""; whoami; echo "" /var/log/app/access.log`, executing `whoami` via the shell.

Passing an argument array to `proc_open()` bypasses the shell entirely. Each array element becomes a separate argument to the target executable, with no shell interpretation. The grep process receives the arguments as-is: the term is never parsed as code, only as literal search text.
