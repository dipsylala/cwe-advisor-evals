## Verdict

Exploitable.

## Source

Untrusted user input `$_GET['term']` (line 41) is passed to the `searchApplicationLog()` function as the `$term` parameter.

## Fix

**Vulnerable code:**
```php
// Line 18: String concatenation passes $term unsafely to proc_open shell command
$process = proc_open('grep -F -- "' . $term . '" ' . $logPath, $descriptors, $pipes);
```

**Fixed code:**
```php
// Line 18: Use proc_open() with argument array to avoid shell interpretation entirely
$process = proc_open(['grep', '-F', '--', $term, $logPath], $descriptors, $pipes);
```

## Explanation

The vulnerability exists because `$term` (derived from `$_GET['term']`) is concatenated into a shell command string passed to `proc_open()`. Although the code uses `grep -F` (literal search, not regex), the `--` end-of-options marker, and double quotes around the value, the injection point remains: an attacker can provide a quote character to break out of the quoted context and inject arbitrary commands. For example, `" || cat /etc/passwd || "` would cause the final command to execute the attacker's injected commands.

The fix eliminates the injection point by passing the command and its arguments as an array to `proc_open()` instead of a concatenated string. When an array is provided (available in PHP 7.4 or later), `proc_open()` bypasses shell interpretation and passes the arguments directly to the target program, preventing any shell metacharacter or quote escaping issues. The arguments `['grep', '-F', '--', $term, $logPath]` are passed to the kernel without shell re-parsing, making injection impossible while preserving the exact functionality and output of the original code.

## Behaviour changes

None. The fixed code preserves the sink contract entirely: it returns the same process resource or false on error, and the subsequent file operations (`fclose()`, `stream_get_contents()`, `proc_close()`) work identically. The output and error handling are unchanged.
