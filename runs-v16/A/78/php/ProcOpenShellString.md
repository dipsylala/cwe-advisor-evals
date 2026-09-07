## Verdict
VULNERABLE. The code constructs a shell command string using user input, allowing command injection despite the `-F` flag and `--` separator.

## Source
Line 18 interpolates the unsanitized `$term` parameter (user-controlled via `$_GET['term']`) into a shell command string passed to `proc_open()`:

```
$process = proc_open('grep -F -- "' . $term . '" ' . $logPath, $descriptors, $pipes);
```

Even though `-F` prevents regex interpretation, a payload like `"; malicious_command; echo "` escapes the quotes and injects arbitrary shell commands.

## Fix
Use `proc_open()`'s array form instead of a shell string. This bypasses shell interpretation entirely, passing arguments directly to the executable:

```php
$process = proc_open(['grep', '-F', '--', $term, $logPath], $descriptors, $pipes);
```

The array form takes the command name as the first element and arguments as subsequent elements. No shell parsing occurs, so shell metacharacters in `$term` cannot escape argument boundaries.

## Explanation
Command injection through shell strings occurs because shell interprets special characters (`"`, `$`, backticks, `;`, `|`, `&`, etc.) even when the attacker's data is quoted. The `-F` flag and `--` option both narrow the attack surface but do not eliminate it—`-F` restricts `grep`'s behavior, not the shell's.

The only robust defense is to bypass the shell. `proc_open()` accepts an array as its command parameter; when given an array, it invokes the executable directly without spawning `/bin/sh`, making shell metacharacters meaningless. The arguments are passed directly to `grep`, where only `grep` itself interprets them—a far narrower and controlled parsing surface.
