## Verdict

The code is vulnerable to OS command injection on line 8. User-supplied input from `$_GET['host']` is concatenated directly into a shell command string passed to `system()` without sanitization, allowing an attacker to inject arbitrary commands by including shell metacharacters (`;`, `|`, `&&`, etc.) in the host parameter.

## Source

Line 8 of the vulnerable code:
```php
system('ping -c 2 -W 2 ' . $host, $resultCode);
```

The `$host` variable originates from unsanitized user input at line 17:
```php
$status = check_host_reachability($_GET['host'] ?? '');
```

## Fix

Replace line 8 with:
```php
system('ping -c 2 -W 2 ' . escapeshellarg($host), $resultCode);
```

The `escapeshellarg()` function wraps the hostname in single quotes and escapes any embedded single quotes, ensuring the value is treated as a literal string argument rather than allowing shell metacharacter interpretation.

## Explanation

OS command injection occurs when user-controlled data is concatenated into a command string passed to a shell execution function like `system()`, `exec()`, `passthru()`, or `shell_exec()`. An attacker can inject shell metacharacters to execute additional commands.

`escapeshellarg()` is PHP's built-in function for escaping a single shell argument. It:
- Wraps the value in single quotes (strong quoting in sh/bash)
- Escapes any single quotes within the value by ending the quote, adding an escaped quote, and resuming the quote
- Produces output safe for use in any shell command

This ensures that even if `$host` contains `example.com; rm -rf /` or similar injection payloads, the argument is treated as a literal hostname string and cannot be interpreted as separate commands or flags.
