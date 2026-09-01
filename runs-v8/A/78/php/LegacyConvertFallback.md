## Verdict

CWE-78 (OS Command Injection) confirmed at line 19. The fallback command execution concatenates unsanitized user input directly into a shell command string.

## Source

User-supplied `$requestedName` (from `$_POST['document']` at line 24) flows into the `convert_document()` function parameter and is concatenated into the shell command at line 19 without escaping.

## Fix

Wrap `$requestedName` and `$target` with `escapeshellarg()`:

```php
exec('/usr/bin/legacy-convert ' . escapeshellarg($requestedName) . ' ' . escapeshellarg($target), $fallbackOutput, $fallbackStatus);
```

## Explanation

The primary command path (lines 8–11) correctly uses `escapeshellarg()` to prevent shell metacharacters in `$source` from breaking out of the intended argument. The fallback path (line 19) omits this escaping, leaving the sink vulnerable to command injection if an attacker includes shell metacharacters (e.g., `; rm -rf /` or `| cat /etc/passwd`) in their input.

`escapeshellarg()` wraps the argument in single quotes and escapes any single quotes within it, ensuring the value is treated as a literal argument to the legacy-convert program and not as shell syntax.
