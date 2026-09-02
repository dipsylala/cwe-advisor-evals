## Verdict

CWE-78 confirmed. The fallback `exec()` call concatenates `$requestedName` directly into a shell command without escaping, allowing command injection via special characters.

## Source

Input reaches the vulnerable function via `$_POST['document']` and is passed as `$requestedName` parameter. The primary conversion correctly uses `escapeshellarg()`, but the fallback path does not.

## Fix

```php
exec('/usr/bin/legacy-convert ' . escapeshellarg($requestedName) . ' ' . escapeshellarg($target), $fallbackOutput, $fallbackStatus);
```

Apply `escapeshellarg()` to both `$requestedName` and `$target` before concatenating them into the shell command.

## Explanation

The primary conversion (lines 8–12) safely handles the source path using `escapeshellarg()`, but the fallback (line 19) breaks that pattern by concatenating `$requestedName` directly into the command string. Although `basename()` was called earlier, it is not used on this code path—the original unsanitized `$requestedName` is passed through. An attacker can inject shell metacharacters like `;`, `|`, `&`, `$()`, or backticks to execute arbitrary commands. Wrapping both arguments with `escapeshellarg()` quotes each value and escapes internal quotes, preventing shell interpretation.
