## Verdict

The finding is confirmed. Line 19 contains an OS Command Injection vulnerability.

## Source

```php
exec('/usr/bin/legacy-convert ' . $requestedName . ' ' . $target, $fallbackOutput, $fallbackStatus);
```

The `$requestedName` variable is derived directly from `$_POST['document']` (line 24) and concatenated into the shell command without any escaping. An attacker can inject arbitrary shell commands by embedding metacharacters or shell operators in the POST parameter.

## Fix

```php
exec('/usr/bin/legacy-convert ' . escapeshellarg($source) . ' ' . escapeshellarg($target), $fallbackOutput, $fallbackStatus);
```

Replace the raw `$requestedName` with the pre-computed `$source` variable (which applies `basename()` to prevent directory traversal), and apply `escapeshellarg()` to both path arguments to safely escape shell metacharacters. The `$target` variable should also be escaped for consistency and defense-in-depth.

## Explanation

The vulnerable code passes unsanitized user input directly into `exec()`, allowing an attacker to inject shell commands. For example, passing `"; rm -rf /"` as the document name would execute the `rm` command after the legitimate conversion attempt.

The fix uses two complementary defenses:

1. **Path constraint via `basename()`**: The `$source` variable already constrains the input to a filename without directory components, preventing traversal attacks.

2. **Shell argument escaping**: `escapeshellarg()` wraps each argument in single quotes and escapes any embedded quotes, neutralizing shell metacharacters and preventing command injection. Using the pre-computed `$source` and `$target` variables ensures both path safety and consistent handling across the call chain.

This approach follows the pattern already established in the primary command (lines 8-11), which correctly uses `escapeshellarg()` on the source path.
