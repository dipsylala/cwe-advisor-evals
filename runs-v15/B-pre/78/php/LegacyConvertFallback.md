## Verdict

True positive. The fallback command execution at line 19 concatenates unsanitized user input directly into a shell command string, allowing OS command injection.

## Source

User-controlled input flows from `$_POST['document']` → `$requestedName` parameter → line 19 as a raw concatenated value into `exec()`.

## Fix

Replace line 19 with properly escaped arguments:

```php
exec(
    '/usr/bin/legacy-convert ' . escapeshellarg($source) . ' ' . escapeshellarg($target),
    $fallbackOutput,
    $fallbackStatus
);
```

The fix applies `escapeshellarg()` to both the source file path and target output path, preventing shell metacharacters from being interpreted as commands. Both values are already computed safely earlier in the function (`$source` and `$target` use `basename()` for path components, and `$target` is statically constructed), so this approach is straightforward and maintains the original behavior.

## Explanation

The vulnerability exists because the fallback command directly concatenates `$requestedName` into the shell command string without escaping, while the primary command (line 8–12) correctly uses `escapeshellarg()` on the same source value. An attacker can inject shell metacharacters such as `;`, `|`, or `&` via the document parameter to execute arbitrary commands.

The fix applies shell argument escaping to both parameters passed to the legacy converter, matching the defensive pattern already established in the primary command. This prevents shell interpretation of special characters while preserving the command's functionality: the converter still receives the file paths as intended, and the function continues to return the target path or empty string based on the status code.

## Behaviour changes

None. The command receives the same input values, and the output (fallback status code, target path on success, empty string on failure) remains identical. Escaping shell arguments does not change the files being accessed or the execution outcome.
