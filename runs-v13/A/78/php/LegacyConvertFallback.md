## Verdict

OS Command Injection vulnerability confirmed. Line 19 passes user-controlled input directly into an `exec()` command without proper sanitization or escaping.

## Source

Line 19 constructs a shell command by concatenating `$requestedName` directly:

```
exec('/usr/bin/legacy-convert ' . $requestedName . ' ' . $target, $fallbackOutput, $fallbackStatus);
```

The `$requestedName` parameter originates from user input (`$_POST['document']` on line 24) and flows into the command string without any escaping. Although the primary conversion attempt (lines 8-12) properly uses `escapeshellarg()` on the derived `$source` variable, the fallback command does not.

## Fix

Replace line 19 with:

```
exec('/usr/bin/legacy-convert ' . escapeshellarg($source) . ' ' . escapeshellarg($target), $fallbackOutput, $fallbackStatus);
```

This reuses the already-sanitized `$source` and `$target` variables (lines 5-6) which are derived from `basename($requestedName)` and the fixed directory paths. The additional `escapeshellarg()` wrapper ensures any shell metacharacters in the filenames are properly escaped before being passed to the `legacy-convert` command.

## Explanation

The vulnerability arises because `$requestedName` carries attacker-controlled input from `$_POST['document']` into the fallback command. An attacker could craft an input like `file.txt; rm -rf /;` to inject arbitrary shell commands.

The fix addresses this by:
1. Using `$source`, which is safely constructed as `/srv/uploads/` concatenated with only the basename of the request (path traversal blocked)
2. Using `$target`, which is safely constructed as `/srv/converted/` concatenated with only the basename plus `.pdf`
3. Wrapping both in `escapeshellarg()` to neutralize any shell metacharacters within the filenames themselves

This approach is consistent with the primary conversion path (lines 8-10) and ensures both conversion attempts are protected against command injection.
