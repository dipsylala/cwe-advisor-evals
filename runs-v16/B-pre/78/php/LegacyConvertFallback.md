## Verdict

Exploitable

## Source

Line 24: `$_POST['document']` is passed to `convert_document()` as the `$requestedName` parameter, which reaches the sink at line 19 without escaping.

## Fix

**Vulnerable code (line 19):**
```php
exec('/usr/bin/legacy-convert ' . $requestedName . ' ' . $target, $fallbackOutput, $fallbackStatus);
```

**Fixed code:**
```php
exec('/usr/bin/legacy-convert ' . escapeshellarg($requestedName) . ' ' . escapeshellarg($target), $fallbackOutput, $fallbackStatus);
```

## Explanation

The fallback `exec()` call at line 19 concatenates user-controlled input (`$requestedName`) directly into the command string without escaping, allowing an attacker to inject arbitrary OS commands. For example, input like `test.txt; rm -rf /` would execute the embedded `rm -rf /` command. The fix applies `escapeshellarg()` to both `$requestedName` and `$target` before the command is executed, properly quoting each argument as a single token so shell metacharacters are treated as literal values. This matches the pattern already established in the primary `exec()` call at line 10, which correctly uses `escapeshellarg()` for the `$source` argument.

## Behaviour changes

None. The `escapeshellarg()` function takes a string and returns it quoted appropriately for use as a single argument in a shell command, preserving the intended value while preventing shell metacharacter interpretation. The command's return code and output capture behavior remain unchanged.
