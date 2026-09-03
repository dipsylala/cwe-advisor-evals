## Verdict

**Exploitable.** The vulnerability is confirmed. Untrusted input (`$_POST['document']`) flows through `$requestedName` into the `exec()` sink on line 19 without shell escaping, allowing arbitrary command injection.

## Source

`$_POST['document']` (attacker-controlled HTTP POST parameter) → `$requestedName` parameter on line 3.

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

The vulnerability occurs because `$requestedName` is concatenated directly into a shell command string without escaping. Although `basename()` is applied earlier to prevent directory traversal, `basename()` does not prevent shell metacharacter injection. An attacker can inject commands by including shell metacharacters (e.g., `;`, `|`, `&`) in the filename.

The fix applies `escapeshellarg()` to both `$requestedName` and `$target` before concatenation. This function quotes each argument and escapes any special characters, ensuring they are treated as literal string arguments to the `legacy-convert` program rather than shell syntax. This matches the safe pattern already used on line 10 for the primary command.

## Behaviour changes

- Arguments containing shell metacharacters are now treated as literal strings and passed safely to the external program
- The command no longer interprets special characters in filenames as shell operators
- Output collection, exit status handling, and error behavior remain unchanged
- Function return values and downstream logic remain unaffected
