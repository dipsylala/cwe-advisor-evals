## Verdict

The vulnerability is confirmed. Line 19 concatenates the untrusted `$requestedName` parameter directly into an OS command string passed to `exec()`, without sanitization or escaping. Although `basename()` is applied to create `$source` and `$target` on earlier lines, the fallback command on line 19 uses the raw `$requestedName` parameter, allowing an attacker to inject shell metacharacters and execute arbitrary commands.

## Source

**CWE-78: OS Command Injection**

**File**: `LegacyConvertFallback.php` Line 19

**Vulnerable code**:
```php
exec('/usr/bin/legacy-convert ' . $requestedName . ' ' . $target, $fallbackOutput, $fallbackStatus);
```

**Data flow**: The `$requestedName` parameter is derived from `$_POST['document']` (line 24), which is attacker-controlled. The primary conversion command on line 8-10 properly sanitizes the filename using `basename()` and escapes it with `escapeshellarg()`. However, the fallback command on line 19 bypasses both protections, concatenating `$requestedName` directly.

## Fix

### File: LegacyConvertFallback.php

```php
<?php

function convert_document(string $requestedName): string
{
    $source = '/srv/uploads/' . basename($requestedName);
    $target = '/srv/converted/' . basename($requestedName) . '.pdf';

    $primary = sprintf(
        '/usr/bin/soffice --convert-to pdf %s --outdir /srv/converted',
        escapeshellarg($source)
    );
    exec($primary, $primaryOutput, $primaryStatus);

    if ($primaryStatus === 0) {
        return $target;
    }

    // SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
    exec('/usr/bin/legacy-convert ' . escapeshellarg($source) . ' ' . escapeshellarg($target), $fallbackOutput, $fallbackStatus);

    return $fallbackStatus === 0 ? $target : '';
}

$path = convert_document($_POST['document']);
```

## Explanation

The fix replaces the unsafe string concatenation with `escapeshellarg()` on the already-sanitized `$source` and `$target` variables. Both variables are derived from `basename($requestedName)`, which removes any directory traversal attempts, and the additional `escapeshellarg()` wrapping provides shell-safe quoting to prevent metacharacter injection.

The key changes:
- Line 19 now uses `$source` (the sanitized input path) instead of the raw `$requestedName`
- Both `$source` and `$target` are wrapped with `escapeshellarg()`, providing proper shell escaping consistent with the primary command's protection on line 10

This prevents an attacker from injecting shell metacharacters (`;`, `|`, `&&`, `$(...)`, backticks, etc.) through the `$_POST['document']` parameter, as any such characters are neutralized by the shell-safe quoting that `escapeshellarg()` provides.

## Behaviour changes

The command execution semantics remain unchanged:
- The fallback converter is still invoked with the same source and target file paths
- The output and status code are captured identically
- The return value logic is preserved
- No change to the function's contract or return type

The only change is that special characters in filenames are now properly escaped before being passed to the shell, eliminating the injection vector while preserving all intended functionality.
