## Verdict

Confirmed OS Command Injection.

## Source

Line 19: `exec('/usr/bin/legacy-convert ' . $requestedName . ' ' . $target, $fallbackOutput, $fallbackStatus);`

The `$requestedName` parameter is concatenated directly into the shell command without escaping. An attacker controlling `$_POST['document']` can inject shell metacharacters (e.g., `; rm -rf /;`) to execute arbitrary commands.

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
    exec('/usr/bin/legacy-convert ' . escapeshellarg($requestedName) . ' ' . escapeshellarg($target), $fallbackOutput, $fallbackStatus);

    return $fallbackStatus === 0 ? $target : '';
}

$path = convert_document($_POST['document']);
```

## Explanation

The primary command (lines 8–12) correctly escapes the `$source` argument using `escapeshellarg()`, which wraps the value in single quotes and escapes any embedded quotes, preventing shell interpretation of metacharacters.

The fallback command on line 19 failed to apply the same protection to `$requestedName` and `$target`. The fix applies `escapeshellarg()` to both arguments before passing them to `exec()`. This ensures both values are treated as literal string operands to the `/usr/bin/legacy-convert` program, blocking command injection regardless of the input content.
