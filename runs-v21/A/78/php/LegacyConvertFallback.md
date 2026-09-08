## Verdict

The vulnerability is confirmed. Line 19 passes user-controlled input (`$requestedName`) directly into a shell command without escaping, enabling OS command injection.

## Source

Line 19 executes a shell command with unescaped user input:

```php
exec('/usr/bin/legacy-convert ' . $requestedName . ' ' . $target, $fallbackOutput, $fallbackStatus);
```

The `$requestedName` parameter originates from `$_POST['document']` (line 24), which is attacker-controlled. Although the primary conversion path (lines 8-12) correctly sanitizes this input using `basename()` and `escapeshellarg()`, the fallback path concatenates it directly into the command string without escaping.

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

The fix applies `escapeshellarg()` to both `$source` and `$target` on line 19, matching the defensive pattern already established in the primary path. Since `$source` and `$target` are already computed using `basename()` to prevent directory traversal, this escaping closes the command injection vector.

`escapeshellarg()` wraps each argument in single quotes and escapes any embedded single quotes, ensuring the shell treats the value as a single, literal argument rather than as command syntax. This prevents an attacker-controlled value from injecting additional commands or options.
