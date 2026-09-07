## Verdict

Exploitable. The untrusted `$requestedName` parameter is directly concatenated into a shell command at line 19 without using `escapeshellarg()`, allowing an attacker to inject arbitrary shell commands.

## Source

`$requestedName` parameter (line 3), sourced from `$_POST['document']` at line 24, which is attacker-controlled.

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

The fix applies `escapeshellarg()` to both command arguments on line 19, matching the pattern already established in the primary conversion at line 10. `escapeshellarg()` properly quotes the arguments to prevent shell metacharacter injection. Additionally, the fix substitutes the original `$requestedName` with `$source`, which has already been passed through `basename()` on line 5—this provides defense-in-depth against directory traversal while ensuring consistency with the primary code path. The `escapeshellarg()` function quotes values when needed, ensuring that characters like `;`, `|`, `&`, `$()`, and backticks cannot break out of the argument and inject commands.

## Behaviour changes

None. The `exec()` function receives properly quoted arguments instead of raw concatenation. The command still receives the same intended arguments (the source and target file paths), but shell special characters in those paths are now neutralized. The return value and error handling remain unchanged.
