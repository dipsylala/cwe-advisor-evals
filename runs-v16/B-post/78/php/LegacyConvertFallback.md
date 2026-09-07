## Verdict

**EXPLOITABLE**

Line 19 directly concatenates user-controlled input into an OS command without escaping, allowing command injection. The source (`$_POST['document']`) flows through the `$requestedName` parameter to the exec() sink on line 19. While `basename()` prevents path traversal, it does not neutralize shell metacharacters (`;`, `|`, `&`, `$()`, backticks, etc.) that enable arbitrary command execution.

## Source

Entry point: `$_POST['document']` (line 24)
- Passed to function parameter `$requestedName` (line 3)
- Used directly in line 19 without escaping

## Fix

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

    // Escape both variables to prevent shell injection
    exec('/usr/bin/legacy-convert ' . escapeshellarg($requestedName) . ' ' . escapeshellarg($target), $fallbackOutput, $fallbackStatus);

    return $fallbackStatus === 0 ? $target : '';
}

$path = convert_document($_POST['document']);
```

## Explanation

The fallback command on line 19 must apply `escapeshellarg()` to both `$requestedName` and `$target` before concatenation into the command string. This matches the pattern already correctly applied to the primary command on line 10.

`escapeshellarg()` quotes the argument and escapes internal quotes, ensuring the entire value is treated as a single argument by the shell. Without it, shell metacharacters in the input (e.g., `; rm -rf /`, `| cat /etc/passwd`) reach the shell interpreter and execute as commands.

The primary command already uses this pattern correctly; the fallback must do the same. Command execution is essential here (conversion feature), so the fix is to execute safely, not to eliminate execution.

## Behaviour changes

None. The command executes identically, with the same output capture and return value semantics. The only change is that shell metacharacters in the input are now neutralized instead of interpreted.
