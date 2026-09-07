## Verdict

Exploitable

## Source

Line 24: User input from HTTP POST request: `$_POST['document']`

This untrusted value flows through the `convert_document()` function parameter `$requestedName` (line 3) to the vulnerable sink on line 19.

## Sink

Line 19: `exec('/usr/bin/legacy-convert ' . $requestedName . ' ' . $target, $fallbackOutput, $fallbackStatus)`

The `$requestedName` parameter is concatenated directly into the shell command string without escaping, allowing an attacker to inject shell metacharacters and execute arbitrary commands.

## Data Flow

1. Line 24: User input `$_POST['document']` (untrusted, attacker-controlled)
2. Line 3: Parameter `$requestedName` receives the untrusted value
3. Line 5: `basename($requestedName)` applied - prevents directory traversal but NOT shell injection
4. Line 19: `$requestedName` concatenated into shell command without escaping
5. The `exec()` function interprets the shell metacharacters and executes attacker-controlled code

**Why `basename()` is insufficient:** The `basename()` function extracts the filename component of a path; it does not neutralize shell metacharacters. An input like `document.pdf; rm -rf /` passes through `basename()` and when concatenated into the `exec()` command string, the shell interprets the semicolon as a command separator and executes the second command.

## Fix

Apply `escapeshellarg()` to properly escape both the source and target file paths before passing them to the shell command, following the same pattern already used in lines 8-12 for the primary conversion method. Also use `$source` instead of `$requestedName` for consistency and clarity.

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

    // FIXED: Use escapeshellarg on both arguments to prevent shell injection
    exec('/usr/bin/legacy-convert ' . escapeshellarg($source) . ' ' . escapeshellarg($target), $fallbackOutput, $fallbackStatus);

    return $fallbackStatus === 0 ? $target : '';
}

$path = convert_document($_POST['document']);
```

## Explanation

The vulnerability arose from concatenating `$requestedName` directly into the shell command on line 19, where the `basename()` function only prevents directory traversal but not shell metacharacter injection. The fix applies `escapeshellarg()` to both the source and target file paths before they are passed to `exec()`. The `escapeshellarg()` function adds single quotes around each argument and properly escapes any single quotes within it, preventing the shell from interpreting special characters or metacharacters as command syntax. This matches the secure pattern already used in the primary conversion method (lines 8-12), and uses `$source` instead of `$requestedName` for consistency since `$source` is the actual file path being operated on.

## Behaviour changes

None. The `escapeshellarg()` function returns a properly escaped and quoted string, which is then concatenated into the command. The shell receives arguments with quotes that protect their contents. The function still captures output in `$fallbackOutput` and status in `$fallbackStatus` identically. The return value and control flow remain unchanged.

Verification: `php -l` syntax check passed without errors.

