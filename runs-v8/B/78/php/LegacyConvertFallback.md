## Verdict

Confirmed. The raw `$requestedName` parameter is concatenated directly into an `exec()` command string without escaping, allowing OS command injection via shell metacharacters.

## Source

User input flows from `$_POST['document']` → `convert_document($requestedName)` parameter (line 24, 3) → directly into the `exec()` sink on line 19 without escaping.

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

    // Use proc_open with argument array to avoid shell interpretation
    $descriptorspec = [
        1 => ['pipe', 'w'],  // stdout
        2 => ['pipe', 'w'],  // stderr
    ];
    
    $process = proc_open(
        ['/usr/bin/legacy-convert', $requestedName, $target],
        $descriptorspec,
        $pipes
    );
    
    if (is_resource($process)) {
        fclose($pipes[1]);
        fclose($pipes[2]);
        $fallbackStatus = proc_close($process);
    } else {
        $fallbackStatus = 1;
    }

    return $fallbackStatus === 0 ? $target : '';
}

$path = convert_document($_POST['document']);
```

## Explanation

The fix replaces the unsafe `exec()` call with `proc_open()` using an argument array. When `proc_open()` receives the command as an array rather than a string, PHP invokes the executable directly without spawning a shell, preventing shell metacharacter injection. The `$requestedName` parameter is passed as a separate array element and interpreted as a single argument to the program, not as part of a command string. This approach leverages the underlying system call that separates the executable path from its arguments at the process-spawn level, eliminating the attack surface entirely.

## Behaviour changes

- Exit status code flow remains unchanged: `$fallbackStatus` captures the process exit code
- Program output is not captured (the original `$fallbackOutput` was also unused)
- Process execution now bypasses shell interpretation on all platforms
- On PHP versions below 7.4, the array form of `proc_open()` is not available; older versions must use `escapeshellarg()` as a secondary defence (less safe but compatible)
