## Verdict

The vulnerability is real and exploitable. Line 19 concatenates `$requestedName` directly into a shell command string passed to `exec()`, allowing OS command injection. An attacker controlling `$_POST['document']` can inject arbitrary shell commands by including metacharacters like `; rm -rf /` or backticks in the input.

## Source

Untrusted input enters via `$_POST['document']` (line 24) and is passed to `convert_document()` as parameter `$requestedName` (line 3). Although line 5 applies `basename()` to create `$source`, this result is not reassigned to `$requestedName`. The original untainted parameter value flows directly into the vulnerable `exec()` call on line 19.

Data flow: `$_POST['document']` → `$requestedName` → line 19 string concatenation → `exec()` (taint sink)

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

    // Use proc_open with argument array to pass arguments without shell interpretation
    $fallbackProc = proc_open(
        ['/usr/bin/legacy-convert', '--', $requestedName, $target],
        [0 => ['inherit'], 1 => ['inherit'], 2 => ['inherit']],
        $pipes
    );

    if ($fallbackProc === false) {
        return '';
    }

    $fallbackStatus = proc_close($fallbackProc);

    return $fallbackStatus === 0 ? $target : '';
}

$path = convert_document($_POST['document']);
```

## Explanation

The original code passed user input through string concatenation into `exec()`, invoking the shell to parse and execute the constructed command. Any shell metacharacters in `$requestedName` (e.g., `;`, `|`, `$()`, backticks) would be interpreted as shell syntax rather than literal argument characters.

The fix replaces `exec()` with `proc_open()` using an argument array. This bypasses the shell entirely—each element in the array becomes a separate argument passed directly to the program via the OS, not through shell parsing. Shell metacharacters lose their special meaning and are treated as literal characters.

The `--` literal before `$requestedName` prevents argument injection (CWE-88): if the filename starts with `-`, it cannot be interpreted as an option flag by the target program, because `--` signals the end of option processing.

Exit code handling and output disposition remain identical to the original.

## Behaviour changes

- Process execution now bypasses the shell; arguments are passed as array elements instead of through string concatenation in a single command string.
- Shell metacharacters and special characters in the filename are treated as literal characters, not shell syntax.
- The `--` argument is added before the user-controlled filename operand to prevent argument injection.
- Exit code and output handling are unchanged; legitimate invocations produce identical results.
- Filenames with spaces, quotes, or other shell metacharacters now work correctly instead of causing command injection or execution errors.
