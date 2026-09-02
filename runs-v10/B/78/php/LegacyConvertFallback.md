## Verdict

Exploitable. The `$requestedName` parameter from `$_POST['document']` is concatenated directly into an `exec()` command string without escaping on line 19, allowing arbitrary OS command injection.

## Source

`$_POST['document']` (line 24) → `$requestedName` parameter (line 3)

## Fix

**Vulnerable Code:**
```php
exec('/usr/bin/legacy-convert ' . $requestedName . ' ' . $target, $fallbackOutput, $fallbackStatus);
```

**Fixed Code:**
```php
// Validate to prevent argument injection (CWE-88)
if (!empty($requestedName) && $requestedName[0] === '-') {
    return '';
}

// Safe execution with argument array prevents shell injection
$process = proc_open(
    ['/usr/bin/legacy-convert', $requestedName, $target],
    [0 => STDIN, 1 => STDOUT, 2 => STDERR],
    $pipes,
    null,
    null,
    ['bypass_shell' => true]
);

if ($process === false) {
    return '';
}

$fallbackStatus = proc_close($process);
```

## Explanation

The fix replaces `exec()` with `proc_open()` using an argument array (PHP 7.4+), which passes command arguments separately from the program name rather than assembling them into a shell command string. This eliminates shell metacharacter injection entirely by bypassing the shell interpreter. The `bypass_shell` option explicitly disables shell invocation. Input validation rejects arguments starting with `-` to prevent argument injection attacks (CWE-88), where a malicious value could be interpreted as a flag by the target program. The fix preserves the original sink contract: it obtains and returns the exit status in the same way.

## Behaviour changes

- **Arguments now passed separately**: Command arguments are provided as array elements rather than concatenated into a string, preventing shell interpretation of metacharacters in `$requestedName` and `$target`.
- **Error handling**: `proc_open()` returns `false` on failure instead of silently failing. The fix explicitly checks for this and returns an empty string on process creation failure. Original `exec()` did not distinguish creation failure from command execution failure.
- **Standard I/O handling**: Output and error streams are now mapped to process-level STDOUT/STDERR rather than captured into `$fallbackOutput`. The captured output from the original command is discarded, so this change preserves that behavior (no information disclosure).
- **Platform safety**: The `bypass_shell` option ensures the shell is not invoked on Windows, preventing `cmd.exe` reparse of batch file wrappers (relevant if `/usr/bin/legacy-convert` is a batch file or similar shell script).
