## Verdict

Exploitable (confidence: high). `$requestedName` is attacker-controlled and reaches `exec()` as raw, unescaped shell-string concatenation with no validation or quoting anywhere on the path.

## Source

`$_POST['document']` (module scope) is passed straight into `convert_document(string $requestedName)`. Inside that function `$requestedName` is used unmodified (no `basename()`, no `escapeshellarg()`) in the fallback branch:

```
exec('/usr/bin/legacy-convert ' . $requestedName . ' ' . $target, $fallbackOutput, $fallbackStatus);
```

That `exec()` call is the sink (line 19). Note the primary conversion attempt a few lines above it already wraps the equivalent value in `escapeshellarg($source)` — the fallback path was never brought up to the same standard.

## Fix

Vulnerable code:

```php
// SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
exec('/usr/bin/legacy-convert ' . $requestedName . ' ' . $target, $fallbackOutput, $fallbackStatus);
```

Fixed code:

```php
// Reject values that could be read as a flag by legacy-convert (argument injection, CWE-88).
if (substr($requestedName, 0, 1) === '-') {
    return '';
}

$descriptorSpec = [
    1 => ['pipe', 'w'], // stdout
    2 => ['pipe', 'w'], // stderr
];

$process = proc_open(
    ['/usr/bin/legacy-convert', $requestedName, $target],
    $descriptorSpec,
    $pipes
);

if (!is_resource($process)) {
    return '';
}

$stdout = stream_get_contents($pipes[1]);
fclose($pipes[1]);
fclose($pipes[2]); // stderr is drained but not surfaced, matching the original's uncaptured stderr
$fallbackStatus = proc_close($process);
$fallbackOutput = $stdout === '' ? [] : preg_split('/\r\n|\r|\n/', rtrim($stdout, "\n"));
```

No third-party library is required — `proc_open()` is a PHP built-in, available since PHP 4, and the array-form command (no shell) has been supported since PHP 7.4.

## Explanation

The vulnerable line builds `/usr/bin/legacy-convert <name> <target>` as a single string and hands it to `exec()`, which runs it through the system shell; any shell metacharacter in `$requestedName` (`;`, `|`, `` ` ``, `$()`, etc.) lets an attacker run arbitrary commands. The fix replaces the string-built `exec()` call with `proc_open()` given an argument array (`['/usr/bin/legacy-convert', $requestedName, $target]`). With the array form PHP invokes the binary directly via `execve`-style dispatch rather than through `/bin/sh -c`, so shell metacharacters in `$requestedName` are passed through as inert, literal argument bytes instead of being interpreted — the injection point is closed structurally rather than by escaping. Because an argument array closes shell-metacharacter injection but not argument/flag injection, a leading `-` in `$requestedName` is rejected before the call, per the PHP guidance's Key Principles. The rest of the function (source/target path construction, the primary `escapeshellarg()`-guarded attempt, and the `$fallbackStatus === 0 ? $target : ''` return contract) is unchanged.

## Behaviour changes

- Requests where `$requestedName` starts with `-` now return `''` (treated as a failed conversion) instead of being passed to the shell. This is new input validation required to close the argument-injection gap the array form leaves open; previously such a value would have gone straight to the shell.
- `$fallbackOutput` is now built by splitting captured stdout on newlines rather than being populated by `exec()`'s own line-splitting; content and count of lines matches wall-for-wall (`exec()` also only captures stdout unless the caller redirects, and the original command performed no redirect).
- The child process's stderr is now explicitly captured via a pipe and discarded (drained via `fclose()` before `proc_close()`) rather than left to inherit the PHP process's own stderr. This is required to avoid the child blocking on a full stderr pipe; it does not add any output the caller can observe (`$fallbackOutput`/`$fallbackStatus` are unchanged in shape), so no information is surfaced that the original discarded.
- `$fallbackStatus` still comes from `proc_close()`, the array-form analogue of `exec()`'s third by-reference parameter, and the function's return value (`$target` on success, `''` otherwise) is unchanged.
- Not fixed here (out of scope for this CWE-78 finding, and would change file-resolution behaviour): the fallback passes raw `$requestedName` as the source-file argument to `legacy-convert`, rather than the same `basename()`-scoped `$source` path the primary `soffice` attempt uses. That is a separate path-handling inconsistency (CWE-22 territory), not a command-injection issue, and is flagged for the developer rather than altered.
