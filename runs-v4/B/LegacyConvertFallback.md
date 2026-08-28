# CWE-78 (OS Command Injection) - LegacyConvertFallback.php

- **CWE:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
- **Location:** `evals/cases/78/php/LegacyConvertFallback/LegacyConvertFallback.php`, line 19 (sink)
- **Confidence:** high

## Verdict

`exploitable`.

The fallback branch builds a shell command string by concatenating an unsanitised request parameter, and passes it to `exec()`, which runs it through `/bin/sh`. Every shell metacharacter in the value is live: a request with `document=x; id > /srv/converted/out` (or backticks, `$(...)`, `&&`, `|`) executes arbitrary commands under the web server's account.

Reaching the sink requires the primary `soffice` conversion to fail, which the same attacker controls - `$source` is `/srv/uploads/` plus `basename($requestedName)`, so any name that does not correspond to an existing, convertible upload makes `soffice` exit non-zero and drops execution straight into the fallback. The guarded branch is not a barrier; it is the normal path for a crafted request.

## Source

- **Source:** `$_POST['document']` (line 24), attacker-controlled HTTP request body.
- **Propagation:** passed as the `$requestedName` parameter of `convert_document()` (line 3). Two derived values are computed from it - `$source` (line 5) and `$target` (line 6) - both of which pass it through `basename()`. `$requestedName` itself is never sanitised.
- **Sink:** `exec('/usr/bin/legacy-convert ' . $requestedName . ' ' . $target, $fallbackOutput, $fallbackStatus)` (line 19). `exec()` invokes a shell, so the concatenated string is parsed for metacharacters before the program is started.
- **Why the primary call is not the finding:** line 12 executes a string built by `sprintf` where the only interpolated value is `escapeshellarg($source)` - quoted, and derived from `basename()`. The raw parameter reaches a shell only on line 19.

Sink contract that the fix has to preserve:

- **Returns:** `exec()`'s return value (the last line of stdout) is discarded at the call site; nothing depends on it.
- **Discards:** the child's stdout is captured into `$fallbackOutput`, which is never read. Nothing is echoed to the response. stderr is not redirected, so it is inherited by the PHP process and goes wherever the parent's stderr goes.
- **Arguments left implicit:** none on the `exec()` call itself; both operands are supplied positionally to `legacy-convert`.
- **Failure behaviour:** `$fallbackStatus` holds the child's exit status. The function returns `$target` when it is `0` and `''` otherwise. A failure to launch the program at all must therefore end up non-zero so the caller still sees `''`.

## Fix

### Library recommendation

None required. The fix uses `proc_open()` from PHP core with an argument array, which needs **PHP 7.4 or later** (the array form of the command was added in 7.4; on earlier versions `proc_open()` accepts only a string and re-introduces the shell).

Where Composer is already in use, `Symfony\Component\Process\Process` constructed with an array of arguments is the better long-term choice - it builds the argument vector itself and only reaches a shell through the explicit `Process::fromShellCommandline()` factory. Take its version from advisory or SCA data rather than from a version named here; either way, confirm the resolved version with dependency-check tooling before merging.

One version note that does *not* apply to this code but is worth recording if the service is ever run on Windows: PHP's argument-array handling for `proc_open()` was fixed for `.bat`/`.cmd` targets in 8.1.28 / 8.2.18 / 8.3.6 (CVE-2024-1874), and a trailing-space bypass of that fix was closed in 8.1.29 / 8.2.20 / 8.3.8 (CVE-2024-5585), so the operative floor on Windows is 8.1.29 / 8.2.20 / 8.3.8. This code invokes an absolute POSIX path (`/usr/bin/legacy-convert`), not a batch file, so the issue is out of scope here.

### Vulnerable code

```php
    // SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
    exec('/usr/bin/legacy-convert ' . $requestedName . ' ' . $target, $fallbackOutput, $fallbackStatus);

    return $fallbackStatus === 0 ? $target : '';
```

`exec()` runs its argument through `/bin/sh`, and `$requestedName` is the raw request value - it never passed through `basename()` the way `$source` and `$target` did.

### Fixed code

Full file:

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

    $fallbackOutput = [];
    $fallbackStatus = 1;

    $fallback = proc_open(
        ['/usr/bin/legacy-convert', $source, $target],
        [1 => ['pipe', 'w']],
        $pipes
    );

    if (is_resource($fallback)) {
        $stdout = rtrim(stream_get_contents($pipes[1]), "\n");
        fclose($pipes[1]);
        $fallbackOutput = $stdout === '' ? [] : explode("\n", $stdout);
        $fallbackStatus = proc_close($fallback);
    }

    return $fallbackStatus === 0 ? $target : '';
}

$path = convert_document($_POST['document']);
```

## Explanation

The concatenated command string is replaced by `proc_open()` with an argument array, so the program is started directly with `/usr/bin/legacy-convert`, the source path and the target path as three separate, already-split arguments. No shell is spawned, which means `;`, `|`, `&&`, backticks, `$(...)`, newlines and quoting in the request value are no longer parsed as syntax - they are ordinary bytes inside a single filename argument, and the worst outcome of a hostile value is that the converter reports a missing file. The second change is which value reaches the sink: the fallback now passes `$source`, the canonical path the function already derived on line 5 via `basename()`, instead of the raw parameter. That matters because an argument array stops shell injection but not argument injection - a raw value beginning with `-` would still be read by the target program as an option, and a value containing `../` would still be read as a path outside the upload directory. `$source` is anchored to the literal prefix `/srv/uploads/` and stripped of directory components, so neither is reachable, and the fallback now converts the same file the primary command was asked to convert. Around that, the sink's contract is kept intact: stdout is still captured into `$fallbackOutput` and still never surfaced to the response, stderr is still inherited rather than redirected, and `$fallbackStatus` still drives the `$target`-or-empty-string return.

## Behaviour changes

- **The fallback's first operand changes from `$requestedName` to `$source`.** Required by the fix, not incidental to it: passing the raw tainted value as a single argument would close shell injection while leaving argument injection (a leading `-` read as a flag) and path traversal (`../`) open. `$source` is the canonical value the function already computes for the same file, so the fallback and the primary conversion now operate on the same input path. If `legacy-convert` had been relying on resolving a bare relative name against the process working directory rather than against `/srv/uploads/`, this changes which file it opens - that is the intended correction, since the previous behaviour let the caller name any path on the filesystem.
- **`$fallbackStatus` is initialised to `1` before the call.** `proc_open()` returns `false` when the program cannot be launched, where `exec()` would have set the status itself. The explicit `1` keeps the failure path identical - the function still returns `''` rather than an unset or stale status leaking through as success.
- **`$fallbackOutput` is populated by reading the stdout pipe instead of by `exec()`.** Same content, same variable, same non-use downstream. The `rtrim`/`explode` pair reproduces `exec()`'s line splitting and its dropping of the single trailing newline. The pipe is read and closed before `proc_close()` so the child cannot block on a full pipe buffer; only stdout is redirected, so stderr is inherited exactly as before.
- **`exec()`'s return value is no longer available.** The original discarded it, so nothing is lost.
- **No output is added to the response.** The captured stdout stays captured, so the fix does not trade the injection for an information leak.
- **Not changed:** the primary `soffice` invocation on lines 8-12 is untouched. It is outside the reported finding and its only interpolated value is already quoted with `escapeshellarg()` over a `basename()`-derived path. Worth flagging separately for a future pass, since `escapeshellarg()` is a secondary defence with platform-dependent quoting rather than a primary one, and the same `proc_open()` argument-array treatment would remove the shell there too.

### Assumptions

- `/usr/bin/legacy-convert` takes exactly two positional operands, source then target, matching the original argument order. Nothing in the case contradicts this, and the argument array preserves that order and count.
- The service runs on POSIX (absolute `/usr/bin` and `/srv` paths). The Windows batch-file caveat in the library recommendation is recorded only in case that assumption changes.
- No `--` end-of-options separator is inserted, because it is not known whether `legacy-convert` supports it and it is not needed: both operands are absolute paths beginning with `/`, so neither can be mistaken for an option.
