## Verdict

exploitable

- **cwe_id**: CWE-78 (OS Command Injection)
- **location**: `LegacyConvertFallback.php`, line 19 (sink); source at line 24
- **confidence**: high

## Source

`$_POST['document']` (line 24) is passed unvalidated into `convert_document()` as `$requestedName`. The primary conversion path (lines 8-12) correctly builds `$source` with `basename($requestedName)` and wraps it in `escapeshellarg()` before handing it to `exec()`. When that primary attempt fails (`$primaryStatus !== 0`), the fallback at line 19 builds its command by directly string-concatenating the raw `$requestedName` (never passed through `basename()` or any escaping function) plus `$target` into a shell command string passed to `exec()`. Both `escapeshellarg()` and `basename()` are absent from this concatenation, so shell metacharacters in `$requestedName` (e.g. `;`, `` ` ``, `|`, `$( )`) reach `/bin/sh` and execute as separate commands. This is a direct, unbroken taint path from an HTTP POST field to a shell-interpreted `exec()` call.

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

    $fallback = sprintf(
        '/usr/bin/legacy-convert %s %s',
        escapeshellarg($requestedName),
        escapeshellarg($target)
    );
    exec($fallback, $fallbackOutput, $fallbackStatus);

    return $fallbackStatus === 0 ? $target : '';
}

$path = convert_document($_POST['document']);
```

## Explanation

Running `/usr/bin/legacy-convert` is the purpose of this fallback path, not an incidental wrapper around something PHP can do natively, so the remediation keeps the `exec()` call and makes its command construction safe rather than removing it. The fix mirrors the pattern already used for the primary `soffice` command two statements above: the command string is built with `sprintf()` and each variable component is passed through `escapeshellarg()` before insertion, so `$requestedName` and `$target` are each delivered to the shell as one literal, quoted argument instead of being concatenated raw into the command line. This closes the injection because shell metacharacters in either value (`;`, `` ` ``, `|`, `$()`, whitespace) can no longer terminate the intended argument or introduce a new command - `escapeshellarg()` quotes the entire value and escapes any embedded quote characters for the target shell. `$target` is included in the escaping as well because, although it is prefixed with a fixed directory, it still embeds `basename($requestedName)` and so can carry attacker-influenced characters other than path separators.

## Behaviour changes

none - `$requestedName` and `$target` are passed to `legacy-convert` as the identical string values the original code used (the raw `$requestedName`, unchanged from the vulnerable version, rather than the `basename()`-normalized `$source` used by the primary command); they are now shell-quoted as single arguments rather than concatenated unescaped. `$fallbackOutput` and `$fallbackStatus` are populated by `exec()` exactly as before, the success/failure branching on `$fallbackStatus === 0` is unchanged, and no previously-discarded command output is now returned or logged.

**Assumptions**: The finding is scoped to CWE-78 (shell metacharacter injection via unescaped string concatenation), which this fix closes. A related but distinct weakness, CWE-88 (argument injection) - `legacy-convert` could still interpret a `$requestedName` beginning with `-` as a flag rather than a filename - is not addressed here: whether `legacy-convert` honors a `--` end-of-options marker is unknown for this legacy, unspecified binary, and inserting one without confirming support could break the tool's argument parsing instead of hardening it. This residual risk should be checked against `legacy-convert`'s actual CLI parsing before considering the finding fully closed against argument-level abuse.

**Verification**: `php -l` (PHP 8.5.8 CLI) against the fixed file in isolation reported "No syntax errors detected". The `escapeshellarg()`/`sprintf()` pattern is not a new API introduced by this fix - it is the exact pattern already present and working in this file's primary-command construction (lines 8-11 of the original), reused verbatim for the fallback command, so no unverified names were introduced. Manually traced: `escapeshellarg()` quotes each argument such that shell metacharacters in a sample payload (`file.txt; rm -rf / #`) are rendered as an inert quoted string rather than being interpreted by the shell.
