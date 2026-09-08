## Verdict

Confirmed. Line 19 builds a shell command by concatenating `$requestedName` - which flows unmodified from `$_POST['document']` - directly into the string passed to `exec()`. An attacker can supply a value such as `foo.docx; rm -rf / #` or use backticks/`$()` to run arbitrary commands with the privileges of the web server process.

## Source

`$_POST['document']` on line 24 is passed as `$requestedName` into `convert_document()`. Inside the function it reaches the fallback sink on line 19 with no shell-safe escaping applied to it (unlike the primary command on lines 8-11, which does escape the derived `$source` path).

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

The fallback command is rebuilt from `$source` and `$target` - the same basename-sanitized path values the primary `soffice` command already uses - instead of the raw `$requestedName`. Both values are wrapped in `escapeshellarg()` before concatenation, which quotes each argument for the shell and neutralizes metacharacters (`;`, `|`, `` ` ``, `$()`, whitespace, etc.), matching the pattern already used for the primary conversion path. `basename()` also removes any directory-traversal segments, so the value can no longer escape `/srv/uploads/` or `/srv/converted/`.

`escapeshellarg()` is preferred over stripping or allowlisting characters here because the value is a filename with an open format (arbitrary uploaded document names) rather than a field with an application-defined structure - rejecting or mangling characters would break legitimate filenames, while shell-argument quoting closes the injection without changing what filenames are accepted.

Verification: exercise `convert_document()` with a name such as `report.docx; touch /tmp/pwned` and confirm no `/tmp/pwned` file is created and the fallback `exec()` call receives the payload as a single literal filename argument (visible via the `$fallbackOutput`/exit status reflecting a "file not found" style failure from `legacy-convert`, not a successful injected command).
