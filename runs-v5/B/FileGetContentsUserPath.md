## Verdict

exploitable (confidence: high)

CWE-22 - Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal').

## Source

`$_GET['file']` (line 9, assigned to `$name`) - fully attacker-controlled, no validation or encoding applied before use.

## Fix

Vulnerable code:

```php
function serve_report(): void
{
    $reportsDir = '/var/www/reports';
    $name = $_GET['file'];

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $name . '"');

    $path = $reportsDir . '/' . $name;

    // SAST FINDING: CWE-22 reported here. Sink is the next statement.
    $contents = file_get_contents($path);

    if ($contents === false) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    echo $contents;
}
```

Fixed code:

```php
function serve_report(): void
{
    $reportsDir = realpath('/var/www/reports');
    $name = $_GET['file'];

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $name . '"');

    $path = $reportsDir . DIRECTORY_SEPARATOR . $name;
    $realPath = realpath($path);

    if ($realPath === false
        || !($realPath === $reportsDir || str_starts_with($realPath, $reportsDir . DIRECTORY_SEPARATOR))
    ) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    $contents = file_get_contents($realPath);

    if ($contents === false) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    echo $contents;
}
```

## Explanation

`$name` reached `file_get_contents()` after only string concatenation with the base directory, so a value like `../../etc/passwd` (or an absolute path, which PHP concatenates literally) resolved outside `/var/www/reports` and was read and returned unmodified. The fix canonicalizes both the known-good root and the requested path with `realpath()`, which collapses `.`/`..` segments and symlinks to an absolute form, and then checks that the resolved candidate is exactly the root or a path component of it (`str_starts_with($realPath, $reportsDir . DIRECTORY_SEPARATOR)`, not a bare prefix match, so a sibling directory such as `/var/www/reports-internal` is not accepted). `realpath()` returns `false` when any path component does not exist, when a component is unreadable, or on an `open_basedir` violation, so that outcome is treated the same as "not found" rather than falling back to the unvalidated string. Only the canonical, contained path (`$realPath`) is passed to `file_get_contents()`, so the value that was checked is the value that is opened. An indirect-reference (ID-to-path map) fix was not used because the source shows the endpoint serving arbitrary report filenames rather than a fixed, enumerable set - canonicalize-then-contain is the applicable pattern from the loaded PHP guidance.

## Behaviour changes

- A request whose resolved path lands outside `/var/www/reports` (traversal sequences, an absolute path, or a symlink escaping the root) now returns HTTP 404 with body `Report not found` instead of returning the contents of the out-of-root file. This is the intended effect of the fix.
- A request for a name that does not exist under the root now also fails via the containment check's `realpath() === false` branch rather than via `file_get_contents()`'s own `false` return; the observable result (404, same body) is unchanged.
- `Content-Disposition`'s `filename` still echoes the raw, unvalidated `$name` value (unchanged from the original). That header is not a filesystem sink and is out of scope for this CWE-22 fix; it may still warrant separate review for response-header injection.
- No other arguments, return values, or output were altered.
