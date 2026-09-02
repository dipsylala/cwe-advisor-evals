## Verdict

exploitable (confidence: high)

CWE-22 - Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal').

## Source

`$_GET['file']` (line 9, assigned to `$name`) - an attacker-controlled HTTP query parameter with no validation, encoding checks, or containment applied before it reaches the sink.

Data flow: `$name = $_GET['file']` -> `$path = $reportsDir . '/' . $name` (line 14, raw string concatenation) -> `file_get_contents($path)` (line 17, the reported sink). A request such as `?file=../../../../etc/passwd` (or an absolute-path/symlink variant) resolves outside `/var/www/reports` and is read and echoed back to the client unchanged.

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

    $candidate = $reportsDir . '/' . $name;
    $path = realpath($candidate);

    $isContained = $path !== false
        && ($path === $reportsDir || str_starts_with($path, $reportsDir . DIRECTORY_SEPARATOR));

    if (!$isContained) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    $contents = file_get_contents($path);

    if ($contents === false) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    echo $contents;
}
```

## Explanation

The fix canonicalizes the constructed path with `realpath()` and verifies containment before it is passed to `file_get_contents()`, following the PHP CWE-22 guidance's read-path pattern. `realpath()` resolves `.`, `..`, and symbolic links and returns `false` if any component cannot be resolved, so a traversal sequence, an absolute-path override, or a symlink escape either collapses to a path outside `$reportsDir` or fails to resolve at all - both cases are caught by the `false` check and the separator-terminated `str_starts_with()` comparison, which prevents a sibling directory such as `/var/www/reports_backup` from passing a bare prefix test. The base directory `$reportsDir` is itself canonicalized once at the top of the function so the comparison operates on two values in the same canonical form. The check and the read now operate on the same variable (`$path`, produced by `realpath()`), rather than validating one string and opening another, so there is no window for the checked and used values to diverge. Both the "could not resolve" and "resolved but outside the root" cases return the same generic 404, avoiding an oracle that would let an attacker distinguish "outside the tree" from "does not exist".

## Behaviour changes

- The `str_starts_with()` containment check requires PHP 8.0+; if the target runtime is older, replace it with an equivalent `substr()`/`strncmp()` comparison. This is an assumption made to resolve ambiguity about the deployment's PHP version (not stated in the finding); confidence on this specific point is medium.
- Requests whose resolved path falls outside `/var/www/reports` (traversal, absolute-path override, or a symlink pointing elsewhere) now return 404 "Report not found" instead of the file's contents. This is the intended effect of closing the weakness, not an incidental change.
- A request for a genuinely nonexistent file within `/var/www/reports` continues to return 404 "Report not found", same as before (previously via `file_get_contents() === false`; now via the `realpath()` containment check, since `realpath()` itself returns `false` for a nonexistent path). The externally observable result for this case is unchanged.
- The `Content-Disposition` header on line 12 still echoes the raw, unvalidated `$name` value. This is outside the scope of the reported CWE-22 finding (the sink here is `file_get_contents`, not the header) and was left unchanged; it is a separate header-injection/reflected-filename concern the reporting tool did not flag, and no change was made to it.
- No other arguments, return values, or output paths were altered.
