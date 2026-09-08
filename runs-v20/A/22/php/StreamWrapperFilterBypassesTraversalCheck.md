## Verdict

Confirmed. The `..` denylist at line 24 is not the control that determines what `fopen()` at line 33 actually opens.

## Source

`$_GET['file']` in `serve_report()` (`StreamWrapperFilterBypassesTraversalCheck.php`, line 15) is fully attacker-controlled and flows unmodified into `fopen()` at line 33.

## Fix

### File: StreamWrapperFilterBypassesTraversalCheck.php

```php
<?php
/**
 * Report viewer endpoint.
 *
 * Streams a report file to the browser. Changes into the reports
 * directory before opening the requested file, on the assumption that
 * blocking '..' in the request is sufficient to keep every read
 * confined to that directory.
 */

$reportsDir = __DIR__ . '/reports';

function serve_report(string $reportsDir): void
{
    $file = $_GET['file'] ?? '';

    if ($file === '') {
        http_response_code(400);
        echo 'Missing file parameter';
        return;
    }

    // Reject anything that is not a bare filename: no directory
    // separators, no stream-wrapper scheme (e.g. "php://", "phar://"),
    // no absolute path, and no ".." component. basename() strips all of
    // that down to the last path segment, so requiring the value to be
    // unchanged after basename() rejects every one of those inputs
    // without needing a denylist of specific sequences.
    if ($file !== basename($file) || $file === '.' || $file === '..') {
        http_response_code(400);
        echo 'Invalid file parameter';
        return;
    }

    $reportsRealDir = realpath($reportsDir);
    if ($reportsRealDir === false) {
        http_response_code(500);
        echo 'Reports directory unavailable';
        return;
    }

    $fullPath = $reportsRealDir . DIRECTORY_SEPARATOR . $file;
    $realPath = realpath($fullPath);

    // Defense in depth: confirm the resolved path (after symlinks, etc.)
    // still lives inside the reports directory before opening it.
    if ($realPath === false || !str_starts_with($realPath, $reportsRealDir . DIRECTORY_SEPARATOR)) {
        http_response_code(404);
        echo 'File not found';
        return;
    }

    $handle = fopen($realPath, 'r');
    if ($handle === false) {
        http_response_code(404);
        echo 'File not found';
        return;
    }

    header('Content-Type: application/octet-stream');
    fpassthru($handle);
    fclose($handle);
}

serve_report($reportsDir);
```

## Explanation

The original code treats `str_contains($file, '..')` as the access-control decision, then calls `chdir($reportsDir)` and hands the raw, unvalidated `$file` to `fopen()`. Neither step actually restricts `fopen()` to the reports directory:

- `chdir()` only changes the *relative* resolution base. `fopen()` still honors any PHP stream wrapper scheme or absolute path the value contains, all of which ignore the current working directory entirely - `php://filter/resource=/etc/passwd`, `phar://...`, or a plain absolute path like `/etc/passwd` reach arbitrary files without ever containing the substring `..`.
- The denylist only ever checks for `..`; it has no notion of what "inside the reports directory" means, so any input that reaches outside without that specific substring sails through.

The fix replaces the substring denylist with a structural check: `basename($file) === $file` forces the value to be a single path segment with no separators, no `scheme://` prefix, and no `..` component, which eliminates the stream-wrapper and absolute-path bypasses at the source rather than trying to enumerate their syntaxes. `chdir()` is removed since it provided no real containment and only obscured that `fopen()` was the unguarded sink. As defense in depth, the code then builds the full path under the reports directory and calls `realpath()` on both the directory and the candidate file, opening the file only if the resolved real path is still prefixed by the reports directory's real path - this also closes off any symlink planted inside the reports directory that points elsewhere.
