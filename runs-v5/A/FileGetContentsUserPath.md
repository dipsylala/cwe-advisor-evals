## Verdict
Confirmed. `$_GET['file']` is concatenated directly into a filesystem path with no traversal check, so a value like `../../etc/passwd` (or an absolute path, which PHP's `.` concatenation still allows through as the tail of a `/`-joined string on some inputs, and via encoded `..%2f` sequences from the query string) lets `file_get_contents()` read any file the web server process can access, outside `/var/www/reports`.

## Source
`$_GET['file']` on line 9 (`$name`), read from the HTTP query string with no validation.

## Fix
```php
<?php

// Serves a document from the shared reports directory. The report name
// is expected to be a filename like "invoice-2024.pdf" under /var/www/reports.

function serve_report(): void
{
    $reportsDir = realpath('/var/www/reports');
    $name = $_GET['file'] ?? '';

    // Strip any directory components the client supplied, then require the
    // remaining name to look like a plain report filename.
    $safeName = basename($name);
    if ($safeName === '' || $safeName === '.' || $safeName === '..'
        || !preg_match('/^[A-Za-z0-9._-]+$/', $safeName)) {
        http_response_code(400);
        echo 'Invalid report name';
        return;
    }

    $path = $reportsDir . '/' . $safeName;

    // Re-resolve and confirm the final path is still inside the reports
    // directory (defense in depth against symlinks or basename edge cases).
    $resolvedPath = realpath($path);
    if ($resolvedPath === false || strncmp($resolvedPath, $reportsDir . DIRECTORY_SEPARATOR, strlen($reportsDir) + 1) !== 0) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $safeName . '"');

    $contents = file_get_contents($resolvedPath);

    if ($contents === false) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    echo $contents;
}

serve_report();
```

## Explanation
The original code builds the filesystem path by string concatenation (`$reportsDir . '/' . $name`) with no restriction on `$name`, so a request such as `?file=../../../../etc/passwd` walks out of `/var/www/reports` and `file_get_contents()` happily reads whatever the traversed path points to.

The fix applies two layers:

1. **Normalize and allowlist the filename.** `basename($name)` discards any directory separators the client sent, collapsing `../../etc/passwd` down to `passwd` before it can do anything. That alone closes the traversal, but `basename()` on its own only strips path components — it does not reject unusual bytes, so a `preg_match` allowlist (`[A-Za-z0-9._-]+`) is added to keep the name to characters a legitimate report filename would use and reject anything else (including a lone `.` or `..`, which `basename` can still return for malformed input).
2. **Verify containment with `realpath()`, not just build the string.** `realpath()` is called on both the base directory and the final candidate path, and the check confirms the resolved report path is a true descendant of the resolved reports directory (`strncmp` against `$reportsDir . DIRECTORY_SEPARATOR`, not a bare substring check, so `/var/www/reports-evil` can't pass by prefix match). This catches cases the allowlist alone wouldn't, such as a symlink inside the reports directory pointing elsewhere, and turns any resolution failure or escape into a 404 rather than exposing filesystem structure.

The read now happens against `$resolvedPath` (the value that was actually validated) rather than the originally constructed `$path`, so there's no window between the check and the use where the two could diverge.

As a secondary hardening note: the `Content-Disposition` header now echoes the sanitized `$safeName` instead of the raw `$name`, which also removes a header-injection avenue (CRLF or quote characters in the original filename) that existed alongside the traversal issue but is outside this finding's scope.
