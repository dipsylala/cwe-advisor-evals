## Verdict
Confirmed. `$_GET['file']` reaches `file_get_contents()` after only string concatenation, with no filename validation or containment check, so a value such as `../../etc/passwd` (or an absolute path, which PHP will honor by discarding the prefix) lets a request read any file the web server process can access, outside `/var/www/reports`.

## Source
`$name = $_GET['file'];` (line 9) — attacker-controlled HTTP query parameter, unvalidated.

## Fix
```php
<?php

// Serves a document from the shared reports directory. The report name
// is expected to be a filename like "invoice-2024.pdf" under /var/www/reports.

function serve_report(): void
{
    $reportsDir = realpath('/var/www/reports');
    $requested = $_GET['file'] ?? '';

    // Strip any directory components so only a bare filename can be requested.
    $name = basename($requested);

    if ($name === '' || $name === '.' || $name === '..') {
        http_response_code(400);
        echo 'Invalid report name';
        return;
    }

    $candidate = $reportsDir . DIRECTORY_SEPARATOR . $name;
    $resolved = realpath($candidate);

    // Confirm the resolved path is still inside the reports directory and
    // actually exists as a regular file before reading it.
    if ($resolved === false
        || strncmp($resolved, $reportsDir . DIRECTORY_SEPARATOR, strlen($reportsDir) + 1) !== 0
        || !is_file($resolved)
    ) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $name . '"');

    $contents = file_get_contents($resolved);

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
The original code builds the file path by directly concatenating the untrusted `file` parameter onto the reports directory, so any `../` sequences (or an absolute path, since PHP's filesystem functions treat a leading `/` as rooted regardless of the prefix already concatenated in front of it) carry straight through to `file_get_contents()`. The fix applies two independent layers:

1. `basename($requested)` discards any directory separators or `..` segments the client supplies, so the value used to build the path can never itself request a parent directory or an absolute location — it can only ever be a single path segment.
2. Even with that normalization, the code re-resolves the candidate path with `realpath()` and checks with `strncmp()` that the resolved absolute path still starts with the resolved reports directory plus a separator, before treating the request as valid. This catches edge cases `basename()` alone would not (such as symlinks inside the reports directory that point outside it) and turns `realpath()`'s `false` return (file doesn't exist) into the same 404 the original handler used for a missing report, so behavior for legitimate requests is unchanged.

Resolving `$reportsDir` itself through `realpath()` up front ensures the containment comparison is between two canonical absolute paths, avoiding false negatives from symlinks or relative components in the base directory. The response headers and 404 handling are preserved so the fix changes only how the target path is derived and validated, not the endpoint's external behavior for valid filenames.
