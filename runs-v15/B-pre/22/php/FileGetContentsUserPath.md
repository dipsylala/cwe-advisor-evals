## Verdict

Exploitable. The `$_GET['file']` parameter is concatenated directly into a filesystem path without validation. An attacker can provide `../../../etc/passwd` or similar traversal sequences to read files outside the intended `/var/www/reports` directory.

## Source

Line 9: `$name = $_GET['file']` receives untrusted input. Line 14 concatenates it into `$path = $reportsDir . '/' . $name`. Line 17 passes `$path` to `file_get_contents()`, the taint sink.

## Fix

Add path canonicalization and containment validation before the file operation:

```php
<?php

// Serves a document from the shared reports directory. The report name
// is expected to be a filename like "invoice-2024.pdf" under /var/www/reports.

function serve_report(): void
{
    $reportsDir = '/var/www/reports';
    $name = $_GET['file'];

    // Reject filenames with path separators or relative references
    if (empty($name) || str_contains($name, '/') || str_contains($name, '\\') || 
        $name === '.' || $name === '..') {
        http_response_code(400);
        echo 'Invalid filename';
        return;
    }

    // Build and canonicalize the path
    $path = $reportsDir . '/' . $name;
    $canonicalPath = realpath($path);
    $canonicalBase = realpath($reportsDir);

    // Verify canonicalization succeeded and path is contained within base directory
    if ($canonicalPath === false || $canonicalBase === false ||
        ($canonicalPath !== $canonicalBase && 
         !str_starts_with($canonicalPath, $canonicalBase . DIRECTORY_SEPARATOR))) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($canonicalPath) . '"');

    // Use the canonical path for the file operation
    $contents = file_get_contents($canonicalPath);

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

The fix applies three controls:

1. **Input rejection**: Reject filenames containing `/`, `\`, `.`, or `..` before any path operations. This rejects traversal sequences at the source.

2. **Canonicalization**: Convert both the requested path and the base directory to their canonical absolute forms using `realpath()`, which resolves symlinks and relative path components. `realpath()` returns `false` if the path cannot be resolved (e.g., does not exist or is inaccessible).

3. **Containment verification**: Verify the canonical path either equals the base directory or starts with the base directory followed by the platform separator (`/` on Linux, `\` on Windows). Using `str_starts_with()` with the separator appended prevents bypass by sibling directories (e.g., `/var/www/reports_backup` would pass a bare prefix check against `/var/www/reports`).

The filename in the `Content-Disposition` header is also switched to `basename($canonicalPath)`, ensuring the served filename matches the resolved path.

## Behaviour changes

- **Request validation**: Requests with filenames containing path separators or relative references (`.`, `..`) now return HTTP 400 instead of being processed.
- **Path resolution**: Requests are validated against the canonicalized paths rather than textual comparison, preventing bypass via symlinks or `.` sequences.
- **Error response**: The 404 response now covers both "file does not exist" and "file is outside the allowed directory", making the two cases indistinguishable to the client (correct for information disclosure hardening).
- **Filename header**: The `Content-Disposition` filename now reflects the canonical basename rather than the raw request value, preventing the client from receiving a potentially misleading filename.
