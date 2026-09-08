## Verdict

Exploitable. The application constructs a file path from user-supplied input without validation, allowing path traversal via sequences like `../` to read files outside the intended `/var/www/reports` directory.

## Source

`$_GET['file']` (line 9) is attacker-controlled input that flows directly into the file path without validation or canonicalization.

## Fix

### File: FileGetContentsUserPath.php

```php
<?php

// Serves a document from the shared reports directory. The report name
// is expected to be a filename like "invoice-2024.pdf" under /var/www/reports.

function serve_report(): void
{
    $reportsDir = '/var/www/reports';
    $name = $_GET['file'];

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $name . '"');

    $path = $reportsDir . '/' . $name;

    // Canonicalize the path and validate it stays within the base directory
    $realPath = realpath($path);

    // Check if canonicalization failed (file not found or traversal attempt)
    if ($realPath === false) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    // Verify the resolved path is within the permitted directory
    if ($realPath !== $reportsDir && !str_starts_with($realPath, $reportsDir . DIRECTORY_SEPARATOR)) {
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

serve_report();
```

## Explanation

The fix applies canonicalization and containment validation before reading the file. After constructing the initial path by concatenating the base directory with user input, the code calls `realpath()` to resolve `.`, `..`, and symlinks to an absolute canonical form. This resolves path traversal attempts like `../../../etc/passwd` to their true target. The code then validates the canonicalized path stays within the permitted directory using a separator-aware containment check: `str_starts_with($realPath, $reportsDir . DIRECTORY_SEPARATOR)`, which correctly rejects sibling directories. Only after both validation checks pass is the canonicalized path passed to `file_get_contents()`, ensuring the sink operates on a validated, containment-verified path. Failed canonicalization or validation returns a 404 response, terminating the request before any unauthorized file access occurs.

## Behaviour changes

- Lines 16-26: Added path canonicalization and containment validation before the `file_get_contents()` call. This changes behavior only for requests that attempt traversal or specify non-existent files, which are now consistently rejected with a 404 response. Legitimate requests for files within `/var/www/reports` are unaffected because the canonicalized path will pass validation and be used in `file_get_contents()` exactly as before.
