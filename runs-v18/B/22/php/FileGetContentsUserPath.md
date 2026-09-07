## Verdict

exploitable

## Source

Line 9: `$_GET['file']` - user-controlled HTTP GET parameter assigned to `$name` without validation or sanitization.

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

    // Canonicalize the path and verify it stays within the reports directory
    $realPath = realpath($path);
    if ($realPath === false || !str_starts_with($realPath, $reportsDir . DIRECTORY_SEPARATOR)) {
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

The vulnerability exists because user input from `$_GET['file']` is concatenated directly into a filesystem path passed to `file_get_contents()` without validation. An attacker can use path traversal sequences like `../../etc/passwd` to access files outside the intended `/var/www/reports/` directory.

The fix eliminates this by canonicalizing the constructed path with `realpath()`, which resolves `.`, `..`, and symbolic links to their absolute forms. The canonicalized path is then validated against a separator-aware containment check using `str_starts_with($realPath, $reportsDir . DIRECTORY_SEPARATOR)` to ensure it remains within the reports directory. The separator is critical to prevent directory-name confusion (e.g., `/var/www/reports_backup` would match a separator-less comparison). The canonical path (not the original user input) is then used for the actual file operation, ensuring only validated paths are accessed. If canonicalization fails or containment is violated, the request is rejected with a 404.

## Behaviour changes

- Non-existent files now return 404 at the canonicalization stage rather than at the `file_get_contents()` stage. The user receives the same 404 response, but the check happens earlier and more securely.
- Symbolic links are now followed and their targets are checked for directory containment. This prevents symlink-based escape attempts.
- Absolute paths or paths attempting traversal are now rejected at containment validation, preventing any path-based escapes from the reports directory.
- The `file_get_contents()` call now uses the canonical path variable (`$realPath`) instead of the user-influenced path variable (`$path`), ensuring no untrusted input reaches the file operation.

