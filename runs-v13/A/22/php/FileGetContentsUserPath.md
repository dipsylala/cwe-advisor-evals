## Verdict

The code is vulnerable to path traversal. An attacker can supply a filename like `../../etc/passwd` to escape the intended `/var/www/reports` directory and read arbitrary files on the system.

## Source

Line 17 calls `file_get_contents($path)` where `$path` is constructed from unsanitized user input (`$_GET['file']`) concatenated with a directory prefix. The concatenation alone does not restrict the final path to the intended directory.

## Fix

Resolve the requested path to its canonical form and verify it remains within the allowed directory:

```php
<?php

function serve_report(): void
{
    $reportsDir = '/var/www/reports';
    $name = $_GET['file'];

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $name . '"');

    $path = $reportsDir . '/' . $name;
    
    // Resolve the path to its canonical form
    $realPath = realpath($path);
    $realReportsDir = realpath($reportsDir);
    
    // Verify the resolved path is within the allowed directory
    if ($realPath === false || strpos($realPath, $realReportsDir . DIRECTORY_SEPARATOR) !== 0) {
        http_response_code(403);
        echo 'Access denied';
        return;
    }

    // SAST FINDING: CWE-22 resolved. Sink is now safe.
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

`realpath()` resolves a path to its absolute, canonical form by resolving symlinks and normalizing `..` and `.` sequences. It returns `false` if the path does not exist or is inaccessible.

The fix uses `realpath()` on both the requested path and the allowed directory, then checks that the resolved requested path starts with the allowed directory (plus a directory separator). This ensures that even if an attacker supplies `../../../etc/passwd`, the resolved path will be rejected because it falls outside `/var/www/reports`.

The check uses `strpos(...) !== 0` to ensure a prefix match at position 0, and includes `DIRECTORY_SEPARATOR` to prevent directory confusion (e.g., `/var/www/reports2/file` appearing to start with `/var/www/reports`).

If the path is invalid or escapes the allowed directory, the handler returns a 403 Forbidden response before attempting to read the file.
