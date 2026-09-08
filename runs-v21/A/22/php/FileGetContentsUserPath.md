## Verdict

The vulnerability is confirmed. The code concatenates user-controlled input from `$_GET['file']` directly with the base directory path without validation, allowing attackers to use path traversal sequences like `../` to access files outside the intended `/var/www/reports` directory. An attacker can request `?file=../../etc/passwd` to read arbitrary files on the system.

## Source

The vulnerable code on line 17 uses `file_get_contents($path)` where `$path` is constructed from unsanitized user input:

```php
$name = $_GET['file'];  // Line 9: Untrusted user input
$path = $reportsDir . '/' . $name;  // Line 14: Direct concatenation
$contents = file_get_contents($path);  // Line 17: Sink - path traversal possible
```

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

    // Resolve the base directory to its canonical path
    $realReportsDir = realpath($reportsDir);
    if ($realReportsDir === false) {
        http_response_code(500);
        echo 'Reports directory not found';
        return;
    }

    // Construct the requested path
    $path = $realReportsDir . DIRECTORY_SEPARATOR . $name;

    // Resolve to the real path to prevent directory traversal
    $realPath = realpath($path);

    // Verify the resolved path is within the reports directory
    if ($realPath === false || strpos($realPath, $realReportsDir . DIRECTORY_SEPARATOR) !== 0) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($realPath) . '"');

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

The fix prevents path traversal by validating that the resolved file path stays within the intended directory:

1. **Canonical path resolution**: `realpath()` resolves both the base directory and the requested path to their absolute canonical forms, eliminating symlinks and `../` sequences.

2. **Containment check**: After resolving both paths, the code verifies that the requested file's real path begins with the directory's real path using `strpos()`. This ensures the file is located within or under the reports directory, not above it.

3. **False return handling**: If `realpath()` returns false (file doesn't exist or path is invalid), the request is rejected with a 404, preventing information leakage about the filesystem structure.

4. **Safe filename in header**: `basename($realPath)` extracts only the filename from the validated path for the Content-Disposition header, preventing injection attacks.

Attack attempts like `?file=../../etc/passwd` now fail: the resolved path for such requests would point outside `/var/www/reports`, triggering the containment check and returning 404.

