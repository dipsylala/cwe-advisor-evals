## Verdict
REMEDIATED

## Source
The vulnerability on line 33 is a path traversal flaw. The original code only checks for `..` sequences, which is insufficient. An attacker can bypass this with:
- PHP stream wrappers: `php://filter/convert.base64-encode/resource=../../sensitive_file`
- Absolute paths: `/etc/passwd`
- Null bytes to truncate paths in certain contexts

## Fix

### File: StreamWrapperFilterBypassesTraversalCheck.php

```php
<?php
/**
 * Report viewer endpoint.
 *
 * Streams a report file to the browser. Validates that the requested file
 * is within the reports directory using realpath() canonicalization.
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

    // Reject stream wrappers, absolute paths, and null bytes
    if (preg_match('#^([a-z][a-z0-9+.-]*:|/|\\\\)#i', $file) || str_contains($file, "\0")) {
        http_response_code(400);
        echo 'Invalid file parameter';
        return;
    }

    // Reject directory traversal sequences
    if (str_contains($file, '..')) {
        http_response_code(400);
        echo 'Invalid file parameter';
        return;
    }

    // Resolve the reports directory to its canonical path
    $realReportsDir = realpath($reportsDir);
    if ($realReportsDir === false) {
        http_response_code(500);
        echo 'Internal error';
        return;
    }

    // Construct the full path
    $fullPath = $realReportsDir . DIRECTORY_SEPARATOR . $file;

    // Validate the resolved path is within the reports directory
    if (file_exists($fullPath)) {
        $realPath = realpath($fullPath);
        if ($realPath === false || strpos($realPath, $realReportsDir . DIRECTORY_SEPARATOR) !== 0) {
            http_response_code(400);
            echo 'Invalid file parameter';
            return;
        }
        $filePath = $realPath;
    } else {
        // For non-existent files, verify the parent directory is in bounds
        $parentDir = dirname($fullPath);
        $realParent = realpath($parentDir);
        if ($realParent === false || strpos($realParent, $realReportsDir . DIRECTORY_SEPARATOR) !== 0) {
            http_response_code(400);
            echo 'Invalid file parameter';
            return;
        }
        $filePath = $fullPath;
    }

    // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
    $handle = fopen($filePath, 'r');
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
The fix implements canonical path validation in three layers:

1. **Input rejection**: Blocks stream wrappers (detected via regex for `scheme:` patterns), absolute paths (leading `/` or `\`), and null bytes that could truncate paths.

2. **Directory traversal denylist**: Retained the `..` check as defense-in-depth, though the canonical path validation is the primary control.

3. **Canonical path validation**: Uses `realpath()` to resolve paths to their actual filesystem locations, which defeats symlink-based traversal and normalizes `../` sequences. For existing files, verifies the resolved path starts with the reports directory. For non-existent files, verifies the parent directory is within bounds.

4. **Removed chdir()**: The original code used `chdir()` then opened files by relative name. The fix instead validates and uses the full absolute path directly, eliminating the implicit reliance on the changed working directory.

Together these prevent bypass vectors while maintaining the ability to serve requested files from the reports directory.
