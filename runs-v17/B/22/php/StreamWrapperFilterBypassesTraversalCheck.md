## Verdict

The finding is real. The denylist check `str_contains($file, '..')` does not prevent PHP stream wrapper bypass, which allows attackers to access arbitrary files outside the intended directory.

## Source

User-controlled input from `$_GET['file']` (line 15) flows through a denylist validation (line 24) that only blocks `..` sequences, then reaches the sink `fopen($file, 'r')` at line 33.

The data flow: `$_GET['file']` → `str_contains($file, '..')` check → `fopen($file, 'r')`

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

    // Reject stream wrappers and absolute paths
    if (str_contains($file, '://')) {
        http_response_code(400);
        echo 'Invalid file parameter';
        return;
    }
    
    if (str_starts_with($file, '/') || str_starts_with($file, '\\')) {
        http_response_code(400);
        echo 'Invalid file parameter';
        return;
    }
    
    // On Windows, reject drive letters (e.g., C:)
    if (strlen($file) >= 2 && ctype_alpha($file[0]) && $file[1] === ':') {
        http_response_code(400);
        echo 'Invalid file parameter';
        return;
    }

    // Build and canonicalize the full path
    $fullPath = $reportsDir . DIRECTORY_SEPARATOR . $file;
    $canonicalPath = realpath($fullPath);
    
    // If realpath() returns false, the path doesn't exist or couldn't be resolved
    if ($canonicalPath === false) {
        http_response_code(404);
        echo 'File not found';
        return;
    }
    
    // Canonicalize the base directory
    $canonicalDir = realpath($reportsDir);
    if ($canonicalDir === false) {
        http_response_code(500);
        echo 'Internal server error';
        return;
    }
    
    // Verify the canonical path is within the reports directory
    if ($canonicalPath !== $canonicalDir && !str_starts_with($canonicalPath, $canonicalDir . DIRECTORY_SEPARATOR)) {
        http_response_code(400);
        echo 'Invalid file parameter';
        return;
    }

    // Open and stream the file
    $handle = fopen($canonicalPath, 'r');
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

The original code relied on a denylist check for `..` sequences, which does not prevent PHP stream wrapper bypass. An attacker could supply `php://filter/convert.base64-encode/resource=../config.php` or similar, which contains no `..` but still escapes the directory restriction.

The fix implements canonical-form validation using `realpath()`:

1. **Rejects stream wrappers** - blocks any input containing `://`, eliminating `php://`, `file://`, `data://`, and other wrapper URLs.

2. **Rejects absolute paths** - blocks paths starting with `/`, `\`, or Windows drive letters (e.g., `C:`), preventing direct access to the filesystem root.

3. **Canonicalizes the requested path** - `realpath()` resolves all `.`, `..`, and symbolic links to their absolute canonical form. For a path inside the reports directory, this succeeds; for one outside, `realpath()` still succeeds but the result lies outside the allowed boundary.

4. **Enforces containment** - compares the canonical path against the canonical reports directory using separator-aware comparison (`str_starts_with($path, $base . DIRECTORY_SEPARATOR)`). This prevents sibling-directory bypass (e.g., `/var/www/documents_backup` will not pass a check for `/var/www/documents`).

5. **Uses the canonicalized path** - passes `$canonicalPath` (not the original `$file`) to `fopen()`, ensuring the sink operates on the validated value.

This satisfies the original code's contract: the sink still streams files as a binary blob, preserves the 404/400/500 error reporting, and operates only on valid filesystem paths within the allowed directory.

## Behaviour changes

- Requests with `../`, stream wrappers (`php://`, `file://`, etc.), absolute paths, or paths resolving outside the reports directory now return HTTP 400 instead of being processed.
- Symlinks within the reports directory are now followed and verified to resolve within bounds (the original code would have followed them without checking).
- Nonexistent files return HTTP 404 instead of HTTP 400 (the original error handling for `fopen()` failure now applies only to true I/O errors after path validation succeeds).
