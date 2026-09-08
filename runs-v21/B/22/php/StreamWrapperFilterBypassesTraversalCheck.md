## Verdict

Real issue. The denylist check for `..` is insufficient; attackers can bypass it using PHP stream wrappers like `php://filter/convert.base64-encode/resource=config.php`, which contain no `..` sequence but still access arbitrary files outside the reports directory.

## Source

Line 15: `$_GET['file']` - user-controlled filename from request parameters.

Data flow: `$_GET['file']` → line 24 (denylist check) → line 30 (`chdir()`) → line 33 (`fopen($file, 'r')`, the sink).

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

    // Reject special path components and filenames containing separators
    // This prevents traversal, stream wrappers, and other bypass attempts
    if ($file === '.' || $file === '..' || strpos($file, '/') !== false || strpos($file, '\\') !== false) {
        http_response_code(400);
        echo 'Invalid file parameter';
        return;
    }

    // Build the full path and canonicalize it with realpath()
    $fullPath = realpath($reportsDir . DIRECTORY_SEPARATOR . $file);
    
    // Verify the path was resolved and is contained within the reports directory
    if ($fullPath === false || strpos($fullPath, $reportsDir . DIRECTORY_SEPARATOR) !== 0) {
        http_response_code(404);
        echo 'File not found';
        return;
    }

    // Use the validated canonical path, not the original input
    $handle = fopen($fullPath, 'r');
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

The original code attempted to prevent traversal by checking for `..` sequences, but this denylist approach is insufficient. PHP stream wrappers like `php://filter/` can access files without using directory traversal syntax.

The fix replaces the denylist with a positive allowlist approach:

1. **Single-component validation**: Rejects filenames containing `/` or `\`, preventing both traversal and stream wrapper attacks. Special path components `.` and `..` are explicitly rejected.

2. **Canonicalization**: Builds the full file path and canonicalizes it using `realpath()`, which resolves `.`, `..`, and symlinks to their absolute form. Returns `false` if the path cannot be resolved (checked with `=== false`).

3. **Containment verification**: Uses separator-terminated string comparison (`strpos($fullPath, $reportsDir . DIRECTORY_SEPARATOR) !== 0`) to ensure the resolved path stays within the reports directory, preventing sibling-directory attacks like `/reports_backup/file.txt`.

4. **Verified path usage**: Passes the validated canonical path `$fullPath` to `fopen()`, never the original untrusted input.

The fix preserves the original function's contract: it returns a 400 for invalid input, 404 for missing files, and streams the file content on success.

## Behaviour changes

- **File component validation**: Only single-component filenames are now accepted. Requests for files in subdirectories (e.g., `subdir/file.txt`) are rejected with a 400 error, whereas the original code would have allowed them after the `chdir()`.
- **Absolute path resolution**: Files are now accessed via absolute canonical paths instead of relative paths after `chdir()`, making the path containment explicit and auditable.
- **Stream wrapper rejection**: Requests using PHP stream wrappers (e.g., `php://filter/...`, `php://filter/resource=...`) are now rejected at validation time instead of being passed to `fopen()`.
- **Error semantics**: Missing files and invalid inputs are now clearly distinguished: 400 for invalid format, 404 for valid format but file not found.
