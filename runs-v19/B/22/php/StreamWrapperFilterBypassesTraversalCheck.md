## Verdict
CONFIRMED - Path traversal via stream wrappers bypasses denylist validation.

## Source
`$_GET['file']` parameter at line 15.

## Fix
The vulnerability stems from using a denylist check (`str_contains($file, '..')`) to validate file paths before passing them to `fopen()`. This approach fails to block stream wrappers like `php://filter` which can access files without traversal sequences, and it also fails to block absolute paths and Windows drive letters.

The fix is to:
1. Reject inputs containing directory separators (`/`, `\`) or stream wrapper indicators (`:`)
2. Build the full path by concatenating the base directory with the filename
3. Canonicalize using `realpath()` to resolve symlinks and relative references
4. Verify the resolved path stays within the allowed directory
5. Use the canonicalized path with `fopen()`

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

    // Reject filename containing directory separators or stream wrappers
    if (str_contains($file, '/') || str_contains($file, '\\') || str_contains($file, ':')) {
        http_response_code(400);
        echo 'Invalid file parameter';
        return;
    }

    // Construct and canonicalize the full path
    $fullPath = realpath($reportsDir . DIRECTORY_SEPARATOR . $file);

    // Verify path is valid and within the allowed directory
    if ($fullPath === false || !str_starts_with($fullPath, $reportsDir . DIRECTORY_SEPARATOR)) {
        http_response_code(404);
        echo 'File not found';
        return;
    }

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
The vulnerability arises from an incomplete denylist approach that only checks for `..` sequences. PHP's stream wrapper system allows attackers to construct URLs like `php://filter/convert.base64-encode/resource=../config` or simply use `php://filter` without any traversal sequence to access arbitrary files. Additionally, absolute paths like `/etc/passwd` or `C:\windows\system32` are not blocked.

The fix implements the proper remediation per CWE-22 guidance for PHP:
1. **Input validation**: Rejects any filename containing `/`, `\` (directory separators), or `:` (stream wrapper indicator). This ensures only plain relative filenames are accepted.
2. **Canonicalization**: Uses `realpath()` to resolve the full path, which resolves symlinks and relative references (`.` and `..`), and returns `false` for non-existent paths and stream wrappers.
3. **Containment check**: Verifies the canonicalized path starts with the allowed directory followed by a separator, ensuring containment. The check uses `=== false` to properly detect `realpath()` failures per PHP documentation.
4. **Taint tracking**: Passes the canonicalized path to `fopen()`, never the original request value.

The removal of `chdir()` eliminates global state changes and ensures the same variable is used for both validation and file operations, as per CWE-22 guidance.

## Behaviour changes
- Filenames containing directory separators (`/`, `\`) are now rejected, preventing nested path access
- Stream wrappers (detected by `:` in the filename) are rejected
- Absolute paths are rejected
- `chdir()` is no longer called, so the working directory is not modified
- The `realpath()` result is used directly with `fopen()`, eliminating any intermediate path re-derivation
- Error responses remain consistent (400 for invalid input, 404 for not found)
