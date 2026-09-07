## Verdict

Exploitable. The denylist check for `..` does not prevent stream wrapper-based path access, such as `php://filter/convert.base64-encode/resource=../../../../etc/passwd`, which contains no traversal sequence but gains unrestricted file access through PHP's stream layer.

## Source

`$_GET['file']` at line 15 of StreamWrapperFilterBypassesTraversalCheck.php

## Fix

### File: StreamWrapperFilterBypassesTraversalCheck.php

```php
<?php
/**
 * Report viewer endpoint.
 *
 * Streams a report file to the browser. Validates the requested file
 * is a plain relative filename, canonicalizes the path, and confirms
 * it stays within the reports directory before opening.
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

    // Reject stream wrappers and directory separators to ensure input is a plain filename
    if (str_contains($file, ':') || str_contains($file, '/') || str_contains($file, '\\')) {
        http_response_code(400);
        echo 'Invalid file parameter';
        return;
    }

    // Build the full path and canonicalize it
    $fullPath = realpath($reportsDir . DIRECTORY_SEPARATOR . $file);

    // Verify the path is canonical and within the reports directory
    if ($fullPath === false || !str_starts_with($fullPath, $reportsDir . DIRECTORY_SEPARATOR)) {
        http_response_code(404);
        echo 'File not found';
        return;
    }

    // Open the validated, canonicalized path
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

The original code relied on a denylist that rejected only the `..` sequence, which is insufficient for path traversal prevention. The fix applies the CWE-22 remediation pattern per the PHP guidance: reject stream wrappers and directory separators to ensure the input is a plain relative filename (lines 23-28), build the full path and canonicalize it with `realpath()` to resolve symlinks and relative references (line 31), then verify containment by checking that the canonical path starts with the base directory followed by a separator (line 34). The canonicalized path is passed directly to `fopen()` (line 37) rather than the original user input, ensuring that only verified paths reach the sink. This eliminates:
- Stream wrapper bypasses like `php://filter/...` (rejected by `:` check)
- Directory traversal via `../` (rejected by `/` check)
- Symlink attacks (resolved by `realpath()`)
- Sibling-directory access (verified by separator-terminated containment check)

## Behaviour changes

- **File parameter validation**: The fix now rejects any filename containing `:`, `/`, or `\`, which is stricter than the original denylist. Legitimate requests must use plain filenames without path components (e.g., `file=report.pdf` instead of `file=subdir/report.pdf`). This aligns with the intended access model, where users select from a fixed set of files, not nested directories.
- **Error response**: When the canonicalized path is not found or falls outside the base directory, the response remains 404 with "File not found", preserving the original error semantics.
- **Path resolution**: The `realpath()` call requires the file to exist on disk and be readable. This differs from the original code only in that it now blocks invalid traversal attempts; legitimate existing files pass through unchanged.
- **Working directory**: The original `chdir($reportsDir)` call has been replaced with explicit path construction. This is operationally equivalent for the file operation but eliminates reliance on process-wide state and makes the containment check explicit in the code.
