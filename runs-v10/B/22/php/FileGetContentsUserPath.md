## Verdict

Exploitable. The `$_GET['file']` parameter is concatenated directly into a filesystem path without validation or canonicalization, allowing path traversal attacks. An attacker can pass `file=../../etc/passwd` to read arbitrary files outside the intended `/var/www/reports` directory.

## Source

Line 9: `$name = $_GET['file'];` - untrusted input from GET parameter.

Data flow: `$_GET['file']` → `$name` (line 9) → concatenated into `$path` (line 14) → passed to `file_get_contents()` (line 17, the sink).

## Fix

**Vulnerable code:**
```php
function serve_report(): void
{
    $reportsDir = '/var/www/reports';
    $name = $_GET['file'];

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $name . '"');

    $path = $reportsDir . '/' . $name;

    // SAST FINDING: CWE-22 reported here
    $contents = file_get_contents($path);

    if ($contents === false) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    echo $contents;
}
```

**Fixed code:**
```php
function serve_report(): void
{
    $reportsDir = '/var/www/reports';
    $name = $_GET['file'];

    // Validate: filename must be a single non-empty component
    if ($name === '' || $name === '.' || $name === '..' || strpbrk($name, '/\\') !== false) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    $path = $reportsDir . '/' . $name;

    // Canonicalize the path and verify it stays within the reports directory
    $realPath = realpath($path);
    $realReportsDir = realpath($reportsDir);

    if ($realPath === false || $realReportsDir === false) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    // Verify the file is within the reports directory
    if (!str_starts_with($realPath, $realReportsDir . DIRECTORY_SEPARATOR)) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    // Read the file before sending headers (in case it doesn't exist)
    $contents = file_get_contents($realPath);

    if ($contents === false) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $name . '"');
    echo $contents;
}
```

## Explanation

The fix applies three layers of defense against path traversal: First, it validates that the filename is a single component with no path separators, empty string, or special names like `.` and `..`. Second, it uses `realpath()` to canonicalize the constructed path, which resolves all `.` and `..` sequences and expands symlinks to their true targets. Third, it verifies the canonicalized path stays within the reports directory using a separator-terminated string comparison (`str_starts_with($realPath, $realReportsDir . DIRECTORY_SEPARATOR)`), which prevents accepting sibling directories like `/var/www/reports-backup`. The file is then read using the trusted canonicalized path. If any validation step fails, the function returns a 404 response, treating all failures uniformly (invalid filenames, path traversal attempts, non-existent files, and inaccessible files).

## Behaviour changes

- **Filename validation added**: The function now rejects filenames containing path separators (`/` or `\`), empty filenames, and the special names `.` and `..`. Previously these were accepted and passed to `file_get_contents()`. This prevents accessing files in subdirectories of `/var/www/reports`, restricting access to the root level only; code serving files from subdirectories would need a different allowlist mechanism.
- **Path canonicalization and containment check**: The function now calls `realpath()` on both the candidate file path and the base directory, then verifies containment using separator-aware string comparison. Previously, simple string concatenation allowed traversal sequences to escape the directory. This adds two calls to `realpath()` (performance impact is negligible for a file-serving operation).
- **Early return on validation failure**: The function returns 404 without sending headers if validation fails. Previously, headers were set before validation. This prevents sending content-type headers for failed requests, which is a minor improvement but does not affect the functional contract.
- **Header ordering**: Headers are now sent after successfully reading the file, not before. This ensures headers are only sent when the file will actually be served, reducing redundant HTTP communication on errors. The Content-Type and Content-Disposition headers remain unchanged.
- **Sink contract preserved**: `file_get_contents()` still returns the file contents as a string or `false` on error; the error check `if ($contents === false)` remains identical. No arguments or behavior of the sink itself are altered.
