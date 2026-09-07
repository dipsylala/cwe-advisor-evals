## Verdict

Exploitable. An attacker can use path traversal sequences in the `file` parameter to access files outside `/var/www/reports/`, such as `../../../etc/passwd`. The user-supplied filename is concatenated directly into the filesystem path without any canonicalization or containment validation before being passed to `file_get_contents()`.

## Source

**Source**: `$_GET['file']` (line 9)  
**Sink**: `file_get_contents($path)` (line 17)  
**Data Flow**: The request parameter is concatenated directly into a filesystem path at line 14 (`$path = $reportsDir . '/' . $name;`) and passed to the file operation without validation.

## Fix

**Vulnerable Code**:
```php
function serve_report(): void
{
    $reportsDir = '/var/www/reports';
    $name = $_GET['file'];

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $name . '"');

    $path = $reportsDir . '/' . $name;

    // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
    $contents = file_get_contents($path);

    if ($contents === false) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    echo $contents;
}
```

**Fixed Code**:
```php
function serve_report(): void
{
    $reportsDir = '/var/www/reports';
    $name = $_GET['file'];

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $name . '"');

    $path = $reportsDir . '/' . $name;

    // Canonicalize the path and validate containment within the reports directory
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
```

## Explanation

The fix closes the path traversal vulnerability by canonicalizing the user-supplied path with `realpath()` before use. The `realpath()` function resolves all relative path components (`.` and `..`) and symbolic links to their true absolute paths, converting an attack sequence like `../../../etc/passwd` into an actual filesystem path. The validation then verifies the canonical path lies within the intended directory using a separator-aware string prefix check: `str_starts_with($realPath, $reportsDir . DIRECTORY_SEPARATOR)`. This prevents directory-escape attacks while still allowing legitimate subdirectory access. Critically, the canonical path stored in `$realPath` is passed to `file_get_contents()`, ensuring the sink receives the validated value, not the original tainted input. If canonicalization fails (returns `false`) or the path escapes the base directory, the code rejects the request with a 404 response.

## Behaviour changes

The fix adds a canonicalization check that rejects file access requests where:
- The requested file path does not exist or cannot be canonicalized (realpath returns false)
- The canonical absolute path lies outside `/var/www/reports/`

**Impact**: Legitimate requests for files within `/var/www/reports/` succeed unchanged. Traversal attempts and nonexistent files are rejected with the existing 404 response, maintaining the original error contract. There is a minor performance cost from the `realpath()` call, which performs filesystem resolution. No external dependencies are required; `realpath()` and `str_starts_with()` are PHP built-in functions.
