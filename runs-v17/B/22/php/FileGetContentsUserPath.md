## Verdict

CONFIRMED - Path traversal vulnerability exists at line 17. Untrusted user input from `$_GET['file']` is concatenated into a filesystem path and passed directly to `file_get_contents()` without canonicalization or containment validation. An attacker can use `../` sequences to read arbitrary files on the system.

## Source

- **Location**: Line 9 (source) → Line 14 (path construction) → Line 17 (sink)
- **Untrusted input**: `$_GET['file']` parameter
- **Data flow**: User-supplied filename is concatenated directly with base directory path, then passed to `file_get_contents()` 
- **Sink**: `file_get_contents($path)` at line 17 is the taint sink listed in CWE-22 PHP guidance

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
    
    // Canonicalize the path
    $canonicalPath = realpath($path);
    if ($canonicalPath === false) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }
    
    // Verify containment within the reports directory
    if (!str_starts_with($canonicalPath, $reportsDir . DIRECTORY_SEPARATOR)) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    $contents = file_get_contents($canonicalPath);

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

The fix applies two defenses from the CWE-22 PHP guidance:

1. **Canonicalization with `realpath()`**: The concatenated path is passed to `realpath()`, which resolves all symbolic links, `.` and `..` sequences, and returns an absolute path. If the path does not exist or cannot be accessed, `realpath()` returns `false`, which is checked and treated as "not found".

2. **Containment validation**: After canonicalization, the resolved path is verified to be within the intended reports directory using `str_starts_with($canonicalPath, $reportsDir . DIRECTORY_SEPARATOR)`. This prevents the canonical path from escaping to sibling directories (e.g., `/var/www/documents_backup`) or parent directories (e.g., `/var/www` or `/etc`).

3. **Broken taint chain**: The original untrusted input `$name` is no longer passed to the file operation. The validated `$canonicalPath` is used instead, ensuring that only files resolved within the restricted directory are accessible.

The fix maintains the original behavior for legitimate requests (files within `/var/www/reports/`) while preventing path traversal attacks using sequences like `../../../etc/passwd` or absolute paths.

Syntax verification: `php -l` passed without errors.

## Behaviour changes

- **Legitimate behavior preserved**: Requests for actual files in `/var/www/reports/` (e.g., `?file=invoice-2024.pdf`) continue to work correctly. The `realpath()` call resolves the file to its canonical absolute path within the directory.

- **Path traversal blocked**: Requests using traversal sequences (e.g., `?file=../../../etc/passwd`, `?file=..%2F..%2Fetc%2Fpasswd`) are rejected with a 404 response because `realpath()` would resolve outside the base directory and the containment check would fail.

- **Symlinks resolved**: Symbolic links pointing inside the reports directory are resolved to their targets and are permitted, while symlinks pointing outside are rejected by the containment check.

- **Non-existent files**: Requests for files that don't exist return 404, which is correct behavior. The `realpath() === false` check handles this.

- **Directory requests blocked**: Requests for the directory itself (e.g., `?file=.` or `?file=`) are rejected because the containment check requires the path to start with `$reportsDir . DIRECTORY_SEPARATOR` (i.e., must be a file inside the directory, not the directory itself).
