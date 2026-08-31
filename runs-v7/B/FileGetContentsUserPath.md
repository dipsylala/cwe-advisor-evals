## Verdict

Real path traversal vulnerability. Attacker can read arbitrary files by passing `?file=../../../etc/passwd` or similar sequences, because the filename is concatenated directly into the path without validation.

## Source

Line 9: `$name = $_GET['file'];` — untrusted GET parameter  
Line 14: `$path = $reportsDir . '/' . $name;` — direct string concatenation without validation  
Line 17: `file_get_contents($path)` — taint sink; `file_get_contents()` is listed in CWE-22/php Taint Sinks

The data flow is: user input → path construction → file read with no containment check.

## Fix

```php
<?php

// Serves a document from the shared reports directory. The report name
// is expected to be a filename like "invoice-2024.pdf" under /var/www/reports.

function serve_report(): void
{
    $reportsDir = realpath('/var/www/reports');
    if ($reportsDir === false) {
        http_response_code(500);
        echo 'Reports directory not found';
        return;
    }
    
    $name = $_GET['file'];
    
    // Reject filenames containing path separators (both Unix and Windows)
    if (strpbrk($name, '/\\') !== false) {
        http_response_code(400);
        echo 'Invalid filename';
        return;
    }
    
    // Build and canonicalize the path
    $path = $reportsDir . DIRECTORY_SEPARATOR . $name;
    $path = realpath($path);
    
    // Verify the resolved path exists and is contained within the reports directory
    if ($path === false || !str_starts_with($path, $reportsDir . DIRECTORY_SEPARATOR)) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }
    
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($path) . '"');
    
    $contents = file_get_contents($path);
    
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

The fix follows CWE-22/php guidance for read scenarios. First, the base directory `/var/www/reports` is canonicalized with `realpath()` to resolve symlinks and relative components into absolute form. Early rejection of filenames containing separators (`/` or `\`) enforces that the user can only select a single file component, not a path. The full target path is then built and canonicalized with `realpath()`, which resolves any `.` or `..` sequences and returns `false` if the file does not exist or cannot be accessed. The resolved path is validated to be contained within the reports directory using the separator-terminated containment check (`str_starts_with($path, $reportsDir . DIRECTORY_SEPARATOR)`), which correctly rejects sibling directories like `/var/www/documents`. Only after this validation passes is the file read. The `Content-Disposition` header is also changed to use `basename($path)` (the validated path component) instead of the raw user input, preventing potential header injection.

## Behaviour changes

- **New 500 error**: If `/var/www/reports` does not exist or cannot be canonicalized, the handler returns 500 instead of silently failing later. This is a backstop and should not occur in normal operation.
- **New 400 error**: Filenames containing path separators are rejected early with 400 (Bad Request) instead of being processed. This clarifies that such input is invalid, not merely "not found".
- **Changed 404 timing**: A request to a nonexistent file still returns 404, but the semantics change: the file would have been outside the permitted directory (caught by the containment check) or genuinely does not exist. Both cases are indistinguishable to the caller.
- **File reads remain successful**: Legitimate reads of files like `invoice-2024.pdf` continue to work unchanged.
- **Symlink resolution**: Symlinks within the reports directory are followed and their targets are validated; symlinks pointing outside the directory are rejected.
