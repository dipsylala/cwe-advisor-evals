## Verdict

exploitable

## Source

`$_GET['file']` at line 9 — untrusted user input from HTTP request parameter, reaches the sink without validation or canonicalization.

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

    // Canonicalize the base directory (must exist)
    $baseReal = realpath($reportsDir);
    if ($baseReal === false) {
        http_response_code(500);
        echo 'Configuration error';
        return;
    }

    // Build and canonicalize the requested path
    $fullPath = $baseReal . DIRECTORY_SEPARATOR . $name;
    $realPath = realpath($fullPath);
    
    // Verify the path is within the base directory
    if ($realPath === false || !str_starts_with($realPath, $baseReal . DIRECTORY_SEPARATOR)) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $name . '"');

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

The original code concatenated user input directly into a filesystem path without validation, allowing attackers to use path-traversal sequences like `../` to escape the intended `/var/www/reports` directory and access arbitrary files. The fix follows PHP CWE-22 guidance by: (1) canonicalizing the base directory with `realpath()` to resolve any symlinks, (2) constructing the full path by concatenating the canonical base with the filename, (3) canonicalizing the full path to resolve relative references and symlinks, (4) verifying that the canonicalized path stays within the base directory using a separator-terminated containment check (`str_starts_with($realPath, $baseReal . DIRECTORY_SEPARATOR)`), and (5) using only the canonicalized path for the `file_get_contents()` call. This prevents directory traversal because `realpath()` fully resolves `../` sequences to their absolute target, and the containment check rejects any path that escapes the approved base directory.

## Behaviour changes

- **Error handling for base directory**: The fix adds an early check that the base directory exists and is resolvable via `realpath()`. If it fails, the function returns a 500 error instead of attempting to serve a file. Reason: A misconfigured or inaccessible base directory indicates a deployment or permission issue, distinct from a missing file (404).
- **Check before headers**: The containment validation now happens before the Content-Type and Content-Disposition headers are sent, preventing headers from being sent if the requested path is invalid. Reason: This is more correct HTTP behavior — headers should be set only when the response will succeed.
- **Canonicalized path used for read**: The `file_get_contents()` call now uses `$realPath` (the canonicalized and validated path) instead of the concatenated `$path`. Reason: This is the core of the fix — it ensures only files within the approved directory can be read, breaking the path-traversal chain.
- **No change to legitimate file access**: Legitimate requests for files within the reports directory (e.g., `file=invoices/2024.pdf`) continue to work as before.

## Verification

PHP syntax check (`php -l`) passed with no errors on the fixed code.

Assumptions:
- The base directory `/var/www/reports` is assumed to exist and be readable by the PHP process during normal operation; if it does not, a 500 error is returned rather than silently falling back to the original unsafe pattern.
- `str_starts_with()` is available (PHP 8.0+); if the server runs PHP 7.x, this function call will raise a fatal error. The fix assumes modern PHP versions.
- `DIRECTORY_SEPARATOR` is used to build paths for portability, though `/var/www/reports` is Unix-style and suggests a Linux deployment.
