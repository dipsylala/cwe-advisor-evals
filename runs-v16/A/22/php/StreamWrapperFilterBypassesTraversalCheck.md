## Verdict
VULNERABLE

## Source
Line 33 calls `fopen($file, 'r')` where `$file` is user-supplied via `$_GET['file']`.

## Fix
Replace the denylist check and unsafe `fopen()` call with a whitelist-based validation using `realpath()`:

```php
// Resolve the requested file to its real, absolute path.
$requestedFile = realpath($reportsDir . DIRECTORY_SEPARATOR . $file);

// Reject if realpath() returns false (path does not exist or cannot be resolved).
if ($requestedFile === false) {
    http_response_code(404);
    echo 'File not found';
    return;
}

// Reject if the resolved path does not start with the reports directory.
// Normalize both paths to handle trailing slashes and symlinks consistently.
$realReportsDir = realpath($reportsDir);
if ($realReportsDir === false || strpos($requestedFile, $realReportsDir . DIRECTORY_SEPARATOR) !== 0) {
    http_response_code(400);
    echo 'Invalid file parameter';
    return;
}

// Safe to open: the path has been verified to resolve within the reports directory.
$handle = fopen($requestedFile, 'r');
```

## Explanation
The original code blocks the literal string `'..'` but does not account for PHP stream wrappers (`php://`, `zip://`, `glob://`, etc.), which bypass the denylist and allow access to files outside the intended directory. The `chdir()` call does not restrict stream wrapper operations.

The fix uses `realpath()` to resolve the full filesystem path and verify it remains within `$reportsDir`. Stream wrappers are ignored by `realpath()` (it returns `false` for non-existent or invalid paths), so they are implicitly rejected. Only files that exist within the reports directory are opened.
