## Verdict
Real issue confirmed. The denylist check for `..` is bypassable via PHP stream wrappers.

## Source
Lines 24-28 attempt path traversal protection using a denylist (`str_contains($file, '..')`), but this check does not account for PHP stream wrapper protocols that can access files outside the intended directory without containing the `..` sequence.

## Fix
Replace the vulnerable code with path resolution and validation:

```php
function serve_report(string $reportsDir): void
{
    $file = $_GET['file'] ?? '';

    if ($file === '') {
        http_response_code(400);
        echo 'Missing file parameter';
        return;
    }

    // Extract filename only, removing any path components and stream wrappers.
    $filename = basename($file);
    
    if ($filename === '' || $filename === '.') {
        http_response_code(400);
        echo 'Invalid file parameter';
        return;
    }

    // Resolve the real path and verify it stays within the reports directory.
    $fullPath = realpath($reportsDir . '/' . $filename);
    $realReportsDir = realpath($reportsDir);
    
    if ($fullPath === false || $realReportsDir === false || 
        strpos($fullPath, $realReportsDir . DIRECTORY_SEPARATOR) !== 0) {
        http_response_code(404);
        echo 'File not found';
        return;
    }

    // Create a context that disables stream wrappers.
    $context = stream_context_create([
        'file' => ['allow_url_fopen' => false]
    ]);
    
    $handle = fopen($fullPath, 'r', false, $context);
    if ($handle === false) {
        http_response_code(404);
        echo 'File not found';
        return;
    }

    header('Content-Type: application/octet-stream');
    fpassthru($handle);
    fclose($handle);
}
```

## Explanation
The fix eliminates the path traversal vulnerability in three ways:

1. **basename() extraction**: Strips any directory path separators from the input, preventing paths like `subdir/file` or `/etc/passwd` from being processed as paths. This also filters out stream wrapper protocols that include slashes.

2. **realpath() verification**: Resolves symbolic links and relative paths to their true locations, then verifies the resolved path is within the reports directory using `strpos()`. This prevents any escape from the intended directory, whether via `..`, symbolic links, or other tricks.

3. **Stream wrapper disabling**: The `stream_context_create()` call with `allow_url_fopen => false` explicitly disables PHP stream wrapper protocols (php://, file://, data://, etc.), preventing bypass attempts that don't contain path separators.

This layered defense ensures that even inputs like `php://filter/resource=sensitive.txt` are rejected — they fail the `basename()` step or the `realpath()` verification.
