## Verdict

The denylist-based path traversal check using `str_contains($file, '..')` is insufficient. PHP stream wrappers like `php://filter/resource=` can be used to bypass the traversal check and read arbitrary files, even though they don't contain the literal `..` sequence.

## Source

The vulnerability is in the `serve_report()` function at line 33. The code attempts to prevent directory traversal by:
1. Checking if the filename contains `'..'` (line 24)
2. Changing to the reports directory with `chdir()` (line 30)
3. Opening the file with `fopen($file, 'r')` (line 33)

However, the denylist check only blocks the literal `..` sequence. Stream wrapper protocols like `php://filter/resource=../../../../etc/passwd` do not contain `..` and can escape the intended directory even after the `chdir()`.

## Fix

### File: StreamWrapperFilterBypassesTraversalCheck.php

```php
<?php
/**
 * Report viewer endpoint.
 *
 * Streams a report file to the browser. Validates that the resolved
 * file path is strictly within the reports directory.
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

    chdir($reportsDir);

    // Resolve the full path and verify it's within the reports directory.
    $realPath = realpath($file);
    $currentDir = getcwd();
    
    if ($realPath === false || strpos($realPath, $currentDir) !== 0) {
        http_response_code(400);
        echo 'Invalid file parameter';
        return;
    }

    // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
    $handle = fopen($realPath, 'r');
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

The fix replaces the denylist check with a positive allowlist validation based on path resolution:

1. **`realpath($file)`** resolves the complete absolute path, normalizing any relative sequences and expanding stream wrapper protocols to their target. If the file doesn't exist or the path is invalid, it returns `false`.

2. **`getcwd()`** returns the current working directory (the reports directory after `chdir()`).

3. **Path containment check** verifies that the resolved real path starts with the reports directory using `strpos($realPath, $currentDir) !== 0`. This ensures the file is strictly within the reports directory tree.

This approach prevents:
- Stream wrapper bypass (`php://filter`, `file://`, etc.)
- Symlink traversal outside the directory
- Null byte injection and other encoding tricks
- Any other path normalization bypass

The resolved real path is then used in `fopen()` to operate on the actual target file.

