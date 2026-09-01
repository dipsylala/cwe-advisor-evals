## Verdict
CWE-22 path traversal confirmed at line 17. User-controlled filename from `$_GET['file']` is concatenated directly into a file path without validation, allowing directory traversal via `../` sequences.

## Source
Line 9 receives untrusted input: `$name = $_GET['file'];`
Line 14 constructs path by concatenation: `$path = $reportsDir . '/' . $name;`
Line 17 reads from unsanitized path: `$contents = file_get_contents($path);`

Attack vector: `?file=../../../../../../etc/passwd` reads arbitrary files outside `/var/www/reports`.

## Fix
Resolve the base directory with `realpath()`, extract the filename component only using `basename()`, construct the path, and verify the resolved path remains within the restricted directory:

```php
function serve_report(): void
{
    $reportsDir = realpath('/var/www/reports');
    if ($reportsDir === false) {
        http_response_code(500);
        echo 'Reports directory not found';
        return;
    }

    $name = $_GET['file'];
    
    // Extract only the filename, stripping any directory components
    $filename = basename($name);
    if (empty($filename)) {
        http_response_code(400);
        echo 'Invalid filename';
        return;
    }

    $path = $reportsDir . DIRECTORY_SEPARATOR . $filename;

    // Verify the constructed path is still within reports directory
    $realPath = realpath($path);
    if ($realPath === false || strpos($realPath, $reportsDir . DIRECTORY_SEPARATOR) !== 0) {
        http_response_code(403);
        echo 'Access denied';
        return;
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $filename . '"');

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
The fix uses three key defences:

1. **`realpath()` on the base directory** resolves `/var/www/reports` to its absolute canonical form, handling symlinks and relative components.

2. **`basename()`** extracts only the filename component from the user input, stripping all directory separators and `../` sequences. `basename('../../etc/passwd')` returns `'passwd'`, neutralizing directory traversal attempts.

3. **`realpath()` on the constructed path** resolves the final path and confirms it starts with the base directory using `strpos()`. This check:
   - Returns `false` if the file doesn't exist (caught before `file_get_contents()`)
   - Detects symlink escapes: a symlink pointing outside the directory will resolve outside and fail the prefix check
   - Ensures `../` in a newly constructed path cannot escape

The additional validation checks prevent empty filenames and use `DIRECTORY_SEPARATOR` for platform independence. The code responds with appropriate HTTP status codes (400 for bad input, 403 for access denied, 404 for missing file) to distinguish error conditions.
