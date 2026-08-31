## Verdict
The code is vulnerable to path traversal. User input from `$_GET['file']` is concatenated directly into a file path without validation, allowing an attacker to traverse directories using sequences like `../` to access files outside `/var/www/reports`.

## Source
Line 9: `$name = $_GET['file'];` receives untrusted input.

Line 14: `$path = $reportsDir . '/' . $name;` concatenates the unsanitized input directly into the file path.

Line 17: `file_get_contents($path)` reads the file at the attacker-controlled path.

## Fix
```php
<?php

function serve_report(): void
{
    $reportsDir = '/var/www/reports';
    $name = $_GET['file'];

    // Reject if empty
    if (empty($name)) {
        http_response_code(400);
        echo 'File parameter required';
        return;
    }

    // Extract only the filename, removing any directory components
    $filename = basename($name);

    // Reject if basename stripped everything (e.g., input was just "../")
    if ($filename === '' || $filename !== $name) {
        http_response_code(400);
        echo 'Invalid file name';
        return;
    }

    $path = $reportsDir . '/' . $filename;

    // Verify the resolved path stays within the allowed directory
    $realPath = realpath($path);
    if ($realPath === false || strpos($realPath, realpath($reportsDir)) !== 0) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . addcslashes($filename, '"\\') . '"');

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
The fix uses two layers of defense:

1. **basename()**: Strips any directory components from the input, so `../../../etc/passwd` becomes just `passwd`. This is the primary control because the application expects only simple filenames.

2. **Comparison check**: After basename(), if the filename changed, the input contained path traversal attempts and is rejected.

3. **realpath() validation**: Resolves the full path and verifies it begins with the allowed directory path. This catches edge cases like symlinks that might point outside.

4. **Header escaping**: The filename in Content-Disposition is escaped with `addcslashes()` to prevent header injection, treating the filename as untrusted data even after validation.

The fix rejects requests with empty filenames, paths containing directory components, and any resolved paths outside the intended directory, while allowing legitimate report filenames.
