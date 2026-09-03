## Verdict

**Confirmed.** Line 17 reads a file from a path constructed by concatenating a user-controlled filename directly to a directory path, without restricting the filename to the intended directory. An attacker can pass directory traversal sequences like `../../etc/passwd` to access files outside `/var/www/reports/`.

## Source

The vulnerability is on line 17, where `file_get_contents($path)` is called. The `$path` variable is built on line 14 by concatenating `$reportsDir` with user input `$_GET['file']` (from line 9), with no validation to prevent directory traversal.

```php
$name = $_GET['file'];  // Line 9: user input
$path = $reportsDir . '/' . $name;  // Line 14: concatenation
$contents = file_get_contents($path);  // Line 17: sink
```

## Fix

Use `basename()` to strip any directory components from the user-supplied filename, ensuring only the filename itself—not a path—can be constructed:

```php
<?php

function serve_report(): void
{
    $reportsDir = '/var/www/reports';
    $name = $_GET['file'];

    // Strip any directory components; only the filename is allowed
    $filename = basename($name);

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $filename . '"');

    $path = $reportsDir . '/' . $filename;

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

`basename()` returns only the trailing filename component of a path, discarding any directory separators. When passed a value like `../../etc/passwd`, it returns `passwd`. When passed a simple filename like `invoice-2024.pdf`, it returns it unchanged.

This ensures the resolved path stays within the intended `/var/www/reports/` directory. An attacker cannot escape to parent directories or absolute paths.

An alternative is `realpath()` with a directory check: resolve the full path, then verify it starts with the allowed directory prefix. However, `basename()` is simpler and sufficient here because the intent is to accept only filenames, not paths.
