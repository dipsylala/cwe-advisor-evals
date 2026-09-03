## Verdict

Path traversal vulnerability confirmed. User-supplied filename from `$_GET['file']` is concatenated into a filesystem path without validation, allowing an attacker to read files outside the intended `/var/www/reports` directory using sequences like `../../`.

## Source

`$_GET['file']` (line 9) - untrusted user input from query parameter.

## Fix

Add path canonicalization and containment validation before calling `file_get_contents()`. Replace lines 14-17 with:

```php
$path = $reportsDir . '/' . $name;
$canonicalPath = realpath($path);

if ($canonicalPath === false || !str_starts_with($canonicalPath, $reportsDir . DIRECTORY_SEPARATOR)) {
    http_response_code(404);
    echo 'Report not found';
    return;
}

$contents = file_get_contents($canonicalPath);
```

## Explanation

The fix validates the path before use by:

1. **Canonicalization**: `realpath()` resolves relative path components (`.`, `..`) and symlinks to their absolute form. It returns `false` if the path does not exist or is inaccessible.

2. **Containment check**: After canonicalization, `str_starts_with($canonicalPath, $reportsDir . DIRECTORY_SEPARATOR)` verifies the resolved path stays within the intended directory. The appended `DIRECTORY_SEPARATOR` prevents false positives (e.g., `/var/www/documents_backup` would pass a bare prefix test against `/var/www/documents`).

3. **Safe sink**: The canonicalized, validated path is passed to `file_get_contents()`, ensuring only files within `/var/www/reports` are accessible.

Attempts to use `../../../etc/passwd`, symlinks to system files, or other traversal sequences will be rejected at the validation step, before any filesystem access occurs.

## Behaviour changes

The refactored code adds an explicit validation gate that returns `404` for any request attempting to read outside the reports directory. Legitimate reads within `/var/www/reports` proceed unchanged. Error handling for missing files is preserved - nonexistent files within the permitted directory will trigger the existing `false` check and return `404`.
