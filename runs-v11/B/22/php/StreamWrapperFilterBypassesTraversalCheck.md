## Verdict
Confirmed. Path traversal via stream wrapper bypass. The denylist check for `..` does not prevent stream wrapper URIs like `php://filter/` from accessing files outside the reports directory.

## Source
Line 15: `$_GET['file']` - untrusted user input from query parameter.

## Fix

**Vulnerable code (line 33):**
```php
// Denylist check: block directory traversal sequences.
if (str_contains($file, '..')) {
    http_response_code(400);
    echo 'Invalid file parameter';
    return;
}

chdir($reportsDir);

// SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
$handle = fopen($file, 'r');
```

**Fixed code:**
```php
// Reject stream wrappers and absolute paths.
if (
    str_contains($file, '://') ||
    str_starts_with($file, '/') ||
    str_starts_with($file, '\\')
) {
    http_response_code(400);
    echo 'Invalid file parameter';
    return;
}

// Reject filenames that attempt directory traversal or are empty.
if (
    $file === '' ||
    $file === '.' ||
    $file === '..' ||
    str_contains($file, '/') ||
    str_contains($file, '\\')
) {
    http_response_code(400);
    echo 'Invalid file parameter';
    return;
}

// Canonicalize and verify containment.
$full = realpath($reportsDir . DIRECTORY_SEPARATOR . $file);
if ($full === false || !str_starts_with($full, $reportsDir . DIRECTORY_SEPARATOR)) {
    http_response_code(404);
    echo 'File not found';
    return;
}

// Use the canonicalized path for the file operation.
$handle = fopen($full, 'r');
```

## Explanation
The original code used a denylist to block `..` sequences but failed to account for PHP stream wrappers (e.g., `php://filter/`) and absolute paths, both of which bypass the containment check. The fix replaces the insufficient denylist with a positive validation strategy:

1. **Reject stream wrappers and absolute paths**: Block any input containing `://` or starting with `/` or `\`, which cannot be legitimate relative filenames within the reports directory.
2. **Reject path separators and special names**: Prevent any input containing `/` or `\` characters or matching `.` or `..`, ensuring only a single filename component is accepted—no subdirectories.
3. **Canonicalize and verify containment**: Use `realpath()` to resolve the full absolute path. If canonicalization fails (returns `false`), the file does not exist or is inaccessible; reject it. Then verify the resolved path stays within the reports directory using a separator-terminated string comparison: `str_starts_with($full, $reportsDir . DIRECTORY_SEPARATOR)`. This prevents a sibling directory (e.g., `../documents_backup`) from passing a bare prefix test.
4. **Use the canonicalized path**: Pass the validated `realpath()` result to `fopen()`, never the original user input, to prevent race conditions where the path might change between validation and use.

## Behaviour changes
- **Legitimate reads**: Requests for files directly in the reports directory (e.g., `file=report.pdf`) still succeed.
- **Subdirectories**: The fix now rejects requests for subdirectory files (e.g., `file=subdir/report.pdf`), treating `/` and `\` as invalid characters in the filename. If subdirectory access is intended, adjust the validation to check whether the canonicalized path is within the reports directory and allow `/` only for that purpose (i.e., remove the `str_contains($file, '/')` check).
- **Path traversal attempts**: Requests containing `..`, `../`, stream wrappers (e.g., `php://filter/`), or absolute paths are rejected with HTTP 400 (Bad Request).
- **Missing or inaccessible files**: `realpath()` returning `false` is now treated as "file not found" (HTTP 404) rather than an exception, matching the original behaviour.
- **Performance**: The additional `realpath()` call has negligible impact for single-file reads but adds a system call per request.
