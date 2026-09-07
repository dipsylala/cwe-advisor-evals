## Verdict

Exploitable. The denylist check for `..` does not prevent stream wrapper syntax like `php://filter/resource=../../../etc/passwd` from accessing files outside the intended directory.

## Source

`$_GET['file']` at line 15 - attacker-controlled filename parameter.

## Fix

**Vulnerable code (line 23-33):**

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
// Reject stream wrappers, absolute paths, and obvious traversal.
if (str_contains($file, '://') || str_starts_with($file, '/') || str_starts_with($file, '\\')) {
    http_response_code(400);
    echo 'Invalid file parameter';
    return;
}

// Build the full path and canonicalize it.
$fullPath = realpath($reportsDir . DIRECTORY_SEPARATOR . $file);

// realpath returns false if the path doesn't exist or is not accessible.
if ($fullPath === false) {
    http_response_code(404);
    echo 'File not found';
    return;
}

// Verify the canonicalized path is within the reports directory.
if (!str_starts_with($fullPath, $reportsDir . DIRECTORY_SEPARATOR)) {
    http_response_code(403);
    echo 'Access denied';
    return;
}

$handle = fopen($fullPath, 'r');
```

## Explanation

The fix replaces the insufficient denylist check with canonicalization and containment verification. First, it rejects stream wrappers (detected by `://`), absolute paths (leading `/` or `\`), which `realpath()` would already reject but are caught early. Then it calls `realpath()` on the constructed path to resolve all `.`, `..`, and symlinks to an absolute canonical form. The canonical path is verified to start with the base directory plus a separator—this comparison must use the separator to avoid matching sibling directories like `/var/www/documents_backup` against `/var/www/documents`. Only the canonical path is passed to `fopen()`, never the original user input. Stream wrapper syntax is rejected by the initial check because it contains `://`, which `realpath()` would fail on anyway.

## Behaviour changes

- **Removed `chdir()` call**: The code no longer changes the working directory. This is safer and clearer because it avoids relying on process state for security. The containment is now explicit in the path comparison.
- **Added stream wrapper check**: `str_contains($file, '://')` rejects any stream wrapper syntax (php://, file://, etc.) before attempting canonicalization. This is necessary because the original denylist did not account for them.
- **Added absolute path checks**: `str_starts_with($file, '/')` and `str_starts_with($file, '\\')` reject absolute paths. Absolute paths would be rejected by `realpath()` in most cases but this provides early detection.
- **Changed validation logic**: Replaced denylist (`str_contains($file, '..')`) with whitelist approach (canonicalize and verify containment). Denylist is insufficient for this vulnerability.
- **Added explicit containment check**: The new `str_starts_with($fullPath, $reportsDir . DIRECTORY_SEPARATOR)` verification is the primary control, replacing the implicit containment from `chdir()`.
- **Added 403 response for out-of-bounds files**: When a file is outside the directory, the code now returns 403 Forbidden instead of silently treating it as accessible. This clarifies that the rejection is due to access control, not file existence.
- **Changed false-case response code**: When `realpath()` returns false, the code returns 404 instead of 400. This is more accurate: a nonexistent or inaccessible file is "not found" (404), while an invalid parameter format would be "bad request" (400).

All changes preserve the sink contract: `fopen()` still receives a string path, returns a resource or false, and the caller still checks for false and handles errors. The file read and close operations remain unchanged.
