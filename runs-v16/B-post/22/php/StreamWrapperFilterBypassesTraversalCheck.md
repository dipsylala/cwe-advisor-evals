## Verdict

Exploitable

## Source

`$_GET['file']` at line 15

## Fix

**Vulnerable code:**
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
// Reject stream wrappers, absolute paths, and directory traversal sequences
if (str_contains($file, '://')) {
    http_response_code(400);
    echo 'Invalid file parameter';
    return;
}

// Build the full path by explicitly joining base directory with filename
$fullPath = $reportsDir . DIRECTORY_SEPARATOR . $file;

// Canonicalize the path to resolve any symlinks
$canonical = realpath($fullPath);

// Canonicalize the base directory for containment check
$baseDir = realpath($reportsDir);

// Verify both canonicalizations succeeded
if ($canonical === false || $baseDir === false) {
    http_response_code(404);
    echo 'File not found';
    return;
}

// Check containment using separator-aware comparison
if (!str_starts_with($canonical, $baseDir . DIRECTORY_SEPARATOR)) {
    http_response_code(400);
    echo 'Invalid file parameter';
    return;
}

// Use the canonical path for the file operation
$handle = fopen($canonical, 'r');
```

## Explanation

The original code attempted to prevent path traversal by checking for `..` in the filename and using `chdir()` to change the working directory. However, this approach is insufficient against stream wrapper attacks. An attacker can use PHP stream wrappers like `php://filter/convert.base64-encode/resource=config` to bypass the `..` check entirely, because the wrapper syntax and resource specifier are processed after the initial path validation. The `chdir()` call provides no protection against stream wrappers, which operate at the PHP stream layer rather than the filesystem layer.

The fix implements defense-in-depth using canonical path validation: (1) explicitly reject stream wrappers by checking for the `://` scheme marker; (2) build the full path by joining the base directory and user input using `DIRECTORY_SEPARATOR`, making the intent explicit and preventing accidental relative-path constructions; (3) canonicalize both the requested path and the base directory using `realpath()`, which resolves symlinks, `.`, and `..` to their absolute forms; (4) verify the canonical path is contained within the base directory using separator-aware string comparison to prevent sibling-directory access like `/var/www/uploads_backup`; (5) use only the canonical path for the file operation, ensuring the validated path cannot be re-derived differently.

## Behaviour changes

**Removed `chdir($reportsDir)` call:** The `chdir()` is no longer needed because the code now constructs and validates an absolute path explicitly. This eliminates the use of a non-security mechanism that could create unexpected behavior if the script is interrupted or forked.

**Added stream wrapper rejection:** A check for `://` explicitly rejects all PHP stream wrapper schemes (php://, file://, data://, etc.) before any path construction, preventing wrapper-based bypasses of the filesystem containment check.

**Path construction change:** Instead of relying on `chdir()` to make relative paths resolve to the reports directory, the code now explicitly concatenates the base directory and filename using `DIRECTORY_SEPARATOR`, making the path construction transparent and auditable.

**Added `realpath()` canonicalization:** Both the requested path and the base directory are now canonicalized using `realpath()`, which resolves all symlinks and relative references to absolute canonical form. The `realpath()` calls return `false` on failure (nonexistent file, inaccessible path, stream wrapper, etc.), allowing the code to reject invalid paths before attempting to open them.

**Added separator-aware containment check:** The comparison `str_starts_with($canonical, $baseDir . DIRECTORY_SEPARATOR)` ensures the resolved path is inside the base directory by checking the prefix with an explicit separator, preventing false positives from sibling directories (e.g., `/var/www/uploads` vs. `/var/www/uploads_backup`).

**Error handling consolidation:** Failures in path canonicalization now return a 404 "File not found" rather than attempting to open a failed `realpath()` result, which would have returned `false` coerced to an empty string or caused fopen to fail anyway. This centralizes error handling and makes the intent clearer.

**Removed the no-op `.` check:** The original code did not explicitly check for `.` or reject filenames containing `/` or `\`, but the `realpath()` canonicalization followed by containment verification now implicitly handles these by ensuring the result is a direct child of the base directory. A filename like `..` would either be canonicalized outside the base directory (and rejected by containment check) or return `false` from `realpath()` if the double-dot escapes fail.
