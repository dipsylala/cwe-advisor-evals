## Verdict

Exploitable. A denylist check for `..` does not block PHP stream wrappers like `php://`, `file://`, `data://`, `zip://`, etc., which allow an attacker to read arbitrary files outside the intended directory without using relative-path traversal sequences. For example, `php://filter/convert.base64-encode/resource=../../../etc/passwd` contains no `..` and is not rejected by the current filter check, but it reaches the filesystem via PHP's stream wrapper mechanism.

## Source

`$_GET['file']` at line 15. Attacker-controlled filename parameter from the request.

## Fix

**Vulnerable code (lines 23-33):**
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
    // Reject stream wrappers and path separators - require a single filename component
    if (str_contains($file, '/') || str_contains($file, '\\') || str_contains($file, '://')) {
        http_response_code(400);
        echo 'Invalid file parameter';
        return;
    }

    // Build the full path and canonicalize
    $fullPath = $reportsDir . DIRECTORY_SEPARATOR . $file;
    $canonicalPath = realpath($fullPath);
    
    // Handle realpath() failure (file doesn't exist or is a stream wrapper)
    if ($canonicalPath === false) {
        http_response_code(404);
        echo 'File not found';
        return;
    }

    // Verify containment: canonicalized path must be within the reports directory
    $canonicalReportsDir = realpath($reportsDir);
    if ($canonicalReportsDir === false || 
        ($canonicalPath !== $canonicalReportsDir && !str_starts_with($canonicalPath, $canonicalReportsDir . DIRECTORY_SEPARATOR))) {
        http_response_code(403);
        echo 'Access denied';
        return;
    }

    // Safe to open the file
    $handle = fopen($canonicalPath, 'r');
```

## Explanation

The fix prevents path traversal in three ways. First, it rejects input containing `/`, `\`, or `://`, which blocks both absolute paths and stream wrapper schemes. Second, it uses `realpath()` to canonicalize the full path, resolving `.`, `..`, and symlinks to their true forms—`realpath()` also returns `false` for stream wrapper URIs, further closing the vulnerability. Third, it enforces containment by comparing the canonical path against the canonical reports directory using `str_starts_with()` with the directory separator appended, preventing sibling-directory escapes. The vulnerable denylist check for `..` is replaced with a canonical-then-contain control that handles all path-traversal encodings and stream-wrapper bypasses in a single validation step. The `chdir()` call is removed because the full path is now built and validated upfront, making the relative-path change unnecessary.

## Behaviour changes

- **Absolute path comparison instead of relative**: The original code relied on `chdir()` and a relative filename. The fix builds an absolute path, canonicalizes it, and opens it by absolute path. This eliminates the implicit working-directory dependency and makes the containment check explicit.
- **HTTP status codes for new conditions**: The fix returns 403 Forbidden if the file exists but is outside the permitted directory (previously would have opened it if the denylist was bypassed). The 404 Not Found response now covers both missing files and stream-wrapper URIs (which `realpath()` rejects). This is correct for the containment and access-control semantics, though it changes the error surface for attack attempts.
- **Removal of `chdir()`**: The original `chdir($reportsDir)` is no longer present because paths are validated and opened as absolute. This reduces implicit state and makes the function's behavior independent of the working directory at invocation time.
- **No change to return type or success path**: On success, the function still opens, streams, and closes the file identically, preserving the existing caller contract.
