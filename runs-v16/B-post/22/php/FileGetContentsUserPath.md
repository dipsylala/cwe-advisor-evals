## Verdict

Exploitable. Untrusted user input (`$_GET['file']`) is concatenated directly into a filesystem path without validation, allowing path traversal via sequences like `../../etc/passwd` to read arbitrary files outside the intended `/var/www/reports` directory.

## Source

Line 9: `$name = $_GET['file']` — attacker-controlled request parameter.

Line 14: `$path = $reportsDir . '/' . $name` — path constructed without containment validation.

## Fix

**Vulnerable code (line 6-26):**

```php
function serve_report(): void
{
    $reportsDir = '/var/www/reports';
    $name = $_GET['file'];

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $name . '"');

    $path = $reportsDir . '/' . $name;

    // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
    $contents = file_get_contents($path);

    if ($contents === false) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    echo $contents;
}
```

**Fixed code:**

```php
function serve_report(): void
{
    $reportsDir = '/var/www/reports';
    $name = $_GET['file'];

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $name . '"');

    $path = $reportsDir . '/' . $name;

    // Canonicalize the path to resolve .. and symlinks
    $realPath = realpath($path);
    
    // Check if the path could be resolved
    if ($realPath === false) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }
    
    // Verify the resolved path stays within the base directory
    $realBase = realpath($reportsDir);
    if ($realBase === false || ($realPath !== $realBase && !str_starts_with($realPath, $realBase . DIRECTORY_SEPARATOR))) {
        http_response_code(403);
        echo 'Access denied';
        return;
    }

    // SAST FINDING: CWE-22 - REMEDIATED
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

The fix eliminates path traversal by canonicalizing user-supplied input and enforcing containment within the intended directory. `realpath()` resolves `.`, `..`, and symlinks to absolute form, converting attack sequences like `../../etc/passwd` to their true targets. The containment check verifies the canonicalized path either equals the base directory or starts with `base . DIRECTORY_SEPARATOR`, preventing sibling-directory escapes. Only the validated path is passed to `file_get_contents()`. Attacks that reference non-existent files (e.g. `../../../../etc/passwd` when intermediate directories do not exist) fail at `realpath()` and return 404 without attempting a read. The separation of "file not found" (404) and "access denied" (403) responses aids debugging.

## Behaviour changes

Two new checks added before the sink:
1. **Canonicalization**: `$realPath = realpath($path)` replaces the untrusted `$path` with a trusted absolute path, resolving all relative and symlink components. Returns `false` on path resolution failure (including non-existent file).
2. **Containment validation**: After establishing `$realPath` is not `false`, a two-part check confirms the path stays within the base directory: exact match (`$realPath !== $realBase`) or prefix match with separator (`!str_starts_with($realPath, $realBase . DIRECTORY_SEPARATOR)`). Failure returns 403 (access denied) rather than 404.

The sink contract is preserved: `file_get_contents()` still receives a valid file path and may return `false` for I/O errors (handled by lines 34-38). The added 403 response distinguishes authorization failures from "not found", improving observability. No return value or argument is changed at the sink itself.
