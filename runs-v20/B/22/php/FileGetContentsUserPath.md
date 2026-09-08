## Verdict

Confirmed. `serve_report()` builds a filesystem path by concatenating the untrusted `$_GET['file']` value directly onto a fixed base directory and passes the result to `file_get_contents()` with no canonicalization or containment check, so a value such as `../../../etc/passwd` (or a sibling directory like `../secret/passwd.txt`) is read and returned in the response.

## Source

`$_GET['file']` (line 9), read into `$name` and concatenated into `$path` at line 14 with no validation in between. Single-file case; no intermediate helper functions.

## Fix

### File: FileGetContentsUserPath.php

```php
<?php

// Serves a document from the shared reports directory. The report name
// is expected to be a filename like "invoice-2024.pdf" under /var/www/reports.

function serve_report(): void
{
    $reportsDir = '/var/www/reports';
    $name = $_GET['file'];

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $name . '"');

    $base = realpath($reportsDir);
    $path = $reportsDir . '/' . $name;
    $resolved = realpath($path);

    $withinBase = $base !== false && $resolved !== false
        && ($resolved === $base || str_starts_with($resolved, $base . DIRECTORY_SEPARATOR));

    if (!$withinBase) {
        http_response_code(404);
        echo 'Report not found';
        return;
    }

    $contents = file_get_contents($resolved);

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

The fix canonicalizes both the fixed reports directory and the requested path with `realpath()`, which resolves `.`, `..`, and symlinks to an absolute form, and then checks the resolved candidate against the resolved base using a separator-terminated comparison (`$resolved === $base || str_starts_with($resolved, $base . DIRECTORY_SEPARATOR)`) rather than a raw string prefix, which would incorrectly admit a sibling directory such as `/var/www/reports_backup`. Because `realpath()` requires the target to exist, a `false` result (traversal target outside the tree, missing file, or an unresolvable component) is treated as "not found" before any comparison runs, matching the existing 404 behaviour for a genuinely missing report and keeping the failure mode fail-closed. The sink now reads from `$resolved` - the same canonicalized, contained value that was just checked - rather than re-deriving or reusing the original tainted `$path`, so the check and the read cannot diverge. Legitimate requests for files that already exist under `/var/www/reports` are unaffected; requests using `../` sequences, absolute paths, or paths resolving into a different directory are rejected. The `Content-Disposition` header still echoes the raw `$name` value; that is a separate CRLF/header-injection concern (not CWE-22) and is out of scope for this path-traversal finding, so it was left unchanged.

## Behaviour changes

- A request whose resolved path escapes `/var/www/reports` (via `../`, an absolute path, or a symlink) now returns HTTP 404 with "Report not found" instead of returning the contents of the out-of-tree file.
- A request for a file that does not exist under the reports directory continues to return HTTP 404 "Report not found", as before (previously via `file_get_contents() === false`, now via the `realpath()` containment check catching it first) - no change in observable behaviour for this case.
- Legitimate requests for existing files inside `/var/www/reports` continue to succeed with identical output.
- If `/var/www/reports` itself is missing or unreadable by the process (a deployment/configuration fault rather than a per-request condition), every request now returns 404 instead of failing later inside `file_get_contents()`; this is a fail-closed change in a misconfiguration scenario that was not previously validated.
