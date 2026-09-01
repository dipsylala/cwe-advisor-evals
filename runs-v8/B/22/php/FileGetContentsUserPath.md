## Verdict

Exploitable. Untrusted input from `$_GET['file']` flows directly into path construction without validation or canonicalization, allowing path traversal sequences like `../` to read arbitrary files outside `/var/www/reports`.

## Source

`$_GET['file']` at line 9, concatenated into `$path` at line 14 without any validation.

## Fix

**Vulnerable code:**
```php
$path = $reportsDir . '/' . $name;

// SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
$contents = file_get_contents($path);

if ($contents === false) {
    http_response_code(404);
    echo 'Report not found';
    return;
}

echo $contents;
```

**Fixed code:**
```php
$path = $reportsDir . '/' . $name;
$realPath = realpath($path);

if ($realPath === false || !str_starts_with($realPath, $reportsDir . DIRECTORY_SEPARATOR)) {
    http_response_code(404);
    echo 'Report not found';
    return;
}

$contents = file_get_contents($realPath);
echo $contents;
```

## Explanation

The fix canonicalizes the constructed path using `realpath()`, which resolves all `.`, `..`, and symbolic links to an absolute path. It then validates containment by confirming the resolved path starts with the allowed directory followed by the directory separator, avoiding false positives from sibling directories like `/var/www/reports_backup`. The validated canonical path is used for the subsequent `file_get_contents()` call, eliminating the path traversal vector. The `realpath() === false` check handles cases where the file doesn't exist or cannot be accessed, and is evaluated before any filesystem operation.

## Behaviour changes

None. The fix validates the path before reading and rejects any file outside `/var/www/reports` with a 404 response, matching the existing error handling contract. The false return from `file_get_contents()` is no longer checked because `realpath()` and containment validation occur upfront; paths that would fail the file read are already rejected. The Content-Disposition header (line 12) still contains the original filename from the request for user convenience, which is appropriate for display purposes and does not re-introduce the traversal risk since the actual file access is controlled by the canonicalized path.
