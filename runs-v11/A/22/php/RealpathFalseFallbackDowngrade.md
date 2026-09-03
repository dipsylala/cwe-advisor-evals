## Verdict

Confirmed. The path traversal vulnerability exists because the containment check uses an uncanonicalized path that still contains unresolved `../` sequences when the target file does not yet exist.

## Source

Line 35 creates a fallback for new files: `$safePath = realpath($candidatePath) ?: $candidatePath;`

When a file doesn't exist, `realpath()` returns `false`, so `$safePath` becomes the original `$candidatePath` without canonicalization. Lines 42-43 then check if this unresolved path starts with `$baseDir`, which passes even for paths like `/path/to/notes/../../../etc/passwd` because the string comparison sees it begins with `/path/to/notes`, but the actual file written by `file_put_contents()` on line 52 resolves the `..` sequences and lands outside the intended directory.

## Fix

Replace the fallback logic and validation check with a basename-based approach that prevents traversal sequences entirely:

```php
function saveNote(string $requestedFile, string $content, string $baseDir): void
{
    // Reject any path component containing traversal sequences or separators
    $fileName = basename($requestedFile);
    
    if ($fileName !== $requestedFile || $fileName === '') {
        http_response_code(403);
        echo 'Access to the requested note path is not permitted.';
        return;
    }
    
    $safePath = $baseDir . DIRECTORY_SEPARATOR . $fileName;
    
    // Verify the resolved path stays within the base directory
    $realSafePath = realpath(dirname($safePath)) . DIRECTORY_SEPARATOR . $fileName;
    $realBase = realpath($baseDir);
    
    if ($realBase === false || !str_starts_with($realSafePath, $realBase . DIRECTORY_SEPARATOR)) {
        http_response_code(403);
        echo 'Access to the requested note path is not permitted.';
        return;
    }
    
    file_put_contents($safePath, $content);
    echo 'Note saved.';
}
```

## Explanation

The fix applies three defensive layers:

1. **Basename extraction**: `basename($requestedFile)` strips any directory path components, so `../../../etc/passwd` becomes `passwd`.

2. **Equality check**: Comparing `basename($fileName) === $requestedFile` ensures the caller supplied only a filename, with no path separators or traversal sequences. If they differ, the request is rejected.

3. **Canonical verification before write**: `realpath(dirname($safePath))` resolves the parent directory (which is guaranteed to be `$baseDir` by construction), then we reconstruct the full path and verify it remains under the base directory. This catches any edge case where `dirname()` behaves unexpectedly. The check now uses the canonical `$realBase` so string comparison against it is reliable.

This prevents path traversal by structure: the filename can only be a basename with no separators, and the parent is always the validated base directory.
