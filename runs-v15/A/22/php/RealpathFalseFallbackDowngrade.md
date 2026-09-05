## Verdict

The code is vulnerable to path traversal. The vulnerability lies in the fallback logic at line 35, which uses an unresolved path when `realpath()` fails (as it does for new files). The subsequent containment check at lines 42-43 validates an uncanonicalised path that still contains `../` segments, allowing traversal outside the intended directory.

## Source

```php
$safePath = realpath($candidatePath) ?: $candidatePath;

$isContained = $safePath === $baseDir
    || str_starts_with($safePath, $baseDir . DIRECTORY_SEPARATOR);

if (!$isContained) {
    http_response_code(403);
    echo 'Access to the requested note path is not permitted.';
    return;
}

file_put_contents($safePath, $content);
```

The problem: when the file does not exist, `realpath($candidatePath)` returns `false`, so `$safePath` becomes the unresolved `$candidatePath`. Since `$candidatePath` is always constructed as `$baseDir . DIRECTORY_SEPARATOR . $requestedFile`, the `str_starts_with()` check always succeeds, even if `$requestedFile` contains `../` sequences. The unresolved path is then passed to `file_put_contents()`, allowing writes outside the intended directory.

## Fix

Replace the `saveNote()` function to validate the requested filename before constructing the path:

```php
function saveNote(string $requestedFile, string $content, string $baseDir): void
{
    // Reject filenames containing directory separators or traversal sequences
    if (strpbrk($requestedFile, '/\\') !== false || str_contains($requestedFile, '..')) {
        http_response_code(400);
        echo 'Invalid file name.';
        return;
    }

    // Construct the full path safely
    $safePath = $baseDir . DIRECTORY_SEPARATOR . $requestedFile;
    
    // Verify the resolved path is within the base directory
    $realBase = realpath($baseDir);
    $realPath = realpath(dirname($safePath));
    
    // If the file exists, realpath() gives us the canonical path; if not, we check the directory
    if ($realPath === false || !str_starts_with($realPath, $realBase)) {
        http_response_code(403);
        echo 'Access to the requested note path is not permitted.';
        return;
    }

    file_put_contents($safePath, $content);
    echo 'Note saved.';
}
```

## Explanation

The fix uses two strategies:

1. **Input validation**: Reject any filename containing `/`, `\`, or `..` sequences. This prevents path traversal attempts at the input stage.

2. **Canonical containment check**: For new files, we validate the parent directory (resolved via `realpath()` on `dirname()`) to ensure it remains within `$baseDir`. This approach works because we've already rejected traversal sequences in the filename, so the parent directory is safe to construct. We resolve `$baseDir` once and check that the file's parent directory is within it.

Together, these prevent an attacker from escaping the notes directory regardless of whether the target file exists.
