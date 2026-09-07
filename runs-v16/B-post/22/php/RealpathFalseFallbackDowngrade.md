## Verdict

Confirmed. The code is vulnerable to path traversal when writing new files.

## Source

Line 56: `$_POST['file']` (user-controlled request parameter)

## Fix

**Vulnerable code (line 24-54):**

```php
function saveNote(string $requestedFile, string $content, string $baseDir): void
{
    $candidatePath = $baseDir . DIRECTORY_SEPARATOR . $requestedFile;

    $safePath = realpath($candidatePath) ?: $candidatePath;

    $isContained = $safePath === $baseDir
        || str_starts_with($safePath, $baseDir . DIRECTORY_SEPARATOR);

    if (!$isContained) {
        http_response_code(403);
        echo 'Access to the requested note path is not permitted.';
        return;
    }

    file_put_contents($safePath, $content);
    echo 'Note saved.';
}
```

**Fixed code:**

```php
function saveNote(string $requestedFile, string $content, string $baseDir): void
{
    // Reject filenames containing path separators or traversal sequences
    if ($requestedFile === '' || $requestedFile === '.' || $requestedFile === '..' ||
        strpos($requestedFile, '/') !== false || strpos($requestedFile, '\\') !== false) {
        http_response_code(400);
        echo 'Invalid filename.';
        return;
    }

    // For writes, canonicalize the parent directory (which exists) instead of the destination
    $safePath = realpath($baseDir);
    if ($safePath === false) {
        http_response_code(500);
        exit('Note store is not configured.');
    }

    // Construct the safe path using only the validated filename
    $safePath = $safePath . DIRECTORY_SEPARATOR . $requestedFile;

    file_put_contents($safePath, $content);
    echo 'Note saved.';
}
```

## Explanation

The vulnerability lies in the use of `realpath($path) ?: $path` on a write destination that does not yet exist. The `realpath()` function returns `false` for paths that don't exist, causing the code to fall back to the unresolved path containing traversal sequences. The subsequent validation performs only a string prefix check on the uncanonical path, which passes for any path that textually starts with the base directory, including malicious paths like `"/var/www/notes/../../../etc/passwd"`.

The fix follows the PHP CWE-22 guidance: canonicalize the parent directory (which does exist) and validate that the filename contains no path separators or traversal sequences. This ensures that `realpath()` always succeeds, the returned path is canonical and verified to exist, and only the validated filename is appended to it. The result is a path that is guaranteed to stay within the base directory by construction, not by a fallible string comparison.

## Behaviour changes

- Filenames are now rejected if they are empty, `.`, `..`, or contain forward or backward slashes
- The code no longer relies on a fallback to an unresolved path
- `realpath()` is called only on the base directory, which is guaranteed to exist, so the false-return case is now a fatal configuration error (http 500) rather than a silent vulnerability
- The resulting path is guaranteed to be within the base directory by construction
