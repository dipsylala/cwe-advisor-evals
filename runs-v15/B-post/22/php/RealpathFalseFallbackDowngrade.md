## Verdict

exploitable

## Source

`$_POST['file']` (line 56), cast to string and passed to `saveNote()` as `$requestedFile`

## Fix

**Vulnerable code:**
```php
function saveNote(string $requestedFile, string $content, string $baseDir): void
{
    $candidatePath = $baseDir . DIRECTORY_SEPARATOR . $requestedFile;

    // realpath() returns false for a destination that does not exist yet,
    // and the fallback returns the unresolved path with '../' still intact
    $safePath = realpath($candidatePath) ?: $candidatePath;

    // String containment check cannot catch traversal in unresolved paths
    $isContained = $safePath === $baseDir
        || str_starts_with($safePath, $baseDir . DIRECTORY_SEPARATOR);

    if (!$isContained) {
        http_response_code(403);
        echo 'Access to the requested note path is not permitted.';
        return;
    }

    // VULNERABLE: $safePath may contain '../' sequences that pass the string check
    file_put_contents($safePath, $content);
    echo 'Note saved.';
}
```

**Fixed code:**
```php
function saveNote(string $requestedFile, string $content, string $baseDir): void
{
    // Reject empty filename or filename components that could escape the base directory
    if ($requestedFile === '' || $requestedFile === '.' || $requestedFile === '..' ||
        strpos($requestedFile, '/') !== false || strpos($requestedFile, '\\') !== false) {
        http_response_code(400);
        echo 'Invalid filename.';
        return;
    }

    // Build the path from the canonicalized base directory and validated filename.
    // Since the filename contains no separators and baseDir is already canonicalized,
    // the result is guaranteed to be within the base directory.
    $safePath = $baseDir . DIRECTORY_SEPARATOR . $requestedFile;

    file_put_contents($safePath, $content);
    echo 'Note saved.';
}
```

## Explanation

The vulnerability is in line 35's `realpath($candidatePath) ?: $candidatePath` pattern, which the CWE-22 PHP guidance explicitly warns against. When a new file is being created, `realpath()` returns false because the destination does not yet exist, triggering the fallback to return the unresolved `$candidatePath` with any `../` sequences still intact. The containment check on lines 42–43 then performs only string matching, which cannot detect traversal sequences in an unresolved path—for example, `../../../etc/passwd` would pass a `str_starts_with()` test against the base directory. The fix validates the filename component upfront to reject any value containing path separators (`/` or `\`), relative references (`.` or `..`), or empty strings. Since `$baseDir` is already canonicalized in `resolveBaseDir()` and the filename is guaranteed to be a single safe component, the concatenated path cannot escape the intended directory.

## Behaviour changes

- The function now rejects filenames containing `/` or `\`, and filenames that are exactly `.` or `..`. Previously, these were allowed and validated only by string matching against the base directory.
- Error responses for invalid filenames changed from a 403 Forbidden (insufficient containment check) to 400 Bad Request (rejected at validation).
- The containment logic is now implicit: instead of trying to canonicalize a non-existent destination and then checking containment, the fix ensures the filename is a single safe component, making containment a structural property of the constructed path.
- The sink contract is preserved: `file_put_contents()` still returns the number of bytes written, or false on error, with the same exception-throwing behavior for invalid paths or permission failures.
