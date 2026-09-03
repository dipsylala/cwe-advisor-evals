## Verdict

Exploitable

## Source

User-supplied filename from `$_POST['file']` (line 56), passed to `saveNote()` as `$requestedFile` parameter (line 64).

## Fix

**Vulnerable code (lines 24-54):**

```php
function saveNote(string $requestedFile, string $content, string $baseDir): void
{
    $candidatePath = $baseDir . DIRECTORY_SEPARATOR . $requestedFile;

    // realpath() canonicalizes '.' and '..' segments and resolves symlinks,
    // but it returns false unless every component of the path already
    // exists. A note being SAVED for the first time is, by definition, a
    // destination that does not exist yet - so realpath() returns false on
    // essentially every legitimate save, not just malicious ones - and this
    // falls back to the original, unresolved candidate path so the save can
    // proceed.
    $safePath = realpath($candidatePath) ?: $candidatePath;

    // Because $safePath is now just $baseDir . DIRECTORY_SEPARATOR . $requestedFile
    // (unresolved, '../' segments and all), it always starts with $baseDir by
    // construction - the check below passes for literally any $requestedFile,
    // traversal sequences included, since nothing here actually canonicalizes
    // the path before comparing it.
    $isContained = $safePath === $baseDir
        || str_starts_with($safePath, $baseDir . DIRECTORY_SEPARATOR);

    if (!$isContained) {
        http_response_code(403);
        echo 'Access to the requested note path is not permitted.';
        return;
    }

    // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
    file_put_contents($safePath, $content);
    echo 'Note saved.';
}
```

**Fixed code (lines 24-36):**

```php
function saveNote(string $requestedFile, string $content, string $baseDir): void
{
    // Validate filename component: reject empty, relative path components, and separators.
    // This prevents traversal via '..' and direct separator injection.
    if ($requestedFile === '' || $requestedFile === '.' || $requestedFile === '..' ||
        str_contains($requestedFile, '/') || str_contains($requestedFile, '\\')) {
        http_response_code(400);
        echo 'Invalid filename.';
        return;
    }

    $safePath = $baseDir . DIRECTORY_SEPARATOR . $requestedFile;
    file_put_contents($safePath, $content);
    echo 'Note saved.';
}
```

## Explanation

The vulnerability stems from the anti-pattern `realpath($path) ?: $path` on line 35. When the destination file does not yet exist (the normal case for a save operation), `realpath()` returns `false`, and the code silently falls back to the unresolved candidate path containing any traversal sequences the attacker supplied. The subsequent containment check (lines 42–43) is then meaningless: it compares a raw string that was constructed by concatenating the base directory with the untrusted filename, so it always passes regardless of whether `$requestedFile` contains `../` sequences. When `file_put_contents()` executes, the OS resolves these sequences, allowing writes outside the intended `notes/` directory.

The fix validates the filename as a single path component before constructing the final path. By rejecting empty strings, `.`, `..`, and any input containing path separators, the code ensures that `$requestedFile` cannot contain traversal sequences. The final path is then guaranteed to be safely contained within `$baseDir`, because the filename itself has no way to escape the directory. The `realpath()` fallback anti-pattern and flawed containment check are removed entirely, replaced by direct filename validation appropriate for a write operation where the destination does not yet exist.

## Behaviour changes

- **Rejects relative path components**: Input containing `.` or `..` now returns HTTP 400 instead of attempting the write.
- **Rejects path separators**: Input containing `/` or `\` now returns HTTP 400 instead of attempting the write.
- **Rejects empty filenames**: Empty `$requestedFile` now returns HTTP 400 instead of attempting to write to the base directory itself.
- **Simpler response**: Returns HTTP 400 (Bad Request) for invalid input rather than HTTP 403 (Forbidden). This is semantically correct because invalid filename format is a client error, not an authorization failure.
- **No change to legitimate use**: Valid single-component filenames (e.g., `notes.txt`, `user-data`) proceed to `file_put_contents()` exactly as before.
