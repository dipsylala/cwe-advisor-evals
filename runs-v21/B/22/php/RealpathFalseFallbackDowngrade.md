## Verdict

CONFIRMED. The path traversal vulnerability is exploitable. An attacker-controlled filename passed via `$_POST['file']` is concatenated directly into the save path without proper canonicalization, allowing traversal sequences like `../../etc/passwd` to escape the intended notes directory.

## Source

`$_POST['file']` at line 56, cast to string and passed to `saveNote()`.

## Fix

Replace the `saveNote()` function to validate the filename (rejecting empty strings, `.`, `..`, and any path separators) rather than attempting to canonicalize a non-existent destination path:

### File: RealpathFalseFallbackDowngrade.php

```php
<?php
declare(strict_types=1);

/**
 * Note-saving endpoint.
 *
 * Writes a plain-text note under the "notes" directory. The file name is
 * supplied as a request field and is expected to name a new file directly
 * inside the notes directory (no subdirectories).
 */

const NOTES_DIR_NAME = 'notes';

function resolveBaseDir(): string
{
    $base = realpath(__DIR__ . DIRECTORY_SEPARATOR . NOTES_DIR_NAME);
    if ($base === false) {
        http_response_code(500);
        exit('Note store is not configured.');
    }
    return $base;
}

function saveNote(string $requestedFile, string $content, string $baseDir): void
{
    // Validate the filename: reject empty, ".", "..", or any path containing separators.
    // This ensures the filename is a single component that cannot traverse directories.
    if ($requestedFile === '' || $requestedFile === '.' || $requestedFile === '..' 
        || str_contains($requestedFile, DIRECTORY_SEPARATOR) 
        || str_contains($requestedFile, '/') 
        || str_contains($requestedFile, '\\')) {
        http_response_code(400);
        echo 'Invalid file name.';
        return;
    }

    // Construct the final path by concatenating the canonicalized parent directory
    // with the validated single-component filename. Since $baseDir is already
    // canonicalized by realpath() in resolveBaseDir(), and the filename is validated
    // to contain no separators, the result is guaranteed to be within $baseDir.
    $safePath = $baseDir . DIRECTORY_SEPARATOR . $requestedFile;

    file_put_contents($safePath, $content);
    echo 'Note saved.';
}

$requestedFile = isset($_POST['file']) ? (string) $_POST['file'] : '';
$content = isset($_POST['content']) ? (string) $_POST['content'] : '';
if ($requestedFile === '') {
    http_response_code(400);
    exit('Missing "file" parameter.');
}

$baseDir = resolveBaseDir();
saveNote($requestedFile, $content, $baseDir);
```

## Explanation

The original code attempted to validate the path by calling `realpath($candidatePath) ?: $candidatePath`. This pattern fails for write operations because `realpath()` returns `false` when the destination does not yet exist (which is always true for a new note save). The fallback then silently uses the uncanonicalized path with any `../` sequences intact. The subsequent containment check using `str_starts_with()` on this unresolved path incorrectly accepts traversal attacks because a literal string like `/notes/../../etc/passwd` does technically start with `/notes/`.

The fix validates the filename **before** path construction. By rejecting any input containing path separators (both forward and backward slashes) or the special directory references (`.`, `..`), we ensure the filename is a single component that cannot reference parent directories. Since the base directory `$baseDir` is already canonicalized via `realpath()`, concatenating it with a validated single-component filename guarantees the result stays within the intended directory. This follows the PHP-specific guidance: for writes to non-existent destinations, canonicalize the parent (already done), validate the filename component, and construct the path by direct concatenation.

## Behaviour changes

- The function now rejects filenames containing any path separators (`/`, `\`) or the special components (`.`, `..`), returning HTTP 400 with an error message instead of proceeding.
- Legitimate single-file saves in the notes directory continue to work unchanged.
- Attack attempts using traversal sequences (e.g., `../../etc/passwd`, `..%2Fetc%2Fpasswd`) are rejected before the file operation.
- The code is simpler and does not rely on the fragile `realpath()` fallback pattern.
