## Verdict

EXPLOITABLE. The vulnerability permits arbitrary file creation outside the intended notes directory through path traversal sequences.

## Source

User-supplied filename from `$_POST['file']` at line 56, passed to `saveNote()` as `$requestedFile` parameter.

## Fix

The vulnerability stems from two defects:

1. **Line 35**: `$safePath = realpath($candidatePath) ?: $candidatePath;` silently downgrades to an unresolved path when the destination file doesn't exist (the common case for a new save), allowing traversal sequences like `../` to persist unchecked.

2. **Lines 42-43**: The containment check uses string comparison on the unresolved path, so `/app/notes/../../../etc/passwd` still starts with `/app/notes` and passes the check.

The fix follows the PHP guidance for write destinations: validate the filename as a single path component (rejecting separators), canonicalize the parent directory to confirm it hasn't escaped via symlinks, and construct the final path from validated inputs.

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
    // For a write, the destination does not exist yet, so canonicalize the parent
    // directory and validate the filename as a single path component.

    // Reject a filename that is empty, '.', '..', or contains path separators.
    if ($requestedFile === '' || $requestedFile === '.' || $requestedFile === '..' ||
        str_contains($requestedFile, '/') || str_contains($requestedFile, '\\')) {
        http_response_code(400);
        echo 'Invalid filename.';
        return;
    }

    // Build the candidate path from the base directory and validated filename.
    $candidatePath = $baseDir . DIRECTORY_SEPARATOR . $requestedFile;

    // Canonicalize the parent directory to verify containment and detect symlink escapes.
    $resolvedParent = realpath(dirname($candidatePath));
    if ($resolvedParent === false || $resolvedParent !== $baseDir) {
        http_response_code(403);
        echo 'Access to the requested note path is not permitted.';
        return;
    }

    // Write the file using the constructed path.
    file_put_contents($candidatePath, $content);
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

The fix eliminates the path traversal by applying three layers of control:

1. **Filename validation**: The filename is tested to ensure it contains no path separators (`/` or `\`) and is not the special names `.` or `..`. This prevents the request from introducing traversal sequences in the first place.

2. **Canonical parent verification**: After constructing the path, the parent directory is canonicalized using `realpath()`, which resolves symlinks and relative references. The resolved parent is verified to equal the base directory. This catches any attempt to escape via symlinks or canonicalization tricks.

3. **Checked-and-used pattern**: The constructed `$candidatePath` (built from validated inputs and a canonicalized parent) is the same variable passed to `file_put_contents()`, ensuring the validation applies to the exact path that gets written.

The fix removes the unsafe `realpath() ?: $path` fallback (which downgraded writes to an unresolved path), replaces the weak string-prefix check with proper path-component validation, and enforces a single-component filename requirement appropriate for user-supplied note filenames.

## Behaviour changes

- **New error case**: Filenames containing `/`, `\`, or the names `.` or `..` are rejected with a 400 response. Previously they were accepted and caused directory traversal.
- **New 400 response**: Empty filenames now receive a 400 response instead of being silently accepted.
- **No change to legitimate saves**: Valid single-component filenames like `notes.txt`, `shopping-list`, or `ideas_2025` are saved normally.
- **Error response change for certain escapes**: Some traversal attempts now return 400 (invalid filename format) instead of 403 (access denied), providing clearer client feedback.
- **Verification result**: PHP syntax check passed (`php -l` returned no errors).
