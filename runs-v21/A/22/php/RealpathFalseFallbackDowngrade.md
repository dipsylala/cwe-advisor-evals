## Verdict
Confirmed. The containment check on lines 42-43 is ineffective when `realpath()` returns false for non-existent files, allowing path traversal to directories outside the notes store.

## Source
The vulnerability is on line 35: `$safePath = realpath($candidatePath) ?: $candidatePath;`

When saving a new file (the common case), `realpath()` returns false because the destination does not yet exist. The fallback uses the unconstructed `$candidatePath`, which still contains any `../` sequences from the request. The subsequent containment check (lines 42-43) then compares the literal unresolved path against the base directory, which passes incorrectly for traversal sequences like `../../../etc/passwd`.

## Fix

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
    // Use basename() to strip any directory path components from the request,
    // ensuring the filename cannot contain traversal sequences like '../' or
    // leading slashes that would escape the base directory.
    $filename = basename($requestedFile);

    // Construct the safe path using only the filename component.
    $safePath = $baseDir . DIRECTORY_SEPARATOR . $filename;

    // Since $filename is now guaranteed to contain no directory separators
    // or leading slashes, $safePath will always be contained within $baseDir.
    // The check remains for defense in depth.
    $isContained = $safePath === $baseDir
        || str_starts_with($safePath, $baseDir . DIRECTORY_SEPARATOR);

    if (!$isContained) {
        http_response_code(403);
        echo 'Access to the requested note path is not permitted.';
        return;
    }

    // Path traversal is now prevented because basename() removes all directory
    // components, ensuring the file is saved directly in the base directory.
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
The fix uses `basename()` to extract only the filename component from the user-supplied request, removing any directory path components. This ensures that:

1. Traversal sequences like `../../../etc/passwd` are stripped to just `passwd`
2. Leading slashes or drive letters are removed
3. The resulting filename cannot escape the base directory regardless of what the request contains

The containment check remains in place for defense in depth, but the real protection now comes from the fact that `$filename` is guaranteed to have no directory structure. When concatenated with `$baseDir`, the resulting path is always directly inside the notes directory.
