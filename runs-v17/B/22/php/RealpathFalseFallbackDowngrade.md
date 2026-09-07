## Verdict

exploitable

## Source

`$_POST['file']` parameter (line 56), passed as `$requestedFile` to `saveNote()` function at line 64.

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
    // Validate filename: reject if empty, is a traversal sequence, or contains path separators
    if ($requestedFile === '' || $requestedFile === '.' || $requestedFile === '..' || str_contains($requestedFile, '/') || str_contains($requestedFile, chr(92))) {
        http_response_code(400);
        echo 'Invalid filename.';
        return;
    }

    $safePath = $baseDir . DIRECTORY_SEPARATOR . $requestedFile;

    // Verify containment using separator-terminated comparison
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

The original code contained the antipattern explicitly warned against in the CWE-22 PHP guidance: `realpath($candidatePath) ?: $candidatePath`. For a write operation creating a non-existent file, `realpath()` always returns `false`, causing the fallback to use the unresolved path containing any `../` sequences intact. The containment check then trivially passes because the string literally starts with the base directory prefix, but the path has never been canonicalized to detect traversal. An attacker sending `../../../etc/passwd` would have their traversal sequences written directly to the file path.

The fix validates the filename upfront before path construction, rejecting any input containing path separators (`/` or `\`) or traversal sequences (`.` or `..`). This ensures that the filename is a single path component, making it impossible for traversal sequences to slip through. The parent directory (`$baseDir`) is already canonicalized by `resolveBaseDir()`, so constructing a path from a validated single-component filename guarantees containment. The containment check is retained for defense-in-depth but is now redundant given the filename validation.

## Behaviour changes

1. Invalid filenames (containing `/`, `\`, or being `.`, `..`, or empty) now return HTTP 400 with "Invalid filename." message, whereas the original code would construct and validate the path. This is a tighter constraint but matches the intended requirement that filenames name files "directly inside the notes directory (no subdirectories)".

2. The sink contract is preserved: `file_put_contents()` still receives a single valid path and writes the content unchanged. Return value and error handling behavior are identical.

3. No new dependencies or library calls beyond PHP 8.0 standard library functions (`str_contains()`, already used in the codebase via `str_starts_with()` on line 43 of the original).
