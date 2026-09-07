## Verdict
CONFIRMED. The code falls back from `realpath()` to an unresolved path when the file doesn't exist, then performs a string prefix check on that unresolved path. This allows `../` sequences in `$requestedFile` to pass the containment check, but those sequences are later resolved by `file_put_contents()`, enabling path traversal outside the notes directory.

## Source
Line 52: `file_put_contents($safePath, $content)` is reached with a path containing unresolved `../` segments because:
- Line 35 uses `realpath()` which returns false for non-existent files
- The fallback `?: $candidatePath` preserves the unreolved path
- Lines 42-43 check string containment (`str_starts_with()`) on the unresolved path, which passes even with traversal sequences
- Line 52 then resolves those sequences during the write, allowing escape from the base directory

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
    // Extract only the filename component, stripping any directory traversal attempts.
    // basename() removes all leading directory separators and path components,
    // preventing ../.. and similar attacks regardless of the input provided.
    $filename = basename($requestedFile);
    
    // Reject any input that contained directory components.
    if ($filename !== $requestedFile) {
        http_response_code(403);
        echo 'Access to the requested note path is not permitted.';
        return;
    }
    
    $candidatePath = $baseDir . DIRECTORY_SEPARATOR . $filename;
    
    // Even though basename() has already stripped traversal sequences,
    // use realpath() for existing files to catch symlink attacks and
    // verify the resolved path remains under the base directory.
    $safePath = realpath($candidatePath);
    
    if ($safePath !== false) {
        // File exists. Verify it is under the base directory.
        $isContained = str_starts_with($safePath, $baseDir . DIRECTORY_SEPARATOR);
        if (!$isContained) {
            http_response_code(403);
            echo 'Access to the requested note path is not permitted.';
            return;
        }
    } else {
        // File does not exist. It is safe to use because basename() has
        // already validated the requested filename.
        $safePath = $candidatePath;
    }
    
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
The fix uses `basename()` to extract only the final path component from `$requestedFile`, which removes all directory separators and parent-directory references. This ensures that even if the user supplies `../../../etc/passwd`, only `passwd` is retained.

Additionally, the fix:
1. Rejects any input where `basename()` differs from the original input, signaling an attempted traversal
2. Still applies `realpath()` to existing files to catch symlink-based escapes
3. Uses the unresolved `$candidatePath` only for new files, which is safe because `basename()` has already stripped all traversal sequences

This approach defends in depth: the initial filtering prevents the traversal sequences from being introduced, and the containment check on existing files provides secondary validation.
