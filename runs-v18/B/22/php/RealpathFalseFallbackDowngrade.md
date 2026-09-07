## Verdict

CONFIRMED: CWE-22 path traversal vulnerability at line 52 of RealpathFalseFallbackDowngrade.php. The code uses the anti-pattern `realpath($path) ?: $path` which silently downgrades to an unresolved path when the destination does not yet exist (the expected case for a write operation). Combined with string-prefix containment checking, this allows attackers to write files outside the intended notes directory via path traversal sequences like `../`.

## Source

**File:** RealpathFalseFallbackDowngrade.php  
**Vulnerable Code Location:** Lines 24-54 (saveNote function)  
**Primary Issue:** Line 35

The vulnerability appears in the write path where:
1. Line 35 attempts to canonicalize the combined path with `realpath()`, but falls back to the unresolved path when it returns false (the normal case for new files)
2. Lines 42-43 perform only string prefix matching to check containment, which is bypassed because the unresolved path naturally starts with the base directory string
3. Line 52 writes the file using the unvalidated, unresolved path

**Attack Scenario:** An attacker supplies `requestedFile` value like `../../../etc/target.txt`, which passes the string prefix check since `"/base/notes/../../../etc/target.txt"` starts with `"/base/notes"`, but the file is written outside the intended directory.

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
    // Validate that the requested file is a single path component (no separators, no traversal sequences).
    if ($requestedFile === '' || $requestedFile === '.' || $requestedFile === '..'
        || str_contains($requestedFile, '/') || str_contains($requestedFile, '\\')) {
        http_response_code(403);
        echo 'Access to the requested note path is not permitted.';
        return;
    }

    $safePath = $baseDir . DIRECTORY_SEPARATOR . $requestedFile;

    // The base directory has been canonicalized in resolveBaseDir().
    // The filename has been validated as a single component above.
    // Open with mode 'x' to atomically create and reject any existing file or symlink.
    try {
        $handle = fopen($safePath, 'x');
        if ($handle === false) {
            http_response_code(500);
            echo 'Failed to save note.';
            return;
        }
        fwrite($handle, $content);
        fclose($handle);
        echo 'Note saved.';
    } catch (ValueError $e) {
        http_response_code(403);
        echo 'Access to the requested note path is not permitted.';
    }
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

The fix applies four key changes from the CWE-22 PHP remediation guidance:

1. **Input Validation for Single Component:** Lines 27-31 now validate that `$requestedFile` is empty, `.`, `..`, or contains path separators (`/` or `\`). This rejects all traversal sequences at the point they enter the code. For writes (where the destination doesn't exist yet), this is the appropriate control—relying on `realpath()` fails because it returns false for non-existent paths.

2. **Removed Fallback Pattern:** Deleted the problematic `realpath($candidatePath) ?: $candidatePath` pattern. The fallback silently kept the original, unvalidated path when the destination didn't exist, defeating the security check.

3. **Removed String-Prefix Containment Check:** Deleted lines 42-43 that checked `str_starts_with($safePath, $baseDir . DIRECTORY_SEPARATOR)`. This check is insufficient for write operations because the path is not canonicalized. It is no longer needed because the filename is now guaranteed to be a single component by validation.

4. **Atomic File Creation:** Replaced `file_put_contents()` with `fopen($safePath, 'x')` (exclusive create mode). Mode `'x'` atomically creates the file and fails if it already exists or if a symlink points outside the base directory. This adds a defense-in-depth hardening layer that prevents symlink-based traversal attacks. The try-catch block handles the `ValueError` raised in strict-types mode when mode `'x'` fails (file exists).

The base directory `$baseDir` remains canonicalized by `resolveBaseDir()`, so path containment is now enforced structurally: the base is real and absolute, the filename is a single component, and the concatenation cannot escape the base.

## Behaviour changes

- **File creation now atomic:** Requests to save a file that already exists now fail (status 500 or caught ValueError → 403) instead of truncating and overwriting the existing content.
- **Symlink attacks prevented:** Planting a symlink in the notes directory that points outside is no longer exploitable because `fopen(..., 'x')` will fail when it detects the symlink resolution.
- **Traversal sequences rejected:** Requests containing `../`, `..\\`, absolute paths, or path separators are rejected with HTTP 403 before any filesystem operation.
- **Error messages refined:** Failures to create the file due to existing files or permission errors now return a 500 "Failed to save note" response instead of silently succeeding or truncating.

All legitimate use cases (saving a new file with a simple filename inside the notes directory) continue to work. A valid filename like `my-note.txt` passes validation and is written atomically.
