## Verdict

Confirmed. `saveNote()` builds `$candidatePath` by concatenating the trusted `$baseDir` with the attacker-controlled `$requestedFile`, then tries to validate containment by resolving that path with `realpath()`. Because the target file does not exist yet (this is a save-new-file endpoint), `realpath()` returns `false` on every legitimate call, and the code falls back to the original, unresolved `$candidatePath`. The subsequent containment check (`$safePath === $baseDir || str_starts_with($safePath, $baseDir . DIRECTORY_SEPARATOR)`) then compares `$baseDir . DIRECTORY_SEPARATOR . $requestedFile` against a prefix built from the same `$baseDir` and separator - it is a tautology that passes for any `$requestedFile`, traversal sequences included. `file_put_contents($safePath, $content)` then writes wherever `$requestedFile` points, e.g. `../../var/www/html/shell.php` or an absolute path.

## Source

`$_POST['file']` (assigned to `$requestedFile` at line 56) flows unmodified into `saveNote()`'s `$requestedFile` parameter and from there into `$candidatePath` / `$safePath` and the `file_put_contents()` sink at line 52.

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
    // realpath() canonicalizes '.' and '..' segments and resolves symlinks,
    // but it returns false unless every component of the path already
    // exists. A note being SAVED for the first time is, by definition, a
    // destination that does not exist yet, so realpath() cannot be used to
    // canonicalize $requestedFile before checking containment.
    //
    // Instead, validate the requested name structurally: this endpoint's
    // contract is a bare file name directly inside $baseDir, with no
    // subdirectories, so reject anything that isn't exactly that - a
    // separator, a null byte, '.', '..', or an empty string - before the
    // path is ever built. basename($requestedFile) !== $requestedFile
    // catches both '/'- and '\'-style traversal and any embedded directory
    // component in one check.
    $isValidFileName = $requestedFile !== ''
        && $requestedFile !== '.'
        && $requestedFile !== '..'
        && !str_contains($requestedFile, "\0")
        && !str_contains($requestedFile, '/')
        && !str_contains($requestedFile, '\\')
        && basename($requestedFile) === $requestedFile;

    if (!$isValidFileName) {
        http_response_code(403);
        echo 'Access to the requested note path is not permitted.';
        return;
    }

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

The vulnerable code tried to validate a not-yet-existing path with `realpath()`, which cannot canonicalize a path whose final component does not exist - so it silently fell back to the raw, attacker-controlled path and then compared that path against a prefix derived from itself, which can never fail. That containment check is deleted entirely rather than patched, because no post-hoc canonicalization of `$baseDir . $requestedFile` can be trusted when the target file is new.

The replacement validates `$requestedFile` on its own terms, before it is ever combined with `$baseDir`: the docblock states the field must name a file directly inside the notes directory with no subdirectories, so the fix enforces exactly that structural contract - reject empty strings, `.`/`..`, null bytes, and any path separator, and require `basename($requestedFile) === $requestedFile` so no embedded directory component of any form survives. This is not a generic character allowlist bolted on for security; it is the application's own stated format for the field, so it rejects nothing the endpoint was ever meant to accept while closing every traversal form (`../`, `..\`, an absolute path, a rooted UNC-style path) without relying on filesystem state. Once `$requestedFile` is known to be a bare name, `$safePath` is built once from `$baseDir` and used directly, so there is no re-derivation for an attacker-controlled value to slip through.
