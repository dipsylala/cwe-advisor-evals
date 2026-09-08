## Verdict

exploitable

- **CWE**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'))
- **Location**: `RealpathFalseFallbackDowngrade.php`, `saveNote()`, sink at line 52 (`file_put_contents($safePath, $content)`)
- **Confidence**: high

## Source

`$_POST['file']` (line 56) is cast to string and, after only an empty-string check, passed unmodified as `$requestedFile` into `saveNote()` (line 64).

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
    // A note is a single file directly inside the notes directory (no
    // subdirectories), so the filename must be exactly one path component.
    // Reject anything empty, '.', '..', or containing a path separator
    // before it is ever concatenated onto $baseDir. This is checked on the
    // raw filename rather than via realpath() + containment, because
    // realpath() cannot canonicalize a path that does not exist yet - which
    // is always true for a note being saved for the first time - so a
    // realpath() failure here would say nothing about traversal.
    $isSingleComponent = $requestedFile !== ''
        && $requestedFile !== '.'
        && $requestedFile !== '..'
        && !str_contains($requestedFile, '/')
        && !str_contains($requestedFile, '\\');

    if (!$isSingleComponent) {
        http_response_code(403);
        echo 'Access to the requested note path is not permitted.';
        return;
    }

    $safePath = $baseDir . DIRECTORY_SEPARATOR . $requestedFile;

    // Open exclusively: an existing file at this name, or a symlink planted
    // there, is refused rather than truncated or followed.
    $handle = @fopen($safePath, 'xb');
    if ($handle === false) {
        http_response_code(409);
        echo 'A note with that name already exists.';
        return;
    }

    fwrite($handle, $content);
    fclose($handle);
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

The original containment check operated on `$safePath = realpath($candidatePath) ?: $candidatePath` - and because a note being saved for the first time never already exists, `realpath()` reliably returns `false` on the legitimate path, `false` on the empty `..` upload it should be catching. The fallback then made `$safePath` identical to the unresolved, attacker-influenced `$baseDir . DIRECTORY_SEPARATOR . $requestedFile`, so `str_starts_with($safePath, $baseDir . DIRECTORY_SEPARATOR)` passed trivially for any `$requestedFile`, traversal sequences included, and `file_put_contents()` wrote wherever the resulting path pointed. The fix drops canonicalize-then-contain entirely for this write path (it cannot work against a destination that does not exist yet) and instead validates the untrusted filename itself before it is ever concatenated: `$requestedFile` must be non-empty, must not be `.` or `..`, and must not contain `/` or `\`. Because a note is documented to live directly inside the notes directory with no subdirectories, rejecting any separator makes containment structural - a value that passes the check cannot escape `$baseDir` no matter what it contains, since it is guaranteed to be exactly one path component appended to an already-canonical base directory (`$baseDir` itself came from `realpath()` in `resolveBaseDir()`). The write additionally opens with `fopen($safePath, 'xb')` instead of `file_put_contents()`'s default overwrite-or-create mode, so an existing file (or a symlink planted at that name) is refused with `fopen()` returning `false` rather than being silently truncated or followed - closing the adjacent symlink-following risk the guidance calls out for write sinks of this kind.

## Behaviour changes

- **Re-saving an existing filename now returns HTTP 409 instead of overwriting it.** Under the original code, once a note existed, `realpath($candidatePath)` would succeed, pass containment, and `file_put_contents()` would overwrite it - so a second save with the same `file` value silently replaced the content. The fixed code opens with `fopen($safePath, 'xb')`, which fails if the target already exists, so a repeat request is rejected with a "already exists" message instead of overwriting. This is intentional: the sink's own doc comment states a note is "a new file" being saved for the first time, and refusing to overwrite (rather than truncating through a possibly-planted symlink) is the write-safety half of the CWE-22 fix for a destination that cannot be canonicalized in advance. If the application in fact needs update-in-place semantics for an existing note, that requires a separate, explicitly-authorized update path rather than reintroducing unconditional overwrite on this endpoint.
- All other behaviour is unchanged: a legitimate single-component filename is saved exactly as before, and a request missing the `file` field still returns 400.

## Assumptions

- The docstring ("expected to name a new file directly inside the notes directory (no subdirectories)") was treated as the intended contract, supporting rejection of separators and of re-saving an existing filename, rather than treating the pre-existing overwrite behaviour as a requirement to preserve.

## Verification

`php -l` (PHP 8.5 CLI) reported no syntax errors on the fixed file. Additionally ran the fixed `saveNote()` logic against a temporary directory: a plain filename saved successfully; `../evil.txt` and `..\evil2.txt` were both rejected with no file written outside the base directory; re-saving the same filename was rejected with a conflict instead of overwriting.
