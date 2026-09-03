## Verdict

**CONFIRMED** — Path traversal vulnerability. An attacker can write to arbitrary locations by supplying a filename containing `../` sequences.

## Source

User-supplied filename from `$_POST['file']` (line 56) flows through string concatenation into a file write operation without proper validation.

## Fix

Replace the `saveNote()` function with filename validation that rejects any component containing separators or traversal sequences:

```php
function saveNote(string $requestedFile, string $content, string $baseDir): void
{
    // Reject empty filenames, '.', '..', and any path containing separators
    if (empty($requestedFile) 
        || $requestedFile === '.' 
        || $requestedFile === '..' 
        || str_contains($requestedFile, '/') 
        || str_contains($requestedFile, '\\')) {
        http_response_code(403);
        echo 'Access to the requested note path is not permitted.';
        return;
    }
    
    // Construct path from validated components; no traversal is possible
    $safePath = $baseDir . DIRECTORY_SEPARATOR . $requestedFile;
    
    file_put_contents($safePath, $content);
    echo 'Note saved.';
}
```

## Explanation

The vulnerability stems from `realpath($candidatePath) ?: $candidatePath` on line 35. When a file does not exist yet, `realpath()` returns `false`, and the fallback silently reverts to the unresolved path containing `../` sequences. The containment check (lines 42–43) cannot catch this because it operates on the unresolved path, which still starts with the base directory as a string prefix.

The fix removes the fallback and instead validates the filename as a single path component—rejecting anything empty, `.`, `..`, or containing `/` or `\`. Since `$baseDir` is already canonical (from `resolveBaseDir()`), concatenating it with a validated single-component filename guarantees the result lies within the intended directory. This aligns with the PHP guidance for CWE-22, which states: "For writes, the destination does not exist yet, so resolve the *parent* with `realpath()` and reject a filename that is empty, `.`, `..`, or contains `/` or `\`."

## Behaviour changes

- The function now rejects filenames containing path separators or relative references (`.`, `..`), returning 403 immediately.
- File creation behavior remains unchanged: `file_put_contents()` still creates the file if it does not exist and overwrites if it does, using the same semantics as before.
- Legitimate save operations (single-component filenames without separators) proceed unchanged.
