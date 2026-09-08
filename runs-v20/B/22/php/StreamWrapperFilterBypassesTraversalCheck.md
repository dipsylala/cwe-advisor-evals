## Verdict

Confirmed. Exploitable path traversal / arbitrary file read.

## Source

`$_GET['file']` in `serve_report()`.

## Fix

The existing denylist only rejects the literal substring `..`. `fopen()` does not just take filesystem paths - any string that matches `scheme://...` is dispatched to PHP's stream-wrapper layer, and `chdir()` has no effect on how a wrapper URL or an absolute path is resolved. So a value such as `php://filter/convert.base64-encode/resource=index.php` (arbitrary local-file disclosure via a filter wrapper) or a bare absolute path such as `/etc/passwd` reaches `fopen()` untouched, because neither contains `..`. The fix requires the value to be a bare filename (no `/` or `\`, which also rules out every `scheme://` wrapper since the `//` requires a slash), then canonicalizes the resolved path with `realpath()` and confirms it stays inside the reports directory before opening it - the pattern in `cwe/22/php/INDEX.md`.

### File: StreamWrapperFilterBypassesTraversalCheck.php
```php
<?php
/**
 * Report viewer endpoint.
 *
 * Streams a report file to the browser. Confines every read to the
 * reports directory by requiring a bare filename (no path separators
 * or stream-wrapper syntax) and verifying the resolved path stays
 * inside the reports directory.
 */

$reportsDir = __DIR__ . '/reports';

function serve_report(string $reportsDir): void
{
    $file = $_GET['file'] ?? '';

    if ($file === '') {
        http_response_code(400);
        echo 'Missing file parameter';
        return;
    }

    // Reject anything that is not a bare filename: a path separator lets
    // the value climb out of the reports directory (../), and it is also
    // required syntax for a PHP stream-wrapper URL (php://, phar://,
    // zlib://, ...), which fopen() honours regardless of chdir() or an
    // absolute-path/".." denylist.
    if (str_contains($file, '/') || str_contains($file, '\\')) {
        http_response_code(400);
        echo 'Invalid file parameter';
        return;
    }

    chdir($reportsDir);

    $base = realpath($reportsDir);
    $real = realpath($file);

    if ($base === false || $real === false) {
        http_response_code(404);
        echo 'File not found';
        return;
    }

    if ($real !== $base && !str_starts_with($real, $base . DIRECTORY_SEPARATOR)) {
        http_response_code(404);
        echo 'File not found';
        return;
    }

    // SAST FINDING (fixed): open the canonicalized, containment-checked
    // path, never the original request value.
    $handle = fopen($real, 'r');
    if ($handle === false) {
        http_response_code(404);
        echo 'File not found';
        return;
    }

    header('Content-Type: application/octet-stream');
    fpassthru($handle);
    fclose($handle);
}

serve_report($reportsDir);
```

## Explanation

The original code guarded against one specific substring (`..`) but the actual sink, `fopen()`, accepts anything PHP's stream layer recognizes as a URL, so an absolute path or a `scheme://` wrapper reaches it untouched regardless of `chdir()`. The fix replaces the substring denylist with a requirement that the value be a single path component (no `/` or `\`), which structurally excludes both absolute paths and every `scheme://` wrapper syntax (the `//` requires a slash). It then canonicalizes the candidate with `realpath()` and checks with a separator-terminated prefix comparison (`$real === $base || str_starts_with($real, $base . DIRECTORY_SEPARATOR)`) that the resolved path is still inside the reports directory before opening it - closing both the wrapper bypass and any traversal via a symlink planted inside the directory. `realpath()`'s `false` return (path does not exist, or cannot be resolved) is handled before any comparison and reported as "not found," matching the sink's existing failure behavior. The `..` denylist is removed because it is now redundant and would otherwise reject a legitimate filename that merely contains the substring (e.g. `notes..v2.txt`).

Checked by hand against the CWE-22 PHP guidance's Key Principles and Remediation Steps (separator-terminated containment, `realpath()` `false`-handling, "confirm the input is a plain relative filename before canonicalizing," "reject a filename containing a separator"). Every function used (`str_contains`, `str_starts_with`, `realpath`, `DIRECTORY_SEPARATOR`, `fopen`, `fpassthru`, `fclose`) is a PHP core builtin already present in the original file or the standard library, so no new external names were introduced. Verified with `php -l` (no syntax errors) and by running the file directly with a real `reports/` fixture: a legitimate filename streamed its content; `../secret.txt`, `php://filter/convert.base64-encode/resource=good.txt`, and `/etc/passwd` were all rejected with 400 "Invalid file parameter"; a nonexistent filename returned 404 "File not found".

## Behaviour changes

- A request for a file inside a subdirectory of `reports/` (a `file` value containing `/`) is now rejected with 400 instead of being attempted - the original code never supported this either in practice (chdir + fopen would have worked for a legitimate subpath), so this narrows accepted input to a single path component. If subdirectory reports are a real use case, the map-based indirect-reference pattern from the guidance should be used instead.
- Filenames containing the literal substring `..` as part of a larger name (e.g. `report..v2.txt`) are now accepted if they resolve inside the reports directory, whereas the original denylist rejected them unconditionally.
- A missing/unreadable file and a rejected wrapper/absolute-path value now both surface through the same "not found"/"invalid parameter" responses as before; no new error paths or status codes were introduced.
