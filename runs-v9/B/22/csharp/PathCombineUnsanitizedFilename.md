## Verdict

Exploitable (confidence: high). `filename` is bound directly from the query string with no validation and flows straight into `Path.Combine` and then `File.ReadAllText`. A value such as `../../../../etc/passwd` traverses out of `_basePath`, and a rooted value (e.g. `/etc/passwd` on Linux, or `C:\Windows\win.ini` on Windows) causes `Path.Combine` to discard `_basePath` entirely per its documented behavior, so the attacker controls the full path.

## Source

The `filename` parameter of `ViewDocument(string filename)`, model-bound by ASP.NET Core from the `filename` query string on `GET api/documents/view` - attacker-controlled, unvalidated.

## Fix

Vulnerable code:

```csharp
[HttpGet("view")]
public IActionResult ViewDocument(string filename)
{
    var filePath = Path.Combine(_basePath, filename);

    // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
    var contents = File.ReadAllText(filePath);

    return Content(contents, "text/plain");
}
```

Fixed code:

```csharp
[HttpGet("view")]
public IActionResult ViewDocument(string filename)
{
    var filePath = Path.GetFullPath(Path.Combine(_basePath, filename));

    var relativePath = Path.GetRelativePath(_basePath, filePath);
    if (relativePath == ".." ||
        relativePath.StartsWith(".." + Path.DirectorySeparatorChar) ||
        relativePath.StartsWith(".." + Path.AltDirectorySeparatorChar) ||
        Path.IsPathRooted(relativePath))
    {
        return BadRequest("Invalid filename.");
    }

    // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
    var contents = File.ReadAllText(filePath);

    return Content(contents, "text/plain");
}
```

## Explanation

The original code combined the untrusted `filename` directly into a filesystem path with no canonicalization or containment check, so `File.ReadAllText` would open whatever `Path.Combine(_basePath, filename)` produced - including paths that escape `_basePath` via `../` sequences, or, because `Path.Combine` discards all earlier components once a later argument is rooted, an entirely attacker-chosen absolute path. The fix canonicalizes the combined path with `Path.GetFullPath()` (resolving `.` and `..` segments) and then compares it to `_basePath` with `Path.GetRelativePath()`, which is path-component aware rather than a raw string prefix check. A result of `..`, a value beginning with `..` plus either directory-separator form, or a rooted result (the case where `Path.Combine` dropped the base entirely) all indicate the resolved path left the allowed root, and the request is rejected with `400 Bad Request` before the file is ever opened. In-bounds filenames resolve to the same canonical path as before and are read exactly as before.

## Behaviour changes

- Requests whose `filename` resolves outside `_basePath` (traversal sequences or a rooted/absolute value) now return `400 Bad Request` instead of reaching `File.ReadAllText`. Previously such a request either threw an unhandled `FileNotFoundException`/`DirectoryNotFoundException`/`UnauthorizedAccessException` (surfaced as a framework-default error response) or, in the rooted-path case, silently succeeded in reading an arbitrary file - both replaced by an explicit, intended rejection.
- For a legitimate filename that stays within `_basePath`, `filePath` after `Path.GetFullPath()` is the same canonical path `Path.Combine` would have produced, so `File.ReadAllText`'s arguments, return value, and the response's content and content-type are unchanged.
