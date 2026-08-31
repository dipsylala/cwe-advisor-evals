## Verdict

**Confirmed exploitable.** The `filename` parameter accepts untrusted user input and is combined with the base directory using `Path.Combine()`, which discards the base path if the user-supplied argument is absolute. No validation of path containment occurs before the sink `File.ReadAllText()`.

An attacker can read arbitrary files on the system by passing:
- Relative traversal: `../../../etc/passwd`
- Absolute paths: `C:\Windows\System32\drivers\etc\hosts`
- Path manipulation that `Path.Combine()` does not handle: UNC paths, absolute paths

## Source

```csharp
[HttpGet("view")]
public IActionResult ViewDocument(string filename)
{
    var filePath = Path.Combine(_basePath, filename);

    // SAST FINDING: CWE-22. Sink: next statement.
    var contents = File.ReadAllText(filePath);

    return Content(contents, "text/plain");
}
```

**Attack vector**: `GET /api/documents/view?filename=../../../../etc/passwd` or `GET /api/documents/view?filename=C:\Windows\System32\drivers\etc\hosts`

## Fix

```csharp
[HttpGet("view")]
public IActionResult ViewDocument(string filename)
{
    // Construct and canonicalize the full path
    var filePath = Path.Combine(_basePath, filename);
    var fullPath = Path.GetFullPath(filePath);
    var baseDirFull = Path.GetFullPath(_basePath);
    
    // Verify the path stays within the base directory
    var relativePath = Path.GetRelativePath(baseDirFull, fullPath);
    
    // Reject traversal attempts and absolute paths
    if (relativePath == ".." || 
        relativePath.StartsWith(".." + Path.DirectorySeparatorChar) ||
        relativePath.StartsWith(".." + Path.AltDirectorySeparatorChar) ||
        Path.IsPathRooted(relativePath))
    {
        return BadRequest("Invalid file path");
    }
    
    var contents = File.ReadAllText(fullPath);

    return Content(contents, "text/plain");
}
```

## Explanation

The fix applies three layers of defense per CWE-22 C# guidance:

1. **Canonicalization**: `Path.GetFullPath()` normalizes both the constructed path and the base directory to absolute form, resolving `..` and `.` sequences. This also expands short 8.3 names to their long form on Windows.

2. **Containment check**: `Path.GetRelativePath()` computes the relative path from base to full path. If this relative path is `..`, starts with `..` + separator (on either Windows or Unix form), or is rooted, the requested file escapes the permitted directory and is rejected.

3. **Reject, do not strip**: Invalid input raises a `BadRequest` response rather than attempting to sanitize it. Stripping `../` sequences (e.g., `....//` becomes `../`) or re-encoding hides the attack attempt from logs.

The attack payloads now fail:
- `../../../etc/passwd` → `GetRelativePath()` returns a path starting with `..` → rejected
- `C:\Windows\System32\drivers\etc\hosts` → `IsPathRooted()` detects absolute path → rejected
- `../windows/system32/drivers/etc/hosts` → relative path starts with `..` + separator → rejected

## Behaviour changes

**Safe reads only**: The endpoint now rejects any filename argument that would read outside `/var/app/documents/`, preventing directory traversal.

**Changed response**: Invalid paths return `400 Bad Request` instead of attempting the read. Legitimate files within the base directory are read and returned as before.

**No silent repairs**: Malformed paths are rejected outright rather than having `../` sequences stripped, ensuring suspicious activity is visible in logs.

**Performance impact**: Minimal — two `Path.GetFullPath()` calls and one `Path.GetRelativePath()` call per request (negligible compared to file I/O).
