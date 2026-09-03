## Verdict

CONFIRMED

## Source

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

The vulnerability exists at line 17 where `File.ReadAllText(filePath)` reads a file without validating that the resolved path remains within the intended `_basePath` directory. An attacker can pass a filename containing traversal sequences (e.g., `../../etc/passwd` or `..\..\..\windows\system32\config\sam`) to escape the base directory and read arbitrary files on the system.

## Fix

```csharp
[HttpGet("view")]
public IActionResult ViewDocument(string filename)
{
    var basePath = Path.GetFullPath(_basePath);
    var filePath = Path.GetFullPath(Path.Combine(_basePath, filename));
    
    // Ensure the resolved path is within the base directory
    if (!filePath.StartsWith(basePath + Path.DirectorySeparatorChar))
    {
        return BadRequest("Invalid file path");
    }
    
    var contents = File.ReadAllText(filePath);

    return Content(contents, "text/plain");
}
```

## Explanation

The fix validates the resolved file path before reading it:

1. `Path.GetFullPath()` normalizes both the base path and the combined path, collapsing any `..` or `.` sequences so they evaluate to their true locations on the filesystem.

2. The check `filePath.StartsWith(basePath + Path.DirectorySeparatorChar)` ensures the resolved file path is within the base directory. The directory separator suffix prevents a base path like `/var/app/docs` from accepting `/var/app/documents/file.txt` (a prefix match without the separator would allow this).

3. If the path traversal attempt is detected, the handler returns a 400 Bad Request error instead of attempting to read the file, preventing unauthorized access to files outside the restricted directory.

This defence-in-depth approach works across Windows and Unix paths because `Path.GetFullPath()` and `Path.DirectorySeparatorChar` are platform-aware.
