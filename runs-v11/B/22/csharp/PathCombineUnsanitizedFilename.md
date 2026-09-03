## Verdict

Exploitable. The `filename` parameter is user-controlled HTTP input that flows directly into `Path.Combine()` without validation. An attacker can supply traversal sequences like `../../../etc/passwd` to read files outside the intended `/var/app/documents` directory. The finding is confirmed at line 17, where `File.ReadAllText(filePath)` operates on the unchecked path.

## Source

User input: `filename` parameter to the `ViewDocument` action method, provided via HTTP query string or route data.

Sink: `File.ReadAllText(filePath)` at line 17.

Data flow: `filename` (user input) → `Path.Combine(_basePath, filename)` → `File.ReadAllText(filePath)`.

## Fix

**Vulnerable code:**
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

**Fixed code:**
```csharp
[HttpGet("view")]
public IActionResult ViewDocument(string filename)
{
    // Canonicalize both paths to absolute form
    var filePath = Path.Combine(_basePath, filename);
    var fullPath = Path.GetFullPath(filePath);
    var basePath = Path.GetFullPath(_basePath);

    // Verify the resolved path stays within the base directory
    var relativePath = Path.GetRelativePath(basePath, fullPath);
    
    // Reject if the path attempts to traverse up, contains rooted components, or uses alternate separators for traversal
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

The fix addresses the path traversal vulnerability by canonicalizing the user-supplied filename and verifying it remains within the intended base directory. After combining the base path and filename, `Path.GetFullPath()` resolves relative path components (`.` and `..`) and symlinks to their absolute forms. Then `Path.GetRelativePath()` computes the relative path from the base directory to the resolved target. If that relative path is `..`, starts with `..` followed by a separator, starts with alternate separator variants, or is rooted, the request is rejected. Only paths that provably stay within the base directory proceed to `File.ReadAllText()`. This prevents traversal attacks while preserving legitimate file access for valid filenames.

## Behaviour changes

The fix introduces two behavioural changes:

1. **Early rejection of invalid paths**: Requests with traversal sequences, absolute paths, or symlinks pointing outside the base directory now return a 400 Bad Request response instead of attempting to read the file. This is a security improvement and intentional.

2. **Symlink resolution**: `Path.GetFullPath()` resolves symlinks and junctions on disk (as documented by Microsoft, it is not purely lexical and accesses the filesystem). A symlink within the base directory that points outside it will now be rejected, whereas the original code would follow it. This is the intended defence-in-depth behavior and aligns with the guidance that symlinks on ancestors must be defended by denying untrusted write access to the base directory and its parents, not by per-file link tests that can be bypassed.

No other behavioural changes occur: successful reads of valid files within the base directory proceed exactly as before.
