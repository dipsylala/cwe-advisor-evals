## Verdict

Exploitable. User-supplied `filename` parameter is passed directly to `Path.Combine()` and then to `File.ReadAllText()` without canonicalization or containment validation, allowing path traversal sequences like `../` to access files outside the intended base directory.

## Source

HTTP GET parameter `filename` in `ViewDocument(string filename)` (line 12), received from request and bound by ASP.NET model binding.

## Fix

**Vulnerable code (line 11-20):**
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
    var basePath = Path.GetFullPath(_basePath);
    var filePath = Path.GetFullPath(Path.Combine(basePath, filename));

    // Verify the resolved path is within the base directory
    var relativePath = Path.GetRelativePath(basePath, filePath);
    if (relativePath == ".." || 
        relativePath.StartsWith(".." + Path.DirectorySeparatorChar) ||
        relativePath.StartsWith(".." + Path.AltDirectorySeparatorChar) ||
        Path.IsPathRooted(relativePath))
    {
        return BadRequest("Invalid file path");
    }

    var contents = File.ReadAllText(filePath);
    return Content(contents, "text/plain");
}
```

## Explanation

The fix canonicalizes both the base path and the combined result using `Path.GetFullPath()`, which resolves `..` sequences and symlinks to their absolute form. After canonicalization, `Path.GetRelativePath()` computes the relative path from the base directory to the target; if this relative path starts with `..`, is rooted, or equals `..` itself, the target has escaped the base directory and is rejected. The validation occurs before the sink, using the canonical `filePath` variable that `File.ReadAllText()` will actually receive, ensuring the check is authoritative. Attackers cannot bypass this with `../`, `..\\`, absolute paths, or other traversal patterns because canonicalization resolves them to their true location before the containment check runs.

## Behaviour changes

Added `Path.GetFullPath()` calls to canonicalize paths before use — required by the security control and does not alter the semantics of file access, only ensures consistent resolution of relative references. Added validation block that rejects paths escaping the base directory and returns HTTP 400 instead of attempting to read them — this changes the response for malicious input from `File.ReadAllText()` throwing `FileNotFoundException` to an explicit rejection, improving security and debugging visibility. The sink contract for `File.ReadAllText()` remains unchanged: it still receives a single canonicalized file path and returns the complete file contents.
