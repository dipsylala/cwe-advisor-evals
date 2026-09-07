## Verdict
The vulnerability is confirmed. The `filename` parameter is combined with the base path using `Path.Combine()` and then directly used to read a file without validating that the resulting path stays within the intended directory. An attacker can supply path traversal sequences (e.g., `../../../etc/passwd`) or absolute paths to read files outside the restricted directory.

## Source
```csharp
[HttpGet("view")]
public IActionResult ViewDocument(string filename)
{
    var filePath = Path.Combine(_basePath, filename);

    // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
    var contents = System.IO.File.ReadAllText(filePath);

    return Content(contents, "text/plain");
}
```

## Fix
### File: PathCombineUnsanitizedFilename.cs
```csharp
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers;

[ApiController]
[Route("api/[controller]")]
public class DocumentsController : ControllerBase
{
    private readonly string _basePath = "/var/app/documents";

    [HttpGet("view")]
    public IActionResult ViewDocument(string filename)
    {
        var fullBasePath = Path.GetFullPath(_basePath);
        var fullFilePath = Path.GetFullPath(Path.Combine(_basePath, filename));
        
        // Validate that the file path stays within the base directory
        var relativePath = Path.GetRelativePath(fullBasePath, fullFilePath);
        if (relativePath.StartsWith(".."))
        {
            return BadRequest("Access denied");
        }

        var contents = System.IO.File.ReadAllText(fullFilePath);

        return Content(contents, "text/plain");
    }
}
```

## Explanation
The fix validates that the resolved file path remains within the intended base directory before reading the file:

1. **Normalize both paths**: `Path.GetFullPath()` resolves relative path components (like `..`) and converts paths to their canonical forms, handling platform-specific separators.

2. **Compute relative path**: `Path.GetRelativePath(fullBasePath, fullFilePath)` returns the relative path from the base directory to the target file. If the target is outside the base directory, it returns a path starting with `..`.

3. **Reject escapes**: If the relative path starts with `..`, the file is outside the allowed directory and access is rejected with a 400 Bad Request response.

4. **Use normalized path**: The normalized `fullFilePath` is passed to `ReadAllText()` after validation succeeds.

This approach blocks:
- Path traversal sequences: `../../../etc/passwd` → resolves outside base directory
- Absolute paths: `/etc/passwd` → `GetRelativePath()` returns a path with `..`
- Symbolic link escapes: The `GetFullPath()` normalization handles link resolution
