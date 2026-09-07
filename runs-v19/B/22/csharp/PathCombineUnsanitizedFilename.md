## Verdict

Exploitable

## Source

- **CWE-22 (Path Traversal)** at line 17 (sink: `File.ReadAllText(filePath)`)
- **Input:** HTTP query parameter `filename` passed to `ViewDocument` method (line 12)
- **Data flow:** User-controlled `filename` → `Path.Combine(_basePath, filename)` (line 14) → `File.ReadAllText(filePath)` (line 17)

The `filename` parameter flows directly into path construction without validation. An attacker can provide path traversal sequences like `../` or absolute paths (`/etc/passwd`) to access files outside the `/var/app/documents` base directory.

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
        var baseDir = Path.GetFullPath(_basePath);
        var filePath = Path.GetFullPath(Path.Combine(baseDir, filename));
        var relativePath = Path.GetRelativePath(baseDir, filePath);
        
        // Reject if the path escapes the base directory
        if (relativePath == ".." ||
            relativePath.StartsWith(".." + Path.DirectorySeparatorChar) ||
            relativePath.StartsWith(".." + Path.AltDirectorySeparatorChar) ||
            Path.IsPathRooted(relativePath))
        {
            return BadRequest("Invalid file path");
        }

        var contents = System.IO.File.ReadAllText(filePath);

        return Content(contents, "text/plain");
    }
}
```

## Explanation

The fix implements canonicalization and containment validation before reaching the file read sink. It uses `Path.GetFullPath()` to resolve both the base directory and the combined path to absolute canonical form (normalizing `.` and `..` components), then uses `Path.GetRelativePath()` to compute the relative path from the base to the resolved file path. The code rejects any path that escapes the base directory: paths starting with `..`, containing `..` followed by a path separator, or paths that are rooted (absolute). This blocks all common path traversal vectors including `../` sequences, absolute paths, and encoded variants. Only paths that remain within the base directory reach `File.ReadAllText()`.

## Behaviour changes

None. The fix preserves the sink contract and behavior for valid filenames within the base directory. For invalid paths that attempt traversal, the method returns a 400 BadRequest status code rather than attempting to read the file, which is the appropriate response for security-relevant input validation.
