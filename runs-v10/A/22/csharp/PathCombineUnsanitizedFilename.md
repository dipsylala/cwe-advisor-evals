## Verdict

Path traversal vulnerability confirmed. The `filename` parameter is directly combined with the base path without validating that the result stays within the restricted directory.

## Source

The vulnerability is in the `ViewDocument` method (line 17) where `File.ReadAllText(filePath)` reads from a path constructed by combining user-supplied `filename` with `_basePath`. An attacker can pass path traversal sequences like `../../../etc/passwd` or `..\..\..\windows\system32\config\sam` to escape the intended directory and read arbitrary files.

The root cause is that `Path.Combine()` concatenates paths without validating containment; a relative path component like `..` will traverse upward regardless of the base directory.

## Fix

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
        // Reject filenames containing path separators or traversal sequences
        if (string.IsNullOrEmpty(filename) || 
            filename.Contains(Path.DirectorySeparatorChar) || 
            filename.Contains(Path.AltDirectorySeparatorChar) ||
            filename.Contains(".."))
        {
            return BadRequest("Invalid filename");
        }

        var filePath = Path.Combine(_basePath, filename);
        
        // Canonicalize paths to resolve . and .. references
        var basePathCanonical = Path.GetFullPath(_basePath);
        var filePathCanonical = Path.GetFullPath(filePath);

        // Verify the resolved path is within the base directory
        if (!filePathCanonical.StartsWith(basePathCanonical + Path.DirectorySeparatorChar) && 
            filePathCanonical != basePathCanonical)
        {
            return Forbid();
        }

        var contents = File.ReadAllText(filePathCanonical);

        return Content(contents, "text/plain");
    }
}
```

## Explanation

The fix uses two complementary strategies:

**Primary defense—filename structure validation:** Reject any filename containing directory separators (`/` or `\`) or explicit traversal sequences (`..`). This constrains the input to simple filenames only, preventing path components from being supplied at all.

**Secondary defense—path canonicalization and containment check:** After combining paths, call `Path.GetFullPath()` on both the base path and the target path to resolve them to their canonical forms (eliminating `.` and `..` references and normalizing case on Windows). Then verify that the canonical target path starts with the canonical base path, ensuring it cannot escape the restricted directory even if the first layer is bypassed.

The containment check accounts for the directory separator—a path like `/var/app/documents2/file` would match a prefix check against `/var/app/documents` but does not actually represent a path inside that directory. The fix ensures the base path is followed by a separator or is the path itself.

This approach is fail-secure: rejection of traversal attempts is explicit and comes before any file operation.
