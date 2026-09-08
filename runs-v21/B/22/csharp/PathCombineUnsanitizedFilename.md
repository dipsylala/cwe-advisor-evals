## Verdict

Real. The application accepts user-supplied filenames from the `filename` parameter and passes them directly to `Path.Combine()` without validation. An attacker can use path traversal sequences like `../` to escape the base directory and read arbitrary files on the system. The sink (`File.ReadAllText()` on line 17) has no containment enforcement.

## Source

User-controlled `filename` parameter accepted via the HTTP query parameter in the `ViewDocument()` method signature. The parameter is bound from the request by ASP.NET model binding and is already percent-decoded before reaching the code.

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
        var filePath = Path.Combine(fullBasePath, filename);
        var canonicalPath = Path.GetFullPath(filePath);
        
        // Verify the resolved path stays within the base directory
        var relativePath = Path.GetRelativePath(fullBasePath, canonicalPath);
        
        // Reject if path escapes the base directory
        if (relativePath.StartsWith("..") || Path.IsPathRooted(relativePath))
        {
            return Forbid();
        }
        
        var contents = System.IO.File.ReadAllText(canonicalPath);
        
        return Content(contents, "text/plain");
    }
}
```

## Explanation

The fix implements path containment validation using two canonicalization steps and a relative-path check, per CWE-22/C# guidance. First, `Path.GetFullPath(_basePath)` resolves the base directory to its canonical form. Then `Path.Combine()` combines the base with user input, followed by a second `Path.GetFullPath(canonicalPath)` to resolve any `../` sequences and symlinks in the result. A call to `Path.GetRelativePath(fullBasePath, canonicalPath)` computes the relative path from the validated base to the target. If this relative path starts with `..` (indicating an escape attempt) or is rooted as an absolute path, the request is rejected with HTTP 403 Forbidden. Only paths that resolve to a location within the base directory pass validation and reach the `File.ReadAllText()` sink. This prevents attackers from using traversal sequences like `../../../etc/passwd` or absolute paths to access files outside the intended directory.

## Behaviour changes

- Requests with path traversal sequences (`../`, `..\\`) are now rejected with HTTP 403 Forbidden instead of attempting the read.
- Requests with absolute paths (e.g., `/etc/passwd`, `C:\Windows\System32\config`) are rejected with HTTP 403 Forbidden.
- Requests for files actually within the base directory work as before; no legitimate access is blocked by the containment check.
- The response code changes from a file read result or 404 Not Found (if file missing) to 403 Forbidden for attempts to escape the directory.
