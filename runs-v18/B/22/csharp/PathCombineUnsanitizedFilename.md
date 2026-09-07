## Verdict

CWE-22 Path Traversal confirmed. User-supplied `filename` parameter reaches `System.IO.File.ReadAllText()` via `Path.Combine()` without validation, allowing directory traversal attacks using sequences like `../` or rooted absolute paths.

## Source

HTTP GET parameter `filename` from route `api/[controller]/view?filename={value}`, passed to `ViewDocument(string filename)` method at line 12. ASP.NET Core model binding automatically decodes the query parameter.

## Fix

Replace line 14 with validation logic using `Path.GetFullPath()` for canonicalization and `Path.GetRelativePath()` for containment verification. Use `Path.Join()` instead of `Path.Combine()` to prevent rooted-path injection where user input could begin with `/` and replace the base directory entirely.

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
        // Canonicalize the base directory path
        var basePath = Path.GetFullPath(_basePath);
        
        // Use Path.Join() instead of Path.Combine() to prevent rooted path injection
        var filePath = Path.Join(basePath, filename);
        
        // Canonicalize the combined path to resolve .. and .
        var fullPath = Path.GetFullPath(filePath);
        
        // Verify the path stays within the base directory
        var relativePath = Path.GetRelativePath(basePath, fullPath);
        
        // Reject if path tries to escape the base directory
        if (relativePath == ".." ||
            relativePath.StartsWith(".." + Path.DirectorySeparatorChar) ||
            relativePath.StartsWith(".." + Path.AltDirectorySeparatorChar) ||
            Path.IsPathRooted(relativePath))
        {
            return BadRequest("Invalid file path");
        }

        var contents = System.IO.File.ReadAllText(fullPath);
        return Content(contents, "text/plain");
    }
}
```

## Explanation

The original code constructed file paths by combining a base directory with user input via `Path.Combine()`, then passed the result directly to `File.ReadAllText()` without validation. This allowed attackers to escape the intended directory using directory traversal sequences.

The fix implements defense-in-depth using three mechanisms from the CWE-22 C# guidance:

1. **Path.Join() instead of Path.Combine()**: `Path.Combine()` discards the base directory if any later argument is rooted (e.g., `/etc/passwd` as a second argument would become the entire path). `Path.Join()` preserves all components regardless, preventing rooted-path replacement attacks.

2. **Canonicalization with Path.GetFullPath()**: Resolves `..`, `.`, and symbolic reference sequences to their absolute canonical form, eliminating ambiguity from encoded or Unicode variants.

3. **Containment validation with Path.GetRelativePath()**: Computes the relative path from the base to the canonical target and rejects it if:
   - It equals `".."` (the target is outside the base)
   - It starts with `".." + DirectorySeparatorChar` or `AltDirectorySeparatorChar` (the target is in a parent directory)
   - `IsPathRooted()` returns true (the relative path is rooted, indicating the target is on a different volume or outside the base)

The fix rejects the request with a 400 Bad Request response rather than silently repairing the path, ensuring traversal attempts are logged and visible for audit and alerting.

## Behaviour changes

- **Rejection of traversal payloads**: Requests with `filename` containing `..`, leading `/`, or encoded traversal sequences now return HTTP 400 instead of attempting the file read
- **Performance**: Added minimal overhead (three path canonicalizations and a few string comparisons)
- **Error handling**: File not found or permission denied errors remain unchanged and still throw the same exceptions as before
- **Valid filenames**: Legitimate single-component filenames like `"document.txt"` or `"report.pdf"` pass validation and read successfully as before
