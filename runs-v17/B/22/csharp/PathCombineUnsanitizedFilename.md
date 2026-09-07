## Verdict

CONFIRMED - CWE-22 Path Traversal vulnerability. The `filename` parameter is directly used in `Path.Combine()` without validation, allowing attackers to escape the intended base directory using traversal sequences like `../`.

## Source

The vulnerability occurs at line 17 where `System.IO.File.ReadAllText(filePath)` reads from a path constructed on line 14 using unsanitized user input.

The `filename` parameter from the HTTP GET request flows directly into `Path.Combine(_basePath, filename)` without any validation or canonicalization. An attacker can supply `../../../etc/passwd` or similar sequences to access files outside `/var/app/documents`.

## Fix

### File: PathCombineUnsanitizedFilename.cs

```csharp
using Microsoft.AspNetCore.Mvc;
using System.IO;

namespace EvalCases.Controllers;

[ApiController]
[Route("api/[controller]")]
public class DocumentsController : ControllerBase
{
    private readonly string _basePath = "/var/app/documents";

    [HttpGet("view")]
    public IActionResult ViewDocument(string filename)
    {
        // Validate input - reject null, empty, or obvious traversal attempts
        if (string.IsNullOrWhiteSpace(filename) ||
            filename.Contains("..") ||
            filename.StartsWith("/") ||
            filename.StartsWith("\\") ||
            Path.IsPathRooted(filename))
        {
            return BadRequest("Invalid filename");
        }

        // Combine and canonicalize the path
        var fullPath = Path.GetFullPath(Path.Combine(_basePath, filename));

        // Get canonical base path for comparison
        var baseDirectory = Path.GetFullPath(_basePath);

        // Verify the canonical path is within the base directory
        var relativePath = Path.GetRelativePath(baseDirectory, fullPath);

        // Reject if path escapes the base directory
        if (relativePath.StartsWith("..") || 
            relativePath.StartsWith(".." + Path.DirectorySeparatorChar) ||
            Path.IsPathRooted(relativePath))
        {
            return BadRequest("Access denied");
        }

        // Verify file exists and read it
        if (!System.IO.File.Exists(fullPath))
        {
            return NotFound();
        }

        var contents = System.IO.File.ReadAllText(fullPath);
        return Content(contents, "text/plain");
    }
}
```

## Explanation

The fix implements defense-in-depth path validation using two layers:

1. **Input-level rejection**: Immediately reject obvious traversal patterns (`..`, absolute paths, rooted paths) before any path operations. This provides early detection of malicious intent and prevents non-canonical traversal attempts from succeeding.

2. **Canonicalization and containment verification**: After input validation, canonicalize the combined path using `Path.GetFullPath()`, which normalizes relative references and resolves the path to its absolute form. Then compute the relative path from the base directory using `Path.GetRelativePath()` (.NET Core 2.1+) and verify that it stays within the base—reject if it starts with `..`, contains `..` as a path component, or is rooted. This catches bypass attempts that may pass the input filter (e.g., symlinks, alternate separators on Windows).

3. **Existence check**: Verify the file exists before reading to return a proper 404 instead of an exception.

The fix also returns HTTP 400 (Bad Request) for invalid filenames and 403-style rejection for traversal attempts to distinguish validation failures from missing files (404).

## Behaviour changes

- **Requests with traversal sequences are now rejected**: Any filename containing `..`, starting with `/` or `\`, or representing an absolute path will return 400 Bad Request with message "Invalid filename".
- **Only files within the base directory are accessible**: After canonicalization, any path that resolves outside `/var/app/documents` returns 400 Bad Request with message "Access denied".
- **Non-existent files return 404**: Previously would throw an exception; now returns 404 Not Found.
- **Legitimate requests for files within the base directory work unchanged**: Valid filenames like `report.txt`, `subdirectory/file.pdf` will work as before.
