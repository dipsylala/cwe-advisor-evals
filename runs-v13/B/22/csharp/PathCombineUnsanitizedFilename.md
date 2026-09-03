## Verdict

Confirmed as exploitable path traversal vulnerability.

## Source

User-controlled input: `filename` parameter from HTTP GET request to `ViewDocument(string filename)`. Attacker can supply traversal sequences like `../../../etc/passwd` to escape the intended `/var/app/documents` directory.

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
        // Canonicalize the path, treating filename as relative to _basePath
        var fullPath = Path.GetFullPath(filename, _basePath);
        
        // Get the relative path to verify it stays within the base directory
        var relativePath = Path.GetRelativePath(_basePath, fullPath);
        
        // Reject if attempting to traverse outside the base directory
        if (relativePath == ".." || 
            relativePath.StartsWith(".." + Path.DirectorySeparatorChar) ||
            relativePath.StartsWith(".." + Path.AltDirectorySeparatorChar) ||
            Path.IsPathRooted(relativePath))
        {
            return BadRequest("Invalid filename");
        }
        
        var contents = File.ReadAllText(fullPath);
        
        return Content(contents, "text/plain");
    }
}
```

## Explanation

The original code used `Path.Combine(_basePath, filename)` without validation, allowing attackers to use `../` sequences to escape the base directory. The fix applies path canonicalization and containment validation:

1. `Path.GetFullPath(filename, _basePath)` resolves `filename` relative to the base directory and expands all relative references (`.`, `..`) to their canonical absolute form.
2. `Path.GetRelativePath(_basePath, fullPath)` computes the path of the resolved file relative to the base directory. If this relative path is `..` (the parent), starts with `..` followed by a separator, or is rooted, the file lies outside the base directory.
3. The validation rejects any such path with a 400 BadRequest error, preventing access to files outside `/var/app/documents`.
4. Only paths that remain within the base directory are allowed to proceed to `File.ReadAllText()`.

This approach follows CWE-22 guidance for C#: canonicalize before validation, use `Path.GetRelativePath()` for containment checks (not string prefix matching), and reject rather than strip traversal sequences.

## Behaviour changes

- **Rejection of out-of-bounds paths**: Requests with `../` or absolute paths in the `filename` parameter now return HTTP 400 BadRequest instead of attempting to read arbitrary files.
- **Path canonicalization**: Symbolic references like `.` and `..` are resolved during validation, ensuring even obfuscated traversal attempts are caught.
- **Preserved functionality**: Valid filenames within `/var/app/documents` are read and returned as before, with identical response behavior and content-type handling.
