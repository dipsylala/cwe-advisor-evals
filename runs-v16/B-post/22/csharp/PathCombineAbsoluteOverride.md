## Verdict

CONFIRMED. Path.Combine() discards the base directory when the second argument is an absolute path, allowing an attacker to read arbitrary files on the system.

## Source

The `file` parameter from `[FromQuery]` on line 15 is user-controlled and passes directly into `Path.Combine()` on line 20 without validation.

## Fix

```csharp
[HttpGet("export")]
public IActionResult ExportReport([FromQuery] string file)
{
    // Canonicalize the combined path
    var reportPath = Path.Combine(_reportsRoot, file);
    var canonicalPath = Path.GetFullPath(reportPath);
    
    // Verify the resolved path is within the base directory
    var relativePath = Path.GetRelativePath(_reportsRoot, canonicalPath);
    if (relativePath == ".." || 
        relativePath.StartsWith(".." + Path.DirectorySeparatorChar) ||
        relativePath.StartsWith(".." + Path.AltDirectorySeparatorChar) ||
        Path.IsPathRooted(relativePath))
    {
        return BadRequest("Invalid file path");
    }
    
    var reportText = File.ReadAllText(canonicalPath);
    
    return Content(reportText, "text/plain");
}
```

## Explanation

`Path.Combine(_reportsRoot, file)` accepts any path as the second argument. If `file` is an absolute path (e.g., `C:\Windows\System32\config\SAM`), `Path.Combine()` discards the base directory entirely and returns only the absolute path. The fix canonicalizes the combined path with `Path.GetFullPath()`, then verifies containment by computing the relative path from the base directory using `Path.GetRelativePath()`. If the result begins with `..` (indicating escape) or is itself an absolute path, the request is rejected. Only paths that are contained within the base directory proceed to the file read operation.

## Behaviour changes

- Requests with absolute paths (e.g., `?file=C:\Windows\System32\config\SAM`) now return 400 Bad Request instead of reading arbitrary files.
- Requests with path traversal sequences (e.g., `?file=..\..\..\Windows\System32\config\SAM`) are rejected.
- Legitimate relative file requests within the reports directory continue to work.
