## Verdict

Exploitable. An attacker can pass an absolute path (e.g., `?file=C:\Windows\System32\config\sam`) as the `file` query parameter. `Path.Combine()` will discard the base directory entirely when the second argument is rooted, allowing arbitrary file reads outside the intended reports directory.

## Source

The `file` parameter from the HTTP query string (`[FromQuery] string file` at line 15) is attacker-controlled and flows directly into path construction without validation.

## Fix

**Vulnerable code:**
```csharp
[HttpGet("export")]
public IActionResult ExportReport([FromQuery] string file)
{
    var reportPath = Path.Combine(_reportsRoot, file);
    
    var reportText = File.ReadAllText(reportPath);
    
    return Content(reportText, "text/plain");
}
```

**Fixed code:**
```csharp
[HttpGet("export")]
public IActionResult ExportReport([FromQuery] string file)
{
    if (string.IsNullOrEmpty(file))
        return BadRequest("File name is required");
    
    // Canonicalize the base path once
    var basePath = Path.GetFullPath(_reportsRoot);
    
    // Use Path.Join (safer than Path.Combine) and canonicalize the result
    var requestedPath = Path.Join(basePath, file);
    var fullPath = Path.GetFullPath(requestedPath);
    
    // Verify the resolved path stays within the base directory
    var relativePath = Path.GetRelativePath(basePath, fullPath);
    if (relativePath == ".." ||
        relativePath.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
        relativePath.StartsWith(".." + Path.AltDirectorySeparatorChar, StringComparison.Ordinal) ||
        Path.IsPathRooted(relativePath))
    {
        return BadRequest("Access denied");
    }
    
    if (!File.Exists(fullPath))
        return NotFound();
    
    var reportText = File.ReadAllText(fullPath);
    
    return Content(reportText, "text/plain");
}
```

## Explanation

The fix closes the vulnerability by replacing `Path.Combine()` with `Path.Join()` (available on .NET Core 2.1+), which does not discard earlier path components when later arguments are rooted. The path is canonicalized with `Path.GetFullPath()` to resolve relative references and symlinks. Containment is then enforced by computing the relative path from the base directory using `Path.GetRelativePath()` and rejecting any result that starts with `..` (escape attempt) or is rooted (absolute path). The file is checked for existence before reading, providing clearer error reporting than allowing `File.ReadAllText()` to throw.

## Behaviour changes

- **Null/empty check (line 16-17)**: Returns `BadRequest` if `file` is missing. Original code would pass an empty string through, resulting in reading from `_reportsRoot` itself (a directory read would fail at the sink).
- **Validation gate (lines 24-30)**: Returns `BadRequest` if the resolved path escapes the base directory. Original code had no validation, allowing arbitrary filesystem access.
- **Existence check (lines 32-33)**: Returns `NotFound` if the file does not exist, rather than letting `File.ReadAllText()` throw `FileNotFoundException`. This is a defensive improvement in error handling.
- **Path.Join instead of Path.Combine (line 22)**: `Path.Join()` does not discard earlier components when later arguments are rooted; `Path.Combine()` does. This is the key fix preventing absolute paths from bypassing the base directory.
- **Use validated path (line 35)**: The call to `File.ReadAllText()` uses `fullPath` (the canonicalized, validated variable) rather than reconstructing the path from user input.
