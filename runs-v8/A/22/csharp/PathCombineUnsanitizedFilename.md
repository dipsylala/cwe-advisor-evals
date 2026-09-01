## Verdict
CONFIRMED

## Source
Line 17: `File.ReadAllText(filePath)` where `filePath` is constructed from untrusted user input (`filename` parameter) without path validation.

## Fix
```csharp
[HttpGet("view")]
public IActionResult ViewDocument(string filename)
{
    var basePath = Path.GetFullPath(_basePath);
    var filePath = Path.Combine(_basePath, filename);
    var fullPath = Path.GetFullPath(filePath);

    if (!fullPath.StartsWith(basePath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) &&
        fullPath != basePath)
    {
        return BadRequest("Access denied");
    }

    if (!System.IO.File.Exists(fullPath))
    {
        return NotFound();
    }

    var contents = System.IO.File.ReadAllText(fullPath);
    return Content(contents, "text/plain");
}
```

## Explanation
`Path.Combine()` does not prevent path traversal attacks. An attacker providing `../../etc/passwd` as the filename parameter bypasses the intended directory restriction. The fix validates the final resolved path by: (1) converting both the base path and constructed path to their full canonical forms using `Path.GetFullPath()`, (2) verifying the file path is within the base directory by checking it starts with the base path, and (3) only then reading the file. This ensures user-supplied input cannot escape the intended directory.
