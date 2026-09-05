## Verdict
Path traversal vulnerability confirmed. `Path.Combine()` discards the root directory when the second argument is an absolute path, allowing an attacker to read arbitrary files on the system.

## Source
```csharp
var reportPath = Path.Combine(_reportsRoot, file);
var reportText = File.ReadAllText(reportPath);
```

The `file` parameter from the query string is not validated before being combined with `_reportsRoot`. An absolute path passed as `file` (e.g., `C:\Windows\System32\hosts`) will cause `Path.Combine()` to return that absolute path unchanged, bypassing the intended restriction to the reports directory.

## Fix
```csharp
[HttpGet("export")]
public IActionResult ExportReport([FromQuery] string file)
{
    var reportPath = Path.Combine(_reportsRoot, file);
    
    // Resolve both paths to their canonical absolute forms
    var fullReportsRoot = Path.GetFullPath(_reportsRoot);
    var fullReportPath = Path.GetFullPath(reportPath);
    
    // Verify the resolved path stays within the intended root directory
    if (!fullReportPath.StartsWith(fullReportsRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) &&
        fullReportPath != fullReportsRoot)
    {
        return BadRequest("Invalid file path");
    }
    
    var reportText = File.ReadAllText(fullReportPath);
    return Content(reportText, "text/plain");
}
```

## Explanation
`Path.Combine()` has a documented behavior where an absolute path in any segment except the first discards all preceding segments. The fix uses `Path.GetFullPath()` to resolve both the reports root and the combined path to their canonical forms, then verifies the resolved path is contained within the restricted directory. The check uses `StartsWith()` with the directory separator to ensure boundary safety (a path like `C:\App\Data\Reports2\file.txt` would otherwise match a root of `C:\App\Data\Reports`). The `StringComparison.OrdinalIgnoreCase` accounts for Windows path case-insensitivity.
