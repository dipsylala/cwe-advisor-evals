## Verdict

**Confirmed.** The vulnerability is exploitable. An attacker can supply an absolute path as the `file` query parameter, which `Path.Combine()` will use to override the base directory, bypassing the intended directory restriction and allowing arbitrary file read access.

## Source

The vulnerability originates in the `ExportReport` method at line 15:

```csharp
public IActionResult ExportReport([FromQuery] string file)
```

The `file` parameter is user-supplied query string input with no validation.

## Fix

Replace the vulnerable code (lines 17-23) with the following remediated version:

```csharp
[HttpGet("export")]
public IActionResult ExportReport([FromQuery] string file)
{
    // Validate input
    if (string.IsNullOrEmpty(file))
    {
        return BadRequest("File name is required");
    }
    
    // Reject absolute paths
    if (Path.IsPathRooted(file))
    {
        return BadRequest("Invalid file path");
    }
    
    // Reject path traversal attempts
    if (file.Contains(".."))
    {
        return BadRequest("Invalid file path");
    }
    
    // Combine the base directory with the file name using Path.Join
    var reportPath = Path.Join(_reportsRoot, file);
    
    // Canonicalize both paths
    var fullReportPath = Path.GetFullPath(reportPath);
    var fullReportsRoot = Path.GetFullPath(_reportsRoot);
    
    // Verify the path stays within the reports directory
    var relativePath = Path.GetRelativePath(fullReportsRoot, fullReportPath);
    if (relativePath.StartsWith("..") || Path.IsPathRooted(relativePath))
    {
        return BadRequest("Access denied");
    }
    
    var reportText = File.ReadAllText(fullReportPath);
    return Content(reportText, "text/plain");
}
```

## Explanation

The original code used `Path.Combine(_reportsRoot, file)` without validating the `file` parameter. `Path.Combine()` has a documented behavior: if any argument after the first is an absolute path, all earlier components are discarded and the result becomes that absolute path. This means an attacker supplying `C:\Windows\System32\config\SAM` or any other rooted path would bypass the `_reportsRoot` restriction entirely.

The fix implements three layers of defense:

1. **Input validation** (lines 20-29): Reject `null`/empty input, absolute paths (detected via `Path.IsPathRooted()`), and traversal sequences (`..`). These checks occur before any path construction.

2. **Safe path construction** (line 32): Replace `Path.Combine()` with `Path.Join()`, which is designed for untrusted input arguments. This is a safer API, though input validation is still required.

3. **Canonicalization and containment check** (lines 34-41): Resolve both the target path and the reports root to canonical form using `Path.GetFullPath()`, which normalizes relative references and symlinks. Then verify the target path remains within the base directory by computing the relative path and rejecting any result that escapes (starts with `..`) or is rooted.

This defense-in-depth approach ensures that even if an unexpected input encoding or filesystem state is encountered, the path cannot escape the intended directory.

## Behaviour changes

- Requests with invalid `file` parameters now return HTTP 400 (Bad Request) instead of attempting file access
- Legitimate requests for files within the reports directory continue to work as before
- The endpoint is no longer vulnerable to path traversal attacks using absolute paths, `..` sequences, or other traversal tricks
