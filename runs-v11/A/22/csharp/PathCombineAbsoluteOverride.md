## Verdict

VULNERABLE. The code uses `Path.Combine(_reportsRoot, file)` without validating that `file` is a relative path. In .NET, `Path.Combine` discards the first argument when the second argument is an absolute path. An attacker can supply an absolute path (e.g., `C:\Windows\System32\config\sam`) to read arbitrary files on the system, completely bypassing the `_reportsRoot` directory restriction.

## Source

Line 20-23:

```csharp
var reportPath = Path.Combine(_reportsRoot, file);
var reportText = File.ReadAllText(reportPath);
```

The vulnerability occurs because `file` is an untrusted query parameter that is not validated before being combined with the restricted root directory. `Path.Combine`'s behavior of accepting absolute paths as the second argument makes this a path traversal sink.

## Fix

```csharp
[HttpGet("export")]
public IActionResult ExportReport([FromQuery] string file)
{
    if (string.IsNullOrEmpty(file) || Path.IsPathRooted(file))
    {
        return BadRequest("Invalid file path");
    }

    var reportPath = Path.GetFullPath(Path.Combine(_reportsRoot, file));

    if (!reportPath.StartsWith(Path.GetFullPath(_reportsRoot) + Path.DirectorySeparatorChar, 
        StringComparison.OrdinalIgnoreCase))
    {
        return BadRequest("Access denied");
    }

    if (!System.IO.File.Exists(reportPath))
    {
        return NotFound();
    }

    var reportText = File.ReadAllText(reportPath);
    return Content(reportText, "text/plain");
}
```

## Explanation

The fix employs multiple layers of defense:

1. **Reject absolute paths:** `Path.IsPathRooted(file)` detects and rejects any path that is rooted (absolute) on the current drive or network, preventing the direct attack of passing `C:\Windows\...`.

2. **Reject empty/null:** Guards against edge cases where an attacker supplies null or empty input.

3. **Normalize both paths:** `Path.GetFullPath()` resolves `.` and `..` sequences and normalizes separators. Both the constructed path and the root are normalized to ensure consistent comparison.

4. **Verify confinement:** After normalization, verify that the full resolved path starts with the normalized root directory (with a trailing separator to prevent directory name prefix attacks, e.g., `C:\App\Data\Reports` being bypassed by `C:\App\Data\Reports-evil\file`). `OrdinalIgnoreCase` is used for the comparison to match Windows path semantics regardless of case.

5. **Fail fast on missing files:** Check file existence before attempting to read, providing clear error responses.

This multi-layered approach prevents both absolute path injection and relative traversal attacks while maintaining the intended restriction to the reports directory.
