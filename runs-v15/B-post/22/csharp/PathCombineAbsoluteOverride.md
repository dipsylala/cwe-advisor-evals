## Verdict

Exploitable

## Source

User-supplied filename from HTTP query parameter `file` in `[FromQuery] string file` (line 15).

## Fix

**Vulnerable Code:**
```csharp
[HttpGet("export")]
public IActionResult ExportReport([FromQuery] string file)
{
    // No check that 'file' is a relative path before combining it with
    // the reports root - Path.Combine will happily discard the root
    // when 'file' is itself rooted.
    var reportPath = Path.Combine(_reportsRoot, file);

    // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
    var reportText = File.ReadAllText(reportPath);

    return Content(reportText, "text/plain");
}
```

**Fixed Code:**
```csharp
[HttpGet("export")]
public IActionResult ExportReport([FromQuery] string file)
{
    // Reject null or empty input
    if (string.IsNullOrWhiteSpace(file))
    {
        return BadRequest("File parameter is required");
    }
    
    // Use Path.Join instead of Path.Combine to prevent absolute paths 
    // from overriding the base directory
    var reportPath = Path.Join(_reportsRoot, file);
    
    // Canonicalize both the constructed path and the base directory
    var fullPath = Path.GetFullPath(reportPath);
    var rootFullPath = Path.GetFullPath(_reportsRoot);
    
    // Verify the resolved path remains within the allowed directory
    var relativePath = Path.GetRelativePath(rootFullPath, fullPath);
    
    // Reject any path that escapes the root or is rooted elsewhere
    if (relativePath.StartsWith("..") || Path.IsPathRooted(relativePath))
    {
        return Forbid();
    }
    
    var reportText = File.ReadAllText(fullPath);

    return Content(reportText, "text/plain");
}
```

## Explanation

The vulnerability occurs because `Path.Combine(_reportsRoot, file)` discards the base directory if the second argument is an absolute path. An attacker can supply `file = "C:\Windows\System32\config\sam"` (or any absolute path), causing `Path.Combine()` to return that absolute path instead of a path under `_reportsRoot`, allowing arbitrary file reads anywhere on the system.

The fix uses three layers of defense from the CWE-22 C# guidance:

1. **Path.Join() instead of Path.Combine()**: `Path.Join()` treats all arguments after the first as relative, preventing absolute paths from overriding the base directory. This is the primary fix and works on .NET Core 2.1+ and .NET Standard 2.1+.

2. **Canonicalization with Path.GetFullPath()**: Resolves relative path sequences like `../` and normalizes the paths to absolute form for comparison.

3. **Containment validation with Path.GetRelativePath()**: After canonicalization, computes the relative path from the root to the resolved file. If this relative path starts with `..` or is rooted elsewhere, the file is outside the allowed directory and the request is rejected. This approach uses path-component-aware comparison rather than a simple string prefix check, which would incorrectly accept sibling directories like `C:\App\Data\Reports-secret`.

The fix rejects (rather than strips) invalid input, preserving evidence of the attack attempt in logs.

## Behaviour changes

1. **New null/empty check** (line 3): Returns `400 BadRequest` if the `file` parameter is missing or whitespace. Reason: Prevents passing empty/null strings to file operations.

2. **Path.Join() replaces Path.Combine()** (line 8): Ensures absolute paths in user input cannot override the base directory. Reason: Core fix - prevents the path traversal mechanism.

3. **Path.GetFullPath() calls** (lines 11-12): Canonicalizes both the constructed path and the root. Reason: Required before containment validation (must compare apples-to-apples in canonical form).

4. **Path.GetRelativePath() validation** (line 15-16): Verifies the resolved file path remains under the root. Reason: Implements allowlist-based containment - rejects any path that attempts to escape upward or reach a different absolute location.

5. **Forbid() response instead of proceeding** (line 19): Returns `403 Forbidden` for rejected paths. Reason: Denies access when validation fails, rather than silently stripping or modifying the input.

6. **File.ReadAllText(fullPath) uses canonicalized path** (line 21): Uses the validated `fullPath` variable instead of re-deriving from the original input. Reason: Time-of-check-time-of-use (TOCTOU) prevention - ensures the path read from disk is the same one that passed validation.

All behaviour changes preserve the sink contract: `File.ReadAllText()` still reads and returns file contents as before, but only after validation has confirmed the file is within the restricted directory.

