## Verdict
VULNERABILITY CONFIRMED

The containment check at line 25 uses a string-prefix comparison (`fullPath.StartsWith(BaseDirectory)`) that is vulnerable to sibling directory bypass. A path like `C:\app\uploads-secret\file.txt` would pass the check because it literally begins with the string `C:\app\uploads`, even though it lies outside the intended directory. This allows an attacker to read files from a sibling directory.

## Source
Line 25, method `Download()`:
```csharp
if (!fullPath.StartsWith(BaseDirectory))
{
    return Forbid();
}
```

**Data flow:**
1. User input enters via `[FromQuery] string userFile` (line 15)
2. Combined with base directory via `Path.Combine()` (line 22)
3. Canonicalized via `Path.GetFullPath()` (line 23)
4. Validated with string prefix check (line 25) ← VULNERABILITY
5. File read via `System.IO.File.ReadAllBytes(fullPath)` (line 36)

**Attack scenario:** An attacker supplies `userFile = "..\uploads-secret\file.txt"`, which resolves to `C:\app\uploads-secret\file.txt` after canonicalization. The string prefix check passes because `"C:\app\uploads-secret"` starts with `"C:\app\uploads"`, but the file is outside the intended directory.

## Fix

### File: UploadsController.cs
```csharp
using System;
using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace FileShare.Controllers
{
    [ApiController]
    [Route("uploads")]
    public class UploadsController : ControllerBase
    {
        private static readonly string BaseDirectory = @"C:\app\uploads";

        // GET /uploads/download?userFile=report.pdf
        [HttpGet("download")]
        public IActionResult Download([FromQuery] string userFile)
        {
            if (string.IsNullOrEmpty(userFile))
            {
                return BadRequest("userFile is required");
            }

            var candidatePath = Path.Combine(BaseDirectory, userFile);
            var fullPath = Path.GetFullPath(candidatePath);

            // Use path-component-aware comparison via GetRelativePath()
            var relPath = Path.GetRelativePath(BaseDirectory, fullPath);
            if (relPath.StartsWith("..") || Path.IsPathRooted(relPath))
            {
                return Forbid();
            }

            if (!System.IO.File.Exists(fullPath))
            {
                return NotFound();
            }

            var bytes = System.IO.File.ReadAllBytes(fullPath);
            return File(bytes, "application/octet-stream", Path.GetFileName(fullPath));
        }
    }
}
```

## Explanation

The fix replaces the string-prefix check with `Path.GetRelativePath()`, which performs path-component-aware comparison. After canonicalizing `fullPath` with `Path.GetFullPath()`, the code computes the relative path from `BaseDirectory` to `fullPath`. If this relative path starts with `..`, it means the target lies outside (or above) the base directory and must be rejected. The additional check for `Path.IsPathRooted(relPath)` rejects any absolute paths that `GetRelativePath()` might return in edge cases.

**Attack prevention:** With the fix, `fullPath = "C:\app\uploads-secret\file.txt"` produces `relPath = "..\uploads-secret\file.txt"`, which starts with `..` and is rejected. Sibling directory access is now blocked.

**Sink contract preserved:** The file read operation at line 36 continues to receive the same validated `fullPath` variable, and behavior remains unchanged for legitimate requests within the base directory.

## Behaviour changes

- Paths that attempt to escape the base directory (e.g., via `..` sequences, absolute paths, or sibling directory access) are now rejected.
- Legitimate files within the base directory continue to be readable without change.
- No change to the HTTP response codes or error handling logic.
