## Verdict
CONFIRMED - Path traversal via string prefix containment sibling bypass

## Source
The vulnerability is a classic path containment bypass using string prefix matching without a directory separator. The code at line 25 checks:
```
if (!fullPath.StartsWith(BaseDirectory))
```

This check fails to account for sibling directories. A path like `C:\app\uploads-backup\file.txt` would pass this check because the string literally starts with `C:\app\uploads`, even though it's not within the uploads directory itself.

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

            if (!fullPath.StartsWith(BaseDirectory + Path.DirectorySeparatorChar) && fullPath != BaseDirectory)
            {
                return Forbid();
            }

            if (!System.IO.File.Exists(fullPath))
            {
                return NotFound();
            }

            // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
            var bytes = System.IO.File.ReadAllBytes(fullPath);
            return File(bytes, "application/octet-stream", Path.GetFileName(fullPath));
        }
    }
}
```

## Explanation
The fix adds a path separator check: `fullPath.StartsWith(BaseDirectory + Path.DirectorySeparatorChar)`. This ensures the path must be within the directory (with a separator following the directory name), or be the directory itself. Without the separator, an attacker cannot bypass the check by using sibling directory names like `uploads-backup` or `uploadsAdmin`.
