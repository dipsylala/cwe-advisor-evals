## Verdict

VULNERABLE. The code uses a bare string `StartsWith()` comparison for path containment validation, which accepts sibling directories with names prefixed by the base directory name. A path like `C:\app\uploads-secret\file.txt` passes the check for base directory `C:\app\uploads` because the string literally starts with `C:\app\uploads`. This is a classic path-prefix-confusion vulnerability (the "sibling bypass").

## Source

User-controlled filename `userFile` from HTTP query parameter `[FromQuery] string userFile` at line 15.

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

            var candidatePath = Path.Join(BaseDirectory, userFile);
            var fullPath = Path.GetFullPath(candidatePath);

            var relPath = Path.GetRelativePath(BaseDirectory, fullPath);
            if (relPath == ".." || relPath.StartsWith(".." + Path.DirectorySeparatorChar) ||
                relPath.StartsWith(".." + Path.AltDirectorySeparatorChar) ||
                Path.IsPathRooted(relPath))
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

The fix replaces the unsafe `StartsWith()` string comparison (line 25 in original) with path-aware containment validation using `Path.GetRelativePath()`. This method computes the relative path from the base directory to the canonicalized full path. If the resolved path escapes the base directory, `GetRelativePath()` returns a value starting with `..` (parent directory references). The validation then rejects any path that:

1. Equals `..` exactly (points to parent)
2. Starts with `..` followed by a separator (escapes and then enters a directory)
3. Is rooted (absolute path on same or different drive)

The fix also upgrades from `Path.Combine()` to `Path.Join()` per C# guidance—while both behave similarly with trailing user input, `Path.Join()` is the recommended method for user-supplied path components in .NET Core 2.1+. Both changes are necessary: `Path.Join()` prevents absolute paths from discarding the base directory, and `GetRelativePath()` prevents the sibling-directory string-prefix bypass.

All four rejection criteria are checked to handle edge cases: bare `..`, relative escapes, rooted paths (including different-drive absolute paths where `GetRelativePath()` returns the unmodified rooted path), and the alternate separator (`/` on Windows) for defense in depth.

## Behaviour changes

- **Rejection behavior:** Paths that previously passed through (sibling directories, parent directory escapes) are now correctly rejected before file access.
- **Normal case:** Requests for files inside the base directory (e.g., `userFile=report.pdf`) remain unaffected and are allowed.
- **API changes:** `Path.Join()` replaces `Path.Combine()`; `Path.GetRelativePath()` replaces `StartsWith()`. Both are available in .NET Core 3.0+ (covered by AspNetCore.Mvc's minimum requirements).
- **Error handling:** No change to exception handling or error responses; the same `Forbid()` response is returned for paths that escape the directory, only now the check is correct.
- **Performance:** Negligible; `Path.GetRelativePath()` is a lexical operation (does not access the filesystem).
