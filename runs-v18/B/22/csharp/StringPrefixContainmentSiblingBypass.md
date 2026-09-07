## Verdict

Exploitable. The vulnerability allows an attacker to access files outside the intended base directory by exploiting a string prefix containment check that fails when the base directory name is a prefix of a sibling directory name (e.g., `C:\app\uploads` vs. `C:\app\uploads-secret`).

## Source

Untrusted user input from the `userFile` query parameter (line 15).

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

            var fullPath = Path.GetFullPath(Path.Join(BaseDirectory, userFile));

            // Validate using Path.GetRelativePath for component-aware comparison
            var relativePath = Path.GetRelativePath(BaseDirectory, fullPath);

            if (relativePath == ".." || 
                relativePath.StartsWith(".." + Path.DirectorySeparatorChar) ||
                relativePath.StartsWith(".." + Path.AltDirectorySeparatorChar) ||
                Path.IsPathRooted(relativePath))
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

The original code validated path containment using a string prefix check (`fullPath.StartsWith(BaseDirectory)`), which fails when the base directory is a prefix of a sibling directory name. For example, `C:\app\uploads-secret` passes the check because the string starts with `C:\app\uploads`. An attacker can exploit this using a path traversal sequence like `../uploads-secret/file.txt`, which resolves to the sibling directory and bypasses the containment validation.

The fix replaces the string prefix check with `Path.GetRelativePath()`, which performs component-aware path comparison. The relative path is then validated to ensure it does not escape the base directory (no `..` at the start, no `..\` sequences, and not rooted). This approach correctly rejects sibling directories and other path traversal attempts while allowing legitimate file access within the intended directory.

Additionally, `Path.Combine()` is replaced with `Path.Join()` to prevent absolute paths in user input from replacing the base directory entirely (a distinct path traversal vector).

## Behaviour changes

1. **Path construction method changed**: `Path.Combine()` replaced with `Path.Join()` for more robust handling of absolute paths in user input on .NET Core 2.1+. Path.Join treats rooted arguments as relative paths when they appear after the first argument, preventing absolute path injection.

2. **Validation logic changed**: String prefix comparison replaced with component-aware validation using `Path.GetRelativePath()`. This correctly identifies parent directory references (`..`) that span path component boundaries, eliminating the sibling bypass.

3. **Defensive separator checks added**: Both `Path.DirectorySeparatorChar` and `Path.AltDirectorySeparatorChar` are tested during validation to ensure correct behavior across Windows path representations (`\` and `/`).

All existing behavioral contracts are preserved: file existence is still checked before reading, the method still returns 400 for missing input, 403 for forbidden access, 404 for missing files, and the file content and metadata are returned unchanged.
