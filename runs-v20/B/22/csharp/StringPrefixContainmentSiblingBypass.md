## Verdict

Exploitable. High confidence.

- **cwe_id**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'))
- **location**: `UploadsController.cs`, line 36 (`System.IO.File.ReadAllBytes(fullPath)`)

## Source

`userFile`, the `[FromQuery] string userFile` parameter of `Download` (`UploadsController.cs` line 15) - an HTTP query-string value under full attacker control, already percent-decoded by ASP.NET Core model binding before the handler runs.

Flow: `userFile` -> `Path.Combine(BaseDirectory, userFile)` (line 22) -> `Path.GetFullPath(candidatePath)` (line 23) -> containment check `fullPath.StartsWith(BaseDirectory)` (line 25) -> `System.IO.File.ReadAllBytes(fullPath)` (line 36, the sink).

The containment check at line 25 is a raw string prefix test, not a component-aware comparison. `BaseDirectory` is `C:\app\uploads` with no trailing separator, so any canonicalized path that merely starts with that character sequence passes - including a sibling directory such as `C:\app\uploads-secret\...` or `C:\app\uploads2\...`. `Path.GetFullPath()` collapses `..` segments before this check runs, so a `userFile` value like `..\uploads-secret\config.json` resolves to `C:\app\uploads-secret\config.json`, which `StartsWith(@"C:\app\uploads")` accepts, and the file is read and returned at line 36. The check breaks exactly at the string-prefix comparison; nothing upstream or downstream of it constrains the value.

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

The vulnerable code contained the resolved path within the base directory using `fullPath.StartsWith(BaseDirectory)`, a raw string-prefix comparison. That test is satisfied by any path that shares the base directory's characters as a leading substring, including an unrelated sibling directory (`C:\app\uploads-secret`), so it does not actually confine access to the intended tree. The fix replaces it with `Path.GetRelativePath(BaseDirectory, fullPath)`, which expresses `fullPath` relative to `BaseDirectory` on a path-component basis rather than a character basis. A path that escapes the base directory produces a relative result that is exactly `..`, starts with `..` followed by a directory separator, or - when `fullPath` is rooted on a different drive or share, which `Path.Combine` can produce if `userFile` itself is absolute - remains fully rooted; the fix checks all three outcomes (covering both `Path.DirectorySeparatorChar` and `Path.AltDirectorySeparatorChar`, since `GetRelativePath` can return either form and `/` is a valid separator on Windows) and rejects the request with `Forbid()` in every case. This closes the sibling-directory bypass while keeping the same canonicalize-then-contain structure, sink, and error-handling shape as the original code.

## Behaviour changes

- The containment test changed from `fullPath.StartsWith(BaseDirectory)` to a `Path.GetRelativePath`-based component check. Reason: closes the sibling-directory bypass (`C:\app\uploads-secret`, `C:\app\uploads2\...`) that the string-prefix test let through; this is the fix itself, not incidental.
- A previously-accepted sibling path (e.g. `..\uploads-secret\config.json`) now returns `403 Forbid()` instead of proceeding to `NotFound()`/`ReadAllBytes()`. Reason: that acceptance was the vulnerability; no legitimate request depends on escaping the base directory, so this is a security-necessary change, not scope creep.
- Everything else is unchanged: the sink (`System.IO.File.ReadAllBytes(fullPath)`), its return value and how the caller uses it (wrapped in `File(bytes, "application/octet-stream", Path.GetFileName(fullPath))`), the `BadRequest`/`NotFound` branches, `Path.Combine`/`Path.GetFullPath` construction, and the response content type and filename derivation are all preserved exactly as in the original.
- **verification**: `dotnet build` (net10.0, ASP.NET Core Web API SDK) against a scratch project containing only the fixed controller file - build succeeded with 0 errors (2 pre-existing NuGet advisory warnings from the scaffold template's own `Microsoft.OpenApi` package reference, unrelated to this change and not present in the original file's dependency set).
- **assumptions**: The project targets a modern .NET (ASP.NET Core / `Microsoft.AspNetCore.Mvc` usage, not .NET Framework), so `Path.GetRelativePath()` (.NET Core 2.0+) is available; this was confirmed compilable against net10.0 and is consistent with the codebase's use of `ControllerBase`/`[ApiController]`. No other ambiguity was resolved.
