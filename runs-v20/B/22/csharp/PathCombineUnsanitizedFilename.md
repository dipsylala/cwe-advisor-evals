## Verdict

Confirmed, exploitable. `filename` is bound directly from the query string with no
validation, passed into `Path.Combine()`, and the result is read with
`File.ReadAllText()`. A value such as `../../etc/passwd` traverses out of
`_basePath`, and an absolute value such as `/etc/passwd` (or `C:\Windows\win.ini`)
causes `Path.Combine()` to discard `_basePath` entirely and use the attacker-supplied
path outright, per Microsoft's documented `Path.Combine()` behaviour for a rooted
later argument.

## Source

`filename`, the `string` parameter of `ViewDocument(string filename)` in
`DocumentsController`, bound by ASP.NET Core model binding from the `view` route's
query string. It reaches the sink unvalidated.

## Fix

### File: PathCombineUnsanitizedFilename.cs

```csharp
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers;

[ApiController]
[Route("api/[controller]")]
public class DocumentsController : ControllerBase
{
    private readonly string _basePath = "/var/app/documents";

    [HttpGet("view")]
    public IActionResult ViewDocument(string filename)
    {
        var basePathFull = Path.GetFullPath(_basePath);
        var combinedPath = Path.GetFullPath(Path.Combine(basePathFull, filename));
        var relativePath = Path.GetRelativePath(basePathFull, combinedPath);

        if (relativePath == ".." ||
            relativePath.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
            relativePath.StartsWith(".." + Path.AltDirectorySeparatorChar, StringComparison.Ordinal) ||
            Path.IsPathRooted(relativePath))
        {
            return BadRequest("Invalid filename.");
        }

        var filePath = combinedPath;

        var contents = System.IO.File.ReadAllText(filePath);

        return Content(contents, "text/plain");
    }
}
```

## Explanation

The fix canonicalizes both the base directory and the combined candidate path with
`Path.GetFullPath()` (which normalizes `..` segments and resolves the path to
absolute form) and then compares them with `Path.GetRelativePath()`, a
path-component-aware comparison rather than a raw string prefix check. If the
relative result is exactly `..`, starts with `..` followed by either directory
separator, or is itself rooted (the case where `filename` was an absolute path,
or an absolute path on a different drive that `GetRelativePath` cannot express
relatively), the request is rejected before the file system is touched. This
closes both traversal vectors present in the original code: relative `../`
sequences escaping `_basePath`, and an absolute `filename` overriding
`_basePath` outright via `Path.Combine()`'s documented rooted-argument behaviour.
The value used for the actual file read (`filePath = combinedPath`) is the same
canonicalized value that was validated, not a re-derived path, so there is no
gap between the check and the use. No allowlist was added, since the application
does not define a fixed set of permitted filenames or extensions here - the
containment check alone is the fix. `File.ReadAllText()` is still called exactly
as before for legitimate filenames, preserving its return value, its `Content`
usage, and its exception behaviour (e.g. `FileNotFoundException` for a missing
file) for the non-malicious case.

## Behaviour changes

- A request whose `filename` resolves outside `_basePath` (relative traversal or
  an absolute/rooted path) now returns `400 Bad Request` with body
  `"Invalid filename."` instead of either succeeding (traversal) or reaching
  `File.ReadAllText()` with an out-of-scope or malformed path.
- Legitimate filenames that resolve inside `_basePath` are read and returned
  exactly as before, with identical success and not-found/error behaviour.
- Verification: the fixed file was compiled with `dotnet build` against a
  minimal ASP.NET Core (net8.0) scratch project referencing
  `Microsoft.AspNetCore.Mvc` - build succeeded with 0 warnings and 0 errors,
  confirming every API used (`Path.GetFullPath`, `Path.Combine`,
  `Path.GetRelativePath`, `Path.DirectorySeparatorChar`,
  `Path.AltDirectorySeparatorChar`, `Path.IsPathRooted`, `BadRequest`) exists
  and is used with a valid signature.
