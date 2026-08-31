## Verdict

exploitable (confidence: high)

## Source

`filename`, the `string` parameter of `ViewDocument` (`DocumentsController.cs`, `[HttpGet("view")]`). ASP.NET Core model binding populates it directly from the request query string with no validation applied by the framework or the action.

## Fix

Vulnerable code:

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
        var filePath = Path.Combine(_basePath, filename);

        // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
        var contents = File.ReadAllText(filePath);

        return Content(contents, "text/plain");
    }
}
```

Fixed code:

```csharp
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers;

[ApiController]
[Route("api/[controller]")]
public class DocumentsController : ControllerBase
{
    private readonly string _basePath = Path.GetFullPath("/var/app/documents");

    [HttpGet("view")]
    public IActionResult ViewDocument(string filename)
    {
        var filePath = Path.GetFullPath(Path.Combine(_basePath, filename));
        var relative = Path.GetRelativePath(_basePath, filePath);

        if (relative == ".." ||
            relative.StartsWith(".." + Path.DirectorySeparatorChar) ||
            relative.StartsWith(".." + Path.AltDirectorySeparatorChar) ||
            Path.IsPathRooted(relative))
        {
            return BadRequest("Invalid filename.");
        }

        var contents = File.ReadAllText(filePath);

        return Content(contents, "text/plain");
    }
}
```

## Explanation

`filename` reaches `Path.Combine(_basePath, filename)` unvalidated and flows straight into `File.ReadAllText()`, so a value such as `../../etc/passwd` (or, per `Path.Combine`'s documented behavior, an absolute path like `/etc/passwd`, which discards `_basePath` entirely and replaces it outright) lets the caller read any file the process account can access. The fix canonicalizes the combined path with `Path.GetFullPath()` - which resolves `..` segments and, for the absolute-path case, simply yields the attacker-supplied absolute path unchanged - and then checks containment with `Path.GetRelativePath()` rather than a raw string prefix. A relative result of `..`, one that starts with `..` plus either directory-separator form, or one that is itself rooted (the cross-drive/absolute-override case, where `GetRelativePath` cannot express the target as relative at all) all indicate the resolved path fell outside `_basePath`, and the request is rejected before the file operation runs. `_basePath` is canonicalized once at the field level so the comparison is between two like-formed absolute paths.

## Behaviour changes

- A request whose `filename` resolves outside `_basePath` (traversal sequences or an absolute/rooted path) now returns `400 Bad Request` instead of reaching `File.ReadAllText()`. Previously such a request either threw an unhandled `FileNotFoundException`/`UnauthorizedAccessException`/`IOException` (surfaced as an unhandled-exception response) or, worse, succeeded and returned the contents of a file outside the intended directory - this is the vulnerability being closed, not an incidental change.
- `_basePath` is now canonicalized once via `Path.GetFullPath()` at initialization. It was already an absolute literal, so this does not change its value; it only guarantees the later containment comparison operates on two paths in the same canonical form.
- For any `filename` that already resolved inside `_basePath` (the legitimate case), `filePath` is unchanged in value (only its computation now runs through `Path.GetFullPath()`), and the success path - `File.ReadAllText()` followed by `Content(contents, "text/plain")` - is untouched: same return value, same content type, same failure behavior (missing/unreadable file still throws as before).
