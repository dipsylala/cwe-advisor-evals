## Verdict

Confirmed. `filename` is an untrusted query parameter that flows unmodified into `Path.Combine` and then into `File.ReadAllText`. `Path.Combine` does not sanitize its inputs: if `filename` contains `..` segments the resulting path can escape `_basePath`, and if `filename` is a rooted/absolute path (e.g. `C:\secrets.txt` or `/etc/passwd`) `Path.Combine` discards `_basePath` entirely and returns the rooted path as-is. Either case lets a caller read arbitrary files reachable by the process, e.g. `GET /api/documents/view?filename=../../../../etc/passwd` or `GET /api/documents/view?filename=C:\Windows\win.ini`.

## Source

`filename` — the `ViewDocument` action parameter, bound directly from the `?filename=` query string in the incoming HTTP request (ASP.NET Core model binding). No validation or sanitization is applied before use.

## Fix

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
        if (string.IsNullOrWhiteSpace(filename) ||
            filename.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            return BadRequest("Invalid filename.");
        }

        // Resolve against the base directory and require the canonical result
        // to stay inside it. This defeats both ../ traversal and absolute-path
        // overrides, since Path.Combine returns a rooted path unchanged.
        var candidatePath = Path.GetFullPath(Path.Combine(_basePath, filename));
        var basePathWithSeparator = _basePath.EndsWith(Path.DirectorySeparatorChar)
            ? _basePath
            : _basePath + Path.DirectorySeparatorChar;

        if (!candidatePath.StartsWith(basePathWithSeparator, StringComparison.Ordinal))
        {
            return BadRequest("Invalid filename.");
        }

        if (!System.IO.File.Exists(candidatePath))
        {
            return NotFound();
        }

        var contents = System.IO.File.ReadAllText(candidatePath);

        return Content(contents, "text/plain");
    }
}
```

## Explanation

`Path.Combine` is a string-concatenation convenience, not a security boundary: it happily accepts `..` segments and, per its documented behavior, returns the second argument unchanged (dropping the first entirely) whenever that argument is itself a rooted path. Both properties let `filename` steer the final path outside `_basePath`.

The fix uses `Path.GetFullPath` to canonicalize the combined path (collapsing `..` and resolving it to an absolute form), then checks with `StartsWith` that the canonical result still falls inside the canonicalized `_basePath`, using a trailing-separator-normalized prefix so a sibling directory that merely shares a name prefix (e.g. `/var/app/documents-secret`) cannot pass the check. `Path.GetInvalidFileNameChars()` is also checked as a cheap early rejection of separator characters and other characters that have no business in a bare filename, though the canonicalization-plus-prefix check is what actually closes the traversal, not the character filter alone. `_basePath` itself is canonicalized once via `Path.GetFullPath` at the field level so the comparison is between two values produced the same way.

`File.Exists` is checked before reading so a rejected or missing path returns a clean `NotFound()`/`BadRequest()` instead of letting `File.ReadAllText` throw an unhandled `FileNotFoundException` that could leak stack trace details in a non-production environment.
