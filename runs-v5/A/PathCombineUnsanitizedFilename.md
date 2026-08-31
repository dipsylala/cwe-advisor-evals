## Verdict
Confirmed. `filename` is an untrusted HTTP query parameter that flows unmodified into `Path.Combine` and then into `File.ReadAllText`, allowing path traversal (e.g. `../../etc/passwd`) or, since `Path.Combine` discards the first argument when the second is rooted, complete override of the base directory (e.g. `filename=/etc/passwd` or `C:\Windows\win.ini`).

## Source
`filename` parameter of `ViewDocument(string filename)` in `DocumentsController.ViewDocument` (`[HttpGet("view")]`, `api/Documents/view?filename=...`) — attacker-controlled, unvalidated.

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
        // Strip any directory component so only a bare filename can be supplied.
        var safeName = Path.GetFileName(filename);
        if (string.IsNullOrEmpty(safeName))
        {
            return BadRequest("Invalid filename.");
        }

        var filePath = Path.GetFullPath(Path.Combine(_basePath, safeName));

        // Verify the resolved path is still inside the intended base directory.
        if (!filePath.StartsWith(_basePath + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            return BadRequest("Invalid filename.");
        }

        if (!System.IO.File.Exists(filePath))
        {
            return NotFound();
        }

        var contents = System.IO.File.ReadAllText(filePath);

        return Content(contents, "text/plain");
    }
}
```

## Explanation
`Path.Combine(_basePath, filename)` does two unsafe things with untrusted input: it happily concatenates `../` segments (traversal), and per its documented behavior it discards `_basePath` entirely whenever `filename` is a rooted path (e.g. starts with `/` or `C:\`), letting the caller name any absolute path on the filesystem.

The fix applies two independent defenses rather than relying on stripping alone, since a stripped value can still be re-interpreted as something unsafe:

1. `Path.GetFileName(safeName)` reduces the input to its last path segment, removing any directory traversal or rooting information before it ever reaches `Path.Combine`.
2. After combining, `Path.GetFullPath` resolves the result to a canonical absolute path (collapsing any remaining `.`/`..` segments), and the code then verifies with `StartsWith` (using the platform's directory separator so a sibling directory like `/var/app/documents-other` cannot pass) that the resolved path is still contained within the canonicalized base directory. This containment check is the actual security boundary; the `GetFileName` strip is defense-in-depth, not a substitute for it.

`_basePath` is also normalized once with `Path.GetFullPath` at field-initialization time so the comparison is between two canonical forms.
