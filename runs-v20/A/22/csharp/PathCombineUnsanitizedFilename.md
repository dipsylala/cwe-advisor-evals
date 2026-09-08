## Verdict

Confirmed. `filename` is an unvalidated query parameter that flows directly into `Path.Combine(_basePath, filename)` and then into `File.ReadAllText`. `Path.Combine` does not restrict traversal: if `filename` contains `../` segments, the resulting path can escape `_basePath`, and if `filename` is rooted (e.g. `C:\secrets\file.txt` or `/etc/passwd`), `Path.Combine` discards `_basePath` entirely and returns the rooted path unchanged, letting the caller read any file the process can access.

## Source

`filename` — the `string filename` parameter of `ViewDocument(string filename)` in `DocumentsController`, bound from the `view` query string in the incoming HTTP request. It is attacker-controlled and reaches the sink with no validation or sanitization.

## Fix

### File: PathCombineUnsanitizedFilename.cs
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
        // Strip any directory information the caller supplied; only a bare
        // file name is a legitimate request.
        var safeFileName = Path.GetFileName(filename);
        if (string.IsNullOrEmpty(safeFileName) || safeFileName != filename)
        {
            return BadRequest("Invalid filename.");
        }

        var filePath = Path.GetFullPath(Path.Combine(_basePath, safeFileName));

        // Defense in depth: confirm the resolved path is still inside the
        // intended base directory before touching the filesystem.
        var basePathWithSeparator = _basePath.EndsWith(Path.DirectorySeparatorChar)
            ? _basePath
            : _basePath + Path.DirectorySeparatorChar;

        if (!filePath.StartsWith(basePathWithSeparator, StringComparison.Ordinal))
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

The fix applies two independent controls so that a change to either one alone cannot regress the whole defense:

1. **Reject directory components outright.** `Path.GetFileName(filename)` extracts only the last path segment. Comparing the result back against the original `filename` rejects any input containing a directory separator, a drive letter, or a UNC prefix (`..\..\etc\passwd`, `/etc/passwd`, `C:\Windows\win.ini`, `\\server\share\file`) instead of silently truncating it to something that looks safe but wasn't what the caller asked for. This closes the case where `Path.Combine` would otherwise honor a rooted `filename` and discard `_basePath` entirely.

2. **Canonicalize and verify containment.** `Path.GetFullPath` resolves `.`/`..` segments and relative components on both `_basePath` and the combined result, then a prefix check (with a trailing separator appended to `_basePath` so `/var/app/documents-evil` cannot pass as a false positive) confirms the resolved file still lives under the intended directory. This is defense in depth in case any future change reintroduces a path that survives step 1 (for example if the allowlist check above is loosened later).

Because `_basePath` is now canonicalized once in the field initializer, both sides of the comparison use the same normalized form, avoiding a mismatch from trailing separators or symlink-free path differences on different platforms.

An existing-file check (`File.Exists`) was added so a rejected/missing file returns `404` rather than letting `File.ReadAllText` throw an unhandled `FileNotFoundException`, which is a minor robustness improvement that falls out of the same code path.
