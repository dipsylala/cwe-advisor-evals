## Verdict

Confirmed. The endpoint accepts any uploaded file and persists it under the caller-supplied name with no restriction on file type, so an attacker can upload a file with a dangerous extension (e.g. `.exe`, `.dll`, `.aspx`, `.php`, `.sh`) alongside any content. Storing the file outside the web root prevents it from being served/executed directly by the web server, but it does not restrict what type of file can be uploaded, and any later code path that reads files from `storage/uploads` (a virus scanner, an image processor, a move-to-public-folder step, a download endpoint that serves them back) inherits the risk of handling an arbitrary/dangerous file type.

## Source

`file.FileName` (and `file` itself) from the `IFormFile file` action parameter bound from the incoming multipart/form-data request in `Upload(IFormFile file)`. This is attacker-controlled: both the name and the content of the uploaded file are supplied entirely by the client.

## Fix

### File: UploadOutsideWebroot.cs
```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases;

[ApiController]
public class UploadOutsideWebrootController : ControllerBase
{
    private readonly IWebHostEnvironment _env;

    private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".txt"
    };

    private static readonly Dictionary<string, string> AllowedContentTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        [".png"] = "image/png",
        [".jpg"] = "image/jpeg",
        [".jpeg"] = "image/jpeg",
        [".gif"] = "image/gif",
        [".pdf"] = "application/pdf",
        [".txt"] = "text/plain",
    };

    private const long MaxFileSizeBytes = 10 * 1024 * 1024; // 10 MB

    public UploadOutsideWebrootController(IWebHostEnvironment env) => _env = env;

    [HttpPost("/upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file is null || file.Length == 0)
        {
            return BadRequest();
        }

        if (file.Length > MaxFileSizeBytes)
        {
            return BadRequest("File exceeds the maximum allowed size.");
        }

        // Validate the extension against an allow-list of file types the application
        // is actually prepared to handle. Do not derive any part of the stored
        // filename from the untrusted original name.
        var extension = Path.GetExtension(file.FileName);
        if (string.IsNullOrEmpty(extension) || !AllowedExtensions.Contains(extension))
        {
            return BadRequest("Unsupported file type.");
        }

        // The client-supplied Content-Type header is attacker-controlled and easily
        // spoofed, but cross-checking it against the extension catches accidental
        // mismatches and raises the bar slightly; it is not relied on alone.
        if (!AllowedContentTypes.TryGetValue(extension, out var expectedContentType) ||
            !string.Equals(file.ContentType, expectedContentType, StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest("File content type does not match its extension.");
        }

        var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
        Directory.CreateDirectory(uploadRoot);

        // Generate an opaque, server-controlled filename using only the validated
        // extension. This removes the untrusted original filename from the path
        // entirely, eliminating both path traversal and dangerous double-extension
        // tricks (e.g. "invoice.pdf.aspx"), and avoids collisions.
        var safeFileName = $"{Guid.NewGuid():N}{extension}";
        var destination = Path.Combine(uploadRoot, safeFileName);

        await using var stream = System.IO.File.Create(destination);
        await file.CopyToAsync(stream);

        return Ok(new { stored = safeFileName, bytes = file.Length });
    }
}
```

## Explanation

The original code took `file.FileName` - a value fully controlled by the client - and used it unmodified both as the on-disk filename and, implicitly, as the only gate on what type of file could be stored (there was none). Nothing checked the extension, so any file type could be written to `storage/uploads`, including executable or server-side-script extensions. Storing the file outside the web root (under `ContentRootPath` rather than `WebRootPath`) is good defense-in-depth against the file being directly requested and executed by the web server, but it does not address CWE-434 itself: the endpoint still has no restriction on the kind of file it accepts, so any downstream consumer of that storage location (an admin UI that lists/downloads uploads, a virus/AV scan step, a later move into a publicly served folder) can still be handed a dangerous file type.

The fix validates the extension against an explicit allow-list of file types the application is actually meant to handle, cross-checks the declared `ContentType` against the expected value for that extension as a secondary check, enforces a maximum size, and - critically - never uses the client-supplied filename to build the destination path. Instead it generates a new `Guid`-based filename with only the validated extension appended. This closes the unrestricted-upload weakness (only allow-listed types can be stored) and, as a side benefit, removes any possibility of path traversal or extension-spoofing (e.g. `shell.aspx.jpg` style tricks) via the filename, since the untrusted name is discarded rather than sanitized.
