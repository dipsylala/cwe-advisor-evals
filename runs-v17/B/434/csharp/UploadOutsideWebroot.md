## Verdict

exploitable

## Source

Line 17: `IFormFile file` parameter - specifically the `file.FileName` property used at line 28.

The filename is supplied by the client in the multipart form data request headers and is untrusted. It is read directly without validation and used to construct a file storage path.

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

    // Mapping of allowed file signatures (hex) to file extensions
    private static readonly Dictionary<string, string> AllowedSignatures = new()
    {
        // PDF: 25 50 44 46 ("%PDF")
        { "25504446", ".pdf" },
        // PNG: 89 50 4E 47
        { "89504E47", ".png" },
        // JPEG: FF D8 FF
        { "FFD8FF", ".jpg" },
        // GIF: 47 49 46 ("GIF")
        { "474946", ".gif" },
    };

    public UploadOutsideWebrootController(IWebHostEnvironment env) => _env = env;

    [HttpPost("/upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file is null || file.Length == 0)
        {
            return BadRequest();
        }

        // Read file signature and validate against allowlist of magic bytes
        using var stream = file.OpenReadStream();
        var signature = await ReadFileSignatureAsync(stream);
        var allowedExtension = FindAllowedExtension(signature);

        if (allowedExtension == null)
        {
            return BadRequest("File type not allowed");
        }

        var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
        Directory.CreateDirectory(uploadRoot);

        // Generate a server-controlled filename based on detected type, never using client-supplied FileName
        var storedFileName = Guid.NewGuid().ToString("N") + allowedExtension;
        var destination = Path.Combine(uploadRoot, storedFileName);

        // Rewind stream to beginning after signature check before copying
        stream.Seek(0, SeekOrigin.Begin);

        await using var fileStream = System.IO.File.Create(destination);
        await stream.CopyToAsync(fileStream);

        return Ok(new { stored = Path.GetFileName(destination), bytes = file.Length });
    }

    private static async Task<string> ReadFileSignatureAsync(Stream stream)
    {
        var buffer = new byte[8];
        int bytesRead = await stream.ReadAsync(buffer, 0, 8);

        if (bytesRead == 0)
            return string.Empty;

        // Convert bytes to hex string for signature comparison
        return BitConverter.ToString(buffer, 0, bytesRead).Replace("-", "").ToUpperInvariant();
    }

    private static string? FindAllowedExtension(string fileSignature)
    {
        foreach (var (signature, extension) in AllowedSignatures)
        {
            // Check if file signature starts with a known magic byte pattern
            if (fileSignature.StartsWith(signature))
            {
                return extension;
            }
        }

        return null;
    }
}
```

## Explanation

The fix eliminates CWE-434 by validating the file's actual content (magic bytes/signature) rather than trusting the client-supplied filename or content-type header. The original code at line 28 used `file.FileName` directly to construct a storage path, allowing an attacker to upload executable files with dangerous extensions (`.exe`, `.aspx`, `.cshtml`) or use path traversal sequences (e.g., `../../../config`).

The fixed code:
1. Reads the first 8 bytes of the uploaded file and converts them to a hexadecimal signature.
2. Checks this signature against an allowlist of known magic byte patterns for permitted file types (PDF, PNG, JPEG, GIF).
3. Rejects the upload if the signature does not match any allowed type.
4. Generates a cryptographically random filename using `Guid.NewGuid().ToString("N")` (eliminating the attacker's ability to choose the stored filename), and appends an extension derived from the detected file type.
5. Stores the file using this server-controlled name, ensuring the stored extension always matches the file's actual content.

The file is still stored outside `wwwroot` (unchanged from the original), preventing direct web access and execution of uploaded content. The response still returns the stored filename and file size, maintaining the original API contract.

## Behaviour changes

- **Added file type validation**: Requests with files that do not match an allowed signature are rejected with HTTP 400 ("File type not allowed"), whereas the original code accepted all files. This is a security-required behaviour change.
- **Filename generation**: Stored files are now named with a GUID instead of the client-supplied filename. The original code returned `Path.GetFileName(destination)` which reflected the client's input; the new code returns the GUID-based name. This is intentional—the client-supplied filename is the attack vector, and exposing the server-generated name is safe. Existing clients expecting to retrieve a file by the name they uploaded will need to use an opaque file ID instead (this is a breaking change for any client relying on the original stored filename).
- **Stream handling**: The code now holds a reference to `file.OpenReadStream()` for both validation and copying. After reading the signature, the stream is rewound with `Seek(0, SeekOrigin.Begin)` before copying the entire file. The original code discarded the stream after checking null/length and opened a fresh write stream. If the stream is not seekable, the seek operation will throw an exception—this is a failure mode not present in the original code, though in practice ASP.NET Core's multipart form file handling ensures the stream is seekable.
- **Return value unchanged**: The response structure (`{ stored = ..., bytes = ... }`) is preserved with the same shape, so dependent code continues to receive a response of the same type.

No other behaviour of the endpoint changes: input validation, directory creation, async handling, and HTTP method/route remain identical.
