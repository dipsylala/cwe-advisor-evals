## Verdict

Exploitable. The application accepts uploaded files without validating their type or content, and stores them using the client-supplied filename (`file.FileName`). An attacker can upload executable scripts (e.g., `.cshtml`, `.aspx`, `.html`, `.svg`) or files with path traversal sequences, which the application persists under their original name. If stored in a location where the server executes or serves content (or if Razor runtime compilation is enabled), the payload executes.

## Source

IFormFile parameter from HTTP multipart request at line 17, carrying untrusted filename and content.

## Fix

### File: UploadOutsideWebroot.cs

```csharp
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases;

[ApiController]
public class UploadOutsideWebrootController : ControllerBase
{
    private readonly IWebHostEnvironment _env;

    // Magic bytes for allowed file types (signature, extension)
    private static readonly (byte[] Signature, string Extension)[] AllowedSignatures = new[]
    {
        (new byte[] { 0x89, 0x50, 0x4E, 0x47 }, "png"),             // PNG
        (new byte[] { 0xFF, 0xD8, 0xFF }, "jpg"),                   // JPEG
        (new byte[] { 0x47, 0x49, 0x46 }, "gif"),                   // GIF
        (new byte[] { 0x25, 0x50, 0x44, 0x46 }, "pdf"),            // PDF
    };

    private const int MaxFileSize = 10 * 1024 * 1024; // 10 MB

    public UploadOutsideWebrootController(IWebHostEnvironment env) => _env = env;

    [HttpPost("/upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file is null || file.Length == 0)
        {
            return BadRequest();
        }

        if (file.Length > MaxFileSize)
        {
            return BadRequest("File too large");
        }

        // Validate file signature and get extension
        await using var uploadStream = file.OpenReadStream();
        var signature = new byte[4];
        var bytesRead = await uploadStream.ReadAsync(signature, 0, signature.Length);

        if (bytesRead == 0)
        {
            return BadRequest("Unable to read file");
        }

        var extension = GetExtensionFromSignature(signature.Take(bytesRead).ToArray());
        if (extension == null)
        {
            return BadRequest("File type not allowed");
        }

        // Rewind stream for copying
        uploadStream.Seek(0, SeekOrigin.Begin);

        var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
        Directory.CreateDirectory(uploadRoot);

        // Generate a unique filename using Guid; append extension mapped from detected type
        var filename = Guid.NewGuid().ToString("N") + "." + extension;
        var destination = Path.Combine(uploadRoot, filename);

        await using var fileStream = System.IO.File.Create(destination);
        await uploadStream.CopyToAsync(fileStream);

        return Ok(new { stored = filename, bytes = file.Length });
    }

    private string? GetExtensionFromSignature(byte[] signature)
    {
        foreach (var (sig, ext) in AllowedSignatures)
        {
            if (signature.Length >= sig.Length && signature.Take(sig.Length).SequenceEqual(sig))
            {
                return ext;
            }
        }
        return null;
    }
}
```

## Explanation

The fix closes CWE-434 by validating file content rather than trusting client-supplied metadata. It reads the first 4 bytes of the uploaded file (magic bytes/file signature) and checks them against an allowlist of known safe types (PNG, JPEG, GIF, PDF). If the signature matches, the corresponding extension is determined and used to generate a new filename using `Guid.NewGuid().ToString("N")`, which produces a cryptographically unique, unpredictable name. The client-supplied `file.FileName` is discarded entirely after the initial null check on file length. The stream is rewound with `Seek(0, SeekOrigin.Begin)` after reading the signature, and the full file content is copied to disk using that generated filename. The file is stored at `ContentRootPath/storage/uploads`, which is outside `wwwroot` and therefore not served as static content by `UseStaticFiles()`. A file size limit (10 MB) is enforced before processing. This breaks the entire attack chain: the attacker cannot control the stored filename, cannot inject path traversal sequences, and cannot upload executable file types.

## Behaviour changes

1. **Filename generation**: Original stored files with their client-supplied names (e.g., `malicious.cshtml`); fixed version generates unique random names (e.g., `a7f3e8c2d1b9a4f6.cshtml`). This is intentional and required to prevent filename-based attacks. The stored filename is returned in the JSON response so the caller can retrieve the file later.

2. **Extension handling**: Original trusted the uploaded filename's extension; fixed version maps the extension from the file's detected type (based on magic bytes). An upload with mismatched extension/content (e.g., a JPEG file named `shell.aspx`) will be stored as `.jpg`, not `.aspx`, breaking the payload.

3. **File size validation**: Original had no explicit size limit; fixed version enforces a 10 MB cap via `MaxFileSize` constant. This prevents disk exhaustion attacks. Error response is `BadRequest("File too large")` instead of silently accepting arbitrarily large uploads.

4. **Rejection of unknown types**: Original accepted any file type; fixed version rejects files whose magic bytes do not match the allowlist (PNG, JPEG, GIF, PDF). Response is `BadRequest("File type not allowed")`.

5. **Stream handling**: Original opened a stream implicitly via `IFormFile.FileName` usage; fixed version explicitly manages the upload stream with `await using`, reads signature bytes, rewinds with `Seek()`, and copies the full content. The pattern ensures the stream is disposed correctly and position is reset before copying.

6. **Error cases**: Original would throw an unhandled exception if the filename was invalid or directory creation failed; fixed version explicitly validates signature readability and returns `BadRequest("Unable to read file")` for empty or unreadable files.

