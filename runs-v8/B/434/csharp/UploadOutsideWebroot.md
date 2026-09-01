## Verdict

Real vulnerability. The code accepts uploaded files without validating file type or content, uses the client-supplied filename directly as the storage path, and lacks file size limits. This violates CWE-434's core requirement to validate by content signature, generate a safe filename, and enforce size constraints.

## Source

`IFormFile file` parameter in the `Upload` action method (line 17). The filename arrives from the HTTP multipart request's `Content-Disposition` header.

## Fix

Replace the unsafe upload handler with signature-based validation and generated filenames:

```csharp
using System;
using System.Collections.Generic;
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
    
    // Map file signatures to allowed extensions
    private static readonly Dictionary<string, string> AllowedSignatures = new()
    {
        { "FFD8FF", "jpg" },      // JPEG
        { "89504E47", "png" },    // PNG
        { "47494638", "gif" },    // GIF
        { "25504446", "pdf" },    // PDF
    };

    public UploadOutsideWebrootController(IWebHostEnvironment env) => _env = env;

    [HttpPost("/upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file is null || file.Length == 0)
        {
            return BadRequest();
        }

        // Enforce size limit (e.g., 5 MB)
        const long MaxFileSize = 5 * 1024 * 1024;
        if (file.Length > MaxFileSize)
        {
            return BadRequest("File exceeds maximum size");
        }

        // Validate file signature
        var signature = await GetFileSignatureAsync(file);
        if (string.IsNullOrEmpty(signature) || !AllowedSignatures.ContainsKey(signature))
        {
            return BadRequest("File type not allowed");
        }

        var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
        Directory.CreateDirectory(uploadRoot);

        // Generate safe filename with extension from detected signature
        var safeFileName = $"{Guid.NewGuid():N}.{AllowedSignatures[signature]}";
        var destination = Path.Combine(uploadRoot, safeFileName);

        // Validate destination path is within uploadRoot to prevent traversal
        var fullUploadPath = Path.GetFullPath(uploadRoot);
        var fullDestinationPath = Path.GetFullPath(destination);
        if (!fullDestinationPath.StartsWith(fullUploadPath))
        {
            return BadRequest("Invalid file path");
        }

        // Rewind stream after signature check and write file
        file.OpenReadStream().Seek(0, SeekOrigin.Begin);
        await using var stream = System.IO.File.Create(destination, 4096, FileOptions.SequentialScan);
        await file.CopyToAsync(stream);

        return Ok(new { stored = safeFileName, bytes = file.Length });
    }

    private static async Task<string> GetFileSignatureAsync(IFormFile file)
    {
        const int HeaderSize = 8;
        var headerBytes = new byte[HeaderSize];

        await using var stream = file.OpenReadStream();
        var bytesRead = await stream.ReadAtLeastAsync(headerBytes, HeaderSize, throwOnEndOfStream: false);

        if (bytesRead == 0)
        {
            return null;
        }

        // Convert read bytes to hex signature
        return BitConverter.ToString(headerBytes, 0, bytesRead).Replace("-", "").ToUpper();
    }
}
```

## Explanation

The fix closes CWE-434 by implementing the three mandatory controls from the guidance:

1. **Signature validation**: `GetFileSignatureAsync` reads the file header and compares it against an allowlist of known magic bytes (JPEG, PNG, GIF, PDF). This prevents uploading executables or scripts disguised with a safe extension.

2. **Generated filename**: `Guid.NewGuid().ToString("N")` creates a cryptographically random filename with no user-supplied content. The extension is derived from the validated signature (`AllowedSignatures` map), not from `file.FileName`, so the attacker cannot control the stored file's type.

3. **File size enforcement**: The 5 MB limit prevents resource exhaustion and should be tuned to business requirements.

4. **Path traversal protection**: After generating the safe filename, the code validates that the resolved full path stays within `uploadRoot` before creation.

5. **Stream rewind**: After reading signature bytes, the stream is rewound with `Seek()` before copying the full file content.

6. **Implicit defense**: Files are stored outside `wwwroot`, so even if an attacker uploaded a `.cshtml` file, ASP.NET Core would not compile or execute it from that location.

The original `IFormFile.FileName` and `IFormFile.ContentType` are now ignored completely, eliminating the taint source.

## Behaviour changes

- **Rejected uploads**: Files with unrecognized signatures are rejected (e.g., executables, archives, scripts).
- **Filename transformation**: The stored filename is now a GUID with a validated extension (e.g., `a1b2c3d4e5f6g7h8.png`), not the original client-supplied name.
- **Response change**: The `stored` field now returns the generated safe filename, not the original.
- **Size enforcement**: Uploads larger than 5 MB are rejected with an error response.
- **Path handling**: Path traversal attempts in the original filename are neutralized by the generated filename and path validation logic.
