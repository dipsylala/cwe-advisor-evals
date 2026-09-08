## Verdict

Confirmed. CWE-434: The code accepts and saves uploaded files without validating the file type, allowing an attacker to upload executable or other dangerous file types. The filename is used directly without path traversal protection.

## Source

Line 28 uses `file.FileName` directly to construct the destination path without:
1. Validating the file extension against a whitelist of safe types
2. Stripping path traversal sequences (e.g., `../`, `..\\`) from the filename

An attacker can upload a `.exe`, `.dll`, `.sh`, or other dangerous file type, or use path traversal to place it outside the intended upload directory.

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
        ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".txt", ".docx", ".xlsx"
    };

    public UploadOutsideWebrootController(IWebHostEnvironment env) => _env = env;

    [HttpPost("/upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file is null || file.Length == 0)
        {
            return BadRequest();
        }

        // Sanitize filename to prevent path traversal
        var safeFileName = Path.GetFileName(file.FileName);
        
        // Validate file extension against whitelist
        var extension = Path.GetExtension(safeFileName);
        if (!AllowedExtensions.Contains(extension))
        {
            return BadRequest(new { error = "File type not allowed" });
        }

        var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
        Directory.CreateDirectory(uploadRoot);

        var destination = Path.Combine(uploadRoot, safeFileName);

        await using var stream = System.IO.File.Create(destination);
        await file.CopyToAsync(stream);

        return Ok(new { stored = Path.GetFileName(destination), bytes = file.Length });
    }
}
```

## Explanation

**Root cause:** The code used `file.FileName` directly without validation, accepting any file type and trusting the filename did not contain path traversal sequences.

**Primary fix:**
1. Call `Path.GetFileName()` on the uploaded filename to strip any directory components, preventing `../` or other path traversal attacks.
2. Define a whitelist (`AllowedExtensions`) of safe file types the application accepts (`.pdf`, `.jpg`, `.png`, etc.).
3. Extract the file extension and check it against the whitelist before saving.
4. Reject uploads that do not match an allowed extension.

**Defense in depth:** This approach prevents both arbitrary file type uploads and path traversal by combining filename normalization with extension validation. An attacker cannot upload executable files (`.exe`, `.dll`, `.sh`, `.bat`) or bypass the whitelist with path traversal tricks.

**Secondary validation:** The `Path.GetFileName()` call is the primary defence for path traversal; the extension check is the primary defence for dangerous file types. Together they close CWE-434.
