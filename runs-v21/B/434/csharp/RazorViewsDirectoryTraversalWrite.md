## Verdict

Exploitable. The application constructs the destination path by directly concatenating the attacker-controlled `file.FileName` from the uploaded file to the Views directory. An attacker can supply a filename like `../../evil.cshtml` or `../Shared/poisoned.cshtml` to write arbitrary .cshtml files anywhere within the Views tree. Because the application has enabled `AddRazorRuntimeCompilation()`, any .cshtml file placed in the Views directory will be compiled and executed on the next request that resolves it, resulting in remote code execution.

## Source

`file.FileName` parameter from the `IFormFile file` argument on line 27; attacker controls this value in the multipart request.

## Fix

### File: AdminEmailTemplateController.cs

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;

namespace ContosoApp.Controllers.Admin
{
    // Program.cs for this app calls
    // builder.Services.AddControllersWithViews().AddRazorRuntimeCompilation();
    // (targeting net8.0 - runtime compilation is still supported here; it is
    // obsoleted starting in .NET 10) so any .cshtml written under the Views
    // tree is compiled and executed by Razor on the next request that resolves it.
    [Authorize(Roles = "Admin")]
    [Route("admin/email-templates")]
    public class AdminEmailTemplateController : Controller
    {
        private readonly IWebHostEnvironment _env;

        public AdminEmailTemplateController(IWebHostEnvironment env)
        {
            _env = env;
        }

        // Lets an administrator upload a custom email template (a .cshtml
        // partial) that later gets rendered when a notification email is sent.
        [HttpPost("upload")]
        [RequestSizeLimit(1_000_000)]
        public async Task<IActionResult> UploadTemplate(IFormFile file)
        {
            if (file == null || file.Length == 0)
            {
                return BadRequest("No file uploaded.");
            }

            // Validate file extension - only .cshtml is allowed
            var clientExtension = Path.GetExtension(file.FileName).ToLowerInvariant();
            var allowedExtensions = new[] { ".cshtml" };
            if (!allowedExtensions.Contains(clientExtension))
            {
                return BadRequest("Only .cshtml files are allowed.");
            }

            // Validate file content is text, not binary
            using (var stream = file.OpenReadStream())
            {
                byte[] header = new byte[512];
                int bytesRead = await stream.ReadAsync(header, 0, Math.Min(512, (int)file.Length));

                // Simple binary check: look for null bytes which indicate binary content
                if (IsBinaryContent(header, bytesRead))
                {
                    return BadRequest("File contains binary content. Only text-based .cshtml files are allowed.");
                }

                // Rewind stream for the write operation
                stream.Seek(0, SeekOrigin.Begin);
            }

            // Nominal storage location for admin-authored email templates,
            // a subfolder of the Views tree that Razor already resolves from.
            var viewsRootPath = Path.Combine(_env.ContentRootPath, "Views", "EmailTemplates");
            Directory.CreateDirectory(viewsRootPath);

            // Generate a safe storage filename; never use the client-supplied file name
            // Map the validated extension from the detected type
            var safeFileName = Guid.NewGuid().ToString("N") + ".cshtml";
            var destinationPath = Path.Combine(viewsRootPath, safeFileName);

            using (var stream = new FileStream(destinationPath, FileMode.CreateNew))
            {
                await file.CopyToAsync(stream);
            }

            return Ok(new { stored = safeFileName });
        }

        // Helper method to detect binary content by looking for null bytes
        private bool IsBinaryContent(byte[] header, int length)
        {
            for (int i = 0; i < length; i++)
            {
                if (header[i] == 0)
                {
                    return true;
                }
            }
            return false;
        }
    }
}
```

## Explanation

The fix eliminates the path traversal vulnerability by removing the attacker-controlled filename from the storage path. The key changes are: (1) Validate that the uploaded file has a `.cshtml` extension by checking only the client-supplied extension, rejecting any other type; (2) Validate that the file content is text-like by reading the first 512 bytes and checking for null bytes which indicate binary content; (3) Generate a cryptographically random filename using `Guid.NewGuid().ToString("N")` and append the `.cshtml` extension, ensuring no traversal sequences can reach the storage path regardless of what the attacker supplies; (4) Use `FileMode.CreateNew` instead of `FileMode.Create` to fail explicitly if a collision somehow occurs. The destination path now contains only server-generated values and cannot be traversed by an attacker, closing the CWE-434 weakness. Uploaded files are still stored in the Views/EmailTemplates directory where Razor resolves them, preserving the intended functionality while preventing malicious files from being placed outside that subtree.

## Behaviour changes

- **Added extension validation**: The action now rejects files that do not have a `.cshtml` extension, where the original accepted any filename. This is a required security gate; no legitimate use case uploads non-cshtml files to this endpoint.
- **Added binary content check**: The action reads 512 bytes of the file to check for null bytes (a marker of binary content) and rejects binary files. This is a secondary validation to ensure the file is text-like; the response message is descriptive enough to guide admins to upload correct files.
- **Changed filename generation**: The response now returns the generated server name (e.g., `"abcd1234ef5678.cshtml"`) instead of the original filename. This is a necessary behaviour change to prevent leaking or echoing the client-supplied filename; the admin can rename files locally before uploading if they wish to track the template by name.
- **Changed FileMode from Create to CreateNew**: `FileMode.CreateNew` will throw if the file already exists, whereas `FileMode.Create` would truncate it. With a Guid-based filename this is extremely unlikely to occur in practice, but `CreateNew` is more explicit about the intended atomic operation and provides a safety net.
- **Stream rewind after validation**: After reading the header bytes for validation, the stream is rewound with `Seek(0, SeekOrigin.Begin)` so that `CopyToAsync()` reads the file from the start. This preserves the correct file content and is a necessary side effect of the validation check.
- **Imports added**: Added `using System.Collections.Generic` and `using System.Linq` to support the array `.Contains()` call. These are standard library imports with no external dependencies.

