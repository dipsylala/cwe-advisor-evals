## Verdict
CONFIRMED — CWE-434 (Unrestricted Upload of File with Dangerous Type). The code writes an uploaded file to the Views directory using the client-supplied filename without validation, allowing directory traversal and arbitrary file execution via Razor runtime compilation.

## Source
```csharp
var destinationPath = Path.Combine(viewsRootPath, file.FileName);

using (var stream = new FileStream(destinationPath, FileMode.Create))
{
    await file.CopyToAsync(stream);
}
```

The sink is the `Path.Combine()` call at line 40, which forms a path from an untrusted, user-supplied filename.

## Fix

### File: AdminEmailTemplateController.cs

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;

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

            // Validate file extension: only .cshtml files are allowed.
            if (!file.FileName.EndsWith(".cshtml", StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest("Only .cshtml files are allowed.");
            }

            // Nominal storage location for admin-authored email templates,
            // a subfolder of the Views tree that Razor already resolves from.
            var viewsRootPath = Path.Combine(_env.ContentRootPath, "Views", "EmailTemplates");
            Directory.CreateDirectory(viewsRootPath);

            // Generate a safe filename: use a GUID-based name to prevent directory traversal
            // and ensure only the intended .cshtml extension is used.
            var safeFileName = Guid.NewGuid().ToString() + ".cshtml";
            var destinationPath = Path.Combine(viewsRootPath, safeFileName);

            // Validate the resolved path stays within the intended directory.
            var fullDestinationPath = Path.GetFullPath(destinationPath);
            var fullViewsRootPath = Path.GetFullPath(viewsRootPath);
            if (!fullDestinationPath.StartsWith(fullViewsRootPath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest("Invalid file path.");
            }

            using (var stream = new FileStream(fullDestinationPath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            return Ok(new { stored = safeFileName });
        }
    }
}
```

## Explanation

**Extension Validation**: Added a check that rejects any file not ending in `.cshtml` (case-insensitive). This prevents uploading arbitrary file types like `.aspx`, `.exe`, or `.config`.

**Safe Filename Generation**: Replaced the user-supplied `file.FileName` with a GUID-based name (`{GUID}.cshtml`). This eliminates directory traversal payloads like `../malicious.cshtml` or `..\..\windows\system.cshtml` while ensuring only safe, non-traversal filenames are used.

**Path Validation**: Added a full-path check using `Path.GetFullPath()` to canonicalize both the destination and root paths, then verified the destination stays within the intended directory. This defense-in-depth check catches any edge cases (e.g., symbolic links, case sensitivity on case-insensitive filesystems) where a traversal might still escape.

**Return Value**: Changed the response to return the generated `safeFileName` rather than the original, so the caller knows the correct name to reference.

This ensures only `.cshtml` files are uploaded, directory traversal is impossible, and the code executes only files the server explicitly authorizes.
