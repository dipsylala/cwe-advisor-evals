## Verdict

Real CWE-434 vulnerability. The application accepts file uploads without validating file type or sanitizing the filename, allowing directory traversal and uploading dangerous executable file types (.cshtml) that will be compiled and executed by Razor's runtime compilation engine.

## Source

Line 40 constructs the destination path using `file.FileName` directly without any validation:
```csharp
var destinationPath = Path.Combine(viewsRootPath, file.FileName);
```

The upstream conditions (lines 29-37) check only that the file is non-null and non-empty, but do not validate the file extension or sanitize the filename for path traversal sequences.

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

            // Validate file extension - only allow .cshtml files
            if (!file.FileName.EndsWith(".cshtml", StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest("Only .cshtml files are allowed.");
            }

            // Nominal storage location for admin-authored email templates,
            // a subfolder of the Views tree that Razor already resolves from.
            var viewsRootPath = Path.Combine(_env.ContentRootPath, "Views", "EmailTemplates");
            Directory.CreateDirectory(viewsRootPath);

            // Sanitize filename: extract only the base filename to prevent directory traversal
            var safeFileName = Path.GetFileName(file.FileName);
            var destinationPath = Path.Combine(viewsRootPath, safeFileName);

            using (var stream = new FileStream(destinationPath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            return Ok(new { stored = file.FileName });
        }
    }
}
```

## Explanation

The fix adds two critical controls:

1. **File type validation** (before line 37): Check that the uploaded filename ends with `.cshtml` using case-insensitive comparison. This restricts uploads to the intended template format and prevents uploading executable types like `.exe`, `.dll`, or other dangerous extensions.

2. **Path sanitization** (replacing line 40): Use `Path.GetFileName()` to extract only the base filename from the user-supplied `file.FileName`. This neutralizes directory traversal attempts by removing any `..` sequences or absolute path components. For example, `../../../malicious.cshtml` is reduced to `malicious.cshtml`. The sanitized name is then combined with the safe base directory, ensuring the file lands only within `viewsRootPath`.

These controls work together to close CWE-434: the extension check prevents uploading file types that would be dangerous if executed, and the filename sanitization prevents storing the file outside the intended restricted directory. Even with an authenticated admin user, the principle of least privilege is maintained by restricting upload capabilities to a specific, safe file type.

