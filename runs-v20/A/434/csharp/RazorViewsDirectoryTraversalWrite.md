## Verdict

Confirmed. `UploadTemplate` writes an authenticated admin's uploaded file straight into `Views/EmailTemplates` using the client-supplied `file.FileName`, with no filename sanitization and no restriction on where the file lands. Because this app registers `AddRazorRuntimeCompilation()`, any `.cshtml` file that ends up under the `Views` tree is compiled and executed by the Razor view engine on the next request that resolves it. `file.FileName` can contain path segments (e.g. `../../wwwroot/shell.cshtml` or an absolute path), so the destination is not actually confined to `Views/EmailTemplates`, and even a file that does stay inside that folder is live, server-executable code the moment it lands - not inert template data. That combination (attacker/administrator-controlled name and content, written to a location the framework auto-executes) is exactly CWE-434: the upload accepts a dangerous type (an executable Razor view) with no gate on name or destination.

## Source

`IFormFile file` parameter of `UploadTemplate(IFormFile file)` in `AdminEmailTemplateController.cs` (line 27) - `file.FileName` is attacker/administrator-supplied and flows unsanitized into `Path.Combine(viewsRootPath, file.FileName)` at line 40, then `file.CopyToAsync(stream)` writes the attacker-controlled bytes to that path (line 44).

## Fix

### File: AdminEmailTemplateController.cs

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;

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
        // Only a plain file name - letters, digits, dash, underscore - ending
        // in .cshtml is accepted. This rejects any path segments (including
        // "..", a leading "/" or a drive letter) in a single check, rather
        // than trying to strip or normalize them after the fact.
        private static readonly Regex SafeTemplateFileName =
            new(@"^[A-Za-z0-9][A-Za-z0-9_-]{0,99}\.cshtml$", RegexOptions.Compiled);

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

            // Validate the client-supplied name outright instead of trying to
            // sanitize it: only a bare "name.cshtml" with no path separators
            // survives, so a crafted name such as "../../wwwroot/shell.cshtml"
            // or an absolute path is rejected before it ever reaches Path.Combine.
            var fileName = file.FileName;
            if (string.IsNullOrEmpty(fileName) || !SafeTemplateFileName.IsMatch(fileName))
            {
                return BadRequest("Invalid file name. Use a plain name ending in .cshtml.");
            }

            // Store uploaded templates outside the Views tree entirely, in a
            // folder Razor's view engine never scans or compiles. Razor
            // runtime compilation only discovers .cshtml files under the
            // registered Views/Areas/Pages locations, so a file written here
            // is inert data - it cannot be resolved and executed as a view
            // regardless of its name or contents. This is what actually closes
            // the remote-code-execution risk; the earlier admin authorization
            // check is not sufficient on its own because it does not stop an
            // uploaded .cshtml file from being live, server-executed code the
            // moment it lands under Views.
            var templateStorePath = Path.Combine(_env.ContentRootPath, "App_Data", "EmailTemplateUploads");
            Directory.CreateDirectory(templateStorePath);

            var destinationPath = Path.Combine(templateStorePath, fileName);

            // Defense in depth: confirm the resolved path still lands inside
            // the intended storage folder before writing to it.
            var fullDestinationPath = Path.GetFullPath(destinationPath);
            var fullStoreRoot = Path.GetFullPath(templateStorePath + Path.DirectorySeparatorChar);
            if (!fullDestinationPath.StartsWith(fullStoreRoot, StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest("Invalid file name.");
            }

            using (var stream = new FileStream(fullDestinationPath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            return Ok(new { stored = fileName });
        }
    }
}
```

## Explanation

Two independent problems fed the same sink and both needed a fix:

1. **Unsanitized name (path traversal).** `file.FileName` was combined into the destination path with no validation, so a name containing `..` segments, a leading `/`, or a drive-qualified path could steer the write outside `Views/EmailTemplates` altogether. The fix replaces ad hoc stripping with an outright allow-list match (`^[A-Za-z0-9][A-Za-z0-9_-]{0,99}\.cshtml$`): if the name isn't a bare, simple filename, the request is rejected before any path arithmetic happens. This is a case where a strict allow-list is appropriate rather than a security-only regression, because the application itself defines the acceptable shape of a template file name - a short identifier plus `.cshtml` - so nothing legitimate is excluded.

2. **Dangerous type via location, not just extension.** The deeper issue is that this app enables `AddRazorRuntimeCompilation()`, which compiles and executes any `.cshtml` file it discovers under the `Views` tree on the next request that resolves it. Writing an admin-controlled file into `Views/EmailTemplates` therefore does not create template *data* - it creates live, server-executed code, and an admin session (or anything that can reach this endpoint, including a compromised admin account or a future authorization regression) becomes a remote-code-execution primitive. Restricting the extension alone would not have closed this: any `.cshtml` in that tree is dangerous regardless of its contents. The fix instead relocates storage to `App_Data/EmailTemplateUploads`, a folder outside every location the Razor view engine scans (`Views`, `Areas`, `Pages`), so an uploaded file - even one that legitimately ends in `.cshtml` - is never discovered or compiled by Razor; it is inert data on disk. Whatever downstream code renders these templates when sending a notification must read this file's content explicitly (e.g. as a string merged with a non-code-executing template engine) rather than invoking it as a Razor view by path, since that code is outside this file's scope.

A `Path.GetFullPath` containment check is kept as defense in depth in case the allow-list regex is ever loosened, but the primary fix is the combination of (1) rejecting anything but a plain file name and (2) removing the file from any path Razor treats as executable.
