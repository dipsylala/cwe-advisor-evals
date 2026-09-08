## Verdict

Confirmed. `UploadTemplate` builds the on-disk destination path with `Path.Combine(viewsRootPath, file.FileName)`, where `file.FileName` is client-supplied multipart request metadata. Nothing strips path-separator or traversal sequences from it, and nothing constrains its extension, before the value reaches `Path.Combine` and then `FileStream`/`CopyToAsync`.

## Source

`file.FileName` from the `IFormFile file` action parameter of `UploadTemplate` (model-bound from the multipart upload body), `AdminEmailTemplateController.cs` line 27.

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

            // Nominal storage location for admin-authored email templates,
            // a subfolder of the Views tree that Razor already resolves from.
            var viewsRootPath = Path.Combine(_env.ContentRootPath, "Views", "EmailTemplates");
            Directory.CreateDirectory(viewsRootPath);

            // The client-supplied file name and extension are request metadata and are never
            // used as, or to build, the storage path: this endpoint only ever writes a Razor
            // partial, so the stored name and extension are entirely server-generated.
            var storedFileName = Guid.NewGuid().ToString("N") + ".cshtml";
            var destinationPath = Path.Combine(viewsRootPath, storedFileName);

            using (var stream = new FileStream(destinationPath, FileMode.CreateNew))
            {
                await file.CopyToAsync(stream);
            }

            return Ok(new { stored = storedFileName });
        }
    }
}
```

## Explanation

`file.FileName` was used verbatim as the last segment of the write path. `Path.Combine` does not neutralize `..` segments or an absolute path in its second argument, so a name such as `..\..\Views\Shared\_Layout.cshtml` or `..\..\wwwroot\shell.html` walks the result outside the intended `Views\EmailTemplates` folder - into the rest of the Razor view tree (where `AddRazorRuntimeCompilation()` on this net8.0 target compiles and executes the next `.cshtml` written there, giving code execution beyond the sandboxed template folder) or into `wwwroot` (served statically). The client also fully controlled the stored extension, so nothing stopped a name ending in some other served type.

The fix removes the client-supplied name and extension from the path entirely rather than trying to filter them: the destination filename is generated server-side with `Guid.NewGuid().ToString("N")` and a hardcoded `.cshtml` extension, matching this endpoint's only legitimate content type. With no attacker-controlled input in `destinationPath`, a `..` sequence, an absolute path, or an alternate extension in `file.FileName` can no longer affect where or as what the upload is written - closing both the traversal-write and the arbitrary-extension write in one change, per the `cwe/434/csharp` guidance's "never use `IFormFile.FileName` as the storage path; generate the stored filename with `Guid.NewGuid().ToString("N")`" pattern. `FileMode.Create` was also changed to `FileMode.CreateNew` so the write fails loudly instead of silently overwriting an existing file on the astronomically unlikely event of a GUID collision, rather than because collision is a practical risk.

Signature/magic-byte verification, which the general and C# guidance both lead with, does not apply here: the accepted content is a plain-text Razor partial, not a binary format with a magic-number header, so there is no byte signature to check. The security boundary for the file's *content* (arbitrary Razor/C# authored by whoever calls this endpoint) is the existing `[Authorize(Roles = "Admin")]` attribute, which this fix leaves untouched; this fix addresses only the path/extension injection identified at the sink, not the inherent trust placed in the Admin role to author executable templates - that is this endpoint's stated purpose, not the reported weakness.

Checked against the sink contract: `CopyToAsync` still returns nothing consumed by the caller (unchanged), and the endpoint still returns 200 with a JSON `stored` field, now carrying the actual generated filename instead of echoing the attacker-controllable one. `Directory.CreateDirectory`, the request size limit, and the null/empty check are untouched. `Guid`, `Path.Combine`, `Directory.CreateDirectory`, `FileStream`, and `FileMode.CreateNew` are all `System`/`System.IO` members already reachable under this project's implicit usings (the original file already called `Path.Combine`, `Directory.CreateDirectory`, and `FileStream`/`FileMode` without an explicit `using System.IO;`, confirming implicit usings are enabled). Verified by copying the fixed file into a scratch ASP.NET Core Web SDK project (`net8.0`, matching this controller's target) alongside a minimal `Program.cs`, then running `dotnet build`: build succeeded with 0 warnings and 0 errors.

## Behaviour changes

- The response's `stored` field now returns the server-generated filename (e.g. `a1b2c3d4e5f6...cshtml`) instead of the client-supplied `file.FileName`. Any caller or downstream process that looked up the stored template by the name it originally uploaded must instead use the name returned in this response.
- Any file extension the client supplied (other than being informational in the multipart body) is discarded; every upload through this endpoint is now stored with a `.cshtml` extension regardless of the original filename, matching the endpoint's sole intended content type.
- Uploading a file whose randomly generated name collides with an existing stored file now fails the request (`FileMode.CreateNew` throws `IOException`, which the action does not currently catch, so it propagates as a 500) instead of silently overwriting it. This is a pre-existing gap in error handling for the file-write, not one this fix introduces - `FileMode.Create` had no explicit error handling either - and collision is not a practical risk given the identifier space.
