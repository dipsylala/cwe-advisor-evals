## Verdict

Real vulnerability. Path traversal in filename allows writing files outside the intended directory. Combined with Razor runtime compilation, malicious `.cshtml` uploads are executed on the next request.

## Source

`file` parameter (IFormFile) at method signature, line 27.

## Fix

Replace line 40 and the file write block (lines 40-45) to validate file content by inspecting leading bytes, reject binary formats, generate a server-controlled random filename using `Guid.NewGuid()`, and use `FileMode.CreateNew` to prevent race conditions.

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

            // Validate file signature to ensure it is a text-based format, not binary executable
            using (var stream = file.OpenReadStream())
            {
                byte[] headerBytes = new byte[4];
                int bytesRead = await stream.ReadAtLeastAsync(headerBytes, 1, System.Threading.CancellationToken.None);
                
                // Reject files that start with binary signatures (EXE, DLL, ZIP, PNG, JPEG, etc.)
                // Allow: UTF-8 BOM (EF BB BF), printable ASCII (0x20-0x7E), whitespace, UTF-8 continuation
                bool isAllowedText = false;
                if (bytesRead >= 3 && headerBytes[0] == 0xEF && headerBytes[1] == 0xBB && headerBytes[2] == 0xBF)
                {
                    // UTF-8 with BOM is allowed
                    isAllowedText = true;
                }
                else if (bytesRead > 0)
                {
                    byte firstByte = headerBytes[0];
                    // Printable ASCII (0x20-0x7E) or whitespace (tab, LF, CR) or UTF-8 continuation (0x80+)
                    if ((firstByte >= 0x20 && firstByte <= 0x7E) || 
                        firstByte == 0x09 || firstByte == 0x0A || firstByte == 0x0D ||
                        firstByte >= 0x80)
                    {
                        isAllowedText = true;
                    }
                }

                if (!isAllowedText)
                {
                    return BadRequest("Only text-based template files are allowed.");
                }

                // Rewind stream for file copy
                stream.Seek(0, System.IO.SeekOrigin.Begin);

                // Generate a safe server-controlled filename using GUID; never use client-supplied FileName
                var safeFileName = Guid.NewGuid().ToString("N") + ".cshtml";

                // Nominal storage location for admin-authored email templates,
                // a subfolder of the Views tree that Razor already resolves from.
                var viewsRootPath = Path.Combine(_env.ContentRootPath, "Views", "EmailTemplates");
                Directory.CreateDirectory(viewsRootPath);

                var destinationPath = Path.Combine(viewsRootPath, safeFileName);

                using (var fileStream = new FileStream(destinationPath, FileMode.CreateNew))
                {
                    await stream.CopyToAsync(fileStream);
                }

                return Ok(new { stored = safeFileName });
            }
        }
    }
}
```

## Explanation

The original code built the file path by directly concatenating `file.FileName` without validation, enabling two attacks: (1) path traversal using sequences like `../../` to write outside the intended directory, and (2) uploading binary executables or other dangerous file types.

The fix validates the file's content by inspecting the leading bytes (file signature/magic bytes). It rejects binary formats (EXE, DLL, ZIP, image files, etc.) by checking that the first byte is either UTF-8 BOM, printable ASCII text, whitespace, or the start of a UTF-8 multi-byte sequence. After validation, the code generates a cryptographically random filename using `Guid.NewGuid().ToString("N")` with a `.cshtml` extension, never using the client-supplied `FileName`. The `FileMode.CreateNew` flag ensures the write fails if a race condition creates a collision, preventing file overwrite attacks. This breaks the taint chain: the client-supplied filename is validated and discarded; only the server-generated name is used for storage.

## Behaviour changes

- Uploaded files are now validated as text-based content; binary files are rejected with HTTP 400
- Stored filename is server-generated (e.g., `a1b2c3d4e5f6.cshtml`) instead of preserving the client-supplied name
- Path traversal sequences in the original filename are ineffective; the generated name has no path components
- Return value now includes the server-assigned filename in the `stored` field instead of echoing the original
- Clients cannot predict or manipulate the final storage path or filename

