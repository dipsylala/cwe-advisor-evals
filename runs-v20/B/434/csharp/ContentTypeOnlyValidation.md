## Verdict

CWE-434 (Unrestricted Upload of File with Dangerous Type) - **exploitable**, confidence: high.

`UploadAvatar` (`ContentTypeOnlyValidation.cs`, line 53 sink) gates the upload solely on `avatar.ContentType`, a client-supplied multipart header that is not verified by the framework. An attacker can set `Content-Type: image/png` while uploading a file whose actual bytes are something else entirely (an HTML/SVG document carrying script, a polyglot, or any other payload) and it will pass the `isAllowedImageType` check, be mapped to a `.png` extension purely because the lying header said so, and be written to disk unmodified.

## Source

- **Source**: `IFormFile avatar` bound from the multipart form body of `POST api/profile/avatar` - `avatar.ContentType` and the raw file bytes are both attacker-controlled.
- **Data flow**: `avatar.ContentType` is compared against a string allowlist (`isAllowedImageType`, lines 28-31), then reused (lines 41-47) to pick a stored extension via a `switch` on the same client-supplied value. The file bytes are never inspected. `avatar.FileName` is not used for the storage path (a `Guid.NewGuid()` name is already generated at line 49), so filename-based traversal is already closed - the open gap is purely that neither the type check nor the extension decision is based on the file's actual content.
- **Sink**: line 53, `System.IO.File.Create(destinationPath)` followed by `avatar.CopyToAsync(destinationStream)` - writes the unverified bytes to `PrivateStorage/avatars` under the content root using the extension chosen from the spoofable header.

## Fix

### File: ContentTypeOnlyValidation.cs

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Hosting;

namespace ProfilePictures.Controllers
{
    [ApiController]
    [Route("api/profile")]
    public class ProfilePictureController : ControllerBase
    {
        private readonly IWebHostEnvironment _env;

        public ProfilePictureController(IWebHostEnvironment env)
        {
            _env = env;
        }

        [HttpPost("avatar")]
        public async Task<IActionResult> UploadAvatar(IFormFile avatar)
        {
            if (avatar == null || avatar.Length == 0)
            {
                return BadRequest("No file uploaded.");
            }

            using (var uploadStream = avatar.OpenReadStream())
            {
                var header = new byte[8];
                int bytesRead = await uploadStream.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false);
                string? detectedExtension = DetectImageExtension(header, bytesRead);

                if (detectedExtension == null)
                {
                    return BadRequest("Only PNG, JPEG, or GIF images are allowed.");
                }

                var storageRoot = Path.Combine(_env.ContentRootPath, "PrivateStorage", "avatars");
                Directory.CreateDirectory(storageRoot);

                var storedFileName = Guid.NewGuid().ToString("N") + detectedExtension;
                var destinationPath = Path.Combine(storageRoot, storedFileName);

                uploadStream.Seek(0, SeekOrigin.Begin);

                using (var destinationStream = new FileStream(destinationPath, FileMode.CreateNew, FileAccess.Write))
                {
                    await uploadStream.CopyToAsync(destinationStream);
                }

                return Ok(new { storedFileName });
            }
        }

        private static string? DetectImageExtension(byte[] header, int bytesRead)
        {
            if (bytesRead >= 8 &&
                header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47 &&
                header[4] == 0x0D && header[5] == 0x0A && header[6] == 0x1A && header[7] == 0x0A)
            {
                return ".png";
            }

            if (bytesRead >= 3 &&
                header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF)
            {
                return ".jpg";
            }

            if (bytesRead >= 6 &&
                header[0] == 0x47 && header[1] == 0x49 && header[2] == 0x46 && header[3] == 0x38 &&
                (header[4] == 0x37 || header[4] == 0x39) && header[5] == 0x61)
            {
                return ".gif";
            }

            return null;
        }
    }
}
```

## Explanation

The fix replaces the client-supplied `ContentType` check with a signature (magic-byte) check read from the file's own stream via `IFormFile.OpenReadStream()`, per the C# guidance for this CWE. It reads the leading bytes with `ReadAtLeastAsync` (so a short read from a small or slow-arriving upload can't leave zeroed bytes matched against a signature that was never actually present), compares them against the known PNG, JPEG, and GIF headers, and rejects anything that doesn't match one of them - regardless of what `Content-Type` claimed. The stored extension is now taken from this detected type rather than from the header, so an attacker cannot use a truthful-looking header to choose the extension under which malicious bytes are saved. The stream is rewound with `Seek(0, SeekOrigin.Begin)` before the bytes are copied to disk so the full file (header included) is written intact, and the destination is opened with `FileMode.CreateNew` instead of `Create` so the write fails loudly rather than silently overwriting on the (practically negligible, given the GUID name) chance of a filename collision. The storage path, random GUID filename, and out-of-webroot `PrivateStorage` location were already correct and are unchanged.

## Behaviour changes

- The extension written to disk is now chosen from the detected file signature instead of the client's `Content-Type` header. For a legitimate client these agree, so behaviour for honest uploads is unchanged; for a spoofed header they now diverge, and the detected type wins - this is the mechanism that closes the weakness, not an incidental change.
- `avatar.ContentType` is no longer read or checked at all; the signature check fully replaces it rather than supplementing it, per the guidance that client-supplied content type must not gate validation.
- The destination file is now opened with `FileMode.CreateNew` instead of the implicit `FileMode.Create` used by `File.Create`. `Create` silently truncates/overwrites an existing file at that path; `CreateNew` throws `IOException` if the path already exists. Since the path is a freshly generated `Guid.NewGuid("N")` name, this only has an observable effect in the practically-impossible event of a GUID collision, where the request now fails instead of silently overwriting another stored avatar - an intentional hardening called for by the language guidance, not a change to normal-path behaviour.
- A file smaller than the shortest signature checked (3 bytes) is now rejected with the same "Only PNG, JPEG, or GIF images are allowed." message that any other invalid type gets; the original code had no equivalent size floor because it never inspected content, but such a file could never have been a valid image either, so no legitimate upload is affected.
- Not changed: the response shape (`Ok(new { storedFileName })`), the rejection message text, the storage directory, and the random-filename scheme. Request size limiting (`FormOptions.MultipartBodyLengthLimit` / `[RequestSizeLimit]`) and image re-encoding to strip embedded active content are secondary controls the guidance also recommends, but they address a distinct concern (resource exhaustion, and defense-in-depth against a polyglot that passes the signature check) from the reported content-type-only validation gap and are left as separate follow-up hardening rather than folded into this fix.

**Verification**: The fixed file was copied into a scratch ASP.NET Core Web API project (`dotnet new webapi`, target framework net10.0, referencing the same `Microsoft.AspNetCore.Mvc`/`Hosting`/`Http` APIs used here) and built with `dotnet build`. Build succeeded with 0 errors (only a pre-existing, unrelated NuGet advisory warning from the scaffolded template). `Stream.ReadAtLeastAsync` resolved against the target framework's `System.IO.Stream`, and `IFormFile.OpenReadStream`, `Seek`, and `CopyToAsync` compiled against the same interfaces the original file already used. The scratch project was deleted after the check; no file under the case directory was modified.
