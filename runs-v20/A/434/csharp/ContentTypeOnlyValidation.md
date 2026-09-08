## Verdict

Confirmed. `UploadAvatar` decides whether an uploaded file is a safe image using only `IFormFile.ContentType`, which is a MIME-type string the client sets in the multipart request and can set to any value it wants. An attacker can upload an executable, script, or web shell while setting the `Content-Type` part header to `image/png` (or `image/jpeg`/`image/gif`), sail through the `isAllowedImageType` check, and have the file written to disk with a `.png`/`.jpg`/`.gif` extension chosen from that same untrusted value. The stored path is under `PrivateStorage`, so this sample does not also grant direct web execution of the dropped file, but the file type check itself is bypassable and the extension assigned to the stored file is driven entirely by attacker-controlled input, which is the CWE-434 finding at the `File.Create` sink on line 53.

## Source

`IFormFile avatar` (the `ContentType` property specifically) from the `UploadAvatar(IFormFile avatar)` action parameter, populated from the client's multipart/form-data request.

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

        private const long MaxAvatarBytes = 5 * 1024 * 1024; // 5 MB

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

            if (avatar.Length > MaxAvatarBytes)
            {
                return BadRequest("File is too large.");
            }

            // The client-supplied ContentType header is attacker-controlled and is not
            // trustworthy evidence of what the file actually is. Determine the real
            // image type by inspecting the file's own magic-number signature instead,
            // and derive the stored extension from that verified type.
            string extension;
            using (var signatureStream = avatar.OpenReadStream())
            {
                extension = await DetectImageExtensionAsync(signatureStream);
            }

            if (extension == null)
            {
                return BadRequest("Only PNG, JPEG, or GIF images are allowed.");
            }

            var storageRoot = Path.Combine(_env.ContentRootPath, "PrivateStorage", "avatars");
            Directory.CreateDirectory(storageRoot);

            var storedFileName = Guid.NewGuid().ToString("N") + extension;
            var destinationPath = Path.Combine(storageRoot, storedFileName);

            using (var destinationStream = System.IO.File.Create(destinationPath))
            using (var uploadStream = avatar.OpenReadStream())
            {
                await uploadStream.CopyToAsync(destinationStream);
            }

            return Ok(new { storedFileName });
        }

        // Reads the leading bytes of the upload and matches them against the known
        // magic numbers for PNG, JPEG, and GIF. Returns the safe extension for the
        // detected type, or null when the content does not match any allowed image
        // format, regardless of what the client claimed via ContentType or file name.
        private static async Task<string> DetectImageExtensionAsync(Stream stream)
        {
            var header = new byte[8];
            int read = 0;
            while (read < header.Length)
            {
                int n = await stream.ReadAsync(header, read, header.Length - read);
                if (n == 0)
                {
                    break;
                }
                read += n;
            }

            if (read >= 8 &&
                header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47 &&
                header[4] == 0x0D && header[5] == 0x0A && header[6] == 0x1A && header[7] == 0x0A)
            {
                return ".png";
            }

            if (read >= 3 && header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF)
            {
                return ".jpg";
            }

            if (read >= 6 &&
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

The original check trusted `avatar.ContentType`, a value the caller fully controls via the multipart part's `Content-Type` header, for two separate decisions: whether to accept the file at all, and which extension to give the file once it accepted it. Both decisions were therefore attacker-controlled regardless of the file's real bytes.

The fix replaces that check with content sniffing: it reads the first bytes of the actual upload stream and matches them against the fixed magic-number signatures for PNG (`89 50 4E 47 0D 0A 1A 0A`), JPEG (`FF D8 FF`), and GIF (`47 49 46 38 37|39 61`). Only a file whose real bytes match one of these signatures is accepted, and the stored extension is derived from the verified signature rather than from any client-supplied header, so the extension can no longer be steered independently of the file's actual content. A file that does not match any of the three signatures - including an executable, script, or polyglot with a spoofed `Content-Type` - is rejected with `BadRequest` before it reaches the filesystem. A file-size cap was also added as defense in depth against unbounded upload sizes; storage location (under `PrivateStorage`, outside the web root) and the randomly generated stored file name were already sound and are unchanged.

Magic-number sniffing verifies the file is *structurally* a PNG/JPEG/GIF; it does not fully parse or re-encode the image, so it does not by itself defend against payloads crafted to exploit a downstream image-processing library. If the stored files are later processed by an image library or ever served from a location where extension-based execution is possible, pair this check with re-encoding the image through a trusted library (e.g. ImageSharp or System.Drawing) before persisting it.
