## Verdict
VULNERABLE

## Source
The file upload handler accepts user-supplied files via `IFormFile avatar` (line 21), reading the client-provided `ContentType` header to determine whether to accept the upload and what file extension to assign.

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

            // Check content type from client (defense in depth, but not sole validation)
            bool isAllowedImageType =
                avatar.ContentType == "image/png" ||
                avatar.ContentType == "image/jpeg" ||
                avatar.ContentType == "image/gif";

            if (!isAllowedImageType)
            {
                return BadRequest("Only PNG, JPEG, or GIF images are allowed.");
            }

            // Validate actual file content by checking magic bytes
            byte[] magicBytes = new byte[8];
            using (var stream = avatar.OpenReadStream())
            {
                await stream.ReadAsync(magicBytes, 0, magicBytes.Length);
            }

            string detectedFormat = DetectImageFormat(magicBytes);
            if (detectedFormat == null)
            {
                return BadRequest("File does not appear to be a valid image.");
            }

            var storageRoot = Path.Combine(_env.ContentRootPath, "PrivateStorage", "avatars");
            Directory.CreateDirectory(storageRoot);

            var extension = detectedFormat switch
            {
                "png" => ".png",
                "jpeg" => ".jpg",
                "gif" => ".gif",
                _ => ".bin"
            };

            var storedFileName = Guid.NewGuid().ToString("N") + extension;
            var destinationPath = Path.Combine(storageRoot, storedFileName);

            // Now safe to store: file content has been validated against magic bytes
            using (var destinationStream = System.IO.File.Create(destinationPath))
            {
                await avatar.CopyToAsync(destinationStream);
            }

            return Ok(new { storedFileName });
        }

        private string DetectImageFormat(byte[] magicBytes)
        {
            // PNG: 89 50 4E 47
            if (magicBytes.Length >= 4 &&
                magicBytes[0] == 0x89 &&
                magicBytes[1] == 0x50 &&
                magicBytes[2] == 0x4E &&
                magicBytes[3] == 0x47)
            {
                return "png";
            }

            // JPEG: FF D8 FF
            if (magicBytes.Length >= 3 &&
                magicBytes[0] == 0xFF &&
                magicBytes[1] == 0xD8 &&
                magicBytes[2] == 0xFF)
            {
                return "jpeg";
            }

            // GIF: 47 49 46 38 (GIF8)
            if (magicBytes.Length >= 4 &&
                magicBytes[0] == 0x47 &&
                magicBytes[1] == 0x49 &&
                magicBytes[2] == 0x46 &&
                magicBytes[3] == 0x38)
            {
                return "gif";
            }

            return null;
        }
    }
}
```

## Explanation
The original code relies solely on the client-provided `ContentType` header to validate file type. An attacker can spoof this header by uploading a malicious executable (e.g., `.exe`, `.dll`) while declaring `ContentType: image/png`, causing the file to be stored with an `.png` extension but containing executable code.

The fix validates the actual file content using magic bytes (file signatures) before accepting the upload:

1. **Read file header**: Extract the first 8 bytes from the uploaded stream using `OpenReadStream()` and `ReadAsync()`.
2. **Detect format**: Use `DetectImageFormat()` to check whether the magic bytes match PNG (`89 50 4E 47`), JPEG (`FF D8 FF`), or GIF (`47 49 46 38`).
3. **Reject mismatches**: If the file header does not match any allowed format, reject the upload immediately.
4. **Assign extension safely**: Use the detected format (not the client-provided ContentType) to determine the stored file extension.
5. **Store only validated files**: The `File.Create()` call now occurs only after magic-byte validation succeeds.

This approach is defence-in-depth: the ContentType check remains as a first-pass filter, but the actual file content is the authoritative validation mechanism. An attacker can no longer bypass the check by spoofing headers.
