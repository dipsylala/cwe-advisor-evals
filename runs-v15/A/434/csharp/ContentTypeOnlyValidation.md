## Verdict

The vulnerability is confirmed. The code validates only the `Content-Type` header from the client request, which can be spoofed. An attacker can upload arbitrary malicious files (executables, scripts, archives) by setting `Content-Type: image/png` without inspection of the actual file content. At line 53, the unsanitized file is written to disk without verifying it is genuinely an image.

## Source

Lines 28–31: Content-Type validation is performed, but this header originates from the client and is not trustworthy.

Lines 41–47: The file extension is derived from the Content-Type, not the actual file format.

Line 53: The file stream is opened and written without validating the actual file content against the claimed type.

## Fix

Replace the Content-Type check with actual image validation by parsing and verifying the file contents:

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Hosting;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats;

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

            // Validate actual image format by parsing the file content
            IImageFormat format;
            try
            {
                using (var stream = avatar.OpenReadStream())
                {
                    if (!Image.TryIdentifyFormat(stream, out format))
                    {
                        return BadRequest("File is not a valid image.");
                    }

                    // Only allow PNG, JPEG, and GIF formats
                    if (format != ImageFormats.Png && format != ImageFormats.Jpeg && format != ImageFormats.Gif)
                    {
                        return BadRequest("Only PNG, JPEG, or GIF images are allowed.");
                    }

                    // Validate the image can be loaded and decoded (catches corrupted files)
                    Image image = Image.Load(stream);
                    image.Dispose();
                }
            }
            catch (Exception)
            {
                return BadRequest("File is not a valid image.");
            }

            var storageRoot = Path.Combine(_env.ContentRootPath, "PrivateStorage", "avatars");
            Directory.CreateDirectory(storageRoot);

            // Determine extension from actual validated format, not Content-Type
            var extension = format == ImageFormats.Png ? ".png" :
                           format == ImageFormats.Jpeg ? ".jpg" :
                           format == ImageFormats.Gif ? ".gif" : ".bin";

            var storedFileName = Guid.NewGuid().ToString("N") + extension;
            var destinationPath = Path.Combine(storageRoot, storedFileName);

            using (var destinationStream = System.IO.File.Create(destinationPath))
            {
                await avatar.CopyToAsync(destinationStream);
            }

            return Ok(new { storedFileName });
        }
    }
}
```

## Explanation

The original code trusts the `Content-Type` header sent by the client. An attacker can set this to `image/png` while uploading an executable `.exe`, script `.ps1`, or other dangerous file type. Content-Type validation is cosmetic and does not prevent malicious uploads.

The fix uses `SixLabors.ImageSharp` (a widely-maintained image library for .NET) to:

1. Call `Image.TryIdentifyFormat()` to probe the actual file bytes and determine the true image format, bypassing the client-supplied Content-Type header.
2. Restrict to PNG, JPEG, and GIF formats only, rejecting any other format.
3. Call `Image.Load()` to fully parse the image bytes and detect corruption or malformed files.
4. Derive the file extension from the validated format, not from the untrusted Content-Type header.

This approach prevents uploading of non-image files regardless of what the client claims and catches corrupted or malformed image files before they reach disk. The file extension is now guaranteed to match the actual file type, closing CWE-434.
