## Verdict

The vulnerable code at line 53 relies solely on the client-supplied `IFormFile.ContentType` header for validation, which is the core weakness of CWE-434. The fix validates the actual file signature (magic bytes) before writing, rejecting files that do not match the allowed image types regardless of their declared content type.

## Source

The upload endpoint receives an `IFormFile` avatar parameter with no actual content validation. The only check is against the `ContentType` header (lines 28-31), which is client-controlled and not verified by the framework.

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

            // Validate file signature (magic bytes) instead of ContentType header
            using (var stream = avatar.OpenReadStream())
            {
                byte[] headerBytes = new byte[12];
                int bytesRead = 0;
                int totalBytesRead = 0;
                
                // Read enough bytes for signature validation
                while (totalBytesRead < 12 && (bytesRead = await stream.ReadAsync(headerBytes, totalBytesRead, 12 - totalBytesRead)) > 0)
                {
                    totalBytesRead += bytesRead;
                }
                
                if (totalBytesRead < 4)
                {
                    return BadRequest("File is too small to be a valid image.");
                }

                // Check magic bytes for PNG, JPEG, GIF
                bool isValidImageSignature = false;
                string detectedExtension = null;

                // PNG: 89 50 4E 47
                if (totalBytesRead >= 4 && headerBytes[0] == 0x89 && headerBytes[1] == 0x50 && 
                    headerBytes[2] == 0x4E && headerBytes[3] == 0x47)
                {
                    isValidImageSignature = true;
                    detectedExtension = ".png";
                }
                // JPEG: FF D8 FF
                else if (totalBytesRead >= 3 && headerBytes[0] == 0xFF && headerBytes[1] == 0xD8 && headerBytes[2] == 0xFF)
                {
                    isValidImageSignature = true;
                    detectedExtension = ".jpg";
                }
                // GIF87a or GIF89a: 47 49 46 38
                else if (totalBytesRead >= 4 && headerBytes[0] == 0x47 && headerBytes[1] == 0x49 && 
                         headerBytes[2] == 0x46 && headerBytes[3] == 0x38)
                {
                    isValidImageSignature = true;
                    detectedExtension = ".gif";
                }

                if (!isValidImageSignature)
                {
                    return BadRequest("File signature does not match allowed image types.");
                }

                var storageRoot = Path.Combine(_env.ContentRootPath, "PrivateStorage", "avatars");
                Directory.CreateDirectory(storageRoot);

                var storedFileName = Guid.NewGuid().ToString("N") + detectedExtension;
                var destinationPath = Path.Combine(storageRoot, storedFileName);

                // Rewind to beginning and write file
                stream.Seek(0, SeekOrigin.Begin);
                using (var destinationStream = System.IO.File.Create(destinationPath))
                {
                    await stream.CopyToAsync(destinationStream);
                }

                return Ok(new { storedFileName });
            }
        }
    }
}
```

## Explanation

The vulnerable code validates only the `IFormFile.ContentType` header, which is client-supplied metadata from the multipart request. An attacker can declare any content type regardless of the actual file contents.

The fix reads the file's actual signature (magic bytes) from the stream and validates against known signatures for PNG (`0x89504E47`), JPEG (`0xFFD8FF`), and GIF (`0x47494638`). Only files matching one of these signatures are accepted. The extension is then derived from the detected type, not the client-supplied ContentType, ensuring the stored file uses the correct extension.

The stream is rewound after reading the signature header (which is small, typically 4-12 bytes) and the full file is written to disk. The filename remains generated via `Guid.NewGuid()`, and the file is stored outside the webroot in `PrivateStorage/avatars`, preventing direct execution by the web server.

## Behaviour changes

- Files with a ContentType header that does not match their actual signature are now rejected, preventing upload of executables disguised with an image content type.
- The stored file extension is determined by the detected signature, not the client-supplied ContentType, preventing extension mismatches that could lead to execution.
- Files smaller than 4 bytes are rejected as too small to contain a valid image signature.
- All successfully uploaded files are stored with a randomly generated filename in a private directory, as before.
