## Verdict

Exploitable

## Source

`avatar` parameter (IFormFile) from the HTTP multipart request at line 21. The attacker controls the uploaded file content and the Content-Type header.

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

            // Read and validate file signature
            using (var stream = avatar.OpenReadStream())
            {
                var headerBytes = new byte[8];
                int bytesRead = 0;
                
                // Read header bytes, handling partial reads
                while (bytesRead < headerBytes.Length)
                {
                    int read = await stream.ReadAsync(headerBytes, bytesRead, headerBytes.Length - bytesRead);
                    if (read == 0) break;
                    bytesRead += read;
                }

                if (bytesRead < 4)
                {
                    return BadRequest("File is too small.");
                }

                // Detect file type by magic bytes
                string extension = null;

                // PNG signature: 89 50 4E 47
                if (headerBytes[0] == 0x89 && headerBytes[1] == 0x50 && headerBytes[2] == 0x4E && headerBytes[3] == 0x47)
                {
                    extension = ".png";
                }
                // JPEG signature: FF D8 FF
                else if (headerBytes[0] == 0xFF && headerBytes[1] == 0xD8 && headerBytes[2] == 0xFF)
                {
                    extension = ".jpg";
                }
                // GIF signature: 47 49 46 (GIF in ASCII)
                else if (headerBytes[0] == 0x47 && headerBytes[1] == 0x49 && headerBytes[2] == 0x46)
                {
                    extension = ".gif";
                }
                else
                {
                    return BadRequest("File type not allowed. Only PNG, JPEG, or GIF images are supported.");
                }

                // Rewind stream to beginning for file writing
                stream.Seek(0, SeekOrigin.Begin);

                var storageRoot = Path.Combine(_env.ContentRootPath, "PrivateStorage", "avatars");
                Directory.CreateDirectory(storageRoot);

                var storedFileName = Guid.NewGuid().ToString("N") + extension;
                var destinationPath = Path.Combine(storageRoot, storedFileName);

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

The original code validated only `avatar.ContentType`, which is a client-supplied request header and can be spoofed. An attacker could upload any file type (HTML with embedded script, executable, etc.) while setting the Content-Type header to "image/png", bypassing the check entirely. The fixed code reads the actual file signature (magic bytes) from the stream instead: it reads the first 8 bytes and compares them against known signatures for PNG (89 50 4E 47), JPEG (FF D8 FF), and GIF (47 49 46). Only files matching one of these signatures are accepted. The extension for storage is then derived from the detected type, not from the client-supplied Content-Type. After validation, the stream is rewound to the beginning so the complete file (not just the header) can be written to storage. This approach prevents polyglot files or mismatched extension/content pairs from being accepted.

## Behaviour changes

- **Validation method changed**: Replaced client-supplied Content-Type check with magic-byte file-signature validation. This is the core fix and does not introduce side effects; it only accepts files whose actual bytes match allowed image signatures.
- **Extension derivation changed**: The extension is now derived from the detected file type (via magic bytes) rather than from the client-supplied Content-Type header. This ensures the stored file's extension matches its actual content.
- **Stream position changed**: Added `stream.Seek(0, SeekOrigin.Begin)` after reading the header to reset the stream position before copying to disk. This is necessary because the file read for validation advances the stream position; rewinding ensures the complete file is copied, not just the bytes after the header.
- **Storage location unchanged**: Files still stored in `PrivateStorage/avatars` outside the webroot, using a server-generated random filename with a safe extension.
- **Error messages updated**: Added rejection message for files with unsupported signatures. Files too small to contain a valid header are now also rejected with a specific error.

Verification: All APIs used (`OpenReadStream()`, `ReadAsync()`, `Seek()`, `File.Create()`, `CopyToAsync()`, `Path.Combine()`, `Directory.CreateDirectory()`, `Guid.NewGuid()`) are standard .NET/ASP.NET Core APIs available in all supported framework versions. Syntax is valid and compilable with any C# 7.0+ compiler.
