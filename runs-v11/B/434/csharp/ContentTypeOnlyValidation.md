## Verdict

Exploitable. The code validates file type based on `IFormFile.ContentType`, which is client-supplied and not verified. An attacker can upload a file with dangerous content while claiming an allowed MIME type in the HTTP request header. File validation must inspect actual file content (magic bytes) instead.

## Source

Line 28-31: `avatar.ContentType` is read directly from the HTTP multipart request header without validation. This client-supplied value is used to derive the file extension at lines 41-46 and determine the storage filename at line 49.

## Fix

**Before (vulnerable):**
```csharp
bool isAllowedImageType =
    avatar.ContentType == "image/png" ||
    avatar.ContentType == "image/jpeg" ||
    avatar.ContentType == "image/gif";

if (!isAllowedImageType)
{
    return BadRequest("Only PNG, JPEG, or GIF images are allowed.");
}

var storageRoot = Path.Combine(_env.ContentRootPath, "PrivateStorage", "avatars");
Directory.CreateDirectory(storageRoot);

var extension = avatar.ContentType switch
{
    "image/png" => ".png",
    "image/jpeg" => ".jpg",
    "image/gif" => ".gif",
    _ => ".bin"
};

var storedFileName = Guid.NewGuid().ToString("N") + extension;
var destinationPath = Path.Combine(storageRoot, storedFileName);

using (var destinationStream = System.IO.File.Create(destinationPath))
{
    await avatar.CopyToAsync(destinationStream);
}
```

**After (fixed):**
```csharp
// Read file signature to validate actual content
const int headerSize = 16;
byte[] header = new byte[headerSize];

using (var stream = avatar.OpenReadStream())
{
    int bytesRead = await stream.ReadAtLeastAsync(header, headerSize, false);
    if (bytesRead < 4) // Minimum for PNG/JPEG/GIF signatures
    {
        return BadRequest("File is too small to verify.");
    }
}

// Validate against magic bytes (file signatures)
string detectedType = null;
string extension = null;

// PNG: 89 50 4E 47
if (header.Length >= 4 && header[0] == 0x89 && header[1] == 0x50 && 
    header[2] == 0x4E && header[3] == 0x47)
{
    detectedType = "image/png";
    extension = ".png";
}
// JPEG: FF D8 FF
else if (header.Length >= 3 && header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF)
{
    detectedType = "image/jpeg";
    extension = ".jpg";
}
// GIF: 47 49 46 38 (GIF87a or GIF89a)
else if (header.Length >= 4 && header[0] == 0x47 && header[1] == 0x49 && 
         header[2] == 0x46 && header[3] == 0x38)
{
    detectedType = "image/gif";
    extension = ".gif";
}
else
{
    return BadRequest("Only PNG, JPEG, or GIF images are allowed.");
}

var storageRoot = Path.Combine(_env.ContentRootPath, "PrivateStorage", "avatars");
Directory.CreateDirectory(storageRoot);

var storedFileName = Guid.NewGuid().ToString("N") + extension;
var destinationPath = Path.Combine(storageRoot, storedFileName);

using (var destinationStream = System.IO.File.Create(destinationPath))
{
    await avatar.CopyToAsync(destinationStream);
}
```

## Explanation

The fix replaces client-supplied `ContentType` validation with actual file-signature validation. The corrected code reads the leading bytes (magic numbers) from the uploaded file stream using `ReadAtLeastAsync()` and compares them against known signatures for PNG, JPEG, and GIF formats. Only when the actual file content matches one of these allowed signatures is the file accepted and stored with the corresponding server-determined extension. The filename remains randomly generated (Guid-based), preventing any attacker control over the stored filename. This ensures that an attacker cannot bypass the type check by simply claiming an allowed MIME type in the request header while uploading a dangerous file format.

## Behaviour changes

- **Signature validation added**: The code now reads and validates file magic bytes instead of trusting the client-supplied Content-Type header. This introduces an I/O operation (`ReadAtLeastAsync()`) before writing, which is a necessary security improvement.
- **Stream rewind not required**: After reading the header with `ReadAtLeastAsync()`, the stream position advances but the file copy operation begins from the start of the stream passed to `CopyToAsync()`. The `IFormFile.CopyToAsync()` method internally uses `OpenReadStream()` which returns a fresh stream from position 0, so no explicit `Seek()` call is needed. The sink contract (writing the full file to destination) is preserved.
- **File size validation added**: Added a check for minimum file size (4 bytes) to ensure the header bytes are meaningful, rejecting corrupted or truncated files.
- **Extension derivation changed**: Extension now comes from validated file content rather than untrusted client metadata, using a byte-pattern matching approach that cannot be manipulated by request headers.
