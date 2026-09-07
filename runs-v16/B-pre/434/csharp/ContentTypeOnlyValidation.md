## Verdict

VULNERABLE. The code validates file uploads against a client-supplied `IFormFile.ContentType` header without inspecting actual file content. An attacker can upload a malicious executable file (e.g., `.exe`, `.aspx`, `.cshtml`) while claiming a safe MIME type (e.g., `image/jpeg`) to bypass validation and write the malicious file to disk.

## Source

`IFormFile avatar` parameter received from multipart POST request at line 21. The `ContentType` property (lines 28-30) is extracted directly from the `Content-Type` header sent by the client and used as the sole validation gate.

## Fix

Replace the `ContentType`-only validation with file signature (magic bytes) validation. Read the leading bytes from `avatar.OpenReadStream()`, compare against known magic numbers for PNG, JPEG, and GIF, and reject any file whose signature does not match. Map the file extension from the detected type (via a fixed allowlist), not from the client-supplied ContentType. Rewind the stream before writing.

**Vulnerable code:**
```csharp
bool isAllowedImageType =
    avatar.ContentType == "image/png" ||
    avatar.ContentType == "image/jpeg" ||
    avatar.ContentType == "image/gif";

if (!isAllowedImageType)
{
    return BadRequest("Only PNG, JPEG, or GIF images are allowed.");
}

var extension = avatar.ContentType switch
{
    "image/png" => ".png",
    "image/jpeg" => ".jpg",
    "image/gif" => ".gif",
    _ => ".bin"
};

using (var destinationStream = System.IO.File.Create(destinationPath))
{
    await avatar.CopyToAsync(destinationStream);
}
```

**Fixed code:**
```csharp
// Read and validate file signature (magic bytes)
using (var stream = avatar.OpenReadStream())
{
    var header = new byte[8];
    int bytesRead = await stream.ReadAtLeastAsync(header, header.Length, false);
    if (bytesRead < 4)
    {
        return BadRequest("File is too short.");
    }

    // Magic bytes for allowed types
    // PNG: 89 50 4E 47
    // JPEG: FF D8 FF
    // GIF: 47 49 46 38 (GIF87a or GIF89a)
    
    string extension = null;

    if (header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47)
    {
        extension = ".png";
    }
    else if (header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF)
    {
        extension = ".jpg";
    }
    else if (header[0] == 0x47 && header[1] == 0x49 && header[2] == 0x46 && 
             header[3] == 0x38)
    {
        extension = ".gif";
    }
    else
    {
        return BadRequest("File type is not allowed. Only PNG, JPEG, or GIF images are permitted.");
    }

    var storedFileName = Guid.NewGuid().ToString("N") + extension;
    var destinationPath = Path.Combine(storageRoot, storedFileName);

    // Rewind stream and write file
    stream.Seek(0, System.IO.SeekOrigin.Begin);
    using (var destinationStream = System.IO.File.Create(destinationPath))
    {
        await stream.CopyToAsync(destinationStream);
    }

    return Ok(new { storedFileName });
}
```

## Explanation

The vulnerability exists because `IFormFile.ContentType` is client-supplied metadata from the multipart request and can be spoofed. The current validation checks only this untrusted header, not the actual file contents. An attacker can upload a `.exe`, `.aspx`, or `.cshtml` file while setting `Content-Type: image/jpeg`, causing the application to accept and write the malicious executable to disk. This enables arbitrary code execution if the file is later executed or served from a directory capable of running scripts.

The fix validates the file's actual content by reading its magic bytes (the first 4-8 bytes that identify file type). Each format has a unique signature: PNG starts with `89 50 4E 47`, JPEG with `FF D8 FF`, and GIF with `47 49 46 38`. The file is rejected if these signatures do not match. The extension is then derived from the detected type via a server-controlled map, not from the client-supplied ContentType. The stream is rewound before copying because `ReadAtLeastAsync` advanced the file pointer; failure to rewind would write only the remainder of the file, omitting the header.

## Behaviour changes

- **Validation now inspects file content.** Files with mismatched extension and magic bytes are rejected, blocking spoofing attacks.
- **Bytesread check added.** Files smaller than 4 bytes are rejected as invalid, since the magic signatures cannot be verified.
- **Stream rewind required.** The `stream.Seek(0, SeekOrigin.Begin)` call ensures the entire file is written, including the header bytes already read during validation.
- **Error message clarified.** The rejection message now reflects signature-based validation rather than ContentType checking.
