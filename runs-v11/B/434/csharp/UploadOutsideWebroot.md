## Verdict

Exploitable

## Source

`IFormFile file` parameter (line 17) - untrusted upload from client. The `FileName` property contains the client-supplied filename; `ContentType` and `FileName` are both request metadata provided by the client and not validated by the framework.

## Fix

**Vulnerable code (line 28):**
```csharp
var destination = Path.Combine(uploadRoot, file.FileName);
```

**Fixed code:**
```csharp
// Define MIME type to file extension mapping (allowlist)
var allowedMimeTypes = new Dictionary<string, string>
{
    { "image/jpeg", ".jpg" },
    { "image/png", ".png" },
    { "image/gif", ".gif" },
    { "application/pdf", ".pdf" }
};

// Read file signature (magic bytes) to validate actual type
using var stream = file.OpenReadStream();
byte[] buffer = new byte[8];
int bytesRead = await stream.ReadAtLeastAsync(buffer, buffer.Length, false).ConfigureAwait(false);

// Validate file signature against known magic bytes
string detectedMimeType = DetectMimeTypeFromSignature(buffer);

if (!allowedMimeTypes.ContainsKey(detectedMimeType))
{
    return BadRequest(new { error = "File type not allowed" });
}

// Rewind stream for subsequent CopyToAsync
stream.Seek(0, SeekOrigin.Begin);

// Generate random filename with extension from detected type
string randomFilename = Guid.NewGuid().ToString("N") + allowedMimeTypes[detectedMimeType];
var destination = Path.Combine(uploadRoot, randomFilename);
```

Helper method to detect MIME type from file signature:
```csharp
private static string DetectMimeTypeFromSignature(byte[] buffer)
{
    // JPEG: FF D8 FF
    if (buffer.Length >= 3 && buffer[0] == 0xFF && buffer[1] == 0xD8 && buffer[2] == 0xFF)
        return "image/jpeg";
    
    // PNG: 89 50 4E 47
    if (buffer.Length >= 4 && buffer[0] == 0x89 && buffer[1] == 0x50 && buffer[2] == 0x4E && buffer[3] == 0x47)
        return "image/png";
    
    // GIF: 47 49 46 (GIF87a or GIF89a)
    if (buffer.Length >= 3 && buffer[0] == 0x47 && buffer[1] == 0x49 && buffer[2] == 0x46)
        return "image/gif";
    
    // PDF: 25 50 44 46 (% P D F)
    if (buffer.Length >= 4 && buffer[0] == 0x25 && buffer[1] == 0x50 && buffer[2] == 0x44 && buffer[3] == 0x46)
        return "application/pdf";
    
    // Unknown type
    return "application/octet-stream";
}
```

## Explanation

The original code at line 28 uses `file.FileName` directly without any validation. This allows an attacker to upload files with arbitrary extensions (executable, script, or other dangerous types) or use path traversal sequences in the filename. The fix implements the allowlist validation pattern by: (1) reading the actual file signature (magic bytes) from the stream, (2) validating that the detected type is in the allowed list, (3) rejecting the upload if the type is not permitted, (4) rewinding the stream after reading the header, and (5) generating a random filename using `Guid.NewGuid().ToString("N")` with an extension derived from the detected type's allowlist entry, not the client-supplied filename. This ensures the stored file's extension and actual content type match, and an attacker cannot control the storage filename or upload dangerous file types.

## Behaviour changes

- Added asynchronous magic-byte validation before file storage (requires `async/await` context)
- Added dictionary-based allowlist for permitted MIME types and their extensions
- Added `DetectMimeTypeFromSignature()` helper method to inspect file signature
- The stream is rewound after reading signature bytes using `stream.Seek(0, SeekOrigin.Begin)`, preserving the full content for `CopyToAsync()`
- Generated filename is now random (GUID-based) instead of client-supplied, eliminating both path traversal and attacker control over the filename
- File extension is now derived from detected file type, not from `IFormFile.FileName`, preventing extension-based exploitation
- Upload is rejected (returns BadRequest) if file type does not match the allowlist
- The `allowedMimeTypes` dictionary must be customized based on application requirements and should include only business-required file types

