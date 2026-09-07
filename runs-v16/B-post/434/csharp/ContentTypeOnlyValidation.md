## Verdict

**Exploitable** (high confidence)

The application validates only the client-supplied `IFormFile.ContentType` header without inspecting the actual file content. An attacker can upload an executable file (e.g., `.aspx`, `.cshtml`, `.html`) while declaring a safe MIME type (e.g., `image/png`), bypassing the allowlist check. The file is then written to storage under a server-generated name, but the actual executable content permits code execution if the file reaches an execution context.

## Source

**Source:** `avatar` parameter (IFormFile) from HTTP request
**Sink:** Line 53 - `System.IO.File.Create(destinationPath)` and line 55 - `avatar.CopyToAsync(destinationStream)`
**Location:** evals/cases/434/csharp/ContentTypeOnlyValidation/ContentTypeOnlyValidation.cs, lines 28-36 (validation gate), lines 41-47 (extension mapping), lines 53-55 (file write)

The vulnerability originates at lines 28-31, where validation trusts only the client-supplied `avatar.ContentType` header, which is not verified by the framework. The extension is then derived from this untrusted value (lines 41-47), and used to generate the storage filename. The file is written without signature validation, allowing a polyglot or mistyped executable to pass validation.

## Fix

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

// SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
using (var destinationStream = System.IO.File.Create(destinationPath))
{
    await avatar.CopyToAsync(destinationStream);
}
```

**Fixed code:**

```csharp
// Read and validate file signature (magic bytes) from the actual stream
using (var stream = avatar.OpenReadStream())
{
    byte[] header = new byte[8];
    int bytesRead = await stream.ReadAsync(header, 0, Math.Min(8, (int)avatar.Length));
    
    if (bytesRead < 3)
    {
        return BadRequest("File is too small to validate.");
    }

    // Validate against magic bytes allowlist; do not trust client-supplied ContentType
    string? detectedType = null;
    
    if (bytesRead >= 4 && header[0] == 0x89 && header[1] == 0x50 && 
        header[2] == 0x4E && header[3] == 0x47)
    {
        // PNG signature: 0x89 'P' 'N' 'G'
        detectedType = "image/png";
    }
    else if (bytesRead >= 3 && header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF)
    {
        // JPEG signature: 0xFF 0xD8 0xFF
        detectedType = "image/jpeg";
    }
    else if (bytesRead >= 4 && header[0] == 0x47 && header[1] == 0x49 && 
             header[2] == 0x46 && (header[3] == 0x38))
    {
        // GIF signature: 'G' 'I' 'F' '8'
        detectedType = "image/gif";
    }

    if (detectedType == null)
    {
        return BadRequest("File type not allowed. Only PNG, JPEG, or GIF are supported.");
    }

    var storageRoot = Path.Combine(_env.ContentRootPath, "PrivateStorage", "avatars");
    Directory.CreateDirectory(storageRoot);

    // Map detected type (not client-supplied ContentType) to extension
    var extension = detectedType switch
    {
        "image/png" => ".png",
        "image/jpeg" => ".jpg",
        "image/gif" => ".gif",
        _ => ".bin"
    };

    var storedFileName = Guid.NewGuid().ToString("N") + extension;
    var destinationPath = Path.Combine(storageRoot, storedFileName);

    // Rewind stream to beginning and write validated file content
    stream.Seek(0, SeekOrigin.Begin);
    using (var destinationStream = System.IO.File.Create(destinationPath))
    {
        await stream.CopyToAsync(destinationStream);
    }

    return Ok(new { storedFileName });
}
```

## Explanation

The fix replaces the trust boundary from the client-supplied `IFormFile.ContentType` header to the file's actual signature (magic bytes). Instead of validating the MIME type declared in the HTTP request, the code now reads the first 3-4 bytes from the actual file stream and compares them against known signatures for PNG, JPEG, and GIF. Only files whose signatures match an allowlisted type are accepted, and the file extension is then derived from the detected type rather than the client-supplied header.

The stream is rewound to the beginning with `Seek(0, SeekOrigin.Begin)` after reading the header, ensuring the full file content is written to storage. This eliminates the polyglot attack where an attacker uploads executable code (e.g., a `.cshtml` file) while claiming a safe MIME type in the Content-Type header. The signature-based validation proves the actual file content, not the client's claim about it.

No third-party library is required; the fix uses only `ReadAsync` and `Seek` from the standard `System.IO` namespace.

## Behaviour changes

1. **Stream position handling:** The original code did not read from the stream before writing; it passed the upload stream directly to `CopyToAsync`. The fixed code reads the first 8 bytes for signature validation, then rewinds the stream with `stream.Seek(0, SeekOrigin.Begin)` to ensure the full file (including the header bytes already read) is written. This preserves the complete file content.

2. **Header read error handling:** The fixed code checks if fewer than 3 bytes were read, since magic-byte validation requires at least 3 bytes. This adds a new failure mode (rejecting files smaller than 3 bytes), which is appropriate for image files and aligns with the CWE-434/csharp guidance requirement to validate file signatures.

3. **Extension derivation source:** The original code mapped the extension from `avatar.ContentType` (client-supplied). The fixed code maps it from `detectedType` (server-determined by magic-byte analysis). This is a critical security change that eliminates the attacker's control over the stored file's extension.

4. **Validation gate:** The original boolean check (`isAllowedImageType`) is replaced with an explicit type-detection algorithm. The new gate rejects files that do not match any known signature, with a more specific error message indicating what types are supported.

5. **Scope of validation:** The original code validated one property (ContentType); the fixed code reads and inspects the file stream. This incurs a small I/O cost (reading 8 bytes) but is necessary to close the weakness and aligns with CWE-434/csharp requirement to "read the file signature from `IFormFile.OpenReadStream()`."

All changes flow from the core weakness: trusting client-supplied metadata. No unrelated changes were made to return types, call signatures, or downstream logic.

