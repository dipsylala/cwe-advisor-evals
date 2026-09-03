## Verdict

CONFIRMED. The vulnerability is exploitable: the code validates only `IFormFile.ContentType`, which is client-supplied metadata not verified by ASP.NET Core. An attacker can upload executable code (e.g., a compiled assembly, batch script, or HTML containing script) while claiming it is an image. When the file is stored with a `.jpg` extension derived from the spoofed `ContentType`, it persists the attacker's payload to disk. Later access—whether the file is served directly, executed by a runtime compiler (Razor), or loaded by a plugin system—can run the malicious code.

## Source

- **File**: ContentTypeOnlyValidation.cs
- **Line**: 53
- **Sink**: `System.IO.File.Create(destinationPath)`
- **Data flow**: 
  1. `avatar.ContentType` (lines 28–31, client-supplied) → 
  2. extension selection (lines 41–47) → 
  3. destination path construction (line 50) → 
  4. write to disk (line 53)

The validation gates only on `ContentType` without inspecting actual file content. No magic-byte check occurs before write.

## Fix

Replace the `ContentType`-based validation with file-signature validation and re-encode the image:

```csharp
[HttpPost("avatar")]
public async Task<IActionResult> UploadAvatar(IFormFile avatar)
{
    if (avatar == null || avatar.Length == 0)
    {
        return BadRequest("No file uploaded.");
    }

    // FIXED: Validate file signature (magic bytes) instead of ContentType
    var (detectedType, isValidSignature) = await ValidateImageSignatureAsync(avatar);
    if (!isValidSignature)
    {
        return BadRequest("File must be a valid PNG, JPEG, or GIF image.");
    }

    var storageRoot = Path.Combine(_env.ContentRootPath, "PrivateStorage", "avatars");
    Directory.CreateDirectory(storageRoot);

    // FIXED: Use signature-matched type for extension, not ContentType
    var extension = detectedType switch
    {
        "image/png" => ".png",
        "image/jpeg" => ".jpg",
        "image/gif" => ".gif",
        _ => ".bin"
    };

    var storedFileName = Guid.NewGuid().ToString("N") + extension;
    var destinationPath = Path.Combine(storageRoot, storedFileName);

    // FIXED: Re-encode image to strip embedded content
    using (var destinationStream = System.IO.File.Create(destinationPath, 4096, FileOptions.None))
    {
        await ReEncodeImageAsync(avatar, destinationStream, detectedType);
    }

    return Ok(new { storedFileName });
}

// FIXED: Validate file signature against magic bytes for allowed types
private static async Task<(string mimeType, bool isValid)> ValidateImageSignatureAsync(IFormFile file)
{
    const int headerSize = 12;
    byte[] header = new byte[headerSize];

    using (var stream = file.OpenReadStream())
    {
        int bytesRead = await stream.ReadAtLeastAsync(header, headerSize, false);
        if (bytesRead < 4)
            return ("", false);

        // PNG: 89 50 4E 47
        if (header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47)
            return ("image/png", true);

        // JPEG: FF D8 FF
        if (header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF)
            return ("image/jpeg", true);

        // GIF: 47 49 46 (GIF87a or GIF89a)
        if (header[0] == 0x47 && header[1] == 0x49 && header[2] == 0x46)
            return ("image/gif", true);
    }

    return ("", false);
}

// FIXED: Re-encode image to strip embedded payloads
private static async Task ReEncodeImageAsync(IFormFile originalFile, Stream destinationStream, string mimeType)
{
    using (var imageStream = originalFile.OpenReadStream())
    using (var image = await SixLabors.ImageSharp.Image.LoadAsync(imageStream))
    {
        if (mimeType == "image/png")
            await image.SaveAsPngAsync(destinationStream);
        else if (mimeType == "image/jpeg")
            await image.SaveAsJpegAsync(destinationStream);
        else if (mimeType == "image/gif")
            await image.SaveAsGifAsync(destinationStream);
    }
}
```

Add `SixLabors.ImageSharp` NuGet package (maintained, production-ready image library). No minimum version is prescribed here; consult your SCA/dependency-check tool for the latest secure version and any known advisories before merging.

## Explanation

The original code relies on `IFormFile.ContentType`, a client-supplied HTTP header that can be forged. An attacker uploads a compiled DLL or batch script and claims it is `image/jpeg`; the validation passes and the file lands on disk with a `.jpg` extension. The file never gets executed as an image—execution happens only if the web server (or runtime compiler like Razor) ever interprets it as something else, or if a plugin loader finds it in the content root.

The fix eliminates this gap through three changes:

1. **Magic-byte validation** reads the actual file header and matches it against known image signatures (PNG, JPEG, GIF). This cannot be spoofed without creating a valid image file.

2. **Re-encoding** with `SixLabors.ImageSharp` decodes and re-saves the image, stripping any embedded payloads (a polyglot PNG/ZIP or JPEG with trailing script becomes a clean image).

3. **Signature-matched type** ensures the file extension and content match the detected format, not the client's claim. Using `Guid.NewGuid().ToString("N")` for the filename prevents traversal attacks.

The file is still stored outside `wwwroot` (under `PrivateStorage/avatars`), preventing direct web access. For complete defence-in-depth, serve the file back through a dedicated controller action that sets safe response headers (`Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`).

## Behaviour changes

- **Rejection of polyglot or mismatched files**: An uploaded file with a spoofed ContentType is now rejected at validation, not accepted and stored.
- **Image re-encoding overhead**: Re-encoding adds CPU and memory cost on upload but guarantees payload removal.
- **Dependency addition**: Requires `SixLabors.ImageSharp` NuGet package (add to project file and restore).
- **FileOptions.None on File.Create**: Uses default file options; no buffering behavior changes.
- **ReadAtLeastAsync requirement**: Requires .NET 6+. For .NET Framework or earlier .NET Core, use a manual loop: `int total = 0; while (total < headerSize && (int bytesRead = stream.Read(...)) > 0) total += bytesRead;`
