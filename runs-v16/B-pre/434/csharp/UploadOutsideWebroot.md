## Verdict

Vulnerable. The endpoint accepts file uploads without validating file type or content, and uses the client-supplied filename directly as the storage path.

## Source

`IFormFile file` parameter, specifically `file.FileName` (client-supplied in the multipart request) and the file stream content.

## Fix

```csharp
[HttpPost("/upload")]
public async Task<IActionResult> Upload(IFormFile file)
{
    if (file is null || file.Length == 0)
    {
        return BadRequest();
    }

    // Allowed file types mapped by magic bytes (file signature)
    var allowedSignatures = new Dictionary<string, (string[] magicBytes, string ext)>
    {
        { "image/jpeg", (new[] { "FF", "D8", "FF" }, ".jpg") },
        { "image/png", (new[] { "89", "50", "4E", "47" }, ".png") },
        { "image/gif", (new[] { "47", "49", "46" }, ".gif") },
    };

    // Read file signature (first 4 bytes)
    var buffer = new byte[4];
    await using var fileStream = file.OpenReadStream();
    int bytesRead = await fileStream.ReadAtLeastAsync(buffer, 3, throwOnEndOfStream: false);

    if (bytesRead < 3)
    {
        return BadRequest("File too small");
    }

    // Validate file signature against allowlist
    var signature = BitConverter.ToString(buffer, 0, bytesRead).Replace("-", "");
    string detectedExt = null;

    foreach (var (mimeType, (magicBytes, ext)) in allowedSignatures)
    {
        var expectedSig = string.Concat(magicBytes);
        if (signature.StartsWith(expectedSig))
        {
            detectedExt = ext;
            break;
        }
    }

    if (detectedExt == null)
    {
        return BadRequest("File type not allowed");
    }

    // Generate secure filename (Guid) and append validated extension
    var uploadRoot = Path.Combine(_env.ContentRootPath, "storage", "uploads");
    Directory.CreateDirectory(uploadRoot);

    var generatedName = Guid.NewGuid().ToString("N");
    var destination = Path.Combine(uploadRoot, generatedName + detectedExt);

    // Rewind stream and write file
    fileStream.Seek(0, SeekOrigin.Begin);
    await using var writeStream = System.IO.File.Create(destination, bufferSize: 4096);
    await fileStream.CopyToAsync(writeStream);

    return Ok(new { stored = Path.GetFileName(destination), bytes = file.Length });
}
```

## Explanation

The original code accepts `file.FileName` directly from the client and uses it as the storage path without validating file type or content. This allows an attacker to upload a dangerous file type (e.g., `.aspx`, `.cshtml`, `.html` containing script, or other executables).

The fix implements the three-part validation pattern from CWE-434 guidance:

1. **Validate file content via magic bytes**: Read the first 3-4 bytes of the stream using `ReadAtLeastAsync` (which ensures sufficient bytes are available; a single `Read` call may return fewer bytes) and compare against known magic numbers for allowed types. `ReadAtLeastAsync` with `throwOnEndOfStream: false` returns the actual bytes read without throwing if the file is shorter than requested.

2. **Generate a server-controlled filename**: Use `Guid.NewGuid().ToString("N")` to create a random filename independent of the client's input. Never use `Path.GetRandomFileName()` for this purpose because it already contains a dot and appending an extension creates a double-extension name.

3. **Map extension from detected type**: Append the extension corresponding to the validated file type from a server-controlled allowlist, not from the client-supplied `FileName`. This prevents extension-based bypasses where an attacker uploads a script with a spoofed `.jpg` extension.

The fix also rewinds the stream after reading the signature (`Seek(0, SeekOrigin.Begin)`) before copying to ensure the full file content is written. Files are still stored outside the webroot (under `storage/uploads` in the content root), preventing direct execution by the web server.

## Behaviour changes

- **Rejection of disallowed types**: Files not matching the allowed signatures are rejected with HTTP 400.
- **Filename changes**: Uploaded files are stored with Guid-based names (e.g., `a1b2c3d4e5f6g7h8.jpg`) rather than the original client-supplied filename.
- **File size threshold**: Files smaller than 3 bytes are rejected as invalid.
- **Extension mapping**: The stored extension reflects the detected file type (from magic bytes), not the client-supplied extension.
