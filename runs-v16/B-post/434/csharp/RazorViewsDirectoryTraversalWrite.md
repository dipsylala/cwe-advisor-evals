## Verdict
Exploitable

## Source
`IFormFile file` parameter from the HTTP POST request (line 27). The `file.FileName` property is client-supplied multipart request metadata.

## Fix

**Vulnerable Code (line 40):**
```csharp
var destinationPath = Path.Combine(viewsRootPath, file.FileName);
```

**Fixed Code:**
```csharp
// Validate that the uploaded file has a .cshtml extension
var fileExtension = Path.GetExtension(file.FileName).ToLowerInvariant();
if (fileExtension != ".cshtml")
{
    return BadRequest("Only .cshtml files are allowed for email templates.");
}

// Generate a random filename to prevent directory traversal attacks
// and ensure consistent storage naming; do not use client-supplied FileName
var storedFileName = Guid.NewGuid().ToString("N") + ".cshtml";
var destinationPath = Path.Combine(viewsRootPath, storedFileName);

using (var stream = new FileStream(destinationPath, FileMode.CreateNew))
{
    await file.CopyToAsync(stream);
}
```

## Explanation

The vulnerability is a directory traversal attack through the client-supplied `IFormFile.FileName`. An attacker authenticated as an admin could upload a file with a name containing path traversal sequences (e.g., `../../../web.cshtml` or `..\..\..\malicious.cshtml`), escaping the intended `Views/EmailTemplates` directory and potentially writing files elsewhere on disk. Since the application enables Razor runtime compilation for views (line 8 comment), a `.cshtml` file written into the Views tree is compiled and executed as server-side code on the next request, leading to remote code execution.

The fix generates a cryptographically random filename using `Guid.NewGuid().ToString("N")` instead of using the client-supplied name. This eliminates the traversal attack vector because a GUID is purely alphanumeric with no special path characters. The fix also validates that uploaded files have a `.cshtml` extension, enforcing the business requirement that only Razor templates are accepted for email rendering. Finally, it uses `FileMode.CreateNew` instead of `FileMode.Create`, which atomically fails if a file with that name already exists (defense in depth against extremely unlikely GUID collision, though the probability is negligible).

## Behaviour changes

1. **Filename generation**: The original code stores the file with the client-supplied `file.FileName`. The fixed code generates a random GUID-based name, so the original filename is no longer preserved in storage. The API response returns the generated filename rather than echoing back the uploaded name. This change is required to close the directory traversal attack surface; the calling client can still retrieve the template if needed through a separate API that returns the stored filename after upload.

2. **File type validation**: The original code accepts any file type; the fixed code rejects uploads that do not end with `.cshtml` and returns a 400 Bad Request. This is a behavioral hardening that aligns with the application's intended use case (email templates rendered via Razor), though it assumes only `.cshtml` files are needed. If other template formats are required in the future, the allowlist would need to be expanded.

3. **FileMode change**: The original uses `FileMode.Create` (overwrite if exists); the fixed code uses `FileMode.CreateNew` (fail if exists). This is a defensive change with negligible practical impact—the probability of a GUID collision is vanishingly small—but it provides fail-fast behavior rather than silent overwrites, making accidental collisions detectable in logs.

4. **Response body change**: The original returns `{ stored = file.FileName }`; the fixed code returns `{ stored = storedFileName }` where `storedFileName` is the generated GUID-based name. This is necessary for the client to later reference the stored template, and makes it explicit that the original filename is not preserved.
