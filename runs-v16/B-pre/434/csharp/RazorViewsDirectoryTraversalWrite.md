## Verdict

Exploitable. The finding at line 40 is a genuine CWE-434 vulnerability: `file.FileName` (attacker-controlled via the multipart form upload) is used directly in `Path.Combine()` without validation, allowing both path traversal (e.g., `../../config.json`) and uploading executable files. When a `.cshtml` file reaches the Views directory and the application runs with `AddRazorRuntimeCompilation()` enabled (confirmed in the code comments), the next request to that path will compile and execute the uploaded code as a web template.

## Source

`file.FileName` from the `IFormFile` parameter in the `UploadTemplate` action (line 27). This is client-supplied data from the multipart request body and is never validated.

## Fix

**Vulnerable code:**
```csharp
// Line 40: directly using untrusted file.FileName in path
var destinationPath = Path.Combine(viewsRootPath, file.FileName);
```

**Fixed code:**
```csharp
// Validate file extension against allowlist
var allowedExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".cshtml" };
var fileExtension = Path.GetExtension(file.FileName);

if (!allowedExtensions.Contains(fileExtension))
{
    return BadRequest($"Only {string.Join(", ", allowedExtensions)} files are allowed.");
}

// Generate a random filename; do not use client-supplied FileName
var storedFilename = $"{Guid.NewGuid():N}{fileExtension}";

// Store outside the Views directory to prevent Razor runtime compilation
var uploadsDirectory = Path.Combine(_env.ContentRootPath, "private", "EmailTemplates");
Directory.CreateDirectory(uploadsDirectory);

var destinationPath = Path.Combine(uploadsDirectory, storedFilename);
```

Then update the response to return the server-generated filename:
```csharp
return Ok(new { stored = storedFilename });
```

## Explanation

The fix eliminates the vulnerability in three steps. First, it validates the file extension against an allowlist of permitted types (in this case, `.cshtml`, since these are email templates). This prevents uploads of executables or dangerous file types. Second, it generates a random filename using `Guid.NewGuid():N` and appends only the validated extension, preventing path traversal attacks (sequences like `../` in the original `FileName` are discarded). Third, it stores the file outside the Views directory—in a `private/EmailTemplates` folder under the content root—so that even if a `.cshtml` file is uploaded, it will not be compiled and executed by Razor's runtime compilation. The stored filename is returned to the caller so they have a reference to what was written; the original client-supplied name is never used for storage or retrieval.

## Behaviour changes

- **Stored path changes from Views directory to private directory**: The application must be updated to serve email templates from the new location via a controller action that reads from `private/EmailTemplates` and streams the file back. This is a required change to prevent code execution; Razor runtime compilation is the danger, not a feature to preserve.
- **Filename changes from user-supplied to server-generated**: The client receives a server-generated filename (a GUID with .cshtml extension) instead of the original filename. This is necessary to prevent traversal and to remove the attacker's control over the storage path. Any application code that later retrieves templates must use the returned filename or a database lookup, not the original client-supplied name.
- **Extension allowlist is enforced**: Only `.cshtml` files are accepted; other file types return a 400 Bad Request. This closes the file-type validation gap.
- **Return value change**: The response now returns `stored` as the server-generated filename instead of `file.FileName`. Calling code must update to use this new name when referring to the uploaded template.

No changes to existing sink contract: `FileStream` is still used with `FileMode.Create`, request size limits are unchanged, and the async copy pattern is preserved.
