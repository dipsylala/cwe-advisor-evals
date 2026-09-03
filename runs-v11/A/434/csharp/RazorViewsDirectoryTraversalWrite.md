## Verdict
VULNERABLE

## Source
Line 40 uses `file.FileName` directly in `Path.Combine()` without validation. An attacker can exploit two attack vectors:

1. **Path Traversal**: An uploaded filename like `../../../dangerous.cshtml` can traverse outside the intended `ViewsRootPath` directory.
2. **Dangerous File Type**: Any file extension is accepted, including executable types. Since `AddRazorRuntimeCompilation()` is enabled, `.cshtml` files are compiled and executed server-side.

The combination creates arbitrary code execution: an attacker uploads a path-traversed `.cshtml` file to an arbitrary location in the Views tree, where Razor compiles and executes it on the next matching request.

## Fix
```csharp
[HttpPost("upload")]
[RequestSizeLimit(1_000_000)]
public async Task<IActionResult> UploadTemplate(IFormFile file)
{
    if (file == null || file.Length == 0)
    {
        return BadRequest("No file uploaded.");
    }

    // Validate filename: extract name only, reject path traversal, allow only .cshtml
    var fileName = Path.GetFileName(file.FileName);
    if (string.IsNullOrWhiteSpace(fileName) || fileName != file.FileName)
    {
        return BadRequest("Invalid filename: path traversal detected.");
    }

    if (!fileName.EndsWith(".cshtml", StringComparison.OrdinalIgnoreCase))
    {
        return BadRequest("Only .cshtml files are allowed.");
    }

    // Further restrict the filename to alphanumeric, underscore, hyphen, and .cshtml
    if (!System.Text.RegularExpressions.Regex.IsMatch(fileName, @"^[a-zA-Z0-9_-]+\.cshtml$", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
    {
        return BadRequest("Filename contains invalid characters.");
    }

    var viewsRootPath = Path.Combine(_env.ContentRootPath, "Views", "EmailTemplates");
    Directory.CreateDirectory(viewsRootPath);

    var destinationPath = Path.Combine(viewsRootPath, fileName);

    using (var stream = new FileStream(destinationPath, FileMode.Create))
    {
        await file.CopyToAsync(stream);
    }

    return Ok(new { stored = fileName });
}
```

## Explanation
The fix implements three layers of validation:

1. **Extract filename only**: `Path.GetFileName()` strips any directory components. Comparing the result against the original `file.FileName` confirms no traversal sequences were present.

2. **Whitelist file extension**: Only `.cshtml` is accepted, rejecting executable types like `.exe`, `.dll`, or other dangerous extensions.

3. **Restrict character set**: A regex limits the filename to alphanumeric characters, underscores, and hyphens before the `.cshtml` extension. This prevents special characters (e.g., `..`, `/`, `\`, `;`) that could be reinterpreted by the filesystem or Razor engine.

These checks ensure the uploaded file:
- Stays within the intended `EmailTemplates` directory
- Is a safe template type (`.cshtml`)
- Has a predictable, safe name structure

The `StringComparison.OrdinalIgnoreCase` ensures the extension check is case-insensitive while the regex is also case-insensitive for flexibility.
