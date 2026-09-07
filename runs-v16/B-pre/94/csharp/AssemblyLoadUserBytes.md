## Verdict

Exploitable. Untrusted user-supplied bytes from an HTTP file upload are loaded directly as a .NET assembly without any validation. An attacker can upload a malicious assembly containing arbitrary code and have it executed within the application process.

## Source

The vulnerable data flow begins at the `pluginFile` parameter (line 22), an `IFormFile` received from an HTTP POST request. The file content is read into a byte array `uploadedBytes` (line 33) without any validation.

## Fix

**Vulnerable code (lines 21-52):**
```csharp
[HttpPost("upload")]
public async Task<IActionResult> UploadPlugin(IFormFile pluginFile)
{
    if (pluginFile == null || pluginFile.Length == 0)
    {
        return BadRequest("A plugin .dll file is required.");
    }

    byte[] uploadedBytes;
    using (var memoryStream = new MemoryStream())
    {
        await pluginFile.CopyToAsync(memoryStream);
        uploadedBytes = memoryStream.ToArray();
    }

    // VULNERABLE: Loads untrusted bytes directly as assembly
    Assembly pluginAssembly = Assembly.Load(uploadedBytes);
    
    // ... rest of method
}
```

**Fixed code:**
```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace PluginHost.Controllers
{
    [ApiController]
    [Route("api/plugins")]
    public class PluginController : ControllerBase
    {
        private const string PluginEntryPointMethodName = "Initialize";
        private readonly IConfiguration _configuration;
        private readonly HashSet<string> _approvedPluginHashes;

        public PluginController(IConfiguration configuration)
        {
            _configuration = configuration;
            // Load approved plugin hashes from configuration (e.g., appsettings.json)
            var hashes = _configuration.GetSection("ApprovedPlugins:Hashes").Get<string[]>();
            _approvedPluginHashes = new HashSet<string>(hashes ?? Array.Empty<string>());
        }

        [HttpPost("upload")]
        public async Task<IActionResult> UploadPlugin(IFormFile pluginFile)
        {
            if (pluginFile == null || pluginFile.Length == 0)
            {
                return BadRequest("A plugin .dll file is required.");
            }

            // Enforce maximum file size to prevent resource exhaustion
            const long maxFileSize = 10 * 1024 * 1024; // 10 MB
            if (pluginFile.Length > maxFileSize)
            {
                return BadRequest("Plugin file exceeds maximum size.");
            }

            byte[] uploadedBytes;
            using (var memoryStream = new MemoryStream())
            {
                await pluginFile.CopyToAsync(memoryStream);
                uploadedBytes = memoryStream.ToArray();
            }

            // Validate uploaded assembly against allowlist before loading
            string pluginHash = ComputeSHA256Hash(uploadedBytes);
            if (!_approvedPluginHashes.Contains(pluginHash))
            {
                return Unauthorized("Plugin is not in the approved plugins list.");
            }

            Assembly pluginAssembly = Assembly.Load(uploadedBytes);

            foreach (Type candidateType in pluginAssembly.GetExportedTypes())
            {
                MethodInfo entryPoint = candidateType.GetMethod(PluginEntryPointMethodName, BindingFlags.Public | BindingFlags.Static);
                if (entryPoint == null)
                {
                    continue;
                }

                object result = entryPoint.Invoke(null, null);
                return Ok(new { loadedType = candidateType.FullName, result });
            }

            return UnprocessableEntity($"No type exporting a public static {PluginEntryPointMethodName}() method was found.");
        }

        private static string ComputeSHA256Hash(byte[] data)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(data);
                return Convert.ToHexString(hash);
            }
        }
    }
}
```

The key changes:
- Add dependency injection of `IConfiguration` to load approved plugin hashes
- Compute SHA256 hash of uploaded bytes
- Validate the hash against an allowlist before calling `Assembly.Load()`
- Add file size validation as a secondary control
- Return `Unauthorized` (403) if the plugin is not approved

## Explanation

The vulnerability exists because `Assembly.Load()` with untrusted binary input (from `uploadedBytes`) allows arbitrary code execution. The fix validates the uploaded assembly against a preconfigured allowlist of approved plugins identified by their SHA256 hash. This prevents any malicious or unapproved assembly from being loaded and executed. The allowlist is stored in configuration (e.g., `appsettings.json`) and maintained by administrators. An additional file size check prevents resource exhaustion attacks. On .NET Core/5+ (the project targets net8.0), there is no sandboxing mechanism like AppDomain isolation, so validation and allowlisting is the primary defence mechanism. The validation must occur before `Assembly.Load()` is called - accepting the hash as an allowlist prevents bypasses through cache poisoning or algorithm substitution.

## Behaviour changes

- **Requires configuration**: The application must be configured with `ApprovedPlugins:Hashes` containing SHA256 hashes of approved plugins. Example configuration in `appsettings.json`:
  ```json
  "ApprovedPlugins": {
    "Hashes": [
      "abc123def...",
      "xyz789...",
    ]
  }
  ```
- **Constructor change**: `PluginController` now requires `IConfiguration` injected via dependency injection.
- **Return status change**: Rejects unapproved plugins with `401 Unauthorized` instead of attempting to load them.
- **File size enforcement**: Adds a 10 MB limit on uploaded files to prevent resource exhaustion.
- **Performance**: Adds SHA256 hashing overhead for every upload (negligible for files under 10 MB).
- **Functional impact**: Only approved plugins can be loaded; the application must be reconfigured to enable new plugins. This is a desired security property, not a regression.
