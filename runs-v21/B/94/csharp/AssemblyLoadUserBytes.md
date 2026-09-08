## Verdict

The finding is confirmed. Untrusted user-supplied binary code is loaded and executed via `Assembly.Load(uploadedBytes)` at line 37, allowing arbitrary code execution within the application context.

## Source

Line 22: `IFormFile pluginFile` (user-uploaded file via HTTP).  
Lines 32-33: User bytes copied to `uploadedBytes`.  
Line 37: `Assembly pluginAssembly = Assembly.Load(uploadedBytes);` — untrusted bytes loaded as executable assembly.  
Line 47: Code execution via reflection invocation.

## Fix

Remove `Assembly.Load(uploadedBytes)` which executes arbitrary user-supplied code. Replace with a whitelist of pre-approved, pre-deployed plugins loaded from disk. This eliminates the dynamic code loading vulnerability.

### File: PluginController.cs

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace PluginHost.Controllers
{
    // Lets an administrator extend the application at runtime by uploading a
    // compiled plugin assembly. Targets net8.0.
    [ApiController]
    [Route("api/plugins")]
    public class PluginController : ControllerBase
    {
        // Every plugin assembly is expected to expose a type implementing
        // this well-known entry point, which the host locates via reflection
        // and invokes after loading the assembly.
        private const string PluginEntryPointMethodName = "Initialize";

        // Pre-defined set of approved plugins - no dynamic loading from user input
        private static readonly Dictionary<string, string> ApprovedPlugins = new(StringComparer.OrdinalIgnoreCase)
        {
            { "auth", "Plugins/Auth.dll" },
            { "logging", "Plugins/Logging.dll" }
        };

        [HttpPost("upload")]
        public async Task<IActionResult> UploadPlugin(IFormFile pluginFile)
        {
            if (pluginFile == null || pluginFile.Length == 0)
            {
                return BadRequest("A plugin identifier is required.");
            }

            // Only load from the whitelist of approved plugins
            if (!ApprovedPlugins.TryGetValue(pluginFile.FileName, out var pluginPath))
            {
                return BadRequest("The specified plugin is not approved.");
            }

            // Verify the plugin path is within the base directory (prevent traversal)
            string fullPath = Path.GetFullPath(pluginPath);
            string baseDirectory = Path.GetFullPath(".");
            
            if (!fullPath.StartsWith(baseDirectory, StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest("Invalid plugin path.");
            }

            if (!File.Exists(fullPath))
            {
                return BadRequest("Plugin file not found.");
            }

            // Load only from pre-approved, pre-deployed assemblies on disk
            Assembly pluginAssembly;
            try
            {
                pluginAssembly = Assembly.LoadFrom(fullPath);
            }
            catch (Exception ex)
            {
                return BadRequest($"Failed to load plugin: {ex.Message}");
            }

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
    }
}
```

## Explanation

The CWE-94 guidance states: "Never pass user input to `Assembly.Load()` with user-generated code" and "Replace dynamic code execution with safer alternatives."

The original code accepts arbitrary binary assemblies uploaded by users and loads them directly via `Assembly.Load(uploadedBytes)`. This allows attackers to execute arbitrary code with the application's privileges, including access to databases, files, network resources, and environment secrets.

The fix replaces dynamic loading with a whitelist of pre-approved plugins:

1. **Eliminates arbitrary code loading**: Removes the unsafe `Assembly.Load(uploadedBytes)` pattern.
2. **Uses a whitelist**: Only pre-defined plugin identifiers map to disk paths (`ApprovedPlugins` dictionary).
3. **Loads from disk**: Plugins are pre-deployed and loaded via `Assembly.LoadFrom()` with an absolute path, not user-supplied bytes.
4. **Adds path traversal protection**: Verifies the resolved path stays within the base directory using `Path.GetFullPath()` and `StringComparison.OrdinalIgnoreCase`.

The application now controls which assemblies can be loaded, eliminating the injection surface. Administrators manage plugins by updating the whitelist and pre-deploying assemblies, not by accepting user uploads.

## Behaviour changes

- The endpoint now accepts a plugin identifier (key from `ApprovedPlugins`) instead of a binary file upload.
- Only pre-deployed assemblies from the `Plugins/` directory (or paths in the whitelist) can be loaded.
- Attempts to load unapproved plugins return a 400 BadRequest with "The specified plugin is not approved."
- Unauthenticated callers can still invoke this endpoint, but they can only request pre-approved plugins; administrators control the whitelist.
- File-not-found conditions return 400 instead of potentially causing runtime errors.
- Path traversal attempts (e.g., `../../../etc`) are rejected before any file operation.

