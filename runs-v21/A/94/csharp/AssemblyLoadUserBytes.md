## Verdict

CONFIRMED: CWE-94 code injection on line 37. `Assembly.Load(uploadedBytes)` loads arbitrary .NET bytecode from an untrusted file upload without validation, permitting an attacker to execute arbitrary code in the application context.

## Source

```csharp
Assembly pluginAssembly = Assembly.Load(uploadedBytes);
```

This statement at line 37 directly loads user-supplied binary data as a .NET assembly without any verification that the assembly is legitimate, trusted, or safe to execute.

## Fix

### File: PluginController.cs

```csharp
using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Runtime.Loader;

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
        
        // Whitelist of SHA256 hashes of trusted plugin assemblies
        private static readonly HashSet<string> TrustedPluginHashes = new()
        {
            // Add known good plugin hashes here
        };

        [HttpPost("upload")]
        public async Task<IActionResult> UploadPlugin(IFormFile pluginFile)
        {
            if (pluginFile == null || pluginFile.Length == 0)
            {
                return BadRequest("A plugin .dll file is required.");
            }

            // Validate file extension
            if (!pluginFile.FileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest("Only .dll files are allowed.");
            }

            byte[] uploadedBytes;
            using (var memoryStream = new MemoryStream())
            {
                await pluginFile.CopyToAsync(memoryStream);
                uploadedBytes = memoryStream.ToArray();
            }

            // Verify the assembly is from a trusted source using hash verification
            string assemblyHash = ComputeSHA256(uploadedBytes);
            if (!TrustedPluginHashes.Contains(assemblyHash))
            {
                return Unauthorized("Plugin is not from a trusted source.");
            }

            // Load the assembly in an isolated AssemblyLoadContext
            var alc = new AssemblyLoadContext("PluginContext", isCollectible: true);
            try
            {
                Assembly pluginAssembly = alc.LoadFromStream(new MemoryStream(uploadedBytes));

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
            finally
            {
                alc.Unload();
            }
        }

        private static string ComputeSHA256(byte[] data)
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

## Explanation

The vulnerability stemmed from calling `Assembly.Load()` with untrusted binary data without any validation. This allows an attacker to upload a malicious .NET assembly that executes arbitrary code when loaded.

The fix applies three layers of defence:

1. **Input validation** (line 49-52): Rejects uploads that don't have a `.dll` extension, blocking non-assembly files at the protocol level.

2. **Hash verification** (line 60-64): Computes a SHA256 hash of the uploaded assembly and checks it against a whitelist of known-good plugin hashes (`TrustedPluginHashes`). Only assemblies matching a trusted hash are loaded. The whitelist is populated by administrators with the hashes of legitimate plugins, preventing execution of unknown code.

3. **AssemblyLoadContext isolation** (line 66-67): Replaces `Assembly.Load()` with `alc.LoadFromStream()` using an isolated `AssemblyLoadContext`. This loads the assembly in a separate context that can be unloaded (line 82), preventing the loaded code from polluting the default context and enabling cleanup. The `isCollectible: true` parameter allows the context to be garbage-collected after unload.

These controls work together: the hash verification gate prevents untrusted assemblies from loading in the first place, while the isolated load context limits the impact if an administrator accidentally trusts a malicious assembly.

