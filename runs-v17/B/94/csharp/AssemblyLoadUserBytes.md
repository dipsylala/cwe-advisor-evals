## Verdict

Exploitable - untrusted bytecode from HTTP file upload is loaded directly via `Assembly.Load()` without validation, allowing arbitrary code execution.

## Source

`IFormFile pluginFile` parameter at line 22: HTTP POST form upload containing attacker-supplied .NET assembly binary.

## Fix

The complete remediated file:

### File: PluginController.cs

```csharp
using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Collections.Generic;
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

        // Trusted plugin hashes (SHA256) - only these assemblies are allowed to load.
        // Add verified plugin hashes here during deployment/configuration.
        private static readonly HashSet<string> TrustedPluginHashes = new HashSet<string>
        {
            // Example trusted plugin hash (developer must populate with actual approved plugins)
            // "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        };

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

            // Validate the assembly against the trusted allowlist before loading.
            // Compute SHA256 hash and verify it is in the approved set.
            string assemblyHash = ComputeSHA256Hash(uploadedBytes);
            if (!TrustedPluginHashes.Contains(assemblyHash))
            {
                return Unauthorized("This plugin assembly is not in the trusted allowlist.");
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

## Explanation

The vulnerability exists because `Assembly.Load(uploadedBytes)` executes arbitrary untrusted .NET bytecode directly from the HTTP upload without any validation. An attacker can upload a malicious assembly that runs with the application's full privileges.

The fix introduces an allowlist-based validation gate: before `Assembly.Load()` executes, the uploaded assembly is hashed using SHA256 and checked against `TrustedPluginHashes`, a static set of approved plugin identifiers. Only assemblies whose hashes match an entry in the allowlist proceed to loading. This prevents execution of unauthorized code while preserving the legitimate plugin capability.

The fix uses the standard library `System.Security.Cryptography.SHA256` and `System.Collections.Generic.HashSet`, which are already available in .NET 8.0. The developer must populate `TrustedPluginHashes` during configuration with the SHA256 digests of approved plugin assemblies, ensuring only vetted plugins can be loaded.

## Behaviour changes

The endpoint now rejects plugin uploads that do not match a trusted hash, returning HTTP 401 Unauthorized with a message "This plugin assembly is not in the trusted allowlist." Previously all assemblies were accepted. This is the intended security hardening - only approved assemblies load. The application must pre-compute and configure the SHA256 hashes of all legitimate plugins during deployment. The method signature and return types of successful uploads remain identical to the original implementation.
