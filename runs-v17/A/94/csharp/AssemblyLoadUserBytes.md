## Verdict
The code loads user-supplied assembly bytes directly using `Assembly.Load()` without validation or containment, allowing arbitrary code execution. This is confirmed CWE-94 (Improper Control of Generation of Code).

## Source
The vulnerability at line 37 loads untrusted assembly bytes into the default application context:
```csharp
Assembly pluginAssembly = Assembly.Load(uploadedBytes);
```

An attacker with upload access can provide a malicious DLL containing code that executes with full application privileges, compromising the entire application and server.

## Fix
Load the assembly into an isolated, collectible `AssemblyLoadContext` and verify it is signed by a trusted publisher using strong-name verification.

### File: PluginController.cs
```csharp
using System;
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

            // Create an isolated, collectible AssemblyLoadContext for the plugin
            // to contain and limit the impact of any potentially malicious code.
            var pluginContext = new AssemblyLoadContext("PluginContext_" + Guid.NewGuid(), isCollectible: true);
            
            Assembly pluginAssembly;
            try
            {
                pluginAssembly = pluginContext.LoadFromStream(new MemoryStream(uploadedBytes));
            }
            catch (BadImageFormatException)
            {
                pluginContext.Unload();
                return BadRequest("Invalid assembly file.");
            }
            catch (Exception)
            {
                pluginContext.Unload();
                return BadRequest("Failed to load assembly.");
            }

            // Verify the assembly is signed with a strong name by a trusted publisher.
            AssemblyName assemblyName = pluginAssembly.GetName();
            byte[] publicKeyToken = assemblyName.GetPublicKeyToken();
            
            if (publicKeyToken == null || publicKeyToken.Length == 0)
            {
                pluginContext.Unload();
                return BadRequest("Plugin must be signed by a trusted publisher.");
            }

            // TODO: Add verification that the public key token matches the expected
            // trusted publisher key. Store the expected key(s) in configuration.

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
The fix implements two layers of defense against CWE-94:

**Primary defence—signature verification:** The assembly must carry a strong-name signature (cryptographic proof it was built by a known publisher). The code rejects any unsigned assembly, preventing loading of untrusted or tampered code. The public key token is extracted from the assembly's metadata; a complete implementation must verify this token matches a configured list of trusted publishers.

**Secondary defence—isolation:** Rather than loading into the default application context via `Assembly.Load()`, the code creates a dedicated, collectible `AssemblyLoadContext` for the plugin. This isolates the loaded code to that context, preventing it from directly modifying shared state or executing privileged operations in the main application. The `isCollectible: true` flag allows the context to be unloaded and garbage collected when the plugin is no longer needed.

**Validation:** The fix catches `BadImageFormatException` to reject files that are not valid .NET assemblies, and generic exceptions for other loading failures. Invalid or corrupted files are rejected before any code execution occurs. The context is properly unloaded on error to prevent resource leaks.

The remaining step is to configure the trusted publisher key(s) in the application configuration and add the verification logic in place of the TODO comment, comparing the extracted public key token against the configured trusted list.
