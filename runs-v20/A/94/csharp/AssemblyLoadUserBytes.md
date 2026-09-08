## Verdict

Confirmed. `UploadPlugin` reads the raw bytes of an attacker-supplied file upload and passes them directly to `Assembly.Load(byte[])`, then reflects over every exported type and invokes any public static `Initialize()` method it finds, with zero verification that the bytes came from a trusted source. Any caller who can reach `POST /api/plugins/upload` can submit a .NET assembly containing arbitrary code and have the host execute it in-process - full remote code execution via Improper Control of Generation of Code.

## Source

The taint source is the HTTP request body: `IFormFile pluginFile` in `UploadPlugin(IFormFile pluginFile)`, read into `uploadedBytes` via `pluginFile.CopyToAsync(memoryStream)` / `memoryStream.ToArray()`. Those bytes flow unmodified and unvalidated into `Assembly.Load(uploadedBytes)` at line 37 (the sink), and the resulting `Assembly` is then reflected over and its discovered entry point is invoked (`entryPoint.Invoke(null, null)`), so the injected code runs immediately with no isolation.

## Fix

### File: PluginController.cs

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

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

        // SHA-256 hashes (lowercase hex, as produced by Convert.ToHexString)
        // of plugin assemblies an administrator has already reviewed and
        // approved out-of-band. Populated from configuration
        // ("Plugins:ApprovedSha256Hashes"), which an administrator manages
        // separately from this upload endpoint. Only bytes whose hash is in
        // this set are ever loaded or executed; an upload is just a
        // transport for a build an administrator already vetted, not a way
        // to introduce new code on its own.
        private readonly HashSet<string> _approvedPluginHashes;

        public PluginController(IConfiguration configuration)
        {
            _approvedPluginHashes = new HashSet<string>(
                configuration.GetSection("Plugins:ApprovedSha256Hashes").Get<string[]>() ?? Array.Empty<string>(),
                StringComparer.OrdinalIgnoreCase);
        }

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

            // Reject anything that isn't a byte-for-byte match with a
            // previously reviewed and approved plugin build. This is what
            // stops an uploaded file from being able to run arbitrary code
            // just because it was posted to this endpoint: an attacker can
            // still upload any bytes they like, but only a hash an
            // administrator already approved is ever loaded.
            string uploadedHash = Convert.ToHexString(SHA256.HashData(uploadedBytes));
            if (!_approvedPluginHashes.Contains(uploadedHash))
            {
                return UnprocessableEntity("This plugin build has not been approved for loading.");
            }

            // Load into a dedicated, collectible AssemblyLoadContext rather
            // than the default load context, and unload it once the entry
            // point has run. This keeps an approved plugin's types and any
            // resources it allocates isolated per-request instead of
            // permanently resident in (and able to interfere with) the
            // host's default context.
            var loadContext = new AssemblyLoadContext($"plugin-{uploadedHash}", isCollectible: true);
            try
            {
                Assembly pluginAssembly;
                using (var assemblyStream = new MemoryStream(uploadedBytes))
                {
                    pluginAssembly = loadContext.LoadFromStream(assemblyStream);
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
            finally
            {
                loadContext.Unload();
            }
        }
    }
}
```

## Explanation

`Assembly.Load(byte[])` will happily load and run any well-formed .NET assembly, so the only thing that made the original endpoint safe or unsafe was whether the bytes reaching it could be trusted - and they could not, since they came straight from the request body. Rejecting malformed input, restricting the file extension, or scanning the upload would not close this: a syntactically valid, "clean-looking" assembly can still carry an arbitrary `Initialize()` implementation, so the fix has to authenticate the *content* itself rather than filter its shape.

The fix pins acceptance to a SHA-256 allowlist populated out-of-band by an administrator (`Plugins:ApprovedSha256Hashes` in configuration), so `Assembly.Load`-equivalent behavior only ever executes a build that has already been reviewed; an attacker can still post arbitrary bytes, but anything not byte-identical to an approved build is rejected before it is loaded. This is the same mechanism used to gate deployment of any other unreviewed binary, applied to the plugin path. Loading through a collectible `AssemblyLoadContext` and unloading it after the call is defense-in-depth isolation, not the primary control - it does not stop an approved-but-malicious build from running, which is why the hash check is the load-bearing check and must happen before any load or reflection occurs.

To verify: uploading bytes whose SHA-256 hash is not present in `Plugins:ApprovedSha256Hashes` now returns 422 without ever reaching `AssemblyLoadContext.LoadFromStream` or invoking any method from the upload; uploading a build whose hash was added to that configuration list still loads and invokes its `Initialize()` method exactly as before, so legitimate plugin delivery is unaffected once an administrator has approved the build's hash.
