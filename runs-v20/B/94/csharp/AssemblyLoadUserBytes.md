## Verdict

- **CWE**: CWE-94 (Improper Control of Generation of Code ('Code Injection'))
- **Verdict**: exploitable
- **Confidence**: high
- **Location**: `PluginController.cs:37`, `Assembly.Load(uploadedBytes)`

## Source

- **Source**: `pluginFile` (`IFormFile`), the body of an unauthenticated-in-code `POST api/plugins/upload` multipart request. The bytes are copied verbatim into `uploadedBytes` (lines 29-34) with no size limit, format check, or provenance check.
- **Sink**: `Assembly.Load(uploadedBytes)` (line 37), immediately followed by `GetExportedTypes()` and `entryPoint.Invoke(null, null)` (lines 39-48), which reflectively calls a public static `Initialize()` method on the first exported type that has one. `Assembly.Load()` is named directly as a CWE-94 taint sink for C# in the loaded language guidance ("Never pass user input to `CSharpCompilation.Create()` or `Assembly.Load()` with user-generated code").
- **Path**: uploaded bytes flow unmodified from the HTTP request body to `Assembly.Load`, and the loaded assembly's own code then runs via reflection with no restriction on what that code may do - full CLR access to the process (file system, network, environment variables, other loaded assemblies). There is no validation, signature check, or allowlist between source and sink, so the path is live.
- **Sink contract**:
  - *Returns*: an `Assembly` handle used to enumerate exported types and locate methods.
  - *Discards*: nothing from `Assembly.Load` itself; the loop discards every exported type that lacks the `Initialize` entry point.
  - *Arguments left implicit*: `Assembly.Load(byte[])` has no overload parameter for validation, signing, or an isolated load context - the single-argument overload always loads into the current `AssemblyLoadContext.Default`, i.e. the calling process, with the calling process's full permissions.
  - *Failure behaviour*: throws `BadImageFormatException` for a non-.NET-assembly payload, propagating as an unhandled exception (500) under the existing code; this is unchanged by the fix below.

## Fix

No third-party library is required; the fix uses only the .NET base class library and the ASP.NET Core configuration abstraction already available to any ASP.NET Core project.

### File: PluginController.cs

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

        private readonly IConfiguration _configuration;

        public PluginController(IConfiguration configuration)
        {
            _configuration = configuration;
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

            // Assembly.Load executes arbitrary code the moment its types are used, so the
            // uploaded bytes must be verified against a server-controlled allowlist of
            // already-approved plugin builds before they ever reach it. The allowlist is
            // populated out-of-band (deployment configuration/secret store), never through
            // this endpoint, so an attacker who can reach this upload cannot add their own
            // payload's hash to it.
            string uploadedHash = Convert.ToHexString(SHA256.HashData(uploadedBytes));
            if (!GetTrustedPluginHashes().Contains(uploadedHash))
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                    $"Plugin rejected: hash {uploadedHash} is not in the trusted plugin registry.");
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

        // Reads the set of SHA-256 hashes (hex, case-insensitive) of plugin builds an
        // administrator has already reviewed and approved. Backed by configuration
        // (e.g. appsettings, a mounted secret, or a key vault reference) rather than
        // anything derived from the request, so it cannot be influenced by the upload.
        private HashSet<string> GetTrustedPluginHashes()
        {
            string[] configuredHashes = _configuration.GetSection("TrustedPlugins:Sha256Hashes").Get<string[]>()
                ?? Array.Empty<string>();
            return new HashSet<string>(configuredHashes.Select(hash => hash.Trim().ToUpperInvariant()), StringComparer.Ordinal);
        }
    }
}
```

## Explanation

The weakness is not the reflective invocation by itself but that `Assembly.Load` will load and run *any* bytes an unauthenticated-in-code caller uploads - the loaded guidance names `Assembly.Load()` directly as a code-injection sink and states the only sound alternative to strict isolation is to keep untrusted bytes from ever reaching it. Because this endpoint's entire purpose is to load a compiled assembly (there is no expression or template to swap for a lookup table), the fix applies the guidance's allowlist pattern to the artifact's provenance instead of to a syntax string: the uploaded bytes are hashed with SHA-256 and compared against a fixed set of hashes an administrator has already approved through a separate, out-of-band channel (configuration/secret store), and only a byte-for-byte match is passed on to `Assembly.Load`. This closes the injection because the check happens before the sink and the trusted set cannot be written to through this endpoint - an attacker can upload anything, but unless its exact hash was already placed in the trusted registry by someone with deployment access, `Assembly.Load` is never reached, so the "code" that ends up executing is always a build the organization itself vetted rather than attacker-supplied content.

## Behaviour changes

- Adds a constructor taking `IConfiguration` (assumption: the host is a standard ASP.NET Core application - either the net8.0 minimal-hosting `WebApplication.CreateBuilder(args).Build()` pattern or a classic `Startup`-based one - both of which register `IConfiguration` in the DI container by default, so no additional startup wiring is required).
- New behaviour, not present before: an upload whose SHA-256 hash is not in `TrustedPlugins:Sha256Hashes` now returns `403 Forbidden` instead of being loaded. This is intentional and is the control that closes the weakness - previously *any* uploaded assembly was loaded and executed; after the fix only pre-approved builds are. Operationally this means an admin must register a new plugin's hash in configuration before it can be uploaded and used; a plugin uploaded without that step will be rejected where it previously would have run.
- Everything downstream of `Assembly.Load` (the exported-type scan, the `Initialize()` lookup and invocation, the `Ok`/`UnprocessableEntity` responses) is unchanged, so the sink's existing return/discard/failure contract is preserved for any upload that passes the new check.
- **Verification**: the fixed file was placed into a scratch ASP.NET Core Web API project (`dotnet new webapi`, target framework net10.0, `Microsoft.AspNetCore.App` shared framework only, no added packages) and built with `dotnet build`. Build succeeded with 0 errors (2 pre-existing-pattern nullable-reference warnings from the scratch project's own `<Nullable>enable</Nullable>` setting, unrelated to the fix). This confirms `SHA256.HashData(byte[])`, `Convert.ToHexString(byte[])`, and `IConfigurationSection.Get<string[]>()` all resolve against the base class library and the ASP.NET Core shared framework with no new NuGet dependency.
- **Assumptions**: the trusted-hash allowlist is assumed to be populated and maintained outside this controller (deployment configuration, a mounted secret, or a key vault reference) - no such mechanism existed in the original file, so this is a new but minimal piece of infrastructure the fix depends on; without at least one entry configured, the endpoint will reject every upload, which is the fail-closed behaviour intended for a control point that previously had no gate at all.
