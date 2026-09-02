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

            // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
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
    }
}
