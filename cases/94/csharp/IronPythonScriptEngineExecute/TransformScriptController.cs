using System;
using System.Threading.Tasks;
using IronPython.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Scripting.Hosting;

namespace DataPipeline.Controllers
{
    // Lets analysts upload a small Python transformation script that is run
    // against each row of an imported dataset before it is persisted.
    [ApiController]
    [Route("api/transforms")]
    public class TransformScriptController : ControllerBase
    {
        // The IronPython engine is created once and reused across requests,
        // matching Microsoft's own hosting guidance for ScriptEngine reuse.
        private static readonly ScriptEngine PythonEngine = Python.CreateEngine();

        public class TransformRequest
        {
            public string ScriptBody { get; set; }
            public string RowJson { get; set; }
        }

        [HttpPost("preview")]
        public async Task<IActionResult> PreviewTransform([FromBody] TransformRequest request)
        {
            if (string.IsNullOrWhiteSpace(request?.ScriptBody))
            {
                return BadRequest("A transformation script is required.");
            }

            ScriptScope scope = PythonEngine.CreateScope();
            scope.SetVariable("row_json", request.RowJson ?? "{}");

            object result;
            try
            {
                // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
                result = PythonEngine.Execute(request.ScriptBody, scope);
            }
            catch (Exception ex)
            {
                return BadRequest($"Script failed: {ex.Message}");
            }

            return await Task.FromResult(Ok(new { preview = result?.ToString() }));
        }
    }
}
