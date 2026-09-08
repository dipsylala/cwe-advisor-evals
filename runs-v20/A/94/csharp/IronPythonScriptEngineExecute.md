## Verdict

Confirmed. `PreviewTransform` passes `request.ScriptBody` — text taken directly from the HTTP request body — into `PythonEngine.Execute(request.ScriptBody, scope)`. IronPython's `ScriptEngine.Execute` compiles and runs the given text as Python source in-process. Any caller of `POST api/transforms/preview` can therefore submit arbitrary Python, which IronPython runs with the full trust of the ASP.NET Core host process, including unrestricted access to the CLR (`import System; System.Diagnostics.Process.Start(...)`, file I/O, sockets, environment variables, etc.) with no engine-level sandbox boundary. This is complete, unauthenticated-by-design remote code execution, not merely an unsafe eval of a data expression.

## Source

`request.ScriptBody`, a property of `TransformRequest` bound by `[FromBody]` on `PreviewTransform` — i.e. attacker-controlled data taken verbatim from the JSON request body of a public API endpoint, with only a null/whitespace check before it reaches the sink at line 40.

## Fix

### File: TransformScriptController.cs

```csharp
using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace DataPipeline.Controllers
{
    // Lets analysts customize how each row of an imported dataset is
    // transformed before it is persisted. Analysts choose from a fixed set
    // of supported field operations rather than supplying a script, so
    // there is no interpreter or compiler anywhere in the request path.
    [ApiController]
    [Route("api/transforms")]
    public class TransformScriptController : ControllerBase
    {
        private static readonly HashSet<string> SupportedOperations = new(StringComparer.OrdinalIgnoreCase)
        {
            "uppercase", "lowercase", "trim", "replace", "round", "rename", "setliteral"
        };

        public class TransformStep
        {
            public string Operation { get; set; }
            public string Field { get; set; }
            public string TargetField { get; set; }
            public string Value { get; set; }
            public string SearchValue { get; set; }
            public int? Digits { get; set; }
        }

        public class TransformRequest
        {
            public List<TransformStep> Steps { get; set; }
            public string RowJson { get; set; }
        }

        [HttpPost("preview")]
        public async Task<IActionResult> PreviewTransform([FromBody] TransformRequest request)
        {
            if (request?.Steps == null || request.Steps.Count == 0)
            {
                return BadRequest("At least one transformation step is required.");
            }

            JsonNode row;
            try
            {
                row = string.IsNullOrWhiteSpace(request.RowJson)
                    ? new JsonObject()
                    : JsonNode.Parse(request.RowJson);
            }
            catch (JsonException ex)
            {
                return BadRequest($"Row JSON is invalid: {ex.Message}");
            }

            if (row is not JsonObject rowObject)
            {
                return BadRequest("Row JSON must be a JSON object.");
            }

            foreach (var step in request.Steps)
            {
                if (string.IsNullOrWhiteSpace(step.Operation) || !SupportedOperations.Contains(step.Operation))
                {
                    return BadRequest($"Unsupported operation: {step.Operation}");
                }

                try
                {
                    ApplyStep(rowObject, step);
                }
                catch (Exception ex)
                {
                    return BadRequest($"Step failed: {ex.Message}");
                }
            }

            return await Task.FromResult(Ok(new { preview = rowObject.ToJsonString() }));
        }

        private static void ApplyStep(JsonObject row, TransformStep step)
        {
            if (string.IsNullOrWhiteSpace(step.Field))
            {
                throw new InvalidOperationException("A field name is required.");
            }

            switch (step.Operation.ToLowerInvariant())
            {
                case "uppercase":
                    row[step.Field] = JsonValue.Create(GetString(row, step.Field)?.ToUpperInvariant());
                    break;

                case "lowercase":
                    row[step.Field] = JsonValue.Create(GetString(row, step.Field)?.ToLowerInvariant());
                    break;

                case "trim":
                    row[step.Field] = JsonValue.Create(GetString(row, step.Field)?.Trim());
                    break;

                case "replace":
                    var current = GetString(row, step.Field) ?? string.Empty;
                    row[step.Field] = JsonValue.Create(current.Replace(step.SearchValue ?? string.Empty, step.Value ?? string.Empty));
                    break;

                case "round":
                    var number = row[step.Field]?.GetValue<double>() ?? 0d;
                    var digits = Math.Clamp(step.Digits ?? 0, 0, 15);
                    row[step.Field] = JsonValue.Create(Math.Round(number, digits));
                    break;

                case "rename":
                    if (string.IsNullOrWhiteSpace(step.TargetField))
                    {
                        throw new InvalidOperationException("A target field name is required for rename.");
                    }
                    var value = row[step.Field]?.DeepClone();
                    row.Remove(step.Field);
                    row[step.TargetField] = value;
                    break;

                case "setliteral":
                    row[step.Field] = JsonValue.Create(step.Value);
                    break;
            }
        }

        private static string GetString(JsonObject row, string field)
        {
            return row[field]?.GetValue<string>();
        }
    }
}
```

## Explanation

IronPython does not provide a security boundary that a hosting application can configure its way around. Once `PythonEngine.Execute` runs a string as Python, that code executes with the same CLR trust as the ASP.NET Core process itself: `import System` alone (no `clr.AddReference` needed, since core assemblies are already loaded) is enough to reach `System.Diagnostics.Process.Start`, `System.IO.File`, sockets, and environment variables. There is no supported hosting option that revokes this — restricting `sys.path`, stripping a few builtins, or blacklisting keywords narrows the surface but does not close it, because the dangerous capability is reached through ordinary, always-available CLR namespaces rather than through anything an allowlist of Python builtins controls. Wrapping the call in try/catch, running it in a fresh `ScriptScope`, or adding a timeout likewise bounds nothing that matters: the damage (process start, file write, outbound connection, secret exfiltration) happens synchronously during `Execute`, before any timeout or exception handler runs.

Given that, sandboxing the engine is not a viable fix; the fix has to stop treating request text as code. The rewrite removes IronPython and the scripting sink entirely and replaces the free-form `ScriptBody` with a `Steps` list drawn from a fixed, server-defined vocabulary of field operations (`uppercase`, `lowercase`, `trim`, `replace`, `round`, `rename`, `setliteral`). Each step names an operation from an allowlist and supplies plain data arguments (field names, literal values) — never executable text — so the request can only ever select among behaviors the server itself implements with ordinary `System.Text.Json` calls. There is no interpreter, no dynamic compilation, and no reflection-driven dispatch in the path, so there is no way for a request to introduce new behavior, let alone reach the CLR, the filesystem, or the network. This keeps the feature analysts actually need — customizing how an imported row is transformed before persistence — while making arbitrary code execution structurally impossible rather than merely harder to trigger. This is a breaking change to the request contract (`ScriptBody` is gone), which is unavoidable: any interface that accepts an executable script body from an untrusted caller is the vulnerability, not an implementation detail of it.
