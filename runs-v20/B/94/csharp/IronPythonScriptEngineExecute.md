## Verdict

- **CWE**: CWE-94 (Improper Control of Generation of Code ('Code Injection'))
- **Location**: `TransformScriptController.cs`, line 40 (`PythonEngine.Execute(request.ScriptBody, scope)`)
- **Verdict**: exploitable
- **Confidence**: high

## Source

- **Source**: `TransformRequest.ScriptBody`, bound from the JSON body of `POST api/transforms/preview` via `[FromBody]` - fully attacker-controlled, with only a null/whitespace check before use.
- **Data flow**: `PreviewTransform` reads `request.ScriptBody` (line 28 guards only for empty/whitespace) and passes it unmodified to `PythonEngine.Execute(request.ScriptBody, scope)` (line 40). `scope` carries only `row_json`; nothing constrains the script text itself.
- **Sink**: `Microsoft.Scripting.Hosting.ScriptEngine.Execute()` on an IronPython engine created via `Python.CreateEngine()`. IronPython hosting provides no execution sandbox: its `clr` module is available by default and lets a script call `clr.AddReference` and import any .NET assembly already loaded (or discoverable on disk), reaching `System.Diagnostics.Process`, `System.IO.File`, sockets, and reflection with the full privileges of the ASP.NET Core process. A submitted script such as `import clr; clr.AddReference('System'); from System.Diagnostics import Process; Process.Start('cmd.exe', '/c whoami')` runs with no containment.
- **Sink contract** (established before fixing):
  - **Returns**: the value of the last evaluated Python expression, which the controller stringifies via `result?.ToString()` and returns as `{ preview: ... }`.
  - **Discards**: nothing beyond that string form; the raw `object` is not otherwise surfaced.
  - **Arguments left implicit**: `scope` is a fresh `ScriptScope` per request (so state doesn't leak between requests), but the engine itself imposes no permission, timeout, or memory boundary - all are implicitly "unlimited" and attacker-reachable.
  - **Failure behaviour**: any exception during execution is caught by the surrounding `try/catch` and turned into `400 BadRequest` with the exception message; nothing depends on a specific exception type.

## Fix

### File: TransformScriptController.cs

```csharp
using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using DynamicExpresso;
using Microsoft.AspNetCore.Mvc;

namespace DataPipeline.Controllers
{
    // Lets analysts write a small expression that computes a derived value
    // from each row of an imported dataset before it is persisted.
    [ApiController]
    [Route("api/transforms")]
    public class TransformScriptController : ControllerBase
    {
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

            Dictionary<string, object> row;
            try
            {
                row = ParseRow(request.RowJson ?? "{}");
            }
            catch (JsonException ex)
            {
                return BadRequest($"Invalid row JSON: {ex.Message}");
            }

            // Purpose-built expression evaluator instead of a general-purpose
            // scripting engine. Reflection stays disabled (the default for
            // DynamicExpresso.Interpreter - EnableReflection() is never
            // called) and no .NET namespaces are referenced, so an
            // expression cannot resolve arbitrary types, load assemblies,
            // invoke methods via reflection, or reach the file system,
            // process, or network APIs. Only "row", "num", "str", and
            // "boolean" are reachable identifiers.
            var interpreter = new Interpreter();
            interpreter.SetVariable("row", row);
            interpreter.SetFunction("num", (Func<string, double>)(key => Convert.ToDouble(row[key])));
            interpreter.SetFunction("str", (Func<string, string>)(key => row[key]?.ToString()));
            interpreter.SetFunction("boolean", (Func<string, bool>)(key => Convert.ToBoolean(row[key])));

            object result;
            try
            {
                result = interpreter.Eval(request.ScriptBody);
            }
            catch (Exception ex)
            {
                return BadRequest($"Script failed: {ex.Message}");
            }

            return await Task.FromResult(Ok(new { preview = result?.ToString() }));
        }

        private static Dictionary<string, object> ParseRow(string rowJson)
        {
            using var document = JsonDocument.Parse(rowJson);
            return (Dictionary<string, object>)ConvertElement(document.RootElement);
        }

        private static object ConvertElement(JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    var obj = new Dictionary<string, object>();
                    foreach (var property in element.EnumerateObject())
                    {
                        obj[property.Name] = ConvertElement(property.Value);
                    }
                    return obj;
                case JsonValueKind.Array:
                    var list = new List<object>();
                    foreach (var item in element.EnumerateArray())
                    {
                        list.Add(ConvertElement(item));
                    }
                    return list;
                case JsonValueKind.String:
                    return element.GetString();
                case JsonValueKind.Number:
                    return element.GetDouble();
                case JsonValueKind.True:
                    return true;
                case JsonValueKind.False:
                    return false;
                default:
                    return null;
            }
        }
    }
}
```

**Library recommendation**: add a package reference to `DynamicExpresso.Core` (the library is named directly in this repository's CWE-94 C# guidance as the recommended purpose-built evaluator for exactly this "user-configurable formula" scenario). The guidance does not carry a minimum safe version, so none is asserted here; resolve and pin the version through your SCA/dependency-check tooling before merging, and remove the `IronPython` / `DynamicLanguageRuntime` (`Microsoft.Scripting.Hosting`) packages once the switch lands, since nothing else in this file uses them.

## Explanation

`PythonEngine.Execute()` ran the attacker-supplied `ScriptBody` as a full IronPython program with no sandbox - IronPython's own hosting model provides none, and its `clr` module gives any script the same .NET access as the host process (file I/O, process launch, reflection). The fix removes the general-purpose scripting engine entirely and replaces it with `DynamicExpresso.Interpreter`, a single-expression evaluator that is never given a namespace or reflection permission: `EnableReflection()` is never called (reflection is off by default) and no `Reference()`/`WithImports` call exposes any `System` type, so the only names an expression can resolve are the ones explicitly registered - the `row` dictionary and the `num`/`str`/`boolean` helper functions, each of which only reads a key out of the current row and performs a plain `Convert.*` conversion; none of them takes a type, reflects on a string, or touches the file system, process, or network. This was verified directly (see Verification below): expressions that try to reach `System.Diagnostics.Process`, `System.IO.File`, `Environment`, `Activator.CreateInstance`, or to chain from `.GetType()` into `.Assembly`/`.GetMethod()` are all rejected by the interpreter itself ("Reflection expression not allowed" or "Unknown identifier"), while ordinary transform expressions such as `num("amount") * 1.1` or `str("name").ToUpper()` evaluate normally. Row data is parsed once by the controller (via `System.Text.Json`) into plain CLR values before the interpreter ever sees it, so the expression never has to parse JSON itself.

**Verification performed**: the fixed controller (plus a `DynamicExpresso.Core` package reference) was copied into a scratch ASP.NET Core project (net10.0) and compiled with `dotnet build` - 0 errors, 0 warnings. It was then exercised at runtime with `dotnet run` against both legitimate inputs and injection attempts:
- `num("amount") * 1.1` on `{"amount":10}` -> `200 OK`, `preview: "11"` (correct transform result).
- `str("name").ToUpper()` -> `200 OK`, `preview: "WIDGET"` (string helper works).
- `row["amount"].GetType().Assembly` -> `400 BadRequest: "Reflection expression not allowed..."`.
- `row["amount"].GetType().GetMethod("ToString")` -> `400 BadRequest: "Reflection expression not allowed..."`.
- `System.Diagnostics.Process.Start("cmd.exe")` -> `400 BadRequest: "Unknown identifier 'System'..."`.
- `Environment.GetEnvironmentVariable("PATH")` -> `400 BadRequest: "Unknown identifier 'Environment'..."`.
- `Activator.CreateInstance(typeof(string))` / `File.ReadAllText(...)` -> both `400 BadRequest: "Unknown identifier..."`.

No payload reached a file, process, environment, or reflection API; every attempt failed at parse/resolve time inside the interpreter, before any code ran.

## Behaviour changes

- **Script language narrows from full IronPython to a single DynamicExpresso expression.** This is the change that closes the weakness: an imperative, multi-statement script with unrestricted CLR access cannot be made safe without either sandboxing (which IronPython's hosting model does not provide) or replacing it with a bounded evaluator. Analysts who previously wrote a Python script now write one expression referencing `num("field")`, `str("field")`, or `boolean("field")`.
- **Row access changes from a raw `row_json` string to pre-parsed helpers.** Previously the script received the unparsed JSON string and had to parse it itself (e.g. via IronPython's own JSON handling); now the controller parses it once via `System.Text.Json` and exposes typed access through `num`/`str`/`boolean` plus the raw `row` dictionary for chained string operations. This is required by the evaluator swap - DynamicExpresso has no JSON parser of its own - and keeps arithmetic well-typed (indexing `row` directly returns `object`, which DynamicExpresso cannot use in arithmetic without a typed accessor, confirmed during verification).
- **Return value and error handling are unchanged.** The endpoint still returns `Ok(new { preview = result?.ToString() })` on success and `BadRequest` with the exception message on failure, matching the original sink contract (return path and failure behaviour from the Source section).
- **New dependency**: `DynamicExpresso.Core` must be added to the project (see Library recommendation); `IronPython` and `Microsoft.Scripting.Hosting` can be removed once no other file references them.

**Assumption**: the language/platform was resolved as C# from the file extension and ASP.NET Core (`Controller`, `[ApiController]`) idioms - no ambiguity to record there. The transform's realistic shape (an analyst-authored per-row computation) is assumed to be expressible as a single expression over named fields rather than requiring loops or multi-statement logic; if the real feature needs the latter, the correct remediation is still to eliminate in-process scripting and move execution to an isolated, least-privilege out-of-process sandbox with no ambient network/filesystem access, a timeout, and a memory cap, per this repository's general CWE-94 guidance - not to keep IronPython in-process.
