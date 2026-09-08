## Verdict

- **CWE**: CWE-94 (Improper Control of Generation of Code ('Code Injection'))
- **Location**: `RuleCompilerService.cs`, `CompileAndRunRule` (compilation call at the reported line, `CSharpCompilation.Create` / `.Emit` / `Assembly.Load` / reflection invoke immediately following it)
- **Verdict**: exploitable
- **Confidence**: high

## Source

- **Source**: `ruleSourceCode`, `ruleTypeName`, and `evaluateArgs`, the parameters of `CompileAndRunRule`. The method's own comment states `ruleSourceCode` is "the raw text of the admin's submitted .cs rule file, taken verbatim from the request body" for `POST /api/admin/rules/compile`.
- **Sink**: `CSharpSyntaxTree.ParseText(ruleSourceCode)` feeds `CSharpCompilation.Create(...)`, whose output is emitted to a `MemoryStream` and loaded with `Assembly.Load(peStream.ToArray())`; `ruleTypeName` selects the type via `GetType()`/`Activator.CreateInstance()`, and `evaluateArgs` is passed straight into `evaluateMethod.Invoke(...)`.
- **Data flow**: source and sink are in the same method with no intermediate hop. Nothing between them constrains the source text, the emitted IL, or the invoked members - the submitted text becomes an arbitrary compiled-and-executed .NET type in this process, with the constructor's `_references` narrowing only what the *compiler* can resolve (`System.Private.CoreLib`, `System.Runtime`, `netstandard`), not what a successfully-compiled rule can do once it is JIT-executed. That reference set alone still exposes `System.IO.File`, `System.IO.Directory`, and `System.Environment` (all resolvable through `System.Private.CoreLib`), so the restriction does not prevent file access, only foreign-assembly APIs. "Admin-facing" does not change the trust boundary: the admin's browser session, not the admin's judgment, is what the endpoint actually trusts, and the same code path executes whatever text arrives, however it got there (compromised admin session, CSRF, an internal proxy, etc). This is a genuine, unconstrained code-injection sink with no isolation - per Roslyn's own maintainers, no in-process sandbox exists for this on modern .NET; the only reliable isolation is a separate OS process with reduced privileges.

## Fix

### File: RuleCompilerService.cs

```csharp
using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace InternalTooling.Rules
{
    // Admin-facing endpoint (POST /api/admin/rules/compile) lets an operator paste a small
    // C# "rule" class that gets compiled and executed on demand, e.g. to prototype a new
    // pricing or eligibility check before it is promoted to a checked-in assembly.
    //
    // Compilation and execution of the submitted source never happen in this process: Roslyn
    // has no in-process sandbox (restricted AppDomains and Code Access Security do not exist
    // on modern .NET), so the only reliable isolation is a separate OS process with reduced
    // privileges. This class only prepares the request, launches that process, enforces a
    // hard timeout, and relays the result - it never calls CSharpCompilation.Create() or
    // Assembly.Load() itself.
    public class RuleCompilerService
    {
        private readonly string _sandboxWorkerAssemblyPath;
        private readonly TimeSpan _executionTimeout;

        public RuleCompilerService(string sandboxWorkerAssemblyPath = "RuleSandboxRunner.dll", TimeSpan? executionTimeout = null)
        {
            _sandboxWorkerAssemblyPath = sandboxWorkerAssemblyPath;
            _executionTimeout = executionTimeout ?? TimeSpan.FromSeconds(5);
        }

        // ruleSourceCode is the raw text of the admin's submitted .cs rule file, taken
        // verbatim from the request body.
        public object CompileAndRunRule(string ruleSourceCode, string ruleTypeName, object[] evaluateArgs)
        {
            var request = new SandboxRequest
            {
                RuleSourceCode = ruleSourceCode,
                RuleTypeName = ruleTypeName,
                EvaluateArgsJson = evaluateArgs == null
                    ? null
                    : Array.ConvertAll(evaluateArgs, arg => JsonSerializer.Serialize(arg))
            };

            var startInfo = new ProcessStartInfo
            {
                FileName = "dotnet",
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetTempPath()
            };
            startInfo.ArgumentList.Add(_sandboxWorkerAssemblyPath);
            // Drop every inherited environment variable so the sandboxed rule cannot read
            // ambient secrets (connection strings, API keys, cloud credentials) that this
            // process holds - the worker gets nothing beyond what .NET itself requires.
            startInfo.EnvironmentVariables.Clear();

            using var worker = new Process { StartInfo = startInfo };
            worker.Start();

            worker.StandardInput.Write(JsonSerializer.Serialize(request));
            worker.StandardInput.Close();

            Task<string> stdoutTask = worker.StandardOutput.ReadToEndAsync();
            Task<string> stderrTask = worker.StandardError.ReadToEndAsync();

            if (!worker.WaitForExit((int)_executionTimeout.TotalMilliseconds))
            {
                worker.Kill(entireProcessTree: true);
                throw new TimeoutException($"Rule '{ruleTypeName}' did not complete within {_executionTimeout}.");
            }

            string stdout = stdoutTask.GetAwaiter().GetResult();
            string stderr = stderrTask.GetAwaiter().GetResult();

            if (worker.ExitCode != 0 || string.IsNullOrWhiteSpace(stdout))
            {
                throw new InvalidOperationException($"Rule sandbox failed (exit {worker.ExitCode}): {stderr}");
            }

            var response = JsonSerializer.Deserialize<SandboxResponse>(stdout)
                ?? throw new InvalidOperationException("Rule sandbox returned no result.");

            if (!response.Success)
            {
                throw new InvalidOperationException(response.Error ?? "Rule sandbox reported an unspecified failure.");
            }

            return response.Result;
        }

        private sealed class SandboxRequest
        {
            public string RuleSourceCode { get; set; }
            public string RuleTypeName { get; set; }
            public string[] EvaluateArgsJson { get; set; }
        }

        private sealed class SandboxResponse
        {
            public bool Success { get; set; }
            public JsonElement? Result { get; set; }
            public string Error { get; set; }
        }
    }
}
```

### File: RuleSandboxRunner/Program.cs

```csharp
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Emit;

namespace InternalTooling.Rules.Sandbox
{
    // Runs inside a dedicated, least-privileged OS process launched by RuleCompilerService.
    // This process - not the admin-facing web process - is where CSharpCompilation.Create()
    // and Assembly.Load() actually run on the admin-submitted source, so a rule that reaches
    // File, Process, or network APIs only has whatever access this worker's OS account is
    // granted. Deploy it under an account with no network egress and no credentials beyond
    // what compiling a rule needs, and cap its memory with a Windows Job Object or a Linux
    // cgroup - .NET has no in-process, cross-platform way to enforce either.
    internal static class Program
    {
        private static int Main()
        {
            string requestJson = Console.In.ReadToEnd();
            var response = new SandboxResponse();

            try
            {
                var request = JsonSerializer.Deserialize<SandboxRequest>(requestJson)
                    ?? throw new InvalidOperationException("Empty sandbox request.");

                object result = CompileAndRun(request);
                response.Success = true;
                response.Result = JsonSerializer.SerializeToElement(result);
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Error = ex.Message;
            }

            Console.Out.Write(JsonSerializer.Serialize(response));
            return 0;
        }

        private static object CompileAndRun(SandboxRequest request)
        {
            // Only the BCL assemblies the rule shape needs to resolve against.
            var trustedAssemblyNames = new[] { "System.Private.CoreLib", "System.Runtime", "netstandard" };
            MetadataReference[] references = AppDomain.CurrentDomain.GetAssemblies()
                .Where(a => trustedAssemblyNames.Contains(a.GetName().Name))
                .Select(a => (MetadataReference)MetadataReference.CreateFromFile(a.Location))
                .ToArray();

            SyntaxTree syntaxTree = CSharpSyntaxTree.ParseText(request.RuleSourceCode);
            var options = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary);

            CSharpCompilation compilation = CSharpCompilation.Create(
                assemblyName: $"AdminRule_{Guid.NewGuid():N}",
                syntaxTrees: new[] { syntaxTree },
                references: references,
                options: options);

            using var peStream = new MemoryStream();
            EmitResult emitResult = compilation.Emit(peStream);
            if (!emitResult.Success)
            {
                var diagnostics = string.Join(Environment.NewLine, emitResult.Diagnostics.Select(d => d.ToString()));
                throw new InvalidOperationException($"Rule failed to compile:{Environment.NewLine}{diagnostics}");
            }

            Assembly ruleAssembly = Assembly.Load(peStream.ToArray());

            Type ruleType = ruleAssembly.GetType(request.RuleTypeName)
                ?? throw new InvalidOperationException($"Rule type '{request.RuleTypeName}' not found in compiled assembly.");
            object ruleInstance = Activator.CreateInstance(ruleType)
                ?? throw new InvalidOperationException($"Could not instantiate '{request.RuleTypeName}'.");
            MethodInfo evaluateMethod = ruleType.GetMethod("Evaluate")
                ?? throw new InvalidOperationException($"Rule type '{request.RuleTypeName}' has no 'Evaluate' method.");

            object[] evaluateArgs = null;
            if (request.EvaluateArgsJson != null)
            {
                ParameterInfo[] parameters = evaluateMethod.GetParameters();
                evaluateArgs = new object[request.EvaluateArgsJson.Length];
                for (int i = 0; i < request.EvaluateArgsJson.Length; i++)
                {
                    Type targetType = i < parameters.Length ? parameters[i].ParameterType : typeof(object);
                    evaluateArgs[i] = JsonSerializer.Deserialize(request.EvaluateArgsJson[i], targetType);
                }
            }

            return evaluateMethod.Invoke(ruleInstance, evaluateArgs);
        }

        private sealed class SandboxRequest
        {
            public string RuleSourceCode { get; set; }
            public string RuleTypeName { get; set; }
            public string[] EvaluateArgsJson { get; set; }
        }

        private sealed class SandboxResponse
        {
            public bool Success { get; set; }
            public JsonElement? Result { get; set; }
            public string Error { get; set; }
        }
    }
}
```

### File: RuleSandboxRunner/RuleSandboxRunner.csproj

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>disable</Nullable>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.CodeAnalysis.CSharp" Version="4.8.0" />
  </ItemGroup>

</Project>
```

## Explanation

The weakness is not "the wrong compilation call" - it is that admin-submitted source is compiled and executed with the same privileges, filesystem access, and (previously) BCL surface as the host process, and no Roslyn API sandboxes that execution. The fix does not try to make `CSharpCompilation`/`Assembly.Load` "safe" in place, because they cannot be: it moves the entire compile-load-invoke sequence out of `RuleCompilerService` (which no longer references `Microsoft.CodeAnalysis` at all) and into `RuleSandboxRunner`, a separate executable launched as its own OS process for every call. `RuleCompilerService` now only serializes the request, starts that process with its environment variables cleared (so it cannot read ambient secrets held by the web process), enforces a wall-clock timeout, and kills the whole process tree if the rule does not finish in time - closing the unbounded-hang/DoS gap the original code also had. This gives the admin-submitted code a process boundary instead of none, which is what the loaded C# guidance identifies as the only reliable isolation Roslyn supports on modern .NET, and it also makes the timeout/no-ambient-credentials defenses concrete rather than aspirational. It is a mitigation through isolation, not an elimination of dynamic compilation - the feature's whole purpose is running admin-authored rule code, so "replace with a dispatch table" is not applicable here the way it would be for a fixed set of operations. The `trustedAssemblyNames` reference restriction from the original constructor is preserved unchanged, just relocated to where compilation now happens.

## Behaviour changes

- **Return value type**: `CompileAndRunRule` still returns `object`, but its runtime type is now `System.Text.Json.JsonElement?` (or `null`) instead of the original CLR type produced by the rule's `Evaluate` method, because the result now crosses a process boundary as JSON. A caller that cast the return value to a specific type (e.g. `(decimal)result`) will need to read it via `JsonElement` accessors instead. This is an unavoidable consequence of process isolation, not an incidental change, and is the one place the original sink's "Returns" contract could not be preserved exactly.
- **Argument marshalling**: `evaluateArgs` are now serialized to JSON in the parent and deserialized to each `Evaluate` parameter's declared type in the worker (matched positionally via reflection on the compiled rule's parameter list). Arguments must be JSON-serializable; a non-serializable CLR object that worked when passed in-process will now throw during deserialization. Ordinary rule inputs (numbers, strings, bools, dates, simple DTOs) are unaffected.
- **New timeout behaviour**: the original method had no timeout and could hang the caller's thread indefinitely on a non-terminating rule. The fix adds a configurable timeout (default 5 seconds) after which the worker process is killed and a `TimeoutException` is thrown. A rule that legitimately needs longer than the configured timeout will now fail where it previously would have (eventually) completed - this is an intended new failure mode, not a defect, but callers relying on long-running rules must raise the timeout via the constructor.
- **No inherited environment variables**: the worker process starts with `EnvironmentVariables.Clear()`. If any existing rule or the compilation step relied on an inherited environment variable, it will no longer see it. This is deliberate (removes ambient-secret exposure) and should be treated as a compatibility check before deployment, not silently worked around by re-adding variables.
- **Per-call process startup cost**: each `CompileAndRunRule` call now starts a new `dotnet` process, adding startup latency (typically tens to a few hundred milliseconds) that the original in-process call did not have.
- **Deployment requirement, not a code change**: `RuleSandboxRunner` must be published and its path supplied to `RuleCompilerService`'s constructor (default `"RuleSandboxRunner.dll"` assumes it is deployed alongside the caller - adjust the argument to match the real deployment layout). This is a new operational dependency the original single-process design did not have.
- **Residual gap, explicitly not closed by this change**: a process boundary alone does not stop the compiled rule from reading or writing files, spawning processes, or reaching the network - it only bounds credential inheritance and wall-clock time. Confirmed by test: a rule using `System.IO.File.WriteAllText` still succeeded, because `System.Private.CoreLib` (already the only reference the original code allowed) exposes `System.IO.File` directly. Closing this requires running `RuleSandboxRunner` under a dedicated least-privileged OS account with no network egress, plus a memory cap via a Windows Job Object or Linux cgroup - .NET has no in-process, cross-platform API to enforce any of that, so it must be provisioned at the OS/container level alongside this code change, not treated as optional hardening.
- **Verification performed**: both files were built with the .NET 10 SDK (`dotnet build`) against a mirrored project layout with zero warnings/errors. An end-to-end harness then exercised the real pipeline: (1) a normal rule with typed `Evaluate(int, string)` arguments compiled, ran, and returned the correct value as a `JsonElement`; (2) a compile-error rule surfaced `InvalidOperationException` with the "Rule failed to compile" message, confirming the error path serializes correctly; (3) a `while(true){}` rule was killed after the configured timeout (observed at ~2.8s against a 2s timeout) with `TimeoutException` thrown and no orphaned worker process left running afterward, confirming `Kill(entireProcessTree: true)` actually terminates the sandboxed process tree. This testing caught and fixed a real defect before finalizing: the original draft used non-nullable `JsonElement Result`, whose default (`Undefined`) throws on serialization for any error response - changed to `JsonElement?` for both request/response DTOs (parent and worker).
- **Assumptions**: (1) `evaluateArgs` in this codebase are JSON-serializable rule parameters (numbers, strings, booleans, dates, simple DTOs), consistent with "pricing or eligibility check" inputs - not opaque, non-serializable CLR objects; (2) the sandbox worker is deployed as a separate published artifact reachable via `dotnet <path>` from the host process's OS user, with network/account restrictions applied at deployment time as described above; (3) no SAST-provided call path was available beyond the single reported file, so the trace above is LLM-navigated (Step 4, Option B) rather than tool-extracted - confidence is high because the file is short and the source-to-sink flow has no branches, but there is no broader-codebase evidence about how `RuleCompilerService` is constructed or deployed today.
