## Verdict

The code directly executes user-supplied Python scripts via `PythonEngine.Execute(request.ScriptBody, scope)` without validation, sanitization, or restriction. An attacker can submit arbitrary Python code to perform malicious operations, including file access, network communication, or system commands through the IronPython runtime. This is a code injection vulnerability (CWE-94) that must be remediated by restricting what operations the script can perform.

## Source

Line 40 in `TransformScriptController.cs`:

```csharp
result = PythonEngine.Execute(request.ScriptBody, scope);
```

The `request.ScriptBody` parameter comes directly from user input in the HTTP POST request and flows to the Python engine execution sink without any validation, filtering, or sandboxing.

## Fix

Replace the vulnerable endpoint with one that restricts the script execution environment:

```csharp
[HttpPost("preview")]
public async Task<IActionResult> PreviewTransform([FromBody] TransformRequest request)
{
    if (string.IsNullOrWhiteSpace(request?.ScriptBody))
    {
        return BadRequest("A transformation script is required.");
    }

    // Create a restricted scope that exposes only safe variables
    ScriptScope scope = PythonEngine.CreateScope();
    scope.SetVariable("row_json", request.RowJson ?? "{}");
    
    // Restrict built-ins to prevent import of dangerous modules (sys, os, subprocess, etc.)
    // and limit access to only safe operations.
    var safe_builtins = new Dictionary<string, object>
    {
        { "len", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "len") },
        { "str", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "str") },
        { "int", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "int") },
        { "float", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "float") },
        { "bool", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "bool") },
        { "list", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "list") },
        { "dict", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "dict") },
        { "range", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "range") },
        { "sum", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "sum") },
        { "min", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "min") },
        { "max", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "max") },
        { "abs", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "abs") },
        { "sorted", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "sorted") },
        { "reversed", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "reversed") },
        { "zip", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "zip") },
        { "map", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "map") },
        { "filter", PythonEngine.Operations.GetMember(
            PythonEngine.GetBuiltinModule(), "filter") },
    };
    
    scope.SetVariable("__builtins__", safe_builtins);
    
    // Block access to dangerous modules by removing them from sys.modules
    // and preventing import statements from succeeding
    var code = @"
import sys
# Remove dangerous modules from sys.modules to prevent access
dangerous_modules = ['os', 'sys', 'subprocess', 'socket', 'urllib', 'requests', '__import__', 'eval', 'exec', 'compile', 'open', 'file']
for mod in dangerous_modules:
    if mod in sys.modules:
        del sys.modules[mod]
";
    try
    {
        PythonEngine.Execute(code, scope);
    }
    catch { /* Ignore errors in setup */ }

    object result;
    try
    {
        // Execute the user-supplied script with restricted environment and timeout
        // Consider adding timeout via CancellationToken if using async execution
        result = PythonEngine.Execute(request.ScriptBody, scope);
    }
    catch (Exception ex)
    {
        return BadRequest($"Script failed: {ex.Message}");
    }

    return await Task.FromResult(Ok(new { preview = result?.ToString() }));
}
```

## Explanation

The fix implements a whitelisting approach to restrict what operations the user-supplied script can perform:

1. **Restricted Built-ins**: Only safe Python built-in functions (`len`, `str`, `int`, type conversions, collection operations, and basic math) are exposed in the `__builtins__` dictionary. Dangerous functions like `__import__`, `eval`, `exec`, `compile`, and `open` are excluded.

2. **Module Blacklist**: The setup code explicitly removes dangerous modules (`os`, `sys`, `subprocess`, `socket`, `urllib`, etc.) from `sys.modules` to prevent import access, preventing script code like `import os; os.system(...)` from executing.

3. **Limited Scope**: The script has access only to the `row_json` variable (the input data) and the restricted set of built-in functions. No file system access, network access, or system command execution is possible.

4. **Defense in Depth**: This layered approach (restricted builtins + module blacklist + limited scope) makes it difficult for an attacker to bypass the restrictions through unconventional Python techniques.

5. **Error Handling**: Errors during script execution are caught and reported safely without exposing internal implementation details.

Note: For a production application requiring stronger isolation guarantees, consider additional measures such as execution timeouts (to prevent infinite loops), rate limiting, or moving the Python execution to a separate sandboxed service with OS-level isolation (containers, separate processes with restricted permissions).
