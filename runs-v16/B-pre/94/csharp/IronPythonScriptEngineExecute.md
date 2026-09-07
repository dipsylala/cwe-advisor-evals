## Verdict

Exploitable

## Source

`request.ScriptBody` from the HTTP POST request body parameter, passed through the ASP.NET Core model binder without validation or sanitization.

## Fix

**Vulnerable code:**

```csharp
// Line 40: Sink - arbitrary Python code execution with untrusted input
result = PythonEngine.Execute(request.ScriptBody, scope);
```

**Fixed code:**

```csharp
// Replace arbitrary code execution with a safe function registry pattern
// Analysts can only invoke pre-registered, vetted transformation functions

// Define the allowlist of safe transformation functions
var allowedTransformations = new Dictionary<string, Func<string, string>>
{
    { "toUpper", json => json.ToUpper() },
    { "toLower", json => json.ToLower() },
    { "trim", json => json.Trim() },
    { "reverse", json => new string(json.Reverse().ToArray()) }
    // Add only explicitly approved transformation functions here
};

// Parse the request as a function name, not as code to execute
if (string.IsNullOrWhiteSpace(request.ScriptBody))
{
    return BadRequest("A transformation function name is required.");
}

string functionName = request.ScriptBody.Trim();
if (!allowedTransformations.ContainsKey(functionName))
{
    return BadRequest($"Transformation '{functionName}' is not allowed. Permitted functions: {string.Join(", ", allowedTransformations.Keys)}");
}

object result;
try
{
    // Execute only the vetted transformation function
    result = allowedTransformations[functionName](request.RowJson ?? "{}");
}
catch (Exception ex)
{
    return BadRequest($"Transformation failed: {ex.Message}");
}
```

## Explanation

The original code passes `request.ScriptBody` directly to `PythonEngine.Execute()`, allowing attackers to inject arbitrary Python code that executes with full access to the application's runtime. This violates the core principle of CWE-94 remediation: never execute dynamically generated code from untrusted input.

The fix replaces arbitrary code execution with a function registry pattern. Instead of allowing analysts to write Python scripts, the system provides a predefined, allowlisted dictionary of safe transformation functions. The request body is now treated as a function name to look up, not as code to interpret. This eliminates the injection vector entirely by removing the dynamic evaluation capability. The allowlist can be extended over time by adding new Func<string, string> entries, but only through code review and explicit deployment, not through user input.

## Behaviour changes

1. **API contract change**: The endpoint now accepts a transformation function name instead of Python code. The `ScriptBody` field is interpreted as a lookup key, not script source. Analysts must use one of the predefined transformation names rather than writing arbitrary Python.

2. **Response on unknown function**: Returns HTTP 400 with a list of allowed functions instead of attempting execution. Callers must validate their input against the known set before sending requests.

3. **No more Python execution**: The application no longer invokes `PythonEngine.Execute()`, so IronPython is no longer needed for this feature (the ScriptEngine and scope objects can be removed entirely if they have no other uses).

4. **Error handling scope**: Errors are now limited to the transformation logic itself (e.g., string operation exceptions) rather than arbitrary Python runtime errors. This also improves debuggability since exceptions come from known, reviewed code.

5. **Performance**: Execution is now faster (no Python compilation/interpretation overhead) and uses far less memory (no script engine state per request).

**Trade-off**: The feature is less flexible. Analysts can no longer write custom Python transformations; they must work within the predefined set of functions. For applications requiring true user-supplied transformation logic, this would require a different architecture (e.g., a separate, isolated Python service with resource limits and network isolation), but that is not practical or secure for a web controller.
