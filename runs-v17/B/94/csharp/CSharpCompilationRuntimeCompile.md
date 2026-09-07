## Verdict

Exploitable. The application accepts arbitrary C# source code from an untrusted admin endpoint, dynamically compiles it via `CSharpCompilation.Create()` (line 37), and executes it with full runtime access. An attacker with admin credentials can inject code to read files, execute processes, exfiltrate secrets, or corrupt data.

## Source

**Parameter:** `ruleSourceCode` (line 30) — raw C# source code string from the HTTP request body, documented as "taken verbatim from the request body."

**Flow:**
- Line 32: `CSharpSyntaxTree.ParseText(ruleSourceCode)` parses untrusted source into an AST
- Lines 37–41: `CSharpCompilation.Create()` receives the AST and compiles it
- Line 44: `compilation.Emit(peStream)` writes the compiled binary
- Line 51: `Assembly.Load(peStream.ToArray())` loads the untrusted compiled code
- Lines 55–60: `Activator.CreateInstance()` and `MethodInfo.Invoke()` execute the injected code with full access to the runtime, BCL, file system, reflection, and environment

## Fix

Remove dynamic compilation entirely. Replace with pre-compiled, reviewed rule assemblies loaded from a trusted directory and validated against an allowlist. Administrators supply rules by checking source into version control and building as part of CI/CD; the API endpoint loads only pre-approved, compiled artifacts.

### File: RuleCompilerService.cs

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace InternalTooling.Rules
{
    // Admin-facing endpoint (POST /api/admin/rules/load) loads pre-compiled, reviewed rule assemblies
    // from a trusted directory. Rule source code must be checked in to version control and compiled
    // as part of the CI/CD process before it can be used.
    public class RuleCompilerService
    {
        private readonly string _trustedRulesDirectory;
        private readonly HashSet<string> _allowedRuleNames;

        public RuleCompilerService(string trustedRulesDirectory, IEnumerable<string> allowedRuleNames)
        {
            _trustedRulesDirectory = trustedRulesDirectory;
            _allowedRuleNames = new HashSet<string>(allowedRuleNames, StringComparer.OrdinalIgnoreCase);
        }

        // ruleName is the name of a pre-compiled rule assembly (without .dll extension), validated against an allowlist.
        public object LoadAndRunRule(string ruleName, string ruleTypeName, object[] evaluateArgs)
        {
            // Validate ruleName against the allowlist
            if (!_allowedRuleNames.Contains(ruleName))
            {
                throw new ArgumentException($"Rule '{ruleName}' is not in the allowlist of approved rules.");
            }

            // Construct path and verify it stays within the trusted directory (path traversal protection)
            string assemblyPath = Path.Combine(_trustedRulesDirectory, $"{ruleName}.dll");
            string fullPath = Path.GetFullPath(assemblyPath);
            string fullTrustedDir = Path.GetFullPath(_trustedRulesDirectory);
            
            if (!fullPath.StartsWith(fullTrustedDir, StringComparison.OrdinalIgnoreCase) || 
                !File.Exists(fullPath))
            {
                throw new InvalidOperationException($"Rule assembly for '{ruleName}' not found in trusted location.");
            }

            // Load pre-compiled, reviewed assembly from trusted directory only
            Assembly ruleAssembly = Assembly.LoadFrom(fullPath);

            Type ruleType = ruleAssembly.GetType(ruleTypeName)
                ?? throw new InvalidOperationException($"Rule type '{ruleTypeName}' not found in compiled assembly.");
            object ruleInstance = Activator.CreateInstance(ruleType)
                ?? throw new InvalidOperationException($"Could not instantiate '{ruleTypeName}'.");
            MethodInfo evaluateMethod = ruleType.GetMethod("Evaluate")
                ?? throw new InvalidOperationException($"Rule type '{ruleTypeName}' has no 'Evaluate' method.");

            return evaluateMethod.Invoke(ruleInstance, evaluateArgs);
        }
    }
}
```

## Explanation

The original code accepts arbitrary C# source as a parameter and compiles it directly with `CSharpCompilation.Create()`. This is code injection: the attacker supplies executable source code that the application parses, compiles, loads, and runs with full runtime permissions. The CWE-94 guidance explicitly forbids dynamic code execution derived from untrusted input and states that no Roslyn API sandboxes execution by default.

The fix eliminates the injection vector by removing dynamic compilation entirely. Rules are now pre-compiled as part of the CI/CD pipeline and stored as `.dll` files in a trusted directory. The API accepts only a rule name, which is validated against an allowlist of approved rules. The name is then used to construct a path within the trusted directory (with path-traversal protection via `Path.GetFullPath()` and directory boundary checks). Only pre-approved, reviewed, compiled assemblies can be loaded and executed. This approach is aligned with the CWE-94 guidance: "Replace dynamic code execution with safer alternatives — lookup tables, predefined functions, switch statements, or configuration-driven logic" and "Use static code paths and predefined logic instead of dynamic execution."

## Behaviour changes

**Constructor signature changed:** Original had a parameterless constructor that populated `_references` for Roslyn compilation. New constructor requires `trustedRulesDirectory` (the path to approved rule assemblies) and `allowedRuleNames` (the allowlist of rule names the API may load). These parameters enforce the security boundary and are supplied at initialization, not per-request.

**Method signature changed:** `CompileAndRunRule(string ruleSourceCode, ...)` → `LoadAndRunRule(string ruleName, ...)`. The parameter changes from raw source code to a rule name. Callers must supply an already-compiled rule identifier rather than source to be compiled.

**Removed Roslyn compilation:** No longer creates `CSharpSyntaxTree`, `CSharpCompilation`, or `EmitResult`. The compilation step is removed entirely; only pre-compiled assemblies are loaded.

**Added path-traversal protection:** Validates the constructed assembly path stays within the trusted directory using `Path.GetFullPath()` and prefix checks. This defends against an attacker overwriting the allowlist to include a name like `../../../evil`.

**Removed metadata reference setup:** The constructor no longer populates `_references` for BCL assemblies, since compilation no longer occurs.

All behaviour changes are necessary to close the injection vector: code execution source is now static (version-controlled, CI-approved) rather than dynamic (supplied at runtime).
