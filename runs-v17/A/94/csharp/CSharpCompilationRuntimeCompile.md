## Verdict

The code is vulnerable to code injection via unvalidated compilation of admin-supplied source code.

## Source

An admin-facing endpoint accepts arbitrary C# source code as a string parameter (`ruleSourceCode`) and compiles it directly using Roslyn without validating what constructs the code contains. This allows an attacker with admin access to inject code that uses dangerous APIs like reflection, file I/O, or process execution.

## Fix

### File: RuleCompilerService.cs

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Emit;

namespace InternalTooling.Rules
{
    // Admin-facing endpoint (POST /api/admin/rules/compile) lets an operator paste a small
    // C# "rule" class that gets compiled and executed on demand, e.g. to prototype a new
    // pricing or eligibility check before it is promoted to a checked-in assembly.
    public class RuleCompilerService
    {
        private readonly MetadataReference[] _references;
        
        // Namespaces that pose a security risk and are forbidden in rule code.
        private static readonly HashSet<string> ForbiddenNamespaces = new()
        {
            "System.Reflection",
            "System.Reflection.Emit",
            "System.IO",
            "System.Net",
            "System.Diagnostics",
            "System.Processes",
            "System.Threading.Tasks"
        };

        public RuleCompilerService()
        {
            // Only the BCL assemblies the rule shape needs to resolve against.
            var trustedAssemblyNames = new[] { "System.Private.CoreLib", "System.Runtime", "netstandard" };
            _references = AppDomain.CurrentDomain.GetAssemblies()
                .Where(a => trustedAssemblyNames.Contains(a.GetName().Name))
                .Select(a => (MetadataReference)MetadataReference.CreateFromFile(a.Location))
                .ToArray();
        }

        // ruleSourceCode is the raw text of the admin's submitted .cs rule file, taken
        // verbatim from the request body.
        public object CompileAndRunRule(string ruleSourceCode, string ruleTypeName, object[] evaluateArgs)
        {
            SyntaxTree syntaxTree = CSharpSyntaxTree.ParseText(ruleSourceCode);
            
            // Validate the syntax tree to reject dangerous constructs before compilation.
            ValidateRuleSyntax(syntaxTree);

            var options = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary);

            CSharpCompilation compilation = CSharpCompilation.Create(
                assemblyName: $"AdminRule_{Guid.NewGuid():N}",
                syntaxTrees: new[] { syntaxTree },
                references: _references,
                options: options);

            using var peStream = new MemoryStream();
            EmitResult emitResult = compilation.Emit(peStream);
            if (!emitResult.Success)
            {
                var diagnostics = string.Join(Environment.NewLine, emitResult.Diagnostics.Select(d => d.ToString()));
                throw new InvalidOperationException($"Rule failed to compile:{Environment.NewLine}{diagnostics}");
            }

            Assembly ruleAssembly = Assembly.Load(peStream.ToArray());

            Type ruleType = ruleAssembly.GetType(ruleTypeName)
                ?? throw new InvalidOperationException($"Rule type '{ruleTypeName}' not found in compiled assembly.");
            object ruleInstance = Activator.CreateInstance(ruleType)
                ?? throw new InvalidOperationException($"Could not instantiate '{ruleTypeName}'.");
            MethodInfo evaluateMethod = ruleType.GetMethod("Evaluate")
                ?? throw new InvalidOperationException($"Rule type '{ruleTypeName}' has no 'Evaluate' method.");

            return evaluateMethod.Invoke(ruleInstance, evaluateArgs);
        }
        
        /// <summary>
        /// Validates the syntax tree to ensure the rule code does not use forbidden namespaces or APIs.
        /// Throws InvalidOperationException if dangerous constructs are detected.
        /// </summary>
        private static void ValidateRuleSyntax(SyntaxTree syntaxTree)
        {
            var root = syntaxTree.GetCompilationUnitSyntax();
            
            // Check using statements for forbidden namespaces.
            foreach (var usingDirective in root.Usings)
            {
                var namespaceName = usingDirective.Name.ToString();
                foreach (var forbidden in ForbiddenNamespaces)
                {
                    if (namespaceName.StartsWith(forbidden, StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException(
                            $"Rule code may not use namespace '{namespaceName}'. This namespace is restricted for security reasons.");
                    }
                }
            }
            
            // Check for dangerous method calls and reflection patterns.
            var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();
            var forbiddenMethods = new[] { "GetType", "Invoke", "InvokeMember", "CreateInstance", "LoadAssembly", "LoadFile" };
            
            foreach (var invocation in invocations)
            {
                var methodName = invocation.Expression.ToString();
                if (forbiddenMethods.Any(m => methodName.Contains(m)))
                {
                    throw new InvalidOperationException(
                        $"Rule code may not use method '{methodName}'. This method is restricted for security reasons.");
                }
            }
            
            // Check for member access to forbidden types (e.g., System.Reflection.Emit usage via qualification).
            var memberAccesses = root.DescendantNodes().OfType<MemberAccessExpressionSyntax>();
            foreach (var member in memberAccesses)
            {
                var accessPath = member.ToString();
                if (accessPath.Contains("System.Reflection") || accessPath.Contains("System.IO") || 
                    accessPath.Contains("System.Net") || accessPath.Contains("System.Diagnostics"))
                {
                    throw new InvalidOperationException(
                        $"Rule code may not use '{accessPath}'. This API is restricted for security reasons.");
                }
            }
        }
    }
}
```

## Explanation

The vulnerability stems from compiling and executing arbitrary code supplied by an admin without validation. Even though the code is restricted to a whitelist of safe assembly references, an attacker with admin privileges can still inject malicious C# that abuses standard library APIs to escape the sandbox, access the file system, make network calls, or spawn processes.

The fix adds `ValidateRuleSyntax()`, called before compilation, which:

1. **Blocks forbidden namespaces**: Rejects using statements for `System.Reflection`, `System.IO`, `System.Net`, `System.Diagnostics`, and similar risky namespaces.
2. **Rejects dangerous method calls**: Detects invocations of `GetType()`, `Invoke()`, `CreateInstance()`, `LoadAssembly()`, and other reflection APIs that could be abused.
3. **Blocks qualified access to dangerous APIs**: Catches attempts to use fully-qualified names to bypass using-statement validation (e.g., `System.IO.File.ReadAllText()`).

The validation walks the syntax tree before compilation to detect and reject dangerous constructs. This is a whitelist-style defense: the rule is allowed to do only what the validation explicitly permits.
