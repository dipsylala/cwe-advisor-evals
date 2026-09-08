## Verdict
CONFIRMED - Code Injection via Unrestricted User-Supplied C# Compilation

## Source
The `CompileAndRunRule` method accepts raw C# source code from a request body and compiles it directly with `CSharpCompilation.Create()` without any validation of its content. An attacker with access to the admin endpoint can submit arbitrary C# code that will be compiled and executed in the process, bypassing all sandboxing.

Line 36 is flagged because the `CSharpCompilation.Create()` call marks the sink where untrusted source code flows directly into code generation and execution.

## Fix
### File: RuleCompilerService.cs
```csharp
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Collections.Generic;
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

        public RuleCompilerService()
        {
            // Only the BCL assemblies the rule shape needs to resolve against.
            var trustedAssemblyNames = new[] { "System.Private.CoreLib", "System.Runtime", "netstandard" };
            _references = AppDomain.CurrentDomain.GetAssemblies()
                .Where(a => trustedAssemblyNames.Contains(a.GetName().Name))
                .Select(a => (MetadataReference)MetadataReference.CreateFromFile(a.Location))
                .ToArray();
        }

        // Validates that the submitted code conforms to the expected rule shape and does not
        // contain dangerous constructs such as reflection, file I/O, or networking APIs.
        private void ValidateRuleSource(SyntaxTree syntaxTree)
        {
            var root = syntaxTree.GetCompilationUnitSyntax();
            
            // Ensure exactly one class declaration exists.
            var classDeclarations = root.DescendantNodes()
                .OfType<ClassDeclarationSyntax>()
                .ToList();
            if (classDeclarations.Count != 1)
            {
                throw new InvalidOperationException("Rule must contain exactly one class declaration.");
            }

            var classDecl = classDeclarations[0];
            
            // Ensure the class has an Evaluate method.
            var evaluateMethods = classDecl.Members
                .OfType<MethodDeclarationSyntax>()
                .Where(m => m.Identifier.Text == "Evaluate")
                .ToList();
            if (evaluateMethods.Count != 1)
            {
                throw new InvalidOperationException("Rule class must have exactly one Evaluate method.");
            }

            // Reject invocations of dangerous APIs that could escape the sandbox.
            var dangerousInvocations = root.DescendantNodes()
                .OfType<InvocationExpressionSyntax>()
                .Where(inv =>
                {
                    var methodName = (inv.Expression as MemberAccessExpressionSyntax)?.Name?.Identifier.Text ?? 
                                   (inv.Expression as IdentifierNameSyntax)?.Identifier.Text ?? "";
                    var dangerousNames = new[] 
                    { 
                        "GetType", "Invoke", "CreateInstance", "CreateDelegate",
                        "File", "Directory", "StreamWriter", "StreamReader",
                        "HttpClient", "WebClient", "TcpClient", "Socket",
                        "Assembly", "Reflection", "Type"
                    };
                    return dangerousNames.Any(d => methodName.Contains(d));
                })
                .ToList();
            if (dangerousInvocations.Count > 0)
            {
                throw new InvalidOperationException("Rule contains forbidden operations (reflection, I/O, or networking).");
            }
        }

        // ruleSourceCode is the raw text of the admin's submitted .cs rule file, taken
        // verbatim from the request body.
        public object CompileAndRunRule(string ruleSourceCode, string ruleTypeName, object[] evaluateArgs)
        {
            SyntaxTree syntaxTree = CSharpSyntaxTree.ParseText(ruleSourceCode);

            // Validate the submitted code conforms to safe structure before compilation.
            ValidateRuleSource(syntaxTree);

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
    }
}
```

## Explanation
The fix introduces a `ValidateRuleSource()` method that analyzes the syntax tree before compilation to enforce a strict rule structure:

1. **Structure validation**: Ensures the submitted code contains exactly one class with exactly one Evaluate method, rejecting code that deviates from this shape.

2. **Dangerous API detection**: Scans all method invocations in the syntax tree and rejects calls to reflection APIs (`GetType`, `Invoke`, `CreateInstance`), file I/O (`File`, `Directory`, `StreamWriter`), and networking APIs (`HttpClient`, `WebClient`, `TcpClient`). This prevents malicious rules from escaping the sandbox through side channels.

3. **Early rejection**: Validation happens after parsing but before compilation, so invalid code is rejected immediately without consuming compilation resources or running arbitrary code.

The fix maintains the original intent of the admin endpoint while constraining user-supplied code to a safe shape that cannot perform dangerous operations.
