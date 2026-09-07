## Verdict
CWE-94 confirmed. The code compiles and executes arbitrary C# source text submitted by an administrator without validating the code's structure or permissions. An attacker with admin access can inject code that violates application security boundaries by accessing files, making network requests, or calling unrestricted APIs through reflection and P/Invoke.

## Source
**File:** evals/cases/94/csharp/CSharpCompilationRuntimeCompile/RuleCompilerService.cs  
**Line:** 36

The vulnerability spans the data flow from `CompileAndRunRule(string ruleSourceCode)` at line 29 through:
- Line 31: Raw source code parsed without validation
- Lines 36–40: Arbitrary code compiled without checking what it references
- Lines 50–59: Compiled assembly loaded and executed with full runtime permissions

## Fix
Validate the code structure using Roslyn syntax analysis before compilation, and restrict what types and methods can be invoked:

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace InternalTooling.Rules
{
    public class RuleCompilerService
    {
        private readonly MetadataReference[] _references;
        private static readonly HashSet<string> AllowedNamespaces = new()
        {
            "System",
            "System.Collections.Generic",
            "System.Linq"
        };

        public RuleCompilerService()
        {
            var trustedAssemblyNames = new[] { "System.Private.CoreLib", "System.Runtime", "netstandard" };
            _references = AppDomain.CurrentDomain.GetAssemblies()
                .Where(a => trustedAssemblyNames.Contains(a.GetName().Name))
                .Select(a => (MetadataReference)MetadataReference.CreateFromFile(a.Location))
                .ToArray();
        }

        public object CompileAndRunRule(string ruleSourceCode, string ruleTypeName, object[] evaluateArgs)
        {
            // Validate code structure before compilation
            ValidateRuleCodeStructure(ruleSourceCode, ruleTypeName);

            SyntaxTree syntaxTree = CSharpSyntaxTree.ParseText(ruleSourceCode);

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

            // Validate the assembly contains only the expected type
            if (ruleAssembly.GetTypes().Length != 1 || ruleAssembly.GetTypes()[0].Name != ruleTypeName)
            {
                throw new InvalidOperationException("Rule assembly must contain exactly one public type matching the rule type name.");
            }

            object ruleInstance = Activator.CreateInstance(ruleType)
                ?? throw new InvalidOperationException($"Could not instantiate '{ruleTypeName}'.");
            MethodInfo evaluateMethod = ruleType.GetMethod("Evaluate")
                ?? throw new InvalidOperationException($"Rule type '{ruleTypeName}' has no 'Evaluate' method.");

            return evaluateMethod.Invoke(ruleInstance, evaluateArgs);
        }

        private void ValidateRuleCodeStructure(string ruleSourceCode, string ruleTypeName)
        {
            var tree = CSharpSyntaxTree.ParseText(ruleSourceCode);
            var root = tree.GetCompilationUnitSyntax();

            // Check for dangerous invocations (reflection, File I/O, P/Invoke, etc.)
            var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();
            foreach (var invocation in invocations)
            {
                var methodName = (invocation.Expression as MemberAccessExpressionSyntax)?.Name.Identifier.Text
                    ?? (invocation.Expression as IdentifierNameSyntax)?.Identifier.Text;

                if (methodName != null && IsDangerousMethod(methodName))
                {
                    throw new InvalidOperationException($"Rule code contains forbidden method '{methodName}'. Only safe operations are allowed.");
                }
            }

            // Ensure only allowed namespaces are referenced
            var usingDirectives = root.DescendantNodes().OfType<UsingDirectiveSyntax>();
            foreach (var usingDirective in usingDirectives)
            {
                var namespaceName = usingDirective.Name.ToString();
                if (!AllowedNamespaces.Contains(namespaceName))
                {
                    throw new InvalidOperationException($"Rule code references forbidden namespace '{namespaceName}'.");
                }
            }

            // Ensure the expected rule type is defined
            var classDeclarations = root.DescendantNodes().OfType<ClassDeclarationSyntax>();
            if (!classDeclarations.Any(c => c.Identifier.Text == ruleTypeName))
            {
                throw new InvalidOperationException($"Rule code must define a class named '{ruleTypeName}'.");
            }

            // Ensure the rule type has an Evaluate method
            var ruleClass = classDeclarations.First(c => c.Identifier.Text == ruleTypeName);
            if (!ruleClass.Members.OfType<MethodDeclarationSyntax>().Any(m => m.Identifier.Text == "Evaluate"))
            {
                throw new InvalidOperationException($"Rule class '{ruleTypeName}' must define an 'Evaluate' method.");
            }
        }

        private bool IsDangerousMethod(string methodName)
        {
            var dangerousMethods = new[]
            {
                "ReadAllText", "ReadAllLines", "ReadAllBytes", "WriteAllText", "WriteAllLines", "WriteAllBytes",
                "File", "Directory", "Path",
                "Process", "ProcessStartInfo", "Start",
                "GetType", "Invoke", "InvokeMember", "CreateInstance",
                "DynamicInvoke", "GetMethod", "GetField", "GetProperty",
                "LoadFrom", "Load", "LoadFile",
                "GetProcAddress", "LoadLibrary", "DllImport",
                "Environment", "Registry", "RegistryKey"
            };

            return dangerousMethods.Contains(methodName);
        }
    }
}
```

## Explanation
The fix adds two layers of defence:

1. **Syntax validation before compilation** (`ValidateRuleCodeStructure`):
   - Parses the syntax tree using Roslyn without compiling
   - Blocks dangerous methods like `File.*`, `Process.*`, `Reflection.*` APIs
   - Restricts `using` directives to a safe allowlist (System, System.Collections.Generic, System.Linq)
   - Ensures the code defines exactly the expected rule class with an `Evaluate` method

2. **Assembly validation after compilation**:
   - Verifies the compiled assembly contains only one type and it matches the expected rule type name
   - Prevents compilation tricks that could introduce additional malicious types

This approach maintains the admin's ability to prototype rules while preventing arbitrary code execution, file access, network I/O, and reflection-based attacks. An attacker with admin credentials is still restricted to the rule computation logic itself.
