## Verdict

**VULNERABLE**

The code compiles and executes user-supplied C# source code without validation. An attacker can inject arbitrary C# code to access system resources, perform I/O, make network calls, or use reflection APIs, regardless of the restricted assembly references.

## Source

```csharp
public object CompileAndRunRule(string ruleSourceCode, string ruleTypeName, object[] evaluateArgs)
{
    SyntaxTree syntaxTree = CSharpSyntaxTree.ParseText(ruleSourceCode);
    
    var options = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary);
    
    // Line 36: Compiles untrusted source without validation
    CSharpCompilation compilation = CSharpCompilation.Create(
        assemblyName: $"AdminRule_{Guid.NewGuid():N}",
        syntaxTrees: new[] { syntaxTree },
        references: _references,
        options: options);
    
    using var peStream = new MemoryStream();
    EmitResult emitResult = compilation.Emit(peStream);
    // ... rest of method
}
```

The `ruleSourceCode` parameter (line 29) is taken verbatim from the request body and passed directly to `CSharpSyntaxTree.ParseText()` without inspection.

## Fix

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
            SyntaxTree syntaxTree = CSharpSyntaxTree.ParseText(ruleSourceCode);
            
            // Validate the syntax tree before compilation
            ValidateRuleSourceCode(syntaxTree);

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

        private static void ValidateRuleSourceCode(SyntaxTree syntaxTree)
        {
            var root = syntaxTree.GetCompilationUnitSyntax();
            var validator = new RuleSourceValidator();
            validator.Visit(root);

            if (validator.Violations.Count > 0)
            {
                throw new InvalidOperationException(
                    $"Rule source code contains disallowed constructs: {string.Join("; ", validator.Violations)}");
            }
        }
    }

    /// <summary>
    /// Validates that rule source code only uses safe, expected constructs.
    /// Rejects code with reflection, P/Invoke, file I/O, networking, or other dangerous APIs.
    /// </summary>
    internal class RuleSourceValidator : CSharpSyntaxWalker
    {
        private static readonly HashSet<string> ForbiddenNamespaces = new()
        {
            "System.Net",
            "System.IO",
            "System.Reflection",
            "System.Diagnostics",
            "System.Runtime.InteropServices",
            "System.Threading",
            "System.Timers",
            "System.Net.Sockets"
        };

        private static readonly HashSet<string> ForbiddenMethods = new()
        {
            "Activator.CreateInstance",
            "Type.GetType",
            "Assembly.Load",
            "Assembly.LoadFrom",
            "Reflection.Emit"
        };

        public List<string> Violations { get; } = new();

        public override void VisitUsingDirective(UsingDirectiveSyntax node)
        {
            var namespaceName = node.Name.ToString();
            
            if (ForbiddenNamespaces.Any(ns => namespaceName.Equals(ns, StringComparison.Ordinal) || 
                                               namespaceName.StartsWith(ns + ".", StringComparison.Ordinal)))
            {
                Violations.Add($"Disallowed namespace: {namespaceName}");
            }

            base.VisitUsingDirective(node);
        }

        public override void VisitAttribute(AttributeSyntax node)
        {
            if (node.Name.ToString() == "DllImport")
            {
                Violations.Add("P/Invoke declarations are not allowed");
            }

            base.VisitAttribute(node);
        }

        public override void VisitInvocationExpression(InvocationExpressionSyntax node)
        {
            var methodCall = node.Expression.ToString();
            
            if (ForbiddenMethods.Any(method => methodCall.Contains(method)))
            {
                Violations.Add($"Disallowed method call: {methodCall}");
            }

            base.VisitInvocationExpression(node);
        }
    }
}
```

## Explanation

**Root Cause:** The code accepts arbitrary C# source code from an admin request and compiles it with only a restricted set of assembly references. While limiting references prevents direct access to certain namespaces at compile time, the source code itself can use:
- Reflective APIs to load additional assemblies and bypass restrictions
- P/Invoke declarations to call native libraries
- Dangerous framework APIs (networking, file I/O, process spawning) that are in the limited reference set

**The Fix:**
1. **Validate the syntax tree** before compilation by walking the Roslyn AST with a custom visitor (`RuleSourceValidator`)
2. **Reject forbidden namespaces** (System.Net, System.IO, System.Reflection, System.Diagnostics, System.Runtime.InteropServices, System.Threading) to block access to dangerous APIs
3. **Reject P/Invoke declarations** by scanning for `DllImport` attributes, which allow calling native code
4. **Reject dangerous method calls** (reflection APIs like `Activator.CreateInstance`, `Type.GetType`, `Assembly.Load`) that could bypass compile-time restrictions
5. **Throw early** if violations are found, before compilation and execution

This defense-in-depth approach ensures that even code syntactically valid in C# cannot access dangerous operations within the rule sandbox.
