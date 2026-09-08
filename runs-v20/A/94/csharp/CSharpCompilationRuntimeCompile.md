## Verdict

Confirmed. `RuleCompilerService.CompileAndRunRule` takes `ruleSourceCode` verbatim from the admin request body, compiles it with Roslyn, and then emits, loads, and reflectively invokes the resulting assembly with no check on what that source is allowed to do. Restricting the compilation's `MetadataReference` list to a few trusted assembly names does not close this off: several of the most dangerous entry points (`System.Type.GetType`, `System.Activator`, `System.AppDomain`, `System.Environment`, `System.GC`) are defined directly in `System.Private.CoreLib`, which is already on the reference list, so a submitted rule can use `Type.GetType("System.Diagnostics.Process, System.Diagnostics.Process")` (or an equivalent assembly-qualified name) to resolve and invoke a type whose assembly was never referenced at compile time, and then reflectively call arbitrary methods on it, defeating the reference allowlist entirely.

## Source

- Source: `ruleSourceCode`, the raw text of the admin's submitted `.cs` rule file taken directly from the `POST /api/admin/rules/compile` request body (per the class comment).
- Sink: `CSharpCompilation.Create(...)` (line 37, flagged) followed immediately by `compilation.Emit(peStream)`, `Assembly.Load(peStream.ToArray())`, and `evaluateMethod.Invoke(ruleInstance, evaluateArgs)` - the untrusted text is compiled to IL and executed in-process with the service's own privileges, with no gate on what the compiled code is permitted to do.

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

            var options = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, allowUnsafe: false);

            CSharpCompilation compilation = CSharpCompilation.Create(
                assemblyName: $"AdminRule_{Guid.NewGuid():N}",
                syntaxTrees: new[] { syntaxTree },
                references: _references,
                options: options);

            // The restricted reference set above stops the rule from resolving types that
            // live in assemblies such as System.Diagnostics.Process or System.IO.FileSystem,
            // but several dangerous entry points (System.Type.GetType, System.Activator,
            // System.AppDomain, System.Environment, System.GC) are defined directly in
            // System.Private.CoreLib and would still resolve. Bind the tree and reject any
            // use of APIs outside a narrow allowlist before the code is ever emitted or run.
            SemanticModel semanticModel = compilation.GetSemanticModel(syntaxTree);
            EnsureRuleSourceIsSafe(syntaxTree, semanticModel);

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

        // Walks the bound syntax tree and throws if the submitted rule references anything
        // outside a narrow, safe API surface. This runs before Emit/Load/Invoke so a rule
        // that reaches for file, process, network, or reflection-based sandbox-escape APIs
        // never gets to execute.
        private static void EnsureRuleSourceIsSafe(SyntaxTree syntaxTree, SemanticModel semanticModel)
        {
            var walker = new RuleSecuritySyntaxWalker(semanticModel, syntaxTree);
            walker.Visit(syntaxTree.GetRoot());

            if (walker.Violations.Count > 0)
            {
                throw new InvalidOperationException(
                    "Rule source uses APIs that are not permitted for admin-submitted rules:" + Environment.NewLine +
                    string.Join(Environment.NewLine, walker.Violations));
            }
        }

        // Allowlist-based gate for admin-submitted rule source. Only a handful of everyday
        // BCL namespaces are permitted; everything else - including types that live in
        // System.Private.CoreLib itself, such as System.Type, System.Activator and
        // System.AppDomain, which a restricted reference list alone does not exclude - is
        // rejected explicitly, because those specific types are how reflection-based code
        // can escape a restricted reference set at runtime (e.g. Type.GetType("<any
        // assembly-qualified name>") loads and activates types the compiler never saw).
        private sealed class RuleSecuritySyntaxWalker : CSharpSyntaxWalker
        {
            private static readonly HashSet<string> AllowedNamespaces = new(StringComparer.Ordinal)
            {
                "System",
                "System.Collections",
                "System.Collections.Generic",
                "System.Linq",
            };

            private static readonly HashSet<string> DeniedTypes = new(StringComparer.Ordinal)
            {
                "System.Type",
                "System.Activator",
                "System.AppDomain",
                "System.Environment",
                "System.GC",
            };

            private readonly SemanticModel _model;
            private readonly SyntaxTree _ruleTree;
            private readonly List<string> _violations = new();

            public RuleSecuritySyntaxWalker(SemanticModel model, SyntaxTree ruleTree)
            {
                _model = model;
                _ruleTree = ruleTree;
            }

            public IReadOnlyList<string> Violations => _violations;

            public override void Visit(SyntaxNode node)
            {
                CheckNode(node);
                base.Visit(node);
            }

            private void CheckNode(SyntaxNode node)
            {
                // "dynamic" defeats static symbol resolution entirely - a dynamically bound
                // call carries no fixed symbol for this walker to check, so the type itself
                // is refused outright rather than trying to inspect what it resolves to.
                if (node is IdentifierNameSyntax { Identifier.ValueText: "dynamic" })
                {
                    _violations.Add("the 'dynamic' type is not permitted in a rule.");
                    return;
                }

                if (node is not ExpressionSyntax expression)
                {
                    return;
                }

                ISymbol symbol = _model.GetSymbolInfo(expression).Symbol;
                if (symbol is null)
                {
                    return;
                }

                // Array types (e.g. "object[]") have no namespace of their own - check the
                // element type instead so ordinary array parameters aren't misflagged.
                while (symbol is IArrayTypeSymbol arrayType)
                {
                    symbol = arrayType.ElementType;
                }

                // Anything declared by the submitted rule itself (its class, fields,
                // methods, locals) is fine - only external, pre-existing APIs are gated.
                if (symbol.Locations.Any(loc => loc.SourceTree == _ruleTree))
                {
                    return;
                }

                if (symbol is INamespaceSymbol namespaceSymbol)
                {
                    string namespaceName = namespaceSymbol.ToDisplayString();
                    if (!AllowedNamespaces.Contains(namespaceName))
                    {
                        _violations.Add($"namespace '{namespaceName}' is not permitted in a rule.");
                    }
                    return;
                }

                string containingTypeName = (symbol as ITypeSymbol)?.ToDisplayString()
                    ?? symbol.ContainingType?.ToDisplayString();
                if (containingTypeName is not null && DeniedTypes.Contains(containingTypeName))
                {
                    _violations.Add($"'{symbol.ToDisplayString()}' is not permitted in a rule.");
                    return;
                }

                INamespaceSymbol containingNamespace = symbol.ContainingNamespace;
                if (containingNamespace is null
                    || containingNamespace.IsGlobalNamespace
                    || !AllowedNamespaces.Contains(containingNamespace.ToDisplayString()))
                {
                    string ns = containingNamespace?.IsGlobalNamespace == false
                        ? containingNamespace.ToDisplayString()
                        : "global namespace";
                    _violations.Add($"'{symbol.ToDisplayString()}' ({ns}) is not permitted in a rule.");
                }
            }
        }
    }
}
```

## Explanation

The restricted `MetadataReference` list was already good defense-in-depth against types that live in separate assemblies (`System.Diagnostics.Process`, `System.IO.FileSystem`, `System.Net.Http`, etc.), since those simply fail to resolve at compile time. It does not, however, restrict the surface of `System.Private.CoreLib` itself, and that assembly is where the real sandbox-escape primitives live: `System.Type.GetType(string)` resolves and loads a type from an arbitrary assembly-qualified name at runtime, independent of what was referenced at compile time, and combined with `MethodInfo.Invoke` (reachable once you have a `Type`) gives full code execution regardless of the reference allowlist. `System.Activator`, `System.AppDomain`, `System.Environment`, and `System.GC` are similar high-value, always-resolvable escape/observability points.

The fix adds a semantic-model-based gate between `CSharpCompilation.Create` and `Emit`: it binds every expression in the submitted syntax tree and only allows symbols that either (a) are declared by the submitted rule itself, or (b) live in a narrow allowlist of everyday namespaces (`System`, `System.Collections`, `System.Collections.Generic`, `System.Linq`) and are not one of the explicitly denied types. `dynamic` is rejected outright because it produces no fixed symbol for the walker to evaluate, which would otherwise let a rule route around static resolution entirely. Verified by compiling this file against `Microsoft.CodeAnalysis.CSharp` 4.8.0 and running it: a benign rule using `List<int>`, a `foreach` loop, and a private helper method compiles and executes normally, while rules attempting `Type.GetType("System.Diagnostics.Process, ...")` + reflective `Invoke`, a direct `System.IO.File.ReadAllText` reference, `Environment.GetEnvironmentVariable`, and a `dynamic`-typed bypass are all rejected with `InvalidOperationException` before `Emit` ever runs.

This is a targeted allowlist for a narrow, application-defined code shape (a rule class with a single `Evaluate` method), not a general input-validation allowlist, so it does not carry the "allowlist as an ill-fitting product decision" risk that applies to validating free-form user data - the application is the one deciding what a rule is permitted to do. `allowUnsafe: false` is made explicit on `CSharpCompilationOptions` for clarity; it was already the constructor's default, so this is documentation rather than a behavior change. Note that a rule that only needs the already-allowed namespaces will continue to work unmodified; a rule that legitimately needs a wider API surface will need that surface added to `AllowedNamespaces` deliberately, which keeps the surface an explicit decision rather than an accidental gap.
