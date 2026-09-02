using System;
using System.IO;
using System.Linq;
using System.Reflection;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

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

            var options = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary);

            // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
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
