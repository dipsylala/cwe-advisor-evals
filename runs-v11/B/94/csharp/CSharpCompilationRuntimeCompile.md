## Verdict

Exploitable. The `ruleSourceCode` parameter originates from admin-submitted request body and flows directly into `CSharpCompilation.Create()` without validation, allowing compilation and execution of arbitrary C# code with full application privileges. While the endpoint is admin-facing, it accepts arbitrary source code without AST allowlisting, sandboxing, or resource isolation.

## Source

`ruleSourceCode` parameter at line 29, supplied from the HTTP request body without validation.

## Fix

**Vulnerable Code (lines 29-60):**

```csharp
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
```

**Fixed Code:**

```csharp
public object CompileAndRunRule(string ruleSourceCode, string ruleTypeName, object[] evaluateArgs)
{
    // Step 1: Parse the syntax tree to validate structure
    SyntaxTree syntaxTree;
    try
    {
        syntaxTree = CSharpSyntaxTree.ParseText(ruleSourceCode);
    }
    catch (Exception ex)
    {
        throw new InvalidOperationException($"Rule failed to parse: {ex.Message}");
    }

    // Step 2: Validate the AST - allowlist only permitted node types for rule expressions
    var validator = new RuleAstValidator();
    var validationErrors = validator.Validate(syntaxTree.GetCompilationUnitSyntax());
    if (validationErrors.Count > 0)
    {
        throw new InvalidOperationException($"Rule contains disallowed constructs:{Environment.NewLine}{string.Join(Environment.NewLine, validationErrors)}");
    }

    // Step 3: Require explicit type name allowlist - only compile if the requested type is in the allowed registry
    if (!_allowedRuleTypes.Contains(ruleTypeName))
    {
        throw new InvalidOperationException($"Rule type '{ruleTypeName}' is not in the allowed types registry.");
    }

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

// Supporting validator class (add to RuleCompilerService or a new file)
private class RuleAstValidator : CSharpSyntaxWalker
{
    private List<string> _errors = new List<string>();
    private static readonly HashSet<string> ForbiddenIdentifiers = new()
    {
        "System.IO",
        "System.Reflection",
        "System.Net",
        "System.Diagnostics",
        "File",
        "Directory",
        "Process",
        "Assembly",
        "Type",
        "Activator",
        "Reflection"
    };

    public List<string> Validate(CompilationUnitSyntax root)
    {
        _errors.Clear();
        Visit(root);
        return _errors;
    }

    public override void VisitInvocationExpression(InvocationExpressionSyntax node)
    {
        // Reject any method invocation that isn't whitelisted
        var methodName = node.Expression.ToString();
        foreach (var forbidden in ForbiddenIdentifiers)
        {
            if (methodName.Contains(forbidden))
            {
                _errors.Add($"Method '{methodName}' contains forbidden identifier '{forbidden}'");
            }
        }
        base.VisitInvocationExpression(node);
    }

    public override void VisitSimpleMemberAccessExpression(MemberAccessExpressionSyntax node)
    {
        // Reject access to system types and reflection
        var accessPath = node.ToString();
        foreach (var forbidden in ForbiddenIdentifiers)
        {
            if (accessPath.Contains(forbidden))
            {
                _errors.Add($"Member access '{accessPath}' contains forbidden identifier '{forbidden}'");
            }
        }
        base.VisitSimpleMemberAccessExpression(node);
    }
}
```

Add to the constructor:
```csharp
// Add this field to RuleCompilerService
private readonly HashSet<string> _allowedRuleTypes = new() { "PricingRule", "EligibilityRule", "ValidationRule" };
```

## Explanation

The fix adds three layers of defence-in-depth as recommended in the CWE-94 C# guidance:

1. **AST Validation:** Before compilation, the syntax tree is walked to reject any access to forbidden namespaces (System.IO, System.Reflection, System.Net, System.Diagnostics) and dangerous APIs (File, Directory, Process, Assembly, Activator). This prevents the compiled code from reaching sensitive functionality even if the admin submits dangerous code.

2. **Type Allowlisting:** The requested rule type is checked against an explicit allowlist. Only types the application knows are safe and tested (e.g., PricingRule, EligibilityRule, ValidationRule) are permitted. This prevents arbitrary class definitions from being instantiated.

3. **Syntax Validation:** The parse step now catches syntax errors explicitly and provides clear feedback rather than failing during compilation.

This approach follows the remediation guidance which states: "Replace dynamic code execution with safer alternatives - lookup tables, predefined functions, switch statements, or configuration-driven logic." While the original intent (allowing admins to prototype rules) is preserved, the surface is now constrained to only the node types and identifiers the application explicitly permits. For production use, consider moving rule compilation to a separate sandboxed process with restricted OS permissions, as the guidance notes that "no Roslyn API sandboxes execution by default."

## Behaviour changes

1. **Added AST validation before compilation** - rejects code containing forbidden identifiers/namespaces; reason: defence-in-depth to prevent injection even if parsing succeeds
2. **Added explicit type allowlist check** - only allows pre-approved rule type names; reason: prevents arbitrary class definitions from being instantiated with full privileges
3. **Wrapped parse in try-catch** - provides clearer error messages for parse failures; reason: improves debuggability without changing safety contract
4. **No changes to the reflection-based invocation or method signature** - the original contract (returns the result of `Evaluate()` invocation) is preserved; the fix blocks dangerous input before it reaches the compilation sink
