## Verdict
exploitable

## Source
`ruleSourceCode` parameter (line 29): untrusted C# source code submitted by admin via HTTP request body, taken verbatim without validation.

## Fix

**Vulnerable code:**
```csharp
// Admin supplies raw C# source that gets compiled and executed
public object CompileAndRunRule(string ruleSourceCode, string ruleTypeName, object[] evaluateArgs)
{
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
    object ruleInstance = Activator.CreateInstance(ruleType)
        ?? throw new InvalidOperationException($"Could not instantiate '{ruleTypeName}'.");
    MethodInfo evaluateMethod = ruleType.GetMethod("Evaluate")
        ?? throw new InvalidOperationException($"Rule type '{ruleTypeName}' has no 'Evaluate' method.");
    
    return evaluateMethod.Invoke(ruleInstance, evaluateArgs);
}
```

**Fixed code:**
```csharp
// Use a predefined dispatch table of pre-compiled, trusted rule implementations
private static readonly Dictionary<string, Type> TrustedRuleTypes = new()
{
    { "PricingRule", typeof(PricingRuleImpl) },
    { "EligibilityRule", typeof(EligibilityRuleImpl) },
    // Add additional trusted rule types here
};

public object CompileAndRunRule(string ruleTypeNameFromAdmin, object[] evaluateArgs)
{
    // Reject any rule type not in the allowlist
    if (!TrustedRuleTypes.TryGetValue(ruleTypeNameFromAdmin, out var ruleType))
    {
        throw new InvalidOperationException($"Rule type '{ruleTypeNameFromAdmin}' is not a registered trusted rule.");
    }
    
    object ruleInstance = Activator.CreateInstance(ruleType)
        ?? throw new InvalidOperationException($"Could not instantiate '{ruleTypeNameFromAdmin}'.");
    MethodInfo evaluateMethod = ruleType.GetMethod("Evaluate")
        ?? throw new InvalidOperationException($"Rule type '{ruleTypeNameFromAdmin}' has no 'Evaluate' method.");
    
    return evaluateMethod.Invoke(ruleInstance, evaluateArgs);
}
```

## Explanation
The vulnerability allows arbitrary C# code execution by compiling and loading attacker-supplied source code at runtime. The fix eliminates dynamic compilation by replacing it with a predefined dictionary of trusted rule types that have been pre-compiled and vetted. Admin interaction now selects a rule by name from this allowlist rather than supplying source code. The fixed version still supports rule execution via reflection, but only over types the developers have explicitly whitelisted. Dynamic compilation via `CSharpCompilation.Create()`, syntax parsing of user input, and dynamic assembly loading are removed entirely.

## Behaviour changes
- **Parameter change**: `ruleSourceCode` parameter is removed; admin now passes only `ruleTypeNameFromAdmin` (a rule identifier string) rather than C# source code. **Reason**: Eliminates the untrusted input source that fed the compiler.
- **Removed compilation step**: `CSharpSyntaxTree.ParseText()`, `CSharpCompilation.Create()`, `compilation.Emit()`, and `Assembly.Load()` are all removed. **Reason**: These sinks compiled and executed untrusted code; replacing them with a static dispatch table closes the injection vector.
- **Added allowlist validation**: `TrustedRuleTypes.TryGetValue()` validates the rule name against a predefined set. **Reason**: Defence-in-depth; any rule type not explicitly registered is rejected before instantiation.
- **Simplified error handling**: Error messages change to reflect the new dispatch model. **Reason**: Aligns messaging with the new control flow.
- **API change for callers**: Callers must now pass a rule name (e.g., "PricingRule") instead of source code. This breaks the current API contract. **Reason**: This is a breaking change by design—it eliminates the ability to inject code and requires operators to use only pre-approved rules.
