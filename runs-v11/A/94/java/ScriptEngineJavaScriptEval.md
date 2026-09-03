## Verdict

CONFIRMED: Code injection vulnerability in `CustomValidationRuleService.java` at line 42. The `eval()` method directly executes untrusted tenant-supplied JavaScript code with no validation or sandboxing, allowing arbitrary code execution.

## Source

Line 42: `Object result = engine.eval(ruleSource);`

The `ruleSource` parameter is documented as "tenant-authored JavaScript rule body, untrusted" (line 27), sourced directly from admin console input with no transformation (line 25). This untrusted string is passed directly to the ScriptEngine's `eval()` method, which interprets and executes it as arbitrary JavaScript code.

## Fix

Replace the unsafe `eval()` approach with a sandboxed execution model. Restrict the script engine's access to system classes and provide only safe, whitelisted bindings for the validation context:

```java
public boolean evaluateCustomRule(String ruleSource, double orderTotal, String customerTier) throws ScriptException {
    ScriptEngine engine = engineManager.getEngineByName("JavaScript");
    if (engine == null) {
        throw new IllegalStateException("JavaScript engine not available on this runtime");
    }

    // Create a new bindings scope to isolate the script's namespace
    SimpleBindings bindings = new SimpleBindings();
    
    // Provide only the necessary safe bindings for the validation rule
    bindings.put("orderTotal", orderTotal);
    bindings.put("customerTier", customerTier);
    
    // Execute the script in the restricted bindings scope
    Object result = engine.eval(ruleSource, bindings);
    
    return Boolean.TRUE.equals(result);
}
```

Add the import: `import javax.script.SimpleBindings;`

## Explanation

The vulnerability exists because `eval()` with default bindings gives the script access to Java's full object model, allowing it to instantiate dangerous classes, execute system commands, or access sensitive resources. 

The fix isolates the script's execution context using `SimpleBindings`, which provides a fresh namespace containing only the explicitly-provided bindings (`orderTotal` and `customerTier`). This prevents the script from accessing Java classes, methods, or system functions outside the intended validation parameters.

The script can still perform arbitrary computation within the JavaScript language itself using the provided values, but cannot break out of the JavaScript sandbox to invoke Java code or system operations. This preserves the intended functionality—evaluating custom validation logic—while eliminating the code injection vector.
