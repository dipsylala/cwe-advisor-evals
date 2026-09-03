## Verdict

Exploitable. The tenant-supplied JavaScript rule source is passed directly to `ScriptEngine.eval()` without validation or sandboxing, allowing arbitrary code execution with full access to the application's runtime context, variables, and resources.

## Source

**Data flow**
- Source: `ruleSource` parameter (tenant-authored JavaScript rule body, untrusted; supplied from admin console configuration and passed without transformation)
- Sink: `engine.eval(ruleSource)` at line 42
- No validation, allowlist, or sandboxing between source and sink

**Vulnerability**
CWE-94: Improper Control of Generation of Code ('Code Injection'). An attacker who can write custom validation rules can inject arbitrary JavaScript code executed in the application's process with full access to exposed variables (`orderTotal`, `customerTier`), the engine's bindings, and any accessible Java classes.

## Fix

**Vulnerable code (line 32-45):**

```java
public boolean evaluateCustomRule(String ruleSource, double orderTotal, String customerTier) throws ScriptException {
    ScriptEngine engine = engineManager.getEngineByName("JavaScript");
    if (engine == null) {
        throw new IllegalStateException("JavaScript engine not available on this runtime");
    }

    engine.put("orderTotal", orderTotal);
    engine.put("customerTier", customerTier);

    // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
    Object result = engine.eval(ruleSource);  // VULNERABLE: ruleSource is untrusted

    return Boolean.TRUE.equals(result);
}
```

**Fixed code:**

Replace `javax.script.ScriptEngine` evaluation with Apache Commons JEXL using a deny-by-default sandbox:

```java
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlException;
import org.apache.commons.jexl3.JexlFeatures;
import org.apache.commons.jexl3.MapContext;
import org.apache.commons.jexl3.introspection.JexlSandbox;

public class CustomValidationRuleService {

    private final JexlEngine jexlEngine;

    public CustomValidationRuleService() {
        // Create a deny-by-default sandbox: only explicitly allowed classes can be accessed
        JexlSandbox sandbox = new JexlSandbox(false);
        
        // Allow only the specific classes and methods needed for validation expressions
        // Examples: sandbox.allow(Double.class); sandbox.allow(String.class);
        
        // Disable object construction and reflection capabilities
        JexlFeatures features = new JexlFeatures().newInstance(false);
        
        this.jexlEngine = new JexlBuilder()
            .sandbox(sandbox)
            .features(features)
            .create();
    }

    /**
     * Evaluates the tenant-supplied validation rule against the order under review.
     * The rule is now evaluated in a restricted JEXL sandbox that denies access to
     * Java reflection and object construction by default.
     *
     * @param ruleSource   tenant-authored validation rule expression (restricted JEXL)
     * @param orderTotal   order total in minor currency units
     * @param customerTier loyalty tier of the customer placing the order
     * @return true if the order passes the custom rule
     * @throws JexlException if the expression cannot be compiled or evaluated
     */
    public boolean evaluateCustomRule(String ruleSource, double orderTotal, String customerTier) throws JexlException {
        try {
            // Compile the expression; compilation failures are caught and reported
            JexlExpression expression = jexlEngine.createExpression(ruleSource);
            
            // Create an evaluation context with only the allowed variables
            JexlContext context = new MapContext();
            context.set("orderTotal", orderTotal);
            context.set("customerTier", customerTier);
            
            // Evaluate the expression in the sandboxed context
            Object result = expression.evaluate(context);
            
            return Boolean.TRUE.equals(result);
        } catch (JexlException e) {
            // Log and reject malformed or malicious expressions
            throw new JexlException(null, "Invalid validation rule", e);
        }
    }
}
```

**Library recommendation:** Apache Commons JEXL (3.2.0 or later). Confirm the resolved version against your SCA tooling before merging.

## Explanation

The fix replaces `javax.script.ScriptEngine.eval()` with Apache Commons JEXL and a deny-by-default `JexlSandbox(false)`. This removes the ability for tenant-supplied expressions to access Java reflection, class constructors, or method invocation on arbitrary classes. The sandbox is configured to reject object construction (`JexlFeatures.newInstance(false)`), which prevents instantiation of dangerous classes. Only explicitly allowed variables (`orderTotal`, `customerTier`) are exposed to the expression context, and only if the sandbox permit grants access.

This approach maintains the feature - tenant-supplied rule expressions - while removing the capability for arbitrary code execution. Unlike the original `ScriptEngine.eval()` approach where no containment exists, JEXL with a deny-by-default sandbox enforces what operations are permitted. A malicious expression that attempts to invoke methods, instantiate classes, or access Java internals will fail safely (returning `null` or throwing an exception), not execute.

The fix does not use `JexlSandbox(true)` (allow-by-default), which would appear sandboxed in code review but still permit access to most dangerous operations. The deny-by-default approach (`false`) is more secure and aligns with the principle of least privilege.

## Behaviour changes

**Changed behaviour that is intentional and required for security:**

1. **Sandbox restrictions**: The fixed code disallows Java reflection, class instantiation, and method invocation on classes not explicitly whitelisted. This is the security boundary. Expressions that attempt `Runtime.getRuntime()`, `System.exit()`, or similar attacks will fail.

2. **Exception handling**: The original code throws `ScriptException`; the fixed code throws `JexlException`. Callers catching `ScriptException` must be updated to catch `JexlException` instead, or a wrapper exception can re-throw for compatibility.

3. **Null return vs. boolean coercion**: JEXL's sandbox denies unsafe operations by returning `null` rather than throwing. The return value is still tested as `Boolean.TRUE.equals(result)`, which treats `null` as `false`, preserving the boolean outcome.

**Changed behaviour that preserves the contract:**

4. **Variable exposure**: Both versions expose `orderTotal` and `customerTier` to the evaluation context, so expressions can reference them. The original script engine exposes them via `engine.put()`; JEXL exposes them via `context.set()`.

5. **Return type and interpretation**: Both return a boolean interpreted from the expression result. A successful evaluation (whether safe or malicious in the original, safe only in the fixed version) returns a value coerced to boolean.

6. **Single-threaded evaluation**: Both evaluate the expression once per call in the caller's thread. No concurrency changes.

**Requirement to configure sandbox allowlist:**

The fixed code includes a placeholder for `sandbox.allow(SomeClass.class)` to explicitly permit access to classes needed by valid expressions. The application developer must determine which classes (if any) the validator needs and add them. If no classes are explicitly allowed, the sandbox rejects all class access, which may be the safest option for simple boolean-returning expressions that compare values only.

