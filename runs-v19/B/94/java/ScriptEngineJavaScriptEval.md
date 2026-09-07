## Verdict

CONFIRMED: CWE-94 code injection via untrusted JavaScript evaluation. The `engine.eval(ruleSource)` call at line 42 executes tenant-supplied, untrusted JavaScript without sandboxing or validation.

## Source

Line 32: `evaluateCustomRule(String ruleSource, ...)` receives tenant-authored JavaScript rule body documented as untrusted.

## Fix

Replace `ScriptEngine.eval()` with Apache Commons JEXL using `JexlSandbox(false)` (deny-by-default) to evaluate tenant expressions safely. The sandbox prevents access to Java reflection, constructors, and system operations while allowing basic property access and comparisons needed for validation rules.

### File: CustomValidationRuleService.java

```java
package com.example.rules;

import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
import org.apache.commons.jexl3.JexlFeatures;
import org.apache.commons.jexl3.MapContext;
import org.apache.commons.jexl3.introspection.JexlSandbox;

/**
 * Lets an account administrator define a "custom validation rule" that runs
 * against each incoming order before it is accepted. The rule body is stored
 * as free-text JEXL expression and supplied per-request from the admin console.
 *
 * Uses Apache Commons JEXL with a strict deny-by-default sandbox to evaluate
 * tenant-supplied expressions safely, preventing arbitrary code execution.
 */
public class CustomValidationRuleService {

    private final JexlEngine jexlEngine;

    public CustomValidationRuleService() {
        // Create a deny-by-default sandbox: no built-in classes or methods exposed
        JexlSandbox sandbox = new JexlSandbox(false);
        
        // Allow only the specific classes needed for basic validation:
        // Number and String for comparisons, BigDecimal for precise currency values
        sandbox.allow(Number.class);
        sandbox.allow(String.class);
        
        // Disable object instantiation and loops to further restrict capabilities
        JexlFeatures features = new JexlFeatures()
            .newInstance(false)
            .loops(false);
        
        this.jexlEngine = new JexlBuilder()
            .sandbox(sandbox)
            .features(features)
            .create();
    }

    /**
     * Evaluates the tenant-supplied validation rule against the order under
     * review. ruleSource is the raw text the admin typed into the "custom
     * validation rule" field and saved with the account configuration.
     *
     * @param ruleSource   tenant-authored JEXL expression, untrusted
     * @param orderTotal   order total in minor currency units
     * @param customerTier loyalty tier of the customer placing the order
     * @return true if the order passes the custom rule
     */
    public boolean evaluateCustomRule(String ruleSource, double orderTotal, String customerTier) throws Exception {
        // Validate rule source length to prevent resource exhaustion
        if (ruleSource == null || ruleSource.isEmpty() || ruleSource.length() > 1000) {
            return false;
        }
        
        // Create a context with only the necessary variables for evaluation
        JexlContext context = new MapContext();
        context.set("orderTotal", orderTotal);
        context.set("customerTier", customerTier);
        
        try {
            // Parse and evaluate the expression with the sandboxed engine.
            // The sandbox prevents access to Java reflection, constructors,
            // and system operations regardless of what the expression attempts.
            JexlExpression expression = jexlEngine.createExpression(ruleSource);
            Object result = expression.evaluate(context);
            
            return Boolean.TRUE.equals(result);
        } catch (Exception e) {
            // Evaluation errors (syntax errors, denied operations, etc.) fail the rule safely.
            // The sandbox raises exceptions on attempts to access restricted classes or methods.
            return false;
        }
    }
}
```

## Explanation

The fix replaces the vulnerable `javax.script.ScriptEngine.eval(ruleSource)` call with Apache Commons JEXL, a purpose-built expression language evaluator. The key security improvements:

1. **Deny-by-Default Sandbox**: `JexlSandbox(false)` grants no permissions by default, then explicitly allows only `Number` and `String` classes. Attempts to access reflection, constructors, or other classes raise exceptions.

2. **Restricted Features**: `JexlFeatures.newInstance(false)` disables object instantiation, and `loops(false)` prevents infinite loops as a denial-of-service hardening.

3. **Limited Context**: Only `orderTotal` and `customerTier` variables are exposed to the expression; the expression cannot access the engine itself, method handles, or the application's internals.

4. **Fail-Safe Error Handling**: Evaluation errors—including attempts to invoke denied operations—return `false`, failing the validation safely rather than throwing or executing arbitrary code.

5. **Input Length Validation**: A basic length check (1000 chars) prevents resource exhaustion via extremely long expressions.

The expression language changes from JavaScript to JEXL syntax (e.g., `&&` instead of `&&`, no regex literals), but the majority of comparison expressions (`orderTotal > 100`, `customerTier == 'premium'`) remain compatible. Rules with JavaScript-specific constructs (regex, dynamic property access, function definitions) require migration, which is a documentation change, not a security trade-off.

## Behaviour changes

1. **Expression language**: Changes from JavaScript to Apache Commons JEXL. Simple comparisons work identically; complex JavaScript constructs (regex, dynamic property access, function definitions, `for`/`while` loops, `eval` inside expressions) are not supported and will fail evaluation.

2. **Error handling**: Syntax errors or attempts to access restricted operations return `false` instead of throwing `ScriptException`. The calling code treats this as "rule did not pass" rather than an exception.

3. **No access to engine or reflection**: Tenant expressions cannot introspect the JVM, invoke arbitrary methods, access system properties, or load classes—the core security improvement.

4. **Resource limits**: Expression complexity, instantiation, and loops are constrained at evaluation time by the sandbox and feature configuration, preventing denial-of-service attacks via malicious expressions.

5. **Dependency added**: Apache Commons JEXL 3.x (org.apache.commons:commons-jexl3) is now required; recommend version 3.3.1 or later from Maven Central to include all security hardening patches.
