## Verdict

CONFIRMED: The vulnerability is exploitable. At line 42, `engine.eval(ruleSource)` passes untrusted tenant-supplied JavaScript directly to the Nashorn/Rhino script engine without sandboxing, allowlisting, or any other control. An attacker with admin console access can inject arbitrary code that executes with the application's full privileges.

## Source

Parameter `ruleSource` at line 32: described as "tenant-authored JavaScript rule body, untrusted" and passed from the admin console with "no transformation."

## Fix

Replace `javax.script.ScriptEngine` with Apache Commons JEXL configured with a deny-by-default sandbox. JEXL provides a purpose-built expression evaluator with sandboxing that restricts the expression to property access on explicitly passed context variables, preventing type references, method invocation, object construction, and other dangerous operations.

### File: CustomValidationRuleService.java

```java
package com.example.rules;

import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlException;
import org.apache.commons.jexl3.JexlExpression;
import org.apache.commons.jexl3.JexlSandbox;
import org.apache.commons.jexl3.MapContext;

/**
 * Lets an account administrator define a "custom validation rule" that runs
 * against each incoming order before it is accepted. The rule body is stored
 * as free-text JavaScript and supplied per-request from the admin console.
 *
 * Targets JDK 11, where the Nashorn engine still ships in the JDK itself
 * (deprecated by JEP 335 but not yet removed; removal followed in JDK 15 per
 * JEP 372), so ScriptEngineManager().getEngineByName("JavaScript") resolves
 * to a live engine and this eval() call is a genuine, reachable sink.
 */
public class CustomValidationRuleService {

    private final JexlEngine jexlEngine;

    public CustomValidationRuleService() {
        // Create a deny-by-default sandbox to restrict expression evaluation
        JexlSandbox sandbox = new JexlSandbox(false);
        
        // Build the JEXL engine with the sandbox
        this.jexlEngine = new JexlBuilder()
                .sandbox(sandbox)
                .create();
    }

    /**
     * Evaluates the tenant-supplied validation rule against the order under
     * review. ruleSource is the raw text the admin typed into the "custom
     * validation rule" field and saved with the account configuration; it is
     * passed straight through to the request handler with no transformation.
     *
     * @param ruleSource   tenant-authored expression rule body, untrusted
     * @param orderTotal   order total in minor currency units
     * @param customerTier loyalty tier of the customer placing the order
     * @return true if the order passes the custom rule
     */
    public boolean evaluateCustomRule(String ruleSource, double orderTotal, String customerTier) throws JexlException {
        // Parse the expression - fails fast if syntax is invalid
        JexlExpression expression = jexlEngine.createExpression(ruleSource);
        
        // Create a context with only the necessary variables
        MapContext context = new MapContext();
        context.set("orderTotal", orderTotal);
        context.set("customerTier", customerTier);
        
        // Evaluate the expression with restricted context and sandbox
        // Sandbox violations return null, so treat null as false
        Object result = expression.evaluate(context);
        
        return Boolean.TRUE.equals(result);
    }
}
```

## Explanation

The fix replaces the Nashorn `ScriptEngine.eval()` sink with Apache Commons JEXL 3.x, configured with a deny-by-default sandbox (`new JexlSandbox(false)`). This eliminates the code injection vulnerability by restricting the untrusted expression to property access on explicitly passed context variables. The sandbox prevents type references (`T(java.lang.Runtime)`), method invocation, object construction, reflection, and field access—all mechanisms an attacker could use to escape the restricted context. The constructor initializes a single shared `JexlEngine` instance with the sandbox, and `evaluateCustomRule()` creates a fresh `MapContext` for each call containing only the two safe variables (`orderTotal` and `customerTier`). Expressions that violate the sandbox (e.g., attempting to call `getRuntime()` or access a method) evaluate to `null` rather than throwing, so `Boolean.TRUE.equals(result)` safely treats both `null` and `false` as failing the rule. Invalid expressions throw `JexlException` on parsing, allowing the caller to log or audit malformed rules.

Add `org.apache.commons:commons-jexl3` (version to be determined by SCA/dependency management; the guidance names the library but not a specific version) to your build configuration.

## Behaviour changes

- The method's throws clause changes from `ScriptException` to `JexlException`. Both are checked exceptions; callers treating either as fatal error will work unchanged.
- Malformed expressions now throw `JexlException` on the `createExpression()` call rather than on the `eval()` call, failing earlier and preventing partial evaluation.
- Expressions that violate the sandbox return `null` (and thus `false`) rather than throwing; this is safe and intentional—the sandbox treats violations as denials, not errors.
- The expression language changes from full JavaScript to JEXL's expression subset (property access, comparison, arithmetic, logical operators, conditional expressions). Complex rules that previously relied on JavaScript function calls, object construction, or method invocation will no longer work; those must be migrated to JEXL-compatible syntax (e.g., `orderTotal > 100 && customerTier == "premium"` instead of JavaScript function calls).
- Each evaluation now creates a fresh context, preventing expressions from modifying engine state or accessing variables from previous evaluations.
