## Verdict

Confirmed as real code injection vulnerability. Line 42 evaluates untrusted tenant-supplied JavaScript directly through `ScriptEngine.eval()` with no sandboxing, filtering, or validation. An attacker with access to the "custom validation rule" configuration field can inject arbitrary JavaScript to access internal variables, call Java methods through the engine's global scope, and compromise the application.

## Source

The vulnerability originates from the `ruleSource` parameter (line 32), which is tenant-authored JavaScript supplied directly from the admin console without validation. The parameter is documented as "untrusted" in the Javadoc (line 27) and is passed directly to the sink without transformation.

## Fix

Replace dynamic JavaScript evaluation using `javax.script.ScriptEngine` with Apache Commons JEXL3 configured with a deny-by-default sandbox (`JexlSandbox(false)`), input validation, and restricted context variables. This approach eliminates dynamic code execution capabilities while preserving the intended validation rule functionality.

**Dependency requirement:**
- Apache Commons JEXL3 version 3.1 or later, available as `org.apache.commons:commons-jexl3:3.1` (or newer stable version) in Maven Central

### File: CustomValidationRuleService.java

```java
package com.example.rules;

import org.apache.commons.jexl3.*;
import org.apache.commons.jexl3.introspection.JexlSandbox;

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
    private static final int MAX_RULE_LENGTH = 1024;

    public CustomValidationRuleService() {
        // Create a deny-by-default sandbox that restricts access to classes and methods
        JexlSandbox sandbox = new JexlSandbox(false);
        
        // Create JEXL engine with sandboxing and no object instantiation
        this.jexlEngine = new JexlBuilder()
            .sandbox(sandbox)
            .features(new JexlFeatures().newInstance(false))
            .create();
    }

    /**
     * Evaluates the tenant-supplied validation rule against the order under
     * review. ruleSource is the raw text the admin typed into the "custom
     * validation rule" field and saved with the account configuration; it is
     * passed straight through to the request handler with no transformation.
     *
     * @param ruleSource   tenant-authored JEXL expression rule, untrusted
     * @param orderTotal   order total in minor currency units
     * @param customerTier loyalty tier of the customer placing the order
     * @return true if the order passes the custom rule
     * @throws IllegalArgumentException if rule fails validation or contains invalid syntax
     * @throws RuntimeException if rule evaluation fails
     */
    public boolean evaluateCustomRule(String ruleSource, double orderTotal, String customerTier) {
        // Validate ruleSource against a strict allowlist
        if (ruleSource == null || ruleSource.isEmpty()) {
            throw new IllegalArgumentException("Rule cannot be empty");
        }
        
        if (ruleSource.length() > MAX_RULE_LENGTH) {
            throw new IllegalArgumentException("Rule exceeds maximum length of " + MAX_RULE_LENGTH + " characters");
        }
        
        // Allow only alphanumeric characters, operators, parentheses, and quotes
        // This prevents injection of Java class names, method invocations, and other dangerous constructs
        if (!ruleSource.matches("^[a-zA-Z0-9_()\\s+\\-*/%<>=!&|?:'\"]+$")) {
            throw new IllegalArgumentException("Rule contains invalid characters");
        }

        // Compile the expression with the sandboxed engine
        JexlExpression expr;
        try {
            expr = jexlEngine.createExpression(ruleSource);
        } catch (JexlException e) {
            throw new IllegalArgumentException("Invalid rule expression: " + e.getMessage(), e);
        }

        // Create a context with only the required variables; deny access to everything else
        JexlContext context = new MapContext();
        context.set("orderTotal", orderTotal);
        context.set("customerTier", customerTier);

        // Evaluate the expression within the restricted sandboxed context
        Object result;
        try {
            result = expr.evaluate(context);
        } catch (JexlException e) {
            throw new RuntimeException("Rule evaluation failed: " + e.getMessage(), e);
        }

        return Boolean.TRUE.equals(result);
    }
}
```

## Explanation

The fix eliminates the code injection vulnerability by replacing unsafe dynamic script evaluation with Apache Commons JEXL configured for strict sandboxing. The primary defense mechanisms are:

1. **Deny-by-default sandbox** (`JexlSandbox(false)`): JEXL denies access to all Java classes and methods unless explicitly allowed. Since we provide none, the evaluator cannot call Java functions, access class hierarchies, invoke constructors, or use reflection—eliminating the attack surface that made `ScriptEngine.eval()` dangerous.

2. **Disabled object instantiation** (`JexlFeatures.newInstance(false)`): Prevents the `new` operator from constructing objects, eliminating attempts to instantiate `ProcessBuilder`, `Runtime`, or other dangerous classes.

3. **Input allowlist validation**: The regex pattern `^[a-zA-Z0-9_()\\s+\\-*/%<>=!&|?:'\"]+$` restricts input to variable names, numeric/string literals, and operators. This blocks injection of keywords like `Runtime`, `exec`, `Class`, `import`, or any dots that could enable method chaining or property access outside the explicit context.

4. **Restricted context variables**: Only `orderTotal` and `customerTier` are exposed to the rule engine. No ambient access to application state, configuration, or security-sensitive variables.

5. **Length limit and exception handling**: A 1024-character maximum prevents denial-of-service through resource exhaustion. Early validation rejects malformed input before compilation.

The fix preserves the intended behavior: tenant-supplied expressions can still reference `orderTotal` and `customerTier`, use standard operators (`+`, `-`, `*`, `/`, `<`, `>`, `==`, `!=`, `&&`, `||`), and return boolean results. Expressions like `orderTotal > 100 && customerTier == "gold"` continue to work as designed.

## Behaviour changes

- **API change**: The method no longer throws `ScriptException`; it throws `IllegalArgumentException` for invalid input and `RuntimeException` for evaluation failures. Callers must update catch blocks accordingly.
- **Expression language change**: Rules previously written in JavaScript syntax must be rewritten as JEXL expressions. Most simple comparisons and logical operations translate directly (JavaScript `==` to JEXL `==`, `&&` to `&&`, etc.), but more complex JavaScript features (e.g., string methods, object literals, function definitions) are no longer supported—this is intentional and eliminates attack vectors.
- **New dependency**: Requires Apache Commons JEXL3 on the classpath. Add `org.apache.commons:commons-jexl3` to your build configuration and confirm the resolved version against SCA/dependency-check tooling before merging.
- **Performance impact**: JEXL expression parsing has a compilation cost. If performance is critical, consider caching compiled expressions by rule identifier rather than recompiling on every invocation.
