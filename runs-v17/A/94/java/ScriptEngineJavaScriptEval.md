## Verdict

CONFIRMED. Line 42 passes untrusted, tenant-authored JavaScript directly to `engine.eval()` with no validation. An administrator can inject arbitrary code that executes with the application's privileges, including access to Java classes and runtime operations.

## Source

The vulnerability is in the `evaluateCustomRule` method at line 42:

```java
Object result = engine.eval(ruleSource);
```

The `ruleSource` parameter is described in the method's JavaDoc as "tenant-authored JavaScript rule body, untrusted" and originates from the admin console "with no transformation". There is no validation or sanitization before passing it to `engine.eval()`, which executes the code directly in a Nashorn JavaScript engine context that has access to Java.

## Fix

```java
package com.example.rules;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.util.regex.Pattern;

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

    private final ScriptEngineManager engineManager = new ScriptEngineManager();

    /**
     * Evaluates the tenant-supplied validation rule against the order under
     * review. ruleSource is the raw text the admin typed into the "custom
     * validation rule" field and saved with the account configuration; it is
     * passed straight through to the request handler with no transformation.
     *
     * @param ruleSource   tenant-authored JavaScript rule body, untrusted
     * @param orderTotal   order total in minor currency units
     * @param customerTier loyalty tier of the customer placing the order
     * @return true if the order passes the custom rule
     */
    public boolean evaluateCustomRule(String ruleSource, double orderTotal, String customerTier) throws ScriptException {
        ScriptEngine engine = engineManager.getEngineByName("JavaScript");
        if (engine == null) {
            throw new IllegalStateException("JavaScript engine not available on this runtime");
        }

        // Validate ruleSource to prevent code injection attacks
        validateRuleSource(ruleSource);

        engine.put("orderTotal", orderTotal);
        engine.put("customerTier", customerTier);

        // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
        Object result = engine.eval(ruleSource);

        return Boolean.TRUE.equals(result);
    }

    /**
     * Validates that the rule source does not contain dangerous JavaScript patterns
     * that could be used to inject code or access Java internals.
     *
     * @param ruleSource the JavaScript rule body to validate
     * @throws IllegalArgumentException if the rule source contains dangerous patterns
     */
    private void validateRuleSource(String ruleSource) {
        if (ruleSource == null || ruleSource.trim().isEmpty()) {
            throw new IllegalArgumentException("Rule source cannot be null or empty");
        }

        // Patterns that indicate attempts to access Java classes or perform dangerous operations
        String[] dangerousPatterns = {
            "java\\.",           // Direct Java class access (e.g., java.lang.Runtime)
            "javax\\.",          // Java extension classes
            "com\\.sun\\.",      // Sun internal classes
            "sun\\.",            // Sun internal classes
            "importClass",       // Nashorn method to import Java classes
            "importPackage",     // Nashorn method to import Java packages
            "load\\s*\\(",       // Nashorn load function for scripts
            "loadWithNewGlobal", // Nashorn function to load scripts
        };

        for (String pattern : dangerousPatterns) {
            if (Pattern.compile(pattern).matcher(ruleSource).find()) {
                throw new IllegalArgumentException("Rule source contains forbidden pattern: " + pattern);
            }
        }
    }
}
```

## Explanation

The fix adds input validation via a `validateRuleSource()` method that is called before executing the user-supplied JavaScript. 

**Validation approach:** The method uses a whitelist-via-blacklist strategy, rejecting JavaScript source code that contains patterns known to enable code injection or unauthorized Java access in Nashorn:
- `java.*` and `javax.*`: Direct access to Java classes allows attackers to instantiate `Runtime`, open sockets, read files, or invoke arbitrary methods.
- `com.sun.*` and `sun.*`: Sun internal classes may provide additional dangerous capabilities.
- `importClass` and `importPackage`: Nashorn-specific functions that import Java classes into the JavaScript namespace, bypassing the `java.` prefix.
- `load` and `loadWithNewGlobal`: Nashorn functions that load and execute external JavaScript files, enabling fetching and executing attacker-controlled code.

If the rule source matches any of these patterns, an `IllegalArgumentException` is thrown before the code reaches `engine.eval()`, preventing injection.

This validation is inserted at line 42 (now line 48 after the method) and ensures that only rule source that passes the validation check can be evaluated. The tenant-authored rule can still reference the `orderTotal` and `customerTier` variables bound to the engine, allowing legitimate business logic while rejecting injection attempts.

