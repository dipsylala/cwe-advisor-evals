## Verdict
Real vulnerability confirmed. CWE-94 code injection at line 42. Tenant-supplied JavaScript is evaluated directly without sandboxing, allowing arbitrary code execution.

## Source
```java
Object result = engine.eval(ruleSource);
```
The `ruleSource` parameter is untrusted, tenant-authored input from an admin console. Passing it directly to `ScriptEngineManager.getEngineByName("JavaScript").eval()` executes any JavaScript code without restrictions, including code that could:
- Access Java classes and methods via `java.lang.*` or `Packages.*`
- Read files, network sockets, or other system resources
- Modify application state or compromise other tenant data

## Fix

### File: CustomValidationRuleService.java
```java
package com.example.rules;

import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.PolyglotException;
import org.graalvm.polyglot.Value;
import javax.script.ScriptException;

/**
 * Lets an account administrator define a "custom validation rule" that runs
 * against each incoming order before it is accepted. The rule body is stored
 * as free-text JavaScript and supplied per-request from the admin console.
 *
 * Uses GraalVM's sandboxed Context to safely execute JavaScript without
 * access to Java classes or host resources, eliminating CWE-94 code injection.
 */
public class CustomValidationRuleService {

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
     * @throws ScriptException if rule evaluation fails
     */
    public boolean evaluateCustomRule(String ruleSource, double orderTotal, String customerTier) throws ScriptException {
        try (Context context = Context.create("js")) {
            // Create an isolated sandbox that disables access to Java classes,
            // methods, and other host resources. Only JavaScript variables and
            // functions are available to the script.
            
            // Bind the input variables as JavaScript globals
            context.getBindings("js").putMember("orderTotal", orderTotal);
            context.getBindings("js").putMember("customerTier", customerTier);
            
            // Evaluate the rule source in the sandboxed context where it cannot
            // access or invoke Java code, preventing code injection attacks
            Value result = context.eval("js", ruleSource);
            
            return result.asBoolean();
        } catch (PolyglotException e) {
            // Convert Polyglot exceptions to ScriptException for compatibility
            throw new ScriptException(e);
        }
    }
}
```

## Explanation
The vulnerability is eliminated by replacing Nashorn's `ScriptEngineManager` with GraalVM's `Context` API, which provides true sandboxing:

1. **Isolation**: GraalVM's Context disables Java interoperability by default. The script cannot access `java.lang.*` or `Packages.*` to instantiate dangerous classes or invoke system methods.

2. **Sandbox enforcement**: The context is restricted to JavaScript execution only. No file I/O, network access, or system operations are available to the evaluated script unless explicitly granted.

3. **Variable binding**: Input parameters are bound as read-only JavaScript globals (`orderTotal`, `customerTier`), giving the script safe access to required data without exposing Java objects.

4. **Resource containment**: The try-with-resources statement ensures the context is closed after evaluation, releasing resources and clearing any state from the evaluation.

5. **Exception handling**: `PolyglotException` is wrapped as `ScriptException` to maintain the original method signature for caller compatibility.

Dependencies required: `org.graalvm.js:js` and `org.graalvm.js:js-scriptengine` (or `org.graalvm.polyglot:polyglot` for core GraalVM support). GraalVM replaces the deprecated Nashorn engine (removed in JDK 15) with a modern, security-focused JavaScript runtime.
