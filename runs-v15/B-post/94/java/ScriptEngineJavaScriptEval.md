## Verdict

exploitable

## Source

The `ruleSource` parameter to `evaluateCustomRule()` method (line 32), documented as "tenant-authored JavaScript rule body, untrusted" and passed directly from the admin console without transformation or validation.

## Fix

**Vulnerable code (line 42):**
```java
Object result = engine.eval(ruleSource);
```

**Fixed code:**
Replace the `ScriptEngine.eval()` call with Apache Commons JEXL evaluated in a deny-by-default sandbox:

```java
package com.example.rules;

import org.apache.commons.jexl3.*;

public class CustomValidationRuleService {

    private final JexlEngine engine;

    public CustomValidationRuleService() {
        // Create a deny-by-default sandbox to restrict what the expression can access
        JexlSandbox sandbox = new JexlSandbox(false);
        this.engine = new JexlBuilder()
            .sandbox(sandbox)
            .create();
    }

    /**
     * Evaluates the tenant-supplied validation rule against the order under
     * review. ruleSource is the raw text the admin typed into the "custom
     * validation rule" field and saved with the account configuration.
     *
     * @param ruleSource   tenant-authored expression rule body, untrusted
     * @param orderTotal   order total in minor currency units
     * @param customerTier loyalty tier of the customer placing the order
     * @return true if the order passes the custom rule
     */
    public boolean evaluateCustomRule(String ruleSource, double orderTotal, String customerTier) throws JexlException {
        // Parse the expression (this validates syntax)
        JexlExpression expr = engine.createExpression(ruleSource);
        if (expr == null) {
            throw new IllegalArgumentException("Invalid rule syntax");
        }

        // Create context and bind safe variables
        JexlContext context = new MapContext();
        context.set("orderTotal", orderTotal);
        context.set("customerTier", customerTier);

        // Evaluate the expression in the sandboxed context
        Object result = expr.evaluate(context);

        return Boolean.TRUE.equals(result);
    }
}
```

**Dependency addition required:**

Add Apache Commons JEXL to your build configuration (version must be confirmed against your SCA/dependency-check tooling):

Maven `pom.xml`:
```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-jexl3</artifactId>
    <version>[check SCA]</version>
</dependency>
```

Gradle `build.gradle`:
```gradle
implementation 'org.apache.commons:commons-jexl3:[check SCA]'
```

## Explanation

The fix eliminates code injection by replacing the unrestricted JavaScript engine eval with Apache Commons JEXL evaluated in a deny-by-default sandbox. The `JexlSandbox(false)` constructor creates a deny-by-default sandbox that blocks access to Java classes, constructors, and method invocations by default, allowing only safe variable access. The expression is parsed and evaluated against this restricted context containing only the `orderTotal` and `customerTier` variables, preventing the attacker from accessing the Java environment, file system, network, or application internals. JEXL is purpose-built for expression evaluation with security in mind, unlike the general-purpose JavaScript engine which exposes the full JVM through its bridge API.

## Behaviour changes

- **Dependency addition**: Apache Commons JEXL3 must be added to the project's build configuration. This is a new runtime dependency required by the fix.
- **Exception type change**: The method now throws `JexlException` (from JEXL) instead of `ScriptException`. Callers must handle this or declare it in their own signature. `JexlException` is thrown when expression parsing or evaluation fails, which is semantically appropriate for invalid rule syntax.
- **Expression language syntax change**: Tenant-supplied rules must now use JEXL expression syntax (subset of JavaScript/Java expressions) instead of full Nashorn JavaScript. This includes differences in string escaping, operator precedence, and available functions. Existing rules may require migration.
- **Removal of deprecated API**: The Nashorn JavaScript engine was deprecated in JDK 11 and removed in JDK 15+, so this fix also removes the dependency on a deprecated and unsupported API.

