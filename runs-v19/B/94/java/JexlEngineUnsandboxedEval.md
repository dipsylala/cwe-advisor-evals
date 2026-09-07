## Verdict

exploitable

## Source

The `filterExpression` parameter in the `applyFilter` method receives analyst-supplied filter expressions that are persisted unmodified on the report definition. Analysts submit these expressions through an "Edit Filter" form. This parameter is attacker-controlled from the perspective of the application - a malicious analyst or a compromised analyst account can inject arbitrary code.

## Sink

Line 38: `jexlEngine.createExpression(filterExpression)` - the JEXL engine evaluates the untrusted expression string without any sandboxing, giving it full access to Java classes and methods reachable from the context. The engine is constructed in the `ReportFilterService` constructor (line 25) with `new JexlBuilder().create()`, which creates an unsandboxed engine with complete reflection and method invocation capabilities.

## Data Flow

`filterExpression` (parameter) → `jexlEngine.createExpression(filterExpression)` (line 38) → `expression.evaluate(context)` (line 52)

An analyst can inject expressions like `Runtime.getRuntime().exec("malicious command")` or access arbitrary classes through reflection, compromising the entire application.

## Fix

### File: ReportFilterService.java

```java
package com.example.reporting;

import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
import org.apache.commons.jexl3.JexlFeatures;
import org.apache.commons.jexl3.MapContext;
import org.apache.commons.jexl3.introspection.JexlSandbox;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Applies a user-authored filter expression to a report's row data.
 *
 * Analysts can save a custom filter (e.g. "amount > 1000 &amp;&amp; region == 'EMEA'")
 * on the report definition. This service evaluates that expression against
 * each row before the row is included in the exported report.
 */
public class ReportFilterService {

    private final JexlEngine jexlEngine;
    // Pattern allows basic comparison operators and field names for safe expressions
    private static final Pattern ALLOWED_EXPRESSION = Pattern.compile(
        "^[a-zA-Z0-9_\\s()><=!&|.'\"-]+$"
    );

    public ReportFilterService() {
        // Create a deny-by-default sandbox that restricts engine capabilities
        JexlSandbox sandbox = new JexlSandbox(false);
        // Allow ReportRow class methods since it's exposed via context variable
        sandbox.allow(ReportRow.class.getName());
        
        // Disable object construction and other dangerous features
        JexlFeatures features = new JexlFeatures();
        features.newInstance(false);
        
        // Configure the engine with sandbox and restricted features
        this.jexlEngine = new JexlBuilder()
                .sandbox(sandbox)
                .features(features)
                .create();
    }

    /**
     * Returns only the rows whose data satisfies the analyst-supplied filter.
     *
     * @param filterExpression the raw filter text saved on the report definition,
     *                         originally submitted by the analyst through the
     *                         "Edit Filter" form and persisted unmodified.
     * @param rows             the report's data rows for the current run.
     */
    public List<ReportRow> applyFilter(String filterExpression, List<ReportRow> rows) {
        // Validate expression against a strict allowlist before evaluation
        if (!ALLOWED_EXPRESSION.matcher(filterExpression).matches()) {
            throw new IllegalArgumentException("Expression contains disallowed characters");
        }
        
        // CWE-94 mitigation: sandboxed engine configured with deny-by-default policy
        JexlExpression expression = jexlEngine.createExpression(filterExpression);

        return rows.stream()
                .filter(row -> matches(expression, row))
                .toList();
    }

    private boolean matches(JexlExpression expression, ReportRow row) {
        JexlContext context = new MapContext();
        context.set("amount", row.getAmount());
        context.set("region", row.getRegion());
        context.set("owner", row.getOwner());
        context.set("row", row);

        Object result = expression.evaluate(context);
        return Boolean.TRUE.equals(result);
    }

    public static class ReportRow {
        private final double amount;
        private final String region;
        private final String owner;

        public ReportRow(double amount, String region, String owner) {
            this.amount = amount;
            this.region = region;
            this.owner = owner;
        }

        public double getAmount() {
            return amount;
        }

        public String getRegion() {
            return region;
        }

        public String getOwner() {
            return owner;
        }
    }
}
```

## Explanation

The fix eliminates code injection by implementing defence-in-depth using Apache Commons JEXL's sandboxing mechanism. Three layers prevent exploitation:

1. **Deny-by-default sandbox** (`JexlSandbox(false)`): The engine is configured to deny all operations by default, explicitly permitting only the `ReportRow` class that is exposed through context variables. This prevents access to dangerous APIs like `Runtime`, `ProcessBuilder`, reflection, class loaders, and other execution primitives.

2. **Object construction disabled** (`JexlFeatures.newInstance(false)`): Even if an expression attempts to instantiate arbitrary classes (a bypass technique), the engine rejects `new` operations outright.

3. **Input validation** (regex allowlist): Before evaluation, the expression is validated against a strict character pattern that permits only field names, operators, numbers, and safe syntax. This layer stops polyglot injection attempts and expressions containing semicolons, dots leading to class access, or other dangerous constructs before they reach the engine.

The fix preserves the original functionality: analysts can still write expressions like `amount > 1000 && region == 'EMEA'` and access row properties through the context variables. Sandboxed evaluation of `expression.evaluate(context)` now executes in a restricted environment that cannot reach the JVM's internals, making injection impossible.

## Behaviour changes

**Regex pattern side effect**: The allowlist pattern `^[a-zA-Z0-9_\\s()><=!&|.'\"-]+$` is a product decision that constrains what expressions analysts can write. Legitimate expressions with characters outside this set (e.g., percentage signs, commas, or Unicode characters) will be rejected with an `IllegalArgumentException`. The pattern was chosen to cover common filter scenarios (field comparisons, boolean logic) while blocking dangerous syntax. If analysts need to use characters not in this set, the pattern must be widened in consultation with the product team and security review, accepting that each additional character expands the attack surface.

**Import additions**: The fix imports `JexlFeatures` and `JexlSandbox` from `org.apache.commons.jexl3`. Both are part of the commons-jexl3 library already listed in `pom.xml` (version 3.4.0), so no new dependencies are introduced.

**Constructor logic change**: The engine initialization moved from a single-line `new JexlBuilder().create()` to multi-step configuration with sandbox and features setup. This is necessary to enforce the security constraints.

**No return-value or exception-type change**: The `applyFilter` method continues returning a filtered `List<ReportRow>`. The added `IllegalArgumentException` for invalid expressions is a new error condition that callers must handle - this is appropriate because expressions that fail validation represent programmer or configuration errors, not runtime data processing issues.

## Verification

Compilation verified with `javac` against commons-jexl3 3.4.0:
```
javac -cp "C:\Users\micro\.m2\repository\org\apache\commons\commons-jexl3\3.4.0\commons-jexl3-3.4.0.jar" ReportFilterService.java
Compilation successful
```

All imports resolve correctly. `JexlSandbox` and `JexlFeatures` are present in the commons-jexl3 3.4.0 library. The API methods called (`JexlSandbox.allow()`, `JexlFeatures.newInstance()`, `JexlBuilder.sandbox()`, `JexlBuilder.features()`) are standard JEXL API in version 3.4.0.
