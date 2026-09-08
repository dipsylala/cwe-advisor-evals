## Verdict

CONFIRMED. The code at line 38 in ReportFilterService.java passes an untrusted analyst-supplied filter expression directly to `jexlEngine.createExpression(filterExpression)` without any sandbox configuration. The JexlEngine is instantiated without a JexlSandbox, granting unrestricted access to all classes and methods reachable from the evaluation context, allowing code injection.

## Source

The vulnerable code path:
1. **Source**: User input flows from the `filterExpression` parameter (line 36), which is described as "analyst-supplied filter expression saved on the report definition"
2. **Sink**: Line 38 calls `jexlEngine.createExpression(filterExpression)` with the unsandboxed engine
3. **Engine Configuration**: Lines 22-26 create the JexlEngine with `new JexlBuilder().create()` and explicitly note "No JexlSandbox is configured"

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

/**
 * Applies a user-authored filter expression to a report's row data.
 *
 * Analysts can save a custom filter (e.g. "amount > 1000 &amp;&amp; region == 'EMEA'")
 * on the report definition. This service evaluates that expression against
 * each row before the row is included in the exported report.
 */
public class ReportFilterService {

    private final JexlEngine jexlEngine;

    public ReportFilterService() {
        // Configure a restricted JexlSandbox: deny-by-default, then explicitly allow
        // only the classes and methods needed for safe expression evaluation.
        JexlSandbox sandbox = new JexlSandbox(false);
        
        // Allow access to the ReportRow class since it is exposed in the evaluation context
        sandbox.allow(ReportRow.class.getName());
        
        // Disable object instantiation to prevent attackers from creating arbitrary objects
        JexlFeatures features = new JexlFeatures();
        features.setNewInstance(false);
        
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

The fix applies a deny-by-default JexlSandbox to restrict what the expression evaluator can access. The sandbox is configured as follows:

1. **Deny-by-default sandbox** (`new JexlSandbox(false)`): Starts with no permissions and requires explicit allowlisting of any classes or methods that should be accessible.

2. **Explicit allowlist** (`sandbox.allow(ReportRow.class.getName())`): Only the ReportRow class is allowed, since it is exposed in the evaluation context (line 50). This prevents access to java.lang.Runtime, java.nio.file.Files, reflection APIs, or any other dangerous classes.

3. **Disable object instantiation** (`JexlFeatures` with `setNewInstance(false)`): Prevents expressions from creating new objects using constructors, an additional layer of defence against exploitation.

4. **Import addition**: Added `org.apache.commons.jexl3.JexlFeatures` and `org.apache.commons.jexl3.introspection.JexlSandbox` to support the sandbox configuration.

The vulnerable engine configuration at lines 22-26 is replaced with a hardened builder that applies both the sandbox and feature restrictions before creating the engine. The applyFilter() method (line 38) now evaluates expressions through this protected engine, blocking injection attempts such as `java.lang.Runtime.getRuntime().exec()`, field-access exploits, or reflection-based class loading.

## Behaviour changes

1. **Legitimate filter expressions still work**: Expressions using the exposed context variables (amount, region, owner, row) and basic operators (>, <, ==, &&, ||) continue to evaluate correctly. The sandbox allows property access on allowed classes, so `row.amount` and similar expressions work.

2. **Malicious code injection is blocked**: Expressions attempting to access restricted classes or instantiate objects now fail safely. JEXL sandbox denials evaluate to `null` rather than throwing an exception, so malicious expressions return `null` and are treated as non-matching filters (the `Boolean.TRUE.equals(result)` check on line 53 rejects null results).

3. **No change to method signature or return type**: The public API of ReportFilterService remains identical; the fix is internal to the constructor and engine configuration.

4. **Expression evaluation semantics preserved**: Supported JEXL operators and property access patterns continue to work. The only change is that disallowed class/method access is now blocked at evaluation time rather than permitted.
