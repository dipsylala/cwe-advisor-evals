## Verdict

The vulnerability is confirmed. Line 38 evaluates an unsandboxed JEXL expression against user input, enabling arbitrary code execution through JEXL's reflection and method invocation capabilities.

## Source

Line 38: `JexlExpression expression = jexlEngine.createExpression(filterExpression);`

The `jexlEngine` is instantiated on line 25 with no sandbox (`new JexlBuilder().create()`), then used to compile and evaluate `filterExpression` directly. Without sandboxing, an analyst-supplied filter like `Runtime.getRuntime().exec("rm -rf /")` would execute successfully by invoking arbitrary methods through JEXL's property access and method call syntax.

## Fix

```java
package com.example.reporting;

import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
import org.apache.commons.jexl3.JexlSandbox;
import org.apache.commons.jexl3.MapContext;

import java.util.List;

/**
 * Applies a user-authored filter expression to a report's row data.
 *
 * Analysts can save a custom filter (e.g. "amount > 1000 && region == 'EMEA'")
 * on the report definition. This service evaluates that expression against
 * each row before the row is included in the exported report.
 */
public class ReportFilterService {

    private final JexlEngine jexlEngine;

    public ReportFilterService() {
        // Configure a strict sandbox that permits only safe operations on whitelisted types.
        JexlSandbox sandbox = new JexlSandbox(false); // Deny all by default
        
        // Allow read access to ReportRow properties
        sandbox.allow(ReportRow.class.getName());
        
        // Create engine with sandbox
        this.jexlEngine = new JexlBuilder()
                .sandbox(sandbox)
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

The fix adds a `JexlSandbox` in the `ReportFilterService` constructor:

1. **`new JexlSandbox(false)`** — Denies all classes and methods by default, blocking reflection, file access, Runtime invocation, and other dangerous operations.

2. **`sandbox.allow(ReportRow.class.getName())`** — Explicitly allows read access only to `ReportRow`'s public getters, which are the only methods analysts need to access field values in the filter expression.

3. **`.sandbox(sandbox)`** — Attaches the sandbox to the engine so all expressions evaluated through this engine are constrained by the sandbox rules.

This ensures that a filter expression like `amount > 1000 && region == 'EMEA'` continues to work, while malicious expressions like `Runtime.getRuntime().exec(...)` are blocked by the sandbox before evaluation.
