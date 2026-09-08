## Verdict
CONFIRMED. The code uses Apache Commons JEXL to evaluate user-supplied filter expressions without configuring a JexlSandbox. An attacker can inject malicious code through the filterExpression parameter to execute arbitrary operations on the application's classes and resources.

## Source
File: ReportFilterService.java
Line: 38

The vulnerable code:
```java
JexlExpression expression = jexlEngine.createExpression(filterExpression);
```

The root cause: The JexlEngine is created without a sandbox (line 25), and user-supplied expressions are evaluated directly without restriction. The comments in the code explicitly acknowledge this: "No JexlSandbox is configured, so the engine has full, unrestricted access to every class and method reachable from the context."

## Fix
### File: ReportFilterService.java
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
 * Analysts can save a custom filter (e.g. "amount > 1000 &amp;&amp; region == 'EMEA'")
 * on the report definition. This service evaluates that expression against
 * each row before the row is included in the exported report.
 */
public class ReportFilterService {

    private final JexlEngine jexlEngine;

    public ReportFilterService() {
        // Create a sandbox that restricts access to only safe operations and the
        // specific classes and methods needed for filter evaluation.
        JexlSandbox sandbox = new JexlSandbox(false);
        
        // Allow access to ReportRow and its public getter methods
        sandbox.allow(ReportRow.class.getName());
        sandbox.allow(ReportRow.class, "getAmount", "getRegion", "getOwner");
        
        // Arithmetic and comparison operators are allowed by default in the sandbox
        // Logical operators (&&, ||, !) are allowed by default
        // String operators are allowed by default
        
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
The fix applies a JexlSandbox to the JexlEngine, restricting what can be accessed during expression evaluation:

1. **Import JexlSandbox**: Added `import org.apache.commons.jexl3.JexlSandbox;` to access the sandboxing API.

2. **Create a restrictive sandbox**: `new JexlSandbox(false)` creates a sandbox with no default permissions, starting from a deny-all posture.

3. **Whitelist only required access**:
   - `sandbox.allow(ReportRow.class.getName())` permits the ReportRow class to be accessed
   - `sandbox.allow(ReportRow.class, "getAmount", "getRegion", "getOwner")` restricts method access to only the safe getter methods needed for filtering

4. **Attach sandbox to JexlBuilder**: The sandbox is passed via `.sandbox(sandbox)` when building the engine, so all subsequent expression evaluations respect these restrictions.

5. **Arithmetic, comparison, and logical operators** remain available by default in JEXL sandboxes, allowing expressions like `amount > 1000 && region == 'EMEA'` to work as intended.

This prevents attackers from injecting code that accesses dangerous classes (System, Runtime, File I/O, etc.) or methods while maintaining the legitimate filtering functionality for analysts.
