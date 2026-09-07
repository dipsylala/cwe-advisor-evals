## Verdict

Real vulnerability confirmed. The JexlEngine is instantiated without a sandbox, allowing arbitrary code execution through analyst-supplied filter expressions. Remediated by applying deny-by-default sandbox restrictions.

## Source

**Location:** E:/Github/cwe-advisor/evals/cases/94/java/JexlEngineUnsandboxedEval/ReportFilterService.java:38

**Call chain:**
1. Analyst supplies `filterExpression` (String) through report definition form
2. `applyFilter(String filterExpression, List<ReportRow> rows)` receives untrusted input
3. `jexlEngine.createExpression(filterExpression)` at line 38 compiles expression without restrictions
4. `expression.evaluate(context)` at line 52 executes the compiled expression with unrestricted access to Java classes

**Vulnerability:** No JexlSandbox configured; the engine has full, unrestricted access to every class and method in the runtime. An attacker who can control the filterExpression can invoke arbitrary methods, access reflection, or construct objects.

## Fix

### File: ReportFilterService.java

```java
package com.example.reporting;

import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
import org.apache.commons.jexl3.JexlFeatures;
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
        // Create a deny-by-default sandbox to restrict what the engine can access.
        // Only allow the ReportRow class; disable object construction.
        JexlSandbox sandbox = new JexlSandbox(false);
        sandbox.allow(ReportRow.class.getName());

        this.jexlEngine = new JexlBuilder()
                .sandbox(sandbox)
                .features(new JexlFeatures().newInstance(false))
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

The fix applies a deny-by-default sandbox to the JexlEngine using Apache Commons JEXL's `JexlSandbox(false)` and `JexlFeatures.newInstance(false)` configuration:

1. **Sandbox (deny-by-default)**: `new JexlSandbox(false)` blocks access to all Java classes except those explicitly allowed via `sandbox.allow()`.
2. **Allowed class**: `sandbox.allow(ReportRow.class.getName())` permits only the ReportRow class, which is safe to expose because it only provides read access to the row's data fields (amount, region, owner) through public getters.
3. **No object construction**: `JexlFeatures.newInstance(false)` prevents the expression from constructing new objects, closing a second attack vector.
4. **Imports added**: JexlSandbox and JexlFeatures (both in org.apache.commons.jexl3 package).

The `applyFilter()` and `matches()` methods remain unchanged; they correctly expose row data through the context's named variables, and the sandbox ensures expressions can only operate on those variables and the restricted ReportRow class.

## Behaviour changes

**Before:** Expressions like `"amount > 1000 && region == 'EMEA'"` work; expressions like `"java.lang.Runtime.getRuntime().exec('cmd')"` or `"java.lang.System.exit(1)"` also execute.

**After:** Legitimate expressions still work. Malicious expressions that attempt to:
- Call arbitrary Java methods (e.g., Runtime.getRuntime(), System.exit())
- Access reflection APIs
- Instantiate classes
- Reference forbidden namespaces

...evaluate to `null` and are safely rejected. The expression can only access:
- Operators (>, ==, &&, etc.)
- Named context variables (amount, region, owner, row)
- Public methods of ReportRow (getAmount(), getRegion(), getOwner())
