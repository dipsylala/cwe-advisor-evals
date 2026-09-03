## Verdict

Confirmed. The JEXL engine is instantiated without a sandbox, allowing arbitrary code execution through user-supplied filter expressions. An analyst can inject expressions accessing `java.lang.Runtime`, reflection, or other unrestricted APIs.

## Source

`ReportFilterService.java`, line 38:
```java
JexlExpression expression = jexlEngine.createExpression(filterExpression);
```

The `filterExpression` parameter originates from analyst input submitted through the "Edit Filter" form and persisted unmodified. The `jexlEngine` is created at line 25 with `new JexlBuilder().create()` — no sandbox is configured.

## Fix

Replace the unsandboxed JEXL engine with a deny-by-default sandbox that permits only property access on context variables:

```java
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
        // Deny-by-default sandbox: no class instantiation, no static methods,
        // no constructor access. Only property access on context variables is permitted.
        JexlSandbox sandbox = new JexlSandbox(false);
        JexlFeatures features = new JexlFeatures()
            .newInstance(false)   // Disallow object construction
            .sideEffect(false);   // Disallow side effects

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

The fix applies three layers of restriction:

1. **`JexlSandbox(false)`** — Deny-by-default mode. No classes are whitelisted by default; the attacker cannot reference or instantiate arbitrary classes such as `java.lang.Runtime`.

2. **`newInstance(false)`** — Disables object construction, preventing expressions like `new java.lang.ProcessBuilder(...)`.

3. **`sideEffect(false)`** — Blocks side-effect operations that could modify state outside the expression context.

The sandboxed engine still permits the expression to read context variables (`amount`, `region`, `owner`, `row`) and perform safe comparisons and arithmetic operations — the legitimate use case. Attempting to inject `java.lang.Runtime.getRuntime()` or access fields via reflection will fail silently (JEXL evaluates to `null`) or throw a restricted-access exception, closing the code injection vector.

## Behaviour changes

- Analyst-authored filters that use only property access, arithmetic, and comparison operators (e.g., `amount > 1000 && region == 'EMEA'`) continue to work unchanged.
- Any attempt to access Java classes, invoke static methods, instantiate objects, or use reflection will fail. Expressions like `java.lang.Runtime.getRuntime().exec(...)` are rejected.
- Invalid expressions now fail safely with `null` or a JexlException rather than executing arbitrary code.
- No change to the public API or the return value of `applyFilter()` — the filtering logic remains functionally identical for legitimate use cases.
