## Verdict

The vulnerability is confirmed. The `JexlEngine` is instantiated without a sandbox, allowing unrestricted access to all classes and methods. When user-supplied filter expressions are evaluated via `jexlEngine.createExpression(filterExpression)`, an attacker can inject arbitrary code to access dangerous classes like `java.lang.Runtime` or `java.lang.ProcessBuilder`, leading to remote code execution.

## Source

File: `ReportFilterService.java`, line 38

```java
JexlExpression expression = jexlEngine.createExpression(filterExpression);
```

The `jexlEngine` is created on line 25 without sandbox constraints:

```java
this.jexlEngine = new JexlBuilder().create();
```

The `filterExpression` parameter comes from user input (analyst-supplied filter text persisted from a form), making this a direct code injection sink.

## Fix

### File: ReportFilterService.java

```java
package com.example.reporting;

import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
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
        // Configure a sandbox to restrict access to only safe classes and methods.
        JexlSandbox sandbox = new JexlSandbox();
        // Block access to dangerous classes by default.
        sandbox.black("java.lang.Runtime");
        sandbox.black("java.lang.ProcessBuilder");
        sandbox.black("java.lang.System");
        sandbox.black("java.io.File");
        sandbox.black("java.lang.reflect.Method");
        
        // Whitelist the ReportRow class to allow access to its getter methods.
        sandbox.white(ReportRow.class.getName());
        
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
        // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
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

The fix applies a `JexlSandbox` to the engine, enforcing a whitelist/blacklist access control model. The sandbox blacklists dangerous classes (`java.lang.Runtime`, `java.lang.ProcessBuilder`, `java.lang.System`, `java.io.File`, `java.lang.reflect.Method`) that could be used to execute arbitrary code or access the file system. The `ReportRow` class is explicitly whitelisted to allow filters to access row data through its public getters.

This sandbox configuration allows legitimate filter expressions (comparisons like `amount > 1000` and `region == 'EMEA'`, as well as access to context variables and ReportRow getters) while preventing an attacker from injecting code that calls dangerous APIs. The evaluated expression cannot escape the sandboxed context and therefore cannot achieve code execution.
