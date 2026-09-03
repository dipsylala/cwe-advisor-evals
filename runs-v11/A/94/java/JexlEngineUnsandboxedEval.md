## Verdict
Code injection vulnerability confirmed. The JEXL engine is instantiated without a sandbox, allowing user-supplied filter expressions to access arbitrary Java classes and methods.

## Source
`ReportFilterService.java` lines 22–26 and 36–38: The `JexlEngine` is created unsandboxed (`new JexlBuilder().create()`), then the analyst-supplied `filterExpression` string is passed directly to `createExpression()` without validation or access restrictions.

## Fix
Apply a `JexlSandbox` to restrict expression evaluation to only the fields needed for filtering:

```java
import org.apache.commons.jexl3.introspection.JexlSandbox;

public class ReportFilterService {

    private final JexlEngine jexlEngine;

    public ReportFilterService() {
        JexlSandbox sandbox = new JexlSandbox();
        // Allow read-only access to the context variables and their public methods
        sandbox.allow(ReportRow.class);
        sandbox.allow(Double.class);
        sandbox.allow(String.class);
        
        this.jexlEngine = new JexlBuilder()
                .sandbox(sandbox)
                .create();
    }

    public List<ReportRow> applyFilter(String filterExpression, List<ReportRow> rows) {
        JexlExpression expression = jexlEngine.createExpression(filterExpression);

        return rows.stream()
                .filter(row -> matches(expression, row))
                .toList();
    }

    // ... rest of the class unchanged
}
```

## Explanation
The `JexlSandbox` restricts the expression parser to allow only whitelisted classes and methods. By calling `sandbox.allow(ReportRow.class)` and the primitive types used in the filter, we permit expressions like `"amount > 1000 && region == 'EMEA'"` while blocking access to `System.exit()`, reflection APIs, or arbitrary Java classes. The sandbox is passed to the `JexlBuilder` during engine creation, enforcing restrictions on every expression parsed by that engine.
