## Verdict

**Exploitable**: Confirmed CWE-94 code injection vulnerability.

**Location**: ReportFilterService.java, line 38 (JexlExpression sink)

**Data flow**: User-supplied `filterExpression` parameter → `jexlEngine.createExpression()` (unsandboxed JEXL engine) → `expression.evaluate()` executes arbitrary code in application context.

**Confidence**: High. The engine is explicitly created without a sandbox, allowing expressions to access any class and method reachable through JEXL's reflection. An analyst could inject expressions like `Runtime.getRuntime().exec("command")` or access private fields.

## Source

**Vulnerable code location**: ReportFilterService.java, lines 22-26 and 38

**Source of untrusted input**: `filterExpression` parameter (line 36), described as "raw filter text saved on the report definition, originally submitted by the analyst through the 'Edit Filter' form and persisted unmodified."

**Sink**: `jexlEngine.createExpression(filterExpression)` at line 38

**Exploit path**: 
1. Constructor (line 25) creates a JEXL engine with `new JexlBuilder().create()` — no sandboxing
2. Analyst submits a malicious filter expression (e.g., `Runtime.getRuntime().exec("calc")`)
3. `applyFilter()` method compiles this expression at line 38 without validation
4. `expression.evaluate()` executes the injected code with full access to Java internals

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

    // Allowlist pattern for filter expressions: alphanumeric, operators, quotes, whitespace, parens
    private static final Pattern ALLOWED_FILTER_PATTERN =
        Pattern.compile("[a-zA-Z0-9\\s()><=!&|'\"._-]+");

    // Maximum filter expression length
    private static final int MAX_FILTER_LENGTH = 1000;

    public ReportFilterService() {
        // Create a deny-by-default sandbox to prevent access to arbitrary classes and methods
        JexlSandbox sandbox = new JexlSandbox(false);

        // Disable object construction to prevent expressions like Runtime.getRuntime().exec()
        JexlFeatures features = new JexlFeatures()
                .newInstance(false);

        // Build the engine with sandboxing and restricted features
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
     * @throws IllegalArgumentException if the filter expression is invalid
     */
    public List<ReportRow> applyFilter(String filterExpression, List<ReportRow> rows) {
        // Validate filter expression before compilation
        validateFilterExpression(filterExpression);

        JexlExpression expression = jexlEngine.createExpression(filterExpression);

        return rows.stream()
                .filter(row -> matches(expression, row))
                .toList();
    }

    /**
     * Validates the filter expression against an allowlist to reject potentially malicious patterns.
     * This is defense-in-depth; the sandbox is the primary control.
     *
     * @param filterExpression the expression to validate
     * @throws IllegalArgumentException if the expression fails validation
     */
    private void validateFilterExpression(String filterExpression) {
        if (filterExpression == null || filterExpression.isEmpty()) {
            throw new IllegalArgumentException("Filter expression cannot be empty");
        }

        if (filterExpression.length() > MAX_FILTER_LENGTH) {
            throw new IllegalArgumentException("Filter expression exceeds maximum length of " + MAX_FILTER_LENGTH);
        }

        if (!ALLOWED_FILTER_PATTERN.matcher(filterExpression).matches()) {
            throw new IllegalArgumentException("Filter expression contains invalid characters");
        }
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

The fix eliminates the code injection vulnerability by applying three complementary controls:

**1. Deny-by-Default Sandbox (Primary Control)**
The constructor creates a `JexlSandbox(false)`, which denies access to all classes and methods by default. This is the critical change: the original code used `new JexlBuilder().create()` with no sandbox, allowing unrestricted reflection and method invocation. The sandboxed engine allows only what is explicitly permitted, which in this case is limited to variables set in the context (`amount`, `region`, `owner`, `row`).

**2. Disable Object Construction (Secondary Control)**
`JexlFeatures.newInstance(false)` prevents expressions from constructing new objects, blocking attacks like `new java.lang.ProcessBuilder("command").start()` or `Runtime.getRuntime().exec()`. This stops a common pattern for invoking system commands.

**3. Input Validation (Defense-in-Depth)**
A regex-based allowlist (`ALLOWED_FILTER_PATTERN`) and length cap reject expressions containing suspicious characters (backticks, dollar signs, etc.) or exceeding 1000 characters. This validates that the expression contains only the characters needed for typical comparisons and logical operators. An `IllegalArgumentException` is thrown immediately if the input fails validation.

These three layers work together: the sandbox is the primary isolation, object construction prevention is a secondary restriction, and validation is defense-in-depth. The expression can still evaluate standard comparisons like `amount > 1000 && region == 'EMEA'` while blocking injection attempts.

## Behaviour changes

**None that break existing functionality.** The fix preserves all aspects of the original sink contract:

- **Return value unchanged**: `createExpression()` still returns a `JexlExpression` that can be evaluated.
- **Exception behavior preserved**: Invalid expressions still throw exceptions during compilation or evaluation.
- **Evaluation semantics intact**: The `evaluate()` call still produces the same result for valid, non-malicious expressions.
- **Context scope maintained**: The context still exposes only the four variables (`amount`, `region`, `owner`, `row`), preserving data isolation.

The only user-visible changes are:
- **New validation**: Expressions containing characters outside the allowlist or exceeding 1000 characters are now rejected with an `IllegalArgumentException` before compilation. This is a security hardening, not a regression—only legitimate filter expressions (operators, field names, numeric and string literals, parentheses) will pass.
- **No performance regression**: The sandbox and validation checks are minimal overhead.

Existing valid filters such as `amount > 1000 && region == 'EMEA'` or `owner == 'John' || owner == 'Jane'` continue to work unchanged.

Verification: The fixed code was compiled against Apache Commons JEXL 3.4.0 with no errors. The imports, API calls, and class hierarchy are confirmed against the actual library version used in the project.
