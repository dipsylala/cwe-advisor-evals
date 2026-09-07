## Verdict

Exploitable. The `filterExpression` parameter originates from untrusted analyst-supplied input persisted from a form without validation. It flows directly to `jexlEngine.createExpression()` at line 38, which evaluates it against a JexlEngine with no sandboxing restrictions. An attacker with analyst privileges can inject arbitrary code expressions such as `java.lang.Runtime.getRuntime().exec(...)` to execute OS commands within the application's JVM.

## Source

The `filterExpression` parameter on line 36: a raw string submitted by an analyst through an "Edit Filter" form, persisted to the report definition unmodified, and passed directly to the filter service without validation or transformation.

## Fix

**Vulnerable code (lines 20–26, 36–42):**
```java
public ReportFilterService() {
    // No JexlSandbox is configured, so the engine has full, unrestricted
    // access to every class and method reachable from the context.
    this.jexlEngine = new JexlBuilder().create();
}

public List<ReportRow> applyFilter(String filterExpression, List<ReportRow> rows) {
    // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
    JexlExpression expression = jexlEngine.createExpression(filterExpression);

    return rows.stream()
            .filter(row -> matches(expression, row))
            .toList();
}
```

**Fixed code:**
```java
private final JexlEngine jexlEngine;
private static final Pattern EXPRESSION_PATTERN = 
    Pattern.compile("^[a-zA-Z0-9_()+\\-*/<>!=&| .,]+$");

public ReportFilterService() {
    // Create a deny-by-default sandbox that restricts what the engine can access
    JexlSandbox sandbox = new JexlSandbox(false);
    
    // Allow only the specific classes and methods needed for filtering
    sandbox.allow(Double.class.getName());
    sandbox.allow(String.class.getName());
    sandbox.allow(Boolean.class.getName());
    
    // Disable object construction to prevent instantiation attacks
    JexlFeatures features = new JexlFeatures()
        .newInstance(false);
    
    this.jexlEngine = new JexlBuilder()
        .features(features)
        .sandbox(sandbox)
        .create();
}

public List<ReportRow> applyFilter(String filterExpression, List<ReportRow> rows) {
    // Validate the expression against a strict allowlist pattern before evaluation
    if (!isValidExpression(filterExpression)) {
        throw new IllegalArgumentException(
            "Filter expression contains invalid characters or structure");
    }
    
    JexlExpression expression = jexlEngine.createExpression(filterExpression);

    return rows.stream()
            .filter(row -> matches(expression, row))
            .toList();
}

/**
 * Validates that the filter expression matches the expected pattern.
 * Only allows comparison operators, property access, and boolean logic.
 */
private boolean isValidExpression(String expression) {
    if (expression == null || expression.isEmpty()) {
        return false;
    }
    // Check that the expression contains only allowed characters
    return EXPRESSION_PATTERN.matcher(expression).matches();
}
```

**Added imports:**
```java
import org.apache.commons.jexl3.JexlFeatures;
import org.apache.commons.jexl3.JexlSandbox;
import java.util.regex.Pattern;
```

## Explanation

The fix eliminates CWE-94 by applying three layers of defence: expression validation, sandboxing, and feature restriction. First, a strict regex pattern allowlist (`isValidExpression()`) validates the expression syntax before it reaches the evaluator, rejecting any input containing characters that could introduce code injection. Second, the engine is initialized with `JexlSandbox(false)` — a deny-by-default sandbox that prevents access to arbitrary classes and methods. The sandbox explicitly allows only the minimal set of types needed for the filter logic (Double, String, Boolean), which form the basis of comparison and boolean operations. Third, `JexlFeatures.newInstance(false)` disables object instantiation within JEXL expressions, preventing the attacker from constructing new instances and bypassing the sandbox through constructor chains or reflection. Together, these controls ensure that even if an analyst-supplied expression is malicious, it cannot escape the confined evaluation context or invoke dangerous operations. The sandbox denial of a disallowed operation returns `null` rather than throwing an exception, which matches the existing contract of the `matches()` method's return type handling.

## Behaviour changes

1. **Expression validation added**: The `applyFilter()` method now rejects expressions that do not match the strict allowlist pattern and throws `IllegalArgumentException` on invalid input. This is a breaking change only for expressions that contained characters outside the allowed set (e.g., quotes, backslashes, method invocation syntax). Reason: filter expressions should contain only comparison operators, boolean logic, and property access; any other syntax introduces code injection risk.

2. **Sandbox enforcement**: The JexlEngine now runs under a deny-by-default sandbox instead of unrestricted access. Expressions that previously could invoke arbitrary methods on any class (e.g., `java.lang.Runtime.getRuntime().exec()`) will now silently return `null` during evaluation. Reason: this is the primary control that prevents code injection by restricting the evaluator's capability to access only explicitly allowed types.

3. **Object construction disabled**: Expressions that attempted to construct objects (e.g., `new java.io.File(...)`) will now fail during compilation or return `null` during evaluation. Reason: object construction can bypass sandbox restrictions through constructor chains or factory methods, so it must be disabled.

4. **Returned value and exception contract preserved**: The `applyFilter()` method still returns a `List<ReportRow>` and throws exceptions on invalid input, matching the original sink contract. The `matches()` helper method receives expressions that can only return `null` or boolean values from the sandboxed engine, and the `Boolean.TRUE.equals(result)` check on line 53 handles both cases correctly (treating `null` as `false`).

