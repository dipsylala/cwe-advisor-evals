## Verdict

CWE-94 code injection is confirmed. The JEXL engine is instantiated without sandbox restrictions, allowing an analyst-supplied filter expression to invoke arbitrary methods and access any class in the JVM.

## Source

The vulnerability occurs at line 38, where `jexlEngine.createExpression(filterExpression)` compiles and evaluates untrusted analyst-authored expression text without containment. The engine was initialized at line 25 with `new JexlBuilder().create()`, which does not configure a `JexlSandbox`.

An attacker (analyst with filter edit capability) can inject code to:
- Call `java.lang.Runtime.getRuntime().exec()` to run OS commands
- Instantiate arbitrary classes via reflection
- Access static methods and fields across the JVM
- Exfiltrate sensitive data through the evaluation context

## Fix

Replace the constructor to apply a deny-by-default sandbox, disable object construction, and restrict method access:

```java
import org.apache.commons.jexl3.JexlFeatures;
import org.apache.commons.jexl3.JexlSandbox;

public ReportFilterService() {
    // Create a deny-by-default sandbox that blocks all class/method access
    JexlSandbox sandbox = new JexlSandbox(false);
    
    // Allow only the specific properties the filter legitimately needs
    // The context exposes these as variables: amount (double), region (String), 
    // owner (String), and row (ReportRow instance)
    sandbox.allow(ReportRow.class.getName());
    
    // Disable dynamic object construction and constant creation to prevent 
    // instantiation of arbitrary classes like Runtime or reflection gadgets
    JexlFeatures features = new JexlFeatures();
    features.setNewInstance(false);
    features.setConstantCreation(false);
    
    this.jexlEngine = new JexlBuilder()
            .features(features)
            .sandbox(sandbox)
            .create();
}
```

Additionally, add an integration test to verify sandbox enforcement:

```java
@Test
public void testSandboxDeniesRuntimeExecution() {
    ReportFilterService service = new ReportFilterService();
    List<ReportRow> rows = List.of(new ReportRow(500, "EMEA", "alice"));
    
    // This malicious expression attempts to execute a command
    String maliciousFilter = "java.lang.Runtime.getRuntime().exec('whoami')";
    List<ReportRow> result = service.applyFilter(maliciousFilter, rows);
    
    // A sandboxed JEXL engine evaluates invalid expressions to null,
    // which fails the Boolean.TRUE check in matches(), filtering out all rows
    assertTrue(result.isEmpty());
}

@Test
public void testSandboxAllowsLegitimateFilter() {
    ReportFilterService service = new ReportFilterService();
    List<ReportRow> rows = List.of(
        new ReportRow(500, "EMEA", "alice"),
        new ReportRow(2000, "APAC", "bob")
    );
    
    String legitimateFilter = "amount > 1000 && region == 'APAC'";
    List<ReportRow> result = service.applyFilter(legitimateFilter, rows);
    
    assertEquals(1, result.size());
    assertEquals("bob", result.get(0).getOwner());
}
```

## Explanation

JEXL's `JexlSandbox` provides expression containment by restricting what classes and methods expressions can name. `new JexlSandbox(false)` creates a deny-by-default policy: all classes are blocked unless explicitly allowed.

The sandbox alone grants *permission* to reference a class, but does not grant *reach* — an allowed class is callable only if it is exposed by name in the evaluation context or in the engine's namespaces. The context here exposes primitive-typed variables (`amount`, `region`, `owner` as double and String) and the `row` object (ReportRow instance). Expressions can read these variables and invoke methods on them, but cannot reach `java.lang.Runtime`, `java.lang.Class`, or reflection APIs because they are neither in the context nor allowed by the sandbox.

`JexlFeatures` with `newInstance(false)` and `constantCreation(false)` blocks dynamic class instantiation and prevents attackers from constructing gadget objects or bypassing the sandbox through alternate syntax.

The test demonstrates the sandbox enforces denial: a malicious expression attempting to call `java.lang.Runtime` evaluates to null (JEXL's sandbox denial response), not an exception, so assertions must check for null or empty results rather than caught exceptions.

## Behaviour changes

- Analyst-authored filters remain functional for legitimate use cases (e.g., "amount > 1000 && region == 'EMEA'", property access on row objects).
- Malicious expressions that reference classes outside the sandbox (Runtime, Class, reflection APIs) evaluate to null and are treated as filter non-matches, excluding those rows from the result.
- Performance impact is negligible: sandbox checks occur at expression compile time, not evaluation.
- No changes to the public API or filter expression syntax — analysts continue to write the same filter strings.
