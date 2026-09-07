## Verdict

Exploitable. The `customFormula` string flows directly from the database (via `PricingRuleRepository.findFormulaByProductId()`) to `GroovyShell.evaluate()` at line 43 without validation or restriction. Although the comments state that admins configure this through a UI, the database is an untrusted source under CWE-94 threat model (subject to SQL injection, admin account compromise, or insider threat). `GroovyShell.evaluate()` executes arbitrary Groovy code with full access to the runtime, variables, methods, and external resources.

## Source

`pricingRuleRepository.findFormulaByProductId(productId)` at line 32 retrieves formula text from the database without validation.

## Fix

Replace `GroovyShell.evaluate()` with Apache Commons JEXL using a deny-by-default sandbox that restricts the evaluator to mathematical expressions over the `basePrice` and `quantity` variables.

**Vulnerable code:**

```java
GroovyShell shell = new GroovyShell(binding);
// SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
Object result = shell.evaluate(customFormula);
```

**Fixed code:**

```java
// Create a deny-by-default sandbox
JexlSandbox sandbox = new JexlSandbox(false);

// Configure JEXL engine with restricted features
JexlFeatures features = new JexlFeatures()
    .newInstance(false)  // Disallow object construction
    .loops(false);       // Disallow loops

JexlEngine engine = new JexlBuilder()
    .features(features)
    .sandbox(sandbox)
    .create();

// Create context with only necessary variables
JexlContext context = new MapContext();
context.set("basePrice", basePrice);
context.set("quantity", quantity);

try {
    // Parse and evaluate the expression
    Object result = engine.createExpression(customFormula).evaluate(context);
```

**Required imports** (add to the file):

```java
import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlFeatures;
import org.apache.commons.jexl3.JexlSandbox;
import org.apache.commons.jexl3.MapContext;
```

**Dependency** (add to pom.xml or equivalent):

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-jexl3</artifactId>
    <version>3.4</version>
</dependency>
```

## Explanation

Groovy's `GroovyShell.evaluate()` is inherently unsafe for dynamic code execution from any untrusted source, including databases. It provides no sandboxing and evaluates code with full runtime access. Apache Commons JEXL is a purpose-built expression evaluator designed for restricted contexts. The fix:

1. Creates a `JexlSandbox(false)` configured deny-by-default: no classes, methods, or constructors are accessible unless explicitly allowed.
2. Disables object construction (`newInstance(false)`) and loops (`loops(false)`) to prevent resource exhaustion and control-flow injection.
3. Restricts the evaluation context to only `basePrice` and `quantity` variables—the formula cannot access the `PricingRuleRepository`, database connections, secrets, or any other application state.
4. Wraps evaluation in a try-catch: if the formula is malformed or references disallowed operations, the catch block returns the safe fallback (`basePrice`), preventing error-based injection.

This replaces dynamic code execution with a sandboxed expression evaluator, eliminating the CWE-94 weakness while preserving the product's pricing formula feature.

## Behaviour changes

1. **Expression language changed from Groovy to JEXL**: JEXL is purpose-built for safe expression evaluation; it does not support arbitrary code constructs (imports, method definitions, loops using `for`/`while` keywords). Formulas must use arithmetic and conditional operators only (e.g., `basePrice * (quantity > 10 ? 0.9 : 1.0)`). This is intentional and eliminates the injection vector. Reason: CWE-94 mitigation.

2. **Exception handling added**: If the formula references a disallowed operation (e.g., `java.lang.Runtime`), method invocation, or object construction, JEXL raises an exception which the catch block catches and returns `basePrice`. The original code would raise an unhandled exception. Reason: Sandboxing requires graceful degradation on denied operations.

3. **No automatic variable binding from `Binding` object**: The original code passes a `Binding` object to `GroovyShell`; the fixed code explicitly adds variables to a `JexlContext`. This is a minor behaviour change: if the original formula ever relied on automatic introspection of the `Binding` object itself (e.g., `binding.getVariable("basePrice")`), that would fail in the fixed version. This is unlikely and represents a reduction in attack surface. Reason: Sandboxing requires explicit variable exposure.

4. **Return type handling unchanged**: The fixed code preserves the original logic: `BigDecimal` results pass through unchanged, other `Number` types are converted to `BigDecimal`, and all other types fall back to `basePrice`. No functional change here.

5. **Sink contract preserved**: The method still returns a `BigDecimal` computed from the formula or the base price on evaluation failure. The caller cannot detect the difference between a formula evaluation error and a denied operation, both of which now return `basePrice` silently. This is acceptable because the alternative—failing the entire quote request—would be a denial of service.
