## Verdict

exploitable (confidence: high)

- CWE-94, Improper Control of Generation of Code ('Code Injection')
- Location: `PricingFormulaEvaluator.java`, line 43, `shell.evaluate(customFormula)`
- Assumption: `customFormula` is treated as untrusted at evaluation time even though it originates from an admin-facing configuration screen. It is stored verbatim in the `pricing_rules` table and read back with no re-validation, and `GroovyShell.evaluate()` compiles and runs it as full Groovy source with no sandbox - so any path that can reach that table with attacker-influenced content (a compromised admin session, an unvalidated admin API, a future self-service pricing feature) gets arbitrary code execution in the application's JVM. This matches the knowledge base's own description of the legitimate use case for a sandboxed expression evaluator ("a merchant's custom pricing formula"), which is the fix pattern applied below.

## Source

- **Source**: `pricingRuleRepository.findFormulaByProductId(productId)` (line 32) - the stored formula text for the product, read from the `pricing_rules` table.
- **Data flow**: the return value is assigned directly to `customFormula` (line 32), passed through only a null/blank check (line 33), bound into a fresh `Binding` alongside `basePrice` and `quantity` (lines 37-39), and handed unmodified to the sink.
- **Sink**: `GroovyShell.evaluate(customFormula)` (line 43) - compiles and executes the string as a full Groovy script with no sandbox, no method/class restriction, and no allowlist.
- **Sink contract established before fixing**:
  - *Returns*: `Object`, narrowed by the caller via `instanceof BigDecimal` / `instanceof Number`, else `basePrice` is returned.
  - *Discards*: nothing else - the only output used is the single evaluation result.
  - *Implicit arguments*: the `GroovyShell` constructor takes only the `Binding`; it applies no `CompilerConfiguration`, `SecureASTCustomizer`, or class-loading restriction, so the script runs with the full capability of the host JVM.
  - *Failure behaviour*: a malformed formula throws an unchecked Groovy exception (`CompilationFailedException`/`GroovyRuntimeException`, both `RuntimeException`), uncaught by this method - it propagates to the caller.

## Fix

**Library recommendation**: Apache Commons JEXL (`org.apache.commons:commons-jexl3`), used as a sandboxed, deny-by-default expression evaluator in place of the unsandboxed Groovy engine, per this repository's CWE-94 Java guidance. The guidance does not carry a minimum safe version for this library - confirm the resolved version against SCA/dependency-check tooling before merging rather than pinning one from memory. Add the dependency to the project's build file, e.g. in `pom.xml`:

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-jexl3</artifactId>
    <version><!-- resolve via SCA/dependency-check --></version>
</dependency>
```

No fixed minimum version is asserted here; do not carry one over from general recollection.

### File: PricingFormulaEvaluator.java

```java
package com.example.pricing;

import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
import org.apache.commons.jexl3.JexlFeatures;
import org.apache.commons.jexl3.MapContext;
import org.apache.commons.jexl3.introspection.JexlSandbox;

import java.math.BigDecimal;

/**
 * Evaluates the admin-configured "custom pricing formula" against a specific
 * order's base price and quantity. Admins manage the formula text through
 * the pricing configuration screen; it is stored verbatim in the
 * pricing_rules table and loaded back in here at quote time.
 */
public class PricingFormulaEvaluator {

    private final PricingRuleRepository pricingRuleRepository;

    // Deny-by-default sandbox: no class, constructor, or method is reachable
    // from an evaluated formula. Formulas may only combine the basePrice and
    // quantity context variables using JEXL's built-in arithmetic, comparison,
    // and ternary operators - the only capability this feature needs.
    private static final JexlEngine PRICING_FORMULA_ENGINE = new JexlBuilder()
            .sandbox(new JexlSandbox(false))
            .features(new JexlFeatures().newInstance(false))
            .create();

    public PricingFormulaEvaluator(PricingRuleRepository pricingRuleRepository) {
        this.pricingRuleRepository = pricingRuleRepository;
    }

    /**
     * Computes the final unit price for a product by running the merchant's
     * custom pricing formula, e.g. "basePrice * (quantity > 10 ? 0.9 : 1.0)".
     *
     * @param productId the product whose custom formula should be applied
     * @param basePrice the catalog base price for the product
     * @param quantity  the quantity being quoted
     * @return the computed price, or basePrice if no custom formula is configured
     */
    public BigDecimal computePrice(String productId, BigDecimal basePrice, int quantity) {
        String customFormula = pricingRuleRepository.findFormulaByProductId(productId);
        if (customFormula == null || customFormula.isBlank()) {
            return basePrice;
        }

        JexlContext context = new MapContext();
        context.set("basePrice", basePrice);
        context.set("quantity", quantity);

        JexlExpression expression = PRICING_FORMULA_ENGINE.createExpression(customFormula);
        Object result = expression.evaluate(context);

        if (result instanceof BigDecimal) {
            return (BigDecimal) result;
        }
        if (result instanceof Number) {
            return BigDecimal.valueOf(((Number) result).doubleValue());
        }
        return basePrice;
    }
}
```

## Explanation

The unsandboxed `GroovyShell.evaluate()` call is replaced with Apache Commons JEXL configured as a deny-by-default expression engine: `new JexlSandbox(false)` removes every class, constructor, and method from what an evaluated formula can reach, and `JexlFeatures().newInstance(false)` additionally blocks object construction. `Binding` becomes `JexlContext`/`MapContext`, still exposing exactly `basePrice` and `quantity` to the formula, and `shell.evaluate(customFormula)` becomes `engine.createExpression(customFormula).evaluate(context)`. JEXL's built-in arithmetic, comparison, and ternary operators do not go through the sandbox's method/class permission checks, so ordinary pricing formulas like `basePrice * (quantity > 10 ? 0.9 : 1.0)` keep working unchanged, while any attempt to reach outside the two provided variables - reflection, `Class.forName`, constructors, or any other method call - is denied. This closes the code-injection weakness because the engine itself, not the shape of the input string, now decides what a formula can execute.

## Behaviour changes

- **Dependency swap**: `groovy.lang.Binding`/`groovy.lang.GroovyShell` are replaced with `org.apache.commons.jexl3.*` and `org.apache.commons.jexl3.introspection.JexlSandbox`. Required by the fix; add `org.apache.commons:commons-jexl3` to the build file (this single-file case has no manifest to edit). The Groovy dependency is no longer used by this class; whether it can be removed from the manifest depends on whether other classes in the application still use it, which is outside this file's scope.
- **Evaluator lifecycle**: the engine is now built once as a `static final` field instead of constructing a new `GroovyShell` on every call. JEXL engines are designed to be built once and reused across evaluations (the sandbox/feature configuration is fixed), while the per-call state (`basePrice`, `quantity`) still moves into a freshly created `JexlContext` on every call, exactly mirroring the original per-call `Binding`. This does not change what any single call computes.
- **Exception type on a malformed formula**: previously an unchecked Groovy exception (`CompilationFailedException`/`GroovyRuntimeException`); now an unchecked `org.apache.commons.jexl3.JexlException` (confirmed by compiling and running the fix against a malformed formula, see Verification). Both are uncaught `RuntimeException`s that propagate to the caller unchanged in this file, so the contract callers see (an unchecked exception on bad input) is preserved; only the concrete exception class differs, which would only matter to code elsewhere that catches a Groovy-specific exception type - none exists in this file.
- **Denied formula content resolves to `null`, not an exception**: a formula that tries to reach outside `basePrice`/`quantity` (e.g. `basePrice.getClass()...`) is not rejected with an error - JEXL's sandbox denial evaluates the disallowed step to `null` and propagates `null` through the rest of the expression, confirmed by direct evaluation in Verification. The existing `instanceof BigDecimal` / `instanceof Number` fallback in `computePrice` already handles a `null` result by returning `basePrice`, so no additional null-handling code was needed - this is a pre-existing safety net, not new code.
- No allowlist or input-format validation was added on top of the sandbox: the set of legitimate pricing formulas has no fixed, narrower format to validate against without risking rejection of legitimate expressions, so the sandboxed evaluator is the complete primary defence here rather than one layer of several.

**Verification**: `javac` (OpenJDK 26) compiled the fixed file plus a stub `PricingRuleRepository` against `commons-jexl3` with zero errors or warnings. It was then run (with `commons-jexl3` and its `commons-logging` runtime dependency on the classpath) against: (1) the example legitimate formula at quantities on both sides of the discount threshold, producing the expected values; (2) a null/absent formula, correctly passed through as `basePrice`; (3) reflective escape attempts chaining `.getClass().forName(...).getMethod(...).invoke(...)` to reach `Runtime.getRuntime()` and `System.getProperty()` - each step evaluated to `null` under the sandbox (confirmed by evaluating the expression directly, not only through `computePrice`'s narrowing return), so no reflective call executed; (4) a malformed formula, which threw `org.apache.commons.jexl3.JexlException$Parsing`, an unchecked exception, consistent with the original's unchecked-exception failure contract.

No unresolved names: `JexlBuilder`, `JexlContext`, `JexlEngine`, `JexlExpression`, `JexlFeatures`, `MapContext` (package `org.apache.commons.jexl3`) and `JexlSandbox` (package `org.apache.commons.jexl3.introspection`) all come from the loaded CWE-94 Java guidance and were confirmed to compile and resolve against the real `commons-jexl3` library during verification.
