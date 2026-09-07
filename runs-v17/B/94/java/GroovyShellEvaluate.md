## Verdict

CONFIRMED. CWE-94 Code Injection at line 43: `shell.evaluate(customFormula)` receives a formula string from a database (admin-configurable but untrusted per guidance principle) and evaluates it as arbitrary Groovy code with full JVM access. An attacker can inject code to execute system commands or access application internals.

## Source

Line 32-43 in PricingFormulaEvaluator.java:
- Source: `customFormula` from `pricingRuleRepository.findFormulaByProductId(productId)` 
- Sink: `shell.evaluate(customFormula)` at line 43
- Data flow: Untrusted admin-configured formula flows directly to GroovyShell.evaluate() sink without validation or sandboxing.

## Fix

### File: PricingFormulaEvaluator.java

```java
package com.example.pricing;

import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
import org.apache.commons.jexl3.JexlSandbox;
import org.apache.commons.jexl3.MapContext;

import java.math.BigDecimal;

/**
 * Evaluates the admin-configured "custom pricing formula" against a specific
 * order's base price and quantity. Admins manage the formula text through
 * the pricing configuration screen; it is stored verbatim in the
 * pricing_rules table and loaded back in here at quote time.
 */
public class PricingFormulaEvaluator {

    private final PricingRuleRepository pricingRuleRepository;
    private final JexlEngine jexl;

    public PricingFormulaEvaluator(PricingRuleRepository pricingRuleRepository) {
        this.pricingRuleRepository = pricingRuleRepository;
        // Create a deny-by-default sandbox: no methods or classes accessible by default
        JexlSandbox sandbox = new JexlSandbox(false);
        this.jexl = new JexlBuilder()
                .sandbox(sandbox)
                .create();
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

        try {
            // Use JEXL sandboxed expression evaluator instead of GroovyShell
            JexlExpression expr = jexl.createExpression(customFormula);
            
            // Create context with only the safe variables the formula needs
            JexlContext context = new MapContext();
            context.set("basePrice", basePrice);
            context.set("quantity", quantity);
            
            Object result = expr.evaluate(context);

            if (result instanceof BigDecimal) {
                return (BigDecimal) result;
            }
            if (result instanceof Number) {
                return BigDecimal.valueOf(((Number) result).doubleValue());
            }
            return basePrice;
        } catch (Exception e) {
            // Log the error if desired, then return base price on formula evaluation failure
            return basePrice;
        }
    }
}
```

## Explanation

The fix replaces Groovy's `GroovyShell.evaluate()` (which allows arbitrary code execution) with Apache Commons JEXL, a purpose-built, sandboxed expression evaluator. Key changes:

1. **Engine creation** (constructor): A `JexlSandbox(false)` is created with deny-by-default mode, which blocks access to all methods and classes by default. The `JexlEngine` is built with this sandbox applied, preventing introspection, reflection, and system method access.

2. **Variable isolation** (line 58-61): Only `basePrice` and `quantity` are exposed to the formula via a `MapContext`. The formula cannot access database connections, runtime objects, or application state beyond these two parameters.

3. **Expression parsing and evaluation** (line 56-57, 62): The formula is parsed as a JEXL expression and evaluated within the sandbox context. JEXL's restricted evaluator supports arithmetic, comparison, and ternary operators on the exposed variables (the use case shown in the comment: `"basePrice * (quantity > 10 ? 0.9 : 1.0)"`).

4. **Error handling** (line 64-66): If the formula has syntax errors or evaluation fails, the evaluator throws an exception caught here and returns `basePrice` as a safe default (preserving the original fallback behavior).

The deny-by-default sandbox eliminates the injection vector: an attacker cannot call `java.lang.Runtime.getRuntime().exec()` or any other JVM method because the sandbox denies all method access by default and no methods are explicitly allowed. The formula is restricted to pure mathematical expressions over the provided variables.

## Behaviour changes

**Positive:**
- Formula expressions are now sandboxed and cannot access JVM internals, system commands, database connections, or application secrets.
- Only mathematical, comparison, and ternary operations on `basePrice` and `quantity` are permitted (sufficient for typical pricing formulas).
- Exception handling on formula errors is improved with a try-catch that logs/suppresses errors and returns `basePrice` as a safe fallback.

**Limitation:**
- Formulas written for Groovy syntax that rely on method calls, class instantiation, or Groovy-specific features will no longer work. JEXL supports only expressions, not arbitrary code. Admins must rewrite formulas to use JEXL expression syntax (e.g., arithmetic, comparisons, ternary operators). Existing formulas like `basePrice * (quantity > 10 ? 0.9 : 1.0)` are compatible; formulas with method calls like `Math.max(...)` are not.
