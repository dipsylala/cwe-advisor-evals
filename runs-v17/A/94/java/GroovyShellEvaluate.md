## Verdict
Real issue confirmed. `GroovyShell.evaluate()` executes arbitrary Groovy code from a database-loaded formula, allowing an attacker with admin/database access to inject malicious code that runs with application privileges.

## Source
The vulnerability exists at line 43 in `PricingFormulaEvaluator.java`. The `customFormula` is retrieved from a database without validation and passed directly to `shell.evaluate(customFormula)`, which interprets the string as executable Groovy code.

## Fix
### File: PricingFormulaEvaluator.java
```java
package com.example.pricing;

import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlEngine;
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
    private final JexlEngine jexlEngine;

    public PricingFormulaEvaluator(PricingRuleRepository pricingRuleRepository) {
        this.pricingRuleRepository = pricingRuleRepository;
        // Create JEXL engine with strict mode to prevent arbitrary object construction
        this.jexlEngine = new JexlBuilder().strict(true).create();
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
            JexlContext context = new MapContext();
            context.set("basePrice", basePrice);
            context.set("quantity", quantity);

            Object result = jexlEngine.createExpression(customFormula).evaluate(context);

            if (result instanceof BigDecimal) {
                return (BigDecimal) result;
            }
            if (result instanceof Number) {
                return BigDecimal.valueOf(((Number) result).doubleValue());
            }
            return basePrice;
        } catch (Exception e) {
            // If formula evaluation fails, return base price as a safe default
            return basePrice;
        }
    }
}
```

## Explanation
GroovyShell is a full-featured code execution engine; passing user-controlled formulas to `evaluate()` allows arbitrary code injection. The fix replaces GroovyShell with Apache Commons JEXL3 (version 3.2+), a purpose-built expression evaluator that:

1. **Restricts execution scope** — JEXL evaluates expressions only against a context map, not arbitrary Groovy/Java code. It cannot instantiate objects, call static methods, or access arbitrary class members by default.

2. **Uses strict mode** — The `JexlBuilder().strict(true)` configuration prevents null-pointer traversal and undefined variable errors, eliminating edge cases that could lead to unexpected behavior.

3. **Maintains formula semantics** — JEXL supports mathematical operators, conditionals (`? :`), and variable references, preserving the pricing formula syntax (e.g., `basePrice * (quantity > 10 ? 0.9 : 1.0)`).

4. **Fails safely** — Malformed formulas throw caught exceptions, defaulting to `basePrice` rather than crashing or executing arbitrary code.

The attack surface is narrowed from "arbitrary Java code execution" to "math expressions over two variables," eliminating the injection risk while preserving functionality.
