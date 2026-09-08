## Verdict

exploitable

## Source

String `customFormula` loaded from `pricingRuleRepository.findFormulaByProductId(productId)` at line 32. The repository retrieves admin-configured formula text from storage without validation, and the formula is passed directly to `shell.evaluate()` without any constraints or sandboxing.

## Fix

### File: PricingFormulaEvaluator.java

```java
package com.example.pricing;

import org.apache.commons.jexl3.*;
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
    private final JexlEngine jexlEngine;

    public PricingFormulaEvaluator(PricingRuleRepository pricingRuleRepository) {
        this.pricingRuleRepository = pricingRuleRepository;
        // Create a deny-by-default sandbox to restrict what expressions can access
        JexlSandbox sandbox = new JexlSandbox(false);
        this.jexlEngine = new JexlBuilder()
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
            // Parse and compile the formula into an expression
            JexlExpression expr = jexlEngine.createExpression(customFormula);

            // Create a context with only the allowed variables for evaluation
            JexlContext context = new MapContext();
            context.set("basePrice", basePrice);
            context.set("quantity", quantity);

            // Evaluate the expression in the sandboxed context
            Object result = expr.evaluate(context);

            if (result instanceof BigDecimal) {
                return (BigDecimal) result;
            }
            if (result instanceof Number) {
                return BigDecimal.valueOf(((Number) result).doubleValue());
            }
            return basePrice;
        } catch (JexlException e) {
            // Formula is invalid or evaluation failed; return the base price
            return basePrice;
        }
    }
}
```

## Explanation

The original code used Groovy's `GroovyShell.evaluate()` to dynamically execute admin-configured pricing formulas, which allowed arbitrary code execution. Although the formula comes from database storage controlled by admins (not direct user input), the CWE-94 guidance treats all untrusted code sources the same—including database-stored code that an admin might have inadvertently corrupted or that an attacker with database write access could compromise. The fix replaces the Groovy evaluator with Apache Commons JEXL 3.4.0 (already in the classpath per pom.xml) configured with a deny-by-default `JexlSandbox(false)`. This sandbox prevents access to Java classes, constructors, reflection, and system resources by default. The formula is now parsed as a JEXL expression rather than executable Groovy code, and evaluation occurs in an isolated context that only exposes the `basePrice` and `quantity` variables. Invalid formulas return the base price rather than throwing an uncaught exception. All JEXL classes (`JexlEngine`, `JexlExpression`, `JexlContext`, `MapContext`) are in the standard Apache Commons JEXL package at `org.apache.commons.jexl3`, and `JexlSandbox` is in the `introspection` subpackage as specified in the guidance.

## Behaviour changes

1. **Expression language changed from Groovy to JEXL**: The syntax of stored formulas must be compatible with JEXL instead of Groovy. JEXL supports arithmetic operators, ternary conditionals, and property access, so the documented example formula `basePrice * (quantity > 10 ? 0.9 : 1.0)` continues to work. However, formulas using Groovy-specific syntax (e.g., list comprehensions, closures, method invocations on arbitrary objects) will no longer parse. This is a security improvement by design—restricting formula syntax reduces attack surface.

2. **Error handling**: Invalid formulas caught by `JexlException` now return the base price instead of propagating the exception. The original code would have thrown an uncaught `GroovyException` for invalid expressions, causing a 500 error to the client. This change makes the system more resilient to malformed formulas.

3. **Constructor initialization**: The constructor now builds and caches a `JexlEngine` with the sandbox, adding a small one-time initialization cost. This improves performance for repeated price calculations and ensures the sandbox is applied consistently to all formula evaluations from this instance.
