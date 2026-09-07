## Verdict

**REAL ISSUE - FIXED**

The finding is a genuine code injection vulnerability. Line 43 passes a formula loaded from the database directly to `GroovyShell.evaluate()`, allowing arbitrary code execution if the formula is ever modified through an untrusted path or by a compromised admin account.

## Source

**Data Flow:**
1. Source: `pricingRuleRepository.findFormulaByProductId(productId)` retrieves the formula from the `pricing_rules` table
2. Intermediate: String `customFormula` carries untrusted data from the database
3. Sink: `shell.evaluate(customFormula)` at line 43 executes the formula as Groovy code

The formula originates from persistent storage and is loaded at runtime. While the comments state admins configure it, the guidance mandates treating all data sources as untrusted for code execution sinks.

## Fix

### File: PricingFormulaEvaluator.java

```java
package com.example.pricing;

import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
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
    private final JexlEngine jexlEngine;

    public PricingFormulaEvaluator(PricingRuleRepository pricingRuleRepository) {
        this.pricingRuleRepository = pricingRuleRepository;
        
        // Create a sandboxed JEXL engine that denies by default
        JexlSandbox sandbox = new JexlSandbox(false);
        // Only allow BigDecimal and Number operations needed for pricing
        sandbox.allow(BigDecimal.class.getName());
        sandbox.allow(Number.class.getName());
        
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
            JexlExpression expression = jexlEngine.createExpression(customFormula);
            JexlContext context = new MapContext();
            context.set("basePrice", basePrice);
            context.set("quantity", quantity);
            
            Object result = expression.evaluate(context);

            if (result instanceof BigDecimal) {
                return (BigDecimal) result;
            }
            if (result instanceof Number) {
                return BigDecimal.valueOf(((Number) result).doubleValue());
            }
            return basePrice;
        } catch (Exception e) {
            // If expression evaluation fails, return base price as fallback
            return basePrice;
        }
    }
}
```

## Explanation

The fix replaces Groovy's unrestricted `GroovyShell` with Apache Commons JEXL, a purpose-built sandboxed expression language. The change eliminates the injection path by:

1. **Sandboxing by default**: `new JexlSandbox(false)` creates a deny-by-default policy. No methods, constructors, or system calls are accessible unless explicitly allowed.

2. **Allowlisting only necessary classes**: Only `BigDecimal` and `Number` are permitted, preventing access to `java.lang.Runtime`, reflection APIs, or class loaders.

3. **Restricted evaluation context**: Variables `basePrice` and `quantity` are bound in the `MapContext`, but the expression cannot access application internals, config, or credentials outside this context.

4. **Error handling**: Failed expressions return the base price rather than throwing, ensuring graceful degradation.

The existing formula syntax (ternary operators, arithmetic, comparisons) is compatible with JEXL, so most admin-configured formulas will work unchanged. Formulas relying on Groovy-specific features (e.g., string interpolation, closures) will fail safely by returning basePrice.

## Behaviour changes

- Formulas using Groovy-only syntax (closures, GString interpolation, `.with {}` blocks) will no longer evaluate and will return the base price.
- Expression evaluation now catches all exceptions and returns basePrice as a fallback, rather than propagating errors.
- Expressions cannot access Java methods, constructors, or system resources outside the `basePrice` and `quantity` variables.
- The first evaluation constructs the sandboxed engine once in the constructor, then reuses it for all subsequent formula evaluations.

**Dependency required**: `org.apache.commons:commons-jexl3` (version 3.2 or later; check SCA tooling for the specific safe version before merging).
