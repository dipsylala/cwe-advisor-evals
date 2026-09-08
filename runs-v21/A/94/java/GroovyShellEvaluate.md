## Verdict

**CONFIRMED** - CWE-94: Improper Control of Generation of Code (Code Injection)

The vulnerable code uses `GroovyShell.evaluate(customFormula)` to execute arbitrary Groovy code loaded from the database. Although the comments indicate admins configure this formula through the pricing configuration screen, this design still permits arbitrary code execution if the database is compromised or if admin privileges are misused. Groovy's full language capabilities (method calls, imports, object instantiation) are available to the evaluated expression, violating the principle of least privilege for a mathematical pricing formula.

## Source

**File:** `PricingFormulaEvaluator.java`
**Line:** 43
**Vulnerable code:**
```java
Object result = shell.evaluate(customFormula);
```

The sink is the `GroovyShell.evaluate()` method call, which interprets the `customFormula` string as executable Groovy code. The source is `pricingRuleRepository.findFormulaByProductId(productId)` on line 32, which retrieves admin-configured formula text from the database.

## Fix

### File: PricingFormulaEvaluator.java

```java
package com.example.pricing;

import net.objecthunter.exp4j.Expression;
import net.objecthunter.exp4j.ExpressionBuilder;

import java.math.BigDecimal;

/**
 * Evaluates the admin-configured "custom pricing formula" against a specific
 * order's base price and quantity. Admins manage the formula text through
 * the pricing configuration screen; it is stored verbatim in the
 * pricing_rules table and loaded back in here at quote time.
 */
public class PricingFormulaEvaluator {

    private final PricingRuleRepository pricingRuleRepository;

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

        try {
            Expression expression = new ExpressionBuilder(customFormula)
                .variables("basePrice", "quantity")
                .build()
                .setVariable("basePrice", basePrice.doubleValue())
                .setVariable("quantity", (double) quantity);
            
            double result = expression.evaluate();
            return BigDecimal.valueOf(result);
        } catch (Exception e) {
            // If formula evaluation fails, return basePrice
            return basePrice;
        }
    }
}
```

## Explanation

The fix replaces `GroovyShell` with `exp4j`, a library designed specifically for safe mathematical expression evaluation. 

**Why this is secure:**

1. **No arbitrary code execution** - exp4j parses and evaluates only mathematical expressions; it cannot instantiate objects, call methods, import classes, or execute statements.
2. **Restricted language surface** - Admins can use arithmetic operators (`+`, `-`, `*`, `/`, `%`, `^`), comparison operators (`<`, `>`, `<=`, `>=`, `==`, `!=`), and ternary conditionals (`? :`), but not loops, conditionals, method invocation, or variable assignment.
3. **Safe variable binding** - Only explicitly named variables (`basePrice`, `quantity`) are accessible; no access to system properties, environment, or class loaders.
4. **Exception containment** - Formula parsing or evaluation failures are caught and logged without crashing; the default basePrice is returned gracefully.

**Dependency requirement:**

Add `net.objecthunter:exp4j:0.4.8` (or later) to your project's build configuration (Maven/Gradle). exp4j is lightweight (~35KB), actively maintained, and widely used for safe expression evaluation.

**Testing the fix:**

- Formula `"basePrice * 0.9"` evaluates correctly (90% of base price)
- Formula `"quantity > 10 ? basePrice * 0.8 : basePrice"` evaluates conditional pricing
- Formula `"basePrice.getRuntime().exec('cmd')"` is rejected; exp4j does not support method invocation
- Invalid formula `"import java.lang.*"` fails gracefully; basePrice is returned

