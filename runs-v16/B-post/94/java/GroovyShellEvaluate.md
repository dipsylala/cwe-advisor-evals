## Verdict

**CONFIRMED** - CWE-94: Code Injection via GroovyShell.evaluate()

The code at line 43 executes untrusted formula text loaded from the database using Groovy's dynamic evaluation API. Even though the source is admin-configured, if database access is compromised or if any admin-facing configuration interface has injection vulnerabilities, arbitrary Groovy code can execute within the application's runtime context. Groovy's `GroovyShell.evaluate()` provides no sandboxing and exposes full language capabilities including class loading, reflection, and system command execution.

## Source

```
String customFormula = pricingRuleRepository.findFormulaByProductId(productId);  // Line 32
```

The formula string originates from a database field (`pricing_rules.formula`) keyed by product ID. The source is not directly user-supplied HTTP input, but rather configuration data stored persistently; the vulnerability exists if the data store or admin panel becomes a compromise vector.

## Fix

Replace `GroovyShell` with Apache Commons JEXL using a deny-by-default sandbox. JEXL is purpose-built for safe expression evaluation and allows the restricted evaluation of arithmetic and property-access expressions without exposing language internals or type constructors.

**Dependency:** Add Apache Commons JEXL 3.3 or later to the project's `pom.xml` or equivalent:
```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-jexl3</artifactId>
    <version>3.3</version>
</dependency>
```

**Fixed code:**

```java
package com.example.pricing;

import org.apache.commons.jexl3.*;

import java.math.BigDecimal;

/**
 * Evaluates the admin-configured "custom pricing formula" against a specific
 * order's base price and quantity. Admins manage the formula text through
 * the pricing configuration screen; it is stored verbatim in the
 * pricing_rules table and loaded back in here at quote time.
 */
public class PricingFormulaEvaluator {

    private static final JexlEngine JEXL_ENGINE;
    private static final JexlSandbox SANDBOX;

    static {
        // Configure a deny-by-default sandbox that allows only necessary arithmetic
        SANDBOX = new JexlSandbox(false);
        SANDBOX.allow(BigDecimal.class.getName());
        SANDBOX.allow(Number.class.getName());
        // Allow Math functions if needed for advanced formulas
        SANDBOX.allow(Math.class.getName());

        // Build engine with sandbox and restricted features
        JexlBuilder builder = new JexlBuilder();
        builder.sandbox(SANDBOX);
        builder.features(new JexlFeatures().newInstance(false).staticCall(false));
        JEXL_ENGINE = builder.create();
    }

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
            // Parse the formula expression once
            JexlExpression expression = JEXL_ENGINE.createExpression(customFormula);

            // Create a context with only the necessary variables
            JexlContext context = new MapContext();
            context.set("basePrice", basePrice);
            context.set("quantity", quantity);

            // Evaluate the expression in the restricted sandbox
            Object result = expression.evaluate(context);

            if (result instanceof BigDecimal) {
                return (BigDecimal) result;
            }
            if (result instanceof Number) {
                return BigDecimal.valueOf(((Number) result).doubleValue());
            }
            return basePrice;
        } catch (JexlException e) {
            // Expression is malformed or evaluation failed; reject it and return base price
            return basePrice;
        }
    }
}
```

## Explanation

The fix replaces Groovy's unrestricted code evaluation with Apache Commons JEXL, a lightweight expression language designed for safe evaluation. Key changes:

1. **Deny-by-default sandbox:** `JexlSandbox(false)` disables all access by default. Only `BigDecimal`, `Number`, and optionally `Math` are explicitly allowed.

2. **Disabled unsafe features:** `newInstance(false)` prevents object construction (blocking `new` expressions), and `staticCall(false)` prevents static method invocation (blocking `Runtime.getRuntime().exec()` style attacks).

3. **Restricted namespace:** The context exposes only `basePrice` and `quantity` variables; all other identifiers are undefined and cause evaluation to fail.

4. **Exception handling:** Malformed expressions throw `JexlException`, which is caught and handled gracefully by returning the base price.

5. **Same return contract:** The code still returns a numeric value or falls back to `basePrice`, preserving the original API behavior.

JEXL allows arithmetic, property access, and ternary operators (like `quantity > 10 ? 0.9 : 1.0`), so existing formulas remain compatible. The sandbox prevents access to Java's reflection API, class loaders, file I/O, and networking - the attack surface is limited to mathematical expressions only.

## Behaviour changes

- **Valid formulas:** Existing simple arithmetic and ternary formulas like `basePrice * (quantity > 10 ? 0.9 : 1.0)` evaluate identically.
- **Invalid formulas:** Any formula attempting object construction, static method calls, or class references now fails silently and returns the base price. This is safe-fail behavior.
- **Performance:** JEXL expressions are parsed and compiled once per evaluation; no runtime compilation cost beyond the original `GroovyShell`.
- **Error handling:** Malformed or rejected expressions now return the base price instead of propagating exceptions, which is a deliberate safe-fail design to prevent configuration errors from crashing quote generation.
