## Verdict

Confirmed exploitable. The code executes arbitrary Groovy expressions stored in the database without validation or sandboxing. An attacker with database access can inject malicious code that executes with the application's privileges.

## Source

The source is the `customFormula` string retrieved from `pricingRuleRepository.findFormulaByProductId(productId)` at line 32. While the documentation states "Admins manage the formula text", the database layer is not a trust boundary against code injection. The formula is executed directly at line 43 via `shell.evaluate(customFormula)`.

## Fix

Replace Groovy's `GroovyShell` with Apache Commons JEXL using a deny-by-default sandbox. JEXL is designed for safe expression evaluation and allows mathematical expressions while blocking method invocation, reflection, and object construction by default.

**1. Add Maven dependency** (pom.xml):
```xml
<dependency>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-jexl3</artifactId>
  <version>3.3</version>
</dependency>
```

**2. Refactor PricingFormulaEvaluator.java**:

Replace the entire computePrice method and update imports:

```java
package com.example.pricing;

import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
import org.apache.commons.jexl3.JexlSandbox;
import org.apache.commons.jexl3.MapContext;

import java.math.BigDecimal;
import java.util.regex.Pattern;

public class PricingFormulaEvaluator {

    private final PricingRuleRepository pricingRuleRepository;
    private final JexlEngine jexlEngine;
    
    // Allowlist pattern: only alphanumerics, operators, parentheses, spaces, and dots for property access
    private static final Pattern FORMULA_ALLOWLIST = Pattern.compile(
        "^[a-zA-Z0-9\\s()\\+\\-\\*/%<>=!&|.?:]+$"
    );

    public PricingFormulaEvaluator(PricingRuleRepository pricingRuleRepository) {
        this.pricingRuleRepository = pricingRuleRepository;
        
        // Create a deny-by-default sandbox
        JexlSandbox sandbox = new JexlSandbox(false);
        
        // Allow only BigDecimal and Number classes for arithmetic operations
        sandbox.allow(BigDecimal.class.getName());
        sandbox.allow(Number.class.getName());
        
        // Create JEXL engine with the restricted sandbox
        this.jexlEngine = new JexlBuilder()
            .sandbox(sandbox)
            .create();
    }

    public BigDecimal computePrice(String productId, BigDecimal basePrice, int quantity) {
        String customFormula = pricingRuleRepository.findFormulaByProductId(productId);
        if (customFormula == null || customFormula.isBlank()) {
            return basePrice;
        }

        // Validate formula against allowlist before evaluation
        if (!FORMULA_ALLOWLIST.matcher(customFormula).matches()) {
            // Formula contains disallowed characters; reject it
            return basePrice;
        }

        try {
            // Compile and evaluate the expression with restricted context
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
            // Evaluation failed (syntax error, sandbox denial, etc.); reject and return base price
            return basePrice;
        }
    }
}
```

## Explanation

The fix replaces Groovy's unrestricted `GroovyShell` with Apache Commons JEXL, which is purpose-built for safe expression evaluation. The deny-by-default sandbox (`JexlSandbox(false)`) blocks all unsafe operations including method invocation, reflection, and object construction. Only arithmetic and property access operations are allowed by default.

The allowlist pattern validates the formula structure before evaluation, rejecting any formula containing characters outside the expected set (letters, numbers, operators, parentheses, and the dot for property access). This prevents injection attempts using escape sequences or encoded payloads.

Evaluation failures (syntax errors, sandbox denials) are caught and cause the method to return the base price, ensuring the application remains functional even if a formula is malformed or malicious.

The restricted `JexlContext` provides only the two variables the formula needs (`basePrice`, `quantity`), preventing access to the repository, runtime, or any other application internals.

## Behaviour changes

- Formulas that use Groovy-specific syntax (method calls, class references, property access beyond the context variables) will no longer execute. Only pure mathematical expressions are supported.
- A formula that was previously valid in Groovy but is not valid JEXL syntax will now be rejected and return the base price.
- If a formula is malformed or triggers a sandbox denial, the method returns the base price instead of throwing an exception.
- The application requires Apache Commons JEXL 3.3 as a new dependency.
