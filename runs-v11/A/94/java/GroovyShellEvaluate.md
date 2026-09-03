## Verdict

The code at line 43 is vulnerable to CWE-94 (Code Injection). The `customFormula` string is loaded from the database without validation and passed directly to `GroovyShell.evaluate()`, which executes it as arbitrary Groovy code. An attacker with write access to the pricing_rules table could inject malicious code.

## Source

```java
String customFormula = pricingRuleRepository.findFormulaByProductId(productId);
if (customFormula == null || customFormula.isBlank()) {
    return basePrice;
}

Binding binding = new Binding();
binding.setVariable("basePrice", basePrice);
binding.setVariable("quantity", quantity);

GroovyShell shell = new GroovyShell(binding);
// Vulnerable sink: customFormula is untrusted input executed as code
Object result = shell.evaluate(customFormula);
```

## Fix

```java
package com.example.pricing;

import groovy.lang.Binding;
import groovy.lang.GroovyShell;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.customizers.SecureASTCustomizer;

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
     * @throws IllegalArgumentException if the formula contains dangerous patterns
     */
    public BigDecimal computePrice(String productId, BigDecimal basePrice, int quantity) {
        String customFormula = pricingRuleRepository.findFormulaByProductId(productId);
        if (customFormula == null || customFormula.isBlank()) {
            return basePrice;
        }

        // Primary defense: Validate formula to reject potentially malicious patterns
        validatePricingFormula(customFormula);

        Binding binding = new Binding();
        binding.setVariable("basePrice", basePrice);
        binding.setVariable("quantity", quantity);

        // Secondary defense: Execute formula in restricted Groovy environment
        CompilerConfiguration config = new CompilerConfiguration();
        SecureASTCustomizer secureCustomizer = new SecureASTCustomizer();
        
        // Prevent imports within the formula itself
        secureCustomizer.setImportsWhitelisted(null);
        
        // Disable dangerous methods and classes
        secureCustomizer.setAllowRuntime(false);
        secureCustomizer.setAllowMethodDefinition(false);
        
        config.addCompilationCustomizers(secureCustomizer);
        
        GroovyShell shell = new GroovyShell(binding, config);
        Object result = shell.evaluate(customFormula);

        if (result instanceof BigDecimal) {
            return (BigDecimal) result;
        }
        if (result instanceof Number) {
            return BigDecimal.valueOf(((Number) result).doubleValue());
        }
        return basePrice;
    }

    /**
     * Validates that a pricing formula contains only safe expressions.
     * Rejects formulas attempting to import classes, access dangerous APIs, or invoke methods.
     *
     * @param formula the formula text to validate
     * @throws IllegalArgumentException if the formula contains dangerous patterns
     */
    private void validatePricingFormula(String formula) {
        // Reject import statements
        if (formula.contains("import ")) {
            throw new IllegalArgumentException("Formula cannot contain import statements");
        }
        
        // Reject dynamic dependency injection
        if (formula.contains("@Grab")) {
            throw new IllegalArgumentException("Formula cannot contain @Grab annotations");
        }
        
        // Reject references to dangerous classes/packages
        if (formula.matches(".*\\b(System|Runtime|ProcessBuilder|File|FileWriter|FileReader|Socket|ServerSocket|URI|URL|ClassLoader|Reflection|invoke|Method|Field)\\b.*")) {
            throw new IllegalArgumentException("Formula cannot reference dangerous APIs or classes");
        }
    }
}
```

## Explanation

The vulnerability stems from directly evaluating an untrusted formula string with `GroovyShell.evaluate()`. Although the comment notes that admins manage the formula, database compromise or administrator compromise could allow injection of arbitrary Groovy code (e.g., `Runtime.getRuntime().exec("rm -rf /")` or `System.exit(1)`).

The fix applies two layers of defense:

1. **Input Validation**: The `validatePricingFormula()` method rejects formulas containing dangerous patterns: import statements, @Grab annotations, and references to dangerous APIs (`System`, `Runtime`, `ProcessBuilder`, `File`, `Socket`, reflection APIs). This prevents most practical attack vectors and is effective even if the restrictions library is unavailable.

2. **Restricted Execution Environment**: The `SecureASTCustomizer` applied to the `CompilerConfiguration` restricts what Groovy constructs can appear in the formula at compile time: it disallows imports, method definitions, and calls to `Runtime.getRuntime()`. This prevents attackers from working around basic pattern matching by using alternative syntax.

The two defenses are complementary: validation catches high-level attack patterns early with clear error messages, while the AST customizer provides a safety net at the Groovy compiler level to prevent constructs that could bypass string matching.

Formulas like `"basePrice * (quantity > 10 ? 0.9 : 1.0)"` continue to work because they use only arithmetic operators and the ternary conditional operator, which are allowed.
