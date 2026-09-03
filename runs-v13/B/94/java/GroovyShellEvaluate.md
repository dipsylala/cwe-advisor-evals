## Verdict
**Real**: GroovyShell.evaluate() at line 43 executes untrusted code from the database. The comments note the formula is admin-configured, but admin accounts can be compromised, and databases can be breached. Dynamic code evaluation should be replaced with static logic.

## Source
```java
public BigDecimal computePrice(String productId, BigDecimal basePrice, int quantity) {
    String customFormula = pricingRuleRepository.findFormulaByProductId(productId);
    if (customFormula == null || customFormula.isBlank()) {
        return basePrice;
    }

    Binding binding = new Binding();
    binding.setVariable("basePrice", basePrice);
    binding.setVariable("quantity", quantity);

    GroovyShell shell = new GroovyShell(binding);
    // VULNERABLE: GroovyShell.evaluate() executes arbitrary Groovy code
    Object result = shell.evaluate(customFormula);
    
    if (result instanceof BigDecimal) {
        return (BigDecimal) result;
    }
    if (result instanceof Number) {
        return BigDecimal.valueOf(((Number) result).doubleValue());
    }
    return basePrice;
}
```

The vulnerability chain: `pricingRuleRepository.findFormulaByProductId()` retrieves the formula string from the database → `shell.evaluate(customFormula)` executes it as Groovy code at line 43 → arbitrary code execution with application privileges.

## Fix
Replace dynamic Groovy evaluation with a strategy pattern using a lookup map of product-specific pricing strategies:

```java
package com.example.pricing;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;

/**
 * Evaluates the admin-configured "custom pricing formula" against a specific
 * order's base price and quantity by dispatching to predefined, safe strategies.
 * Admins select a formula name (key) rather than supplying formula text.
 */
public class PricingFormulaEvaluator {

    private final PricingRuleRepository pricingRuleRepository;
    private final Map<String, BiFunction<BigDecimal, Integer, BigDecimal>> strategies;

    public PricingFormulaEvaluator(PricingRuleRepository pricingRuleRepository) {
        this.pricingRuleRepository = pricingRuleRepository;
        this.strategies = initializeStrategies();
    }

    private Map<String, BiFunction<BigDecimal, Integer, BigDecimal>> initializeStrategies() {
        Map<String, BiFunction<BigDecimal, Integer, BigDecimal>> map = new HashMap<>();
        // Define safe, predefined pricing formulas
        map.put("BASE", (basePrice, quantity) -> basePrice);
        map.put("QUANTITY_DISCOUNT_10", (basePrice, quantity) ->
            quantity > 10 ? basePrice.multiply(BigDecimal.valueOf(0.9)) : basePrice);
        map.put("QUANTITY_DISCOUNT_20", (basePrice, quantity) ->
            quantity > 20 ? basePrice.multiply(BigDecimal.valueOf(0.8)) : basePrice);
        map.put("TIERED", (basePrice, quantity) -> {
            if (quantity > 50) return basePrice.multiply(BigDecimal.valueOf(0.7));
            if (quantity > 20) return basePrice.multiply(BigDecimal.valueOf(0.8));
            if (quantity > 10) return basePrice.multiply(BigDecimal.valueOf(0.9));
            return basePrice;
        });
        return map;
    }

    /**
     * Computes the final unit price for a product using a safe, predefined pricing strategy.
     *
     * @param productId the product whose strategy should be applied
     * @param basePrice the catalog base price for the product
     * @param quantity  the quantity being quoted
     * @return the computed price, or basePrice if no matching strategy is found
     */
    public BigDecimal computePrice(String productId, BigDecimal basePrice, int quantity) {
        // Retrieve the strategy name (not formula text) from the repository
        String strategyName = pricingRuleRepository.findFormulaByProductId(productId);
        if (strategyName == null || strategyName.isBlank()) {
            return basePrice;
        }

        // Look up the safe, predefined strategy by name
        BiFunction<BigDecimal, Integer, BigDecimal> strategy = strategies.get(strategyName);
        if (strategy == null) {
            // Strategy not recognized; return basePrice as default
            return basePrice;
        }

        // Apply the safe strategy
        BigDecimal result = strategy.apply(basePrice, quantity);
        return result != null ? result : basePrice;
    }
}
```

## Explanation
The fix eliminates the dynamic code evaluation by replacing `GroovyShell.evaluate()` with a lookup table of predefined, safe pricing strategies. Instead of storing and executing arbitrary Groovy expressions, the database now stores only strategy names (keys like "QUANTITY_DISCOUNT_10"), which are looked up in a `Map<String, BiFunction<...>>` initialized with hardcoded pricing logic. This:

1. **Removes code injection risk**: No untrusted code is evaluated; only predefined, developer-controlled functions run.
2. **Preserves the external contract**: The method signature and behaviour remain unchanged—it still computes discounted prices based on quantity.
3. **Enables safe product-specific configuration**: Admins configure which predefined strategy applies to each product, not write custom expressions.
4. **Defaults safely**: Unknown strategy names return the base price instead of attempting evaluation.

The strategy pattern can be extended by adding new entries to `initializeStrategies()` without risk, and complex pricing logic remains testable as standard Java code rather than parsed expressions.

## Behaviour changes
- **Database schema implication**: If the database currently stores arbitrary Groovy expressions in `pricing_rules`, it must be migrated to store only recognized strategy names. Existing rows containing complex expressions will be treated as unknown strategies and default to basePrice.
- **Admin workflow**: Admins can no longer write custom expressions; they select from a fixed list of predefined strategies (e.g., "QUANTITY_DISCOUNT_10", "TIERED").
- **Extensibility shift**: Adding new pricing strategies now requires a code change (adding an entry to the strategy map and redeploying), not a database update.
- **Error handling**: Invalid strategy names silently default to basePrice instead of throwing a GroovyException; this is more forgiving for deployments with stale or malformed data.
