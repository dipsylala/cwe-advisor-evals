package com.example.pricing;

import groovy.lang.Binding;
import groovy.lang.GroovyShell;

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

        Binding binding = new Binding();
        binding.setVariable("basePrice", basePrice);
        binding.setVariable("quantity", quantity);

        GroovyShell shell = new GroovyShell(binding);
        // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
        Object result = shell.evaluate(customFormula);

        if (result instanceof BigDecimal) {
            return (BigDecimal) result;
        }
        if (result instanceof Number) {
            return BigDecimal.valueOf(((Number) result).doubleValue());
        }
        return basePrice;
    }
}
