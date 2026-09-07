package com.example.pricing;


/** Compile-only collaborator the fixture references but does not ship. */
public interface PricingRuleRepository {
    String findFormulaByProductId(String productId);
    default String findFormulaByProductId(long productId) { return findFormulaByProductId(Long.toString(productId)); }
}
