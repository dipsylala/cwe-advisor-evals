## Verdict

Exploitable. The code dereferences a nullable `Long` from `DiscountRepository.findDiscountCentsForSku()` without a null check. In `applyDiscount()` line 13, unboxing the null `Long` into arithmetic (`priceCents - discountCents`) throws `NullPointerException`. In `isDiscountApplied()` line 19, the comparison `discountCents > 0` also dereferences the boxed null and throws.

## Source

`DiscountRepository.findDiscountCentsForSku(String sku)` returns `Long` with explicit javadoc contract: "Returns null when no discount is configured for the given sku."

## Fix

### File: PricingService.java

```java
package evalcases;

public class PricingService {
    private final DiscountRepository discounts;

    public PricingService(DiscountRepository discounts) {
        this.discounts = discounts;
    }

    public long applyDiscount(String sku, long priceCents) {
        Long discountCents = discounts.findDiscountCentsForSku(sku);
        // Handle null case: no configured discount means apply 0 discount
        long discount = discountCents != null ? discountCents : 0L;
        long discounted = priceCents - discount;
        return Math.max(discounted, 0L);
    }

    public boolean isDiscountApplied(String sku) {
        Long discountCents = discounts.findDiscountCentsForSku(sku);
        // Check for null before comparison
        return discountCents != null && discountCents > 0;
    }
}
```

## Explanation

The fix adds null checks before dereference. In `applyDiscount()`, a null discount is treated as 0L (no discount applied), which is the correct business-logic interpretation: if no discount row exists for a SKU, the price is unchanged. The ternary `discountCents != null ? discountCents : 0L` assigns a primitive-typed value so the subsequent arithmetic `priceCents - discount` operates on primitives only, avoiding unboxing entirely. In `isDiscountApplied()`, the short-circuit `discountCents != null && discountCents > 0` returns false when the discount is absent (no configured discount means none is applied) and true only when a configured discount exists and is positive. Both methods now handle the documented null case from the repository and eliminate the unboxing-null crash.

## Behaviour changes

None. The fix preserves the existing contract: `applyDiscount()` still returns a non-negative value (Math.max enforces it), and `isDiscountApplied()` still returns a boolean. The null case is now handled explicitly rather than crashing. If a discount-not-found scenario was previously caught by a try-catch around this method (anti-pattern, but worth checking), removing the NPE changes behavior by not triggering that catch - that is correct and intended, as the handler is then gone.
