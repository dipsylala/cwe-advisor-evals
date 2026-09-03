## Verdict

Confirmed. CWE-476 NULL Pointer Dereference on line 13.

## Source

The vulnerability occurs in `PricingService.applyDiscount()`. The method calls `discounts.findDiscountCentsForSku(sku)`, which returns a nullable `Long` (as documented in the `DiscountRepository` interface: "Returns null when no discount is configured"). On line 13, the code attempts to unbox this `Long` directly in arithmetic without checking for null:

```java
Long discountCents = discounts.findDiscountCentsForSku(sku);
long discounted = priceCents - discountCents;
```

Unboxing a null `Long` throws a `NullPointerException`. The sibling method `isDiscountApplied()` has the same issue on line 19.

## Fix

```java
package evalcases;

public class PricingService {
    private final DiscountRepository discounts;

    public PricingService(DiscountRepository discounts) {
        this.discounts = discounts;
    }

    public long applyDiscount(String sku, long priceCents) {
        Long discountCents = discounts.findDiscountCentsForSku(sku);
        long discount = discountCents != null ? discountCents : 0L;
        long discounted = priceCents - discount;
        return Math.max(discounted, 0L);
    }

    public boolean isDiscountApplied(String sku) {
        Long discountCents = discounts.findDiscountCentsForSku(sku);
        return discountCents != null && discountCents > 0;
    }
}
```

## Explanation

The fix adds explicit null checks before unboxing the nullable `Long` value:

1. **In `applyDiscount()`**: Check if `discountCents` is null. If null (no discount configured), use `0L` as the discount amount. This is semantically correct—a missing discount means no reduction in price.

2. **In `isDiscountApplied()`**: Check if `discountCents` is null before comparing to 0. If null, the method returns false, meaning no discount is applied, which is the correct logical interpretation.

The fix addresses the root cause: the producer (`DiscountRepository.findDiscountCentsForSku()`) can legitimately return null, but both callers were ignoring this contract. By handling absence explicitly at the call site with a meaningful default value, we prevent unboxing a null and ensure correct semantics.

## Behaviour changes

- **Before**: Calling `applyDiscount()` when no discount exists for the SKU throws `NullPointerException`.
- **After**: When no discount exists, `applyDiscount()` treats it as a 0-cent discount and returns the original price (after rounding to non-negative).

- **Before**: Calling `isDiscountApplied()` when no discount exists for the SKU throws `NullPointerException`.
- **After**: When no discount exists, `isDiscountApplied()` returns `false`, indicating no discount is applied.

Both changes are correct and expected; the system now handles the documented null return value properly rather than crashing.
