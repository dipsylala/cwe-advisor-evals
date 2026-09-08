## Verdict
CONFIRMED. CWE-476 NULL pointer dereference at line 13. `discountCents` is a nullable `Long` object that is auto-unboxed without null checking, causing a NullPointerException when the discount repository returns null.

## Source
The `DiscountRepository.findDiscountCentsForSku()` method explicitly returns null when no discount is configured. The `applyDiscount()` method assigns this potentially null value to a `Long` field and immediately uses it in arithmetic (`priceCents - discountCents`) without checking for null. The `isDiscountApplied()` method has the same vulnerability in its comparison (`discountCents > 0`).

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
        // Default to 0 discount if no discount is configured
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
The fix adds explicit null checks before using the potentially null `Long` value:

1. In `applyDiscount()`: Check if `discountCents` is null and default to 0L (no discount) if so. This prevents NullPointerException during auto-unboxing in the arithmetic operation.

2. In `isDiscountApplied()`: Add a null check in the boolean condition. The expression `discountCents != null && discountCents > 0` short-circuits to false if `discountCents` is null, preventing NullPointerException in the comparison.

Both fixes follow the semantics of the DiscountRepository contract: null means "no discount configured", which should be treated as 0 discount cents.
