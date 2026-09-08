## Verdict
Confirmed. `PricingService.applyDiscount` unboxes the `Long` returned by `DiscountRepository.findDiscountCentsForSku(sku)` into a primitive `long` at line 13 (`priceCents - discountCents`). The repository interface's own contract states this method "Returns null when no discount is configured for the given sku," so any sku without a configured discount triggers an auto-unboxing `NullPointerException` at that subtraction.

## Source
The null originates from `DiscountRepository.findDiscountCentsForSku(sku)`, called in `PricingService.applyDiscount(String sku, long priceCents)`. The result is assigned to the boxed local `Long discountCents`, which flows unchecked into the arithmetic expression `priceCents - discountCents` on the next line, where Java auto-unboxes it to `long` and dereferences the null reference.

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
        long discountValue = (discountCents != null) ? discountCents : 0L;
        long discounted = priceCents - discountValue;
        return Math.max(discounted, 0L);
    }

    public boolean isDiscountApplied(String sku) {
        Long discountCents = discounts.findDiscountCentsForSku(sku);
        return discountCents != null && discountCents > 0;
    }
}
```

## Explanation
`applyDiscount` now checks `discountCents` for null before it is unboxed, substituting `0L` (no discount) when the repository has none configured for the sku, matching the documented "no discount configured" case rather than treating it as an error. This preserves the intended pricing behavior: a sku with no discount is charged full price instead of crashing.

`isDiscountApplied` had the identical latent defect on the same repository call (`discountCents > 0` auto-unboxes just as the arithmetic in `applyDiscount` does), so it is fixed the same way with a short-circuiting null check, `discountCents != null && discountCents > 0`, so a sku with no discount correctly reports `false` instead of throwing.

No other files needed changes; `DiscountRepository` already documents its null-return contract correctly, and the fix simply makes `PricingService` honor that contract at both call sites.
