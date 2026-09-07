## Verdict

The NULL pointer dereference is confirmed. The method `applyDiscount()` at line 13 performs unboxing on `discountCents` without checking for null. The `DiscountRepository.findDiscountCentsForSku()` method returns `Long` (boxed type) that can be null, as documented in its interface. Attempting to unbox null to primitive `long` causes a NullPointerException.

Additionally, `isDiscountApplied()` at line 19 has the same vulnerability.

## Source

The vulnerability originates from `DiscountRepository.findDiscountCentsForSku(sku)` returning `null` when no discount is configured, and the caller attempting to unbox this null value to a primitive type without null checking.

Call chain:
1. `DiscountRepository.findDiscountCentsForSku(String)` returns `Long` (nullable)
2. `PricingService.applyDiscount()` calls it and stores result in `Long discountCents`
3. Line 13: Arithmetic operation `priceCents - discountCents` triggers unboxing of potentially null value
4. NullPointerException when `discountCents` is null

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
        // Null-check before unboxing: treat absent discount as zero discount
        if (discountCents == null) {
            discountCents = 0L;
        }
        long discounted = priceCents - discountCents;
        return Math.max(discounted, 0L);
    }

    public boolean isDiscountApplied(String sku) {
        Long discountCents = discounts.findDiscountCentsForSku(sku);
        // Null-check before unboxing and comparison
        return discountCents != null && discountCents > 0;
    }
}
```

## Explanation

The fix adds explicit null checks before any use of the potentially null `Long` value:

1. In `applyDiscount()`: Check if `discountCents` is null and assign a default value of `0L` (representing no discount). This allows the arithmetic operation to proceed safely with a primitive `long`.

2. In `isDiscountApplied()`: Use short-circuit evaluation with `&&` to check for null before the `>` comparison. This prevents unboxing a null value and returns `false` when no discount is configured, which is semantically correct—if there's no discount configured, then no discount is applied.

The remediation preserves the original behavior while preventing the NULL pointer dereference vulnerability. When the repository returns null (indicating no discount configured), the code now treats it as a discount of zero cents, which is the correct logical interpretation.
