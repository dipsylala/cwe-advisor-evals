## Verdict

The finding is real. Line 13 unboxes a nullable `Long` value in an arithmetic operation without checking for null, causing a `NullPointerException` when `discounts.findDiscountCentsForSku()` returns null (its documented behavior when no discount is configured). A secondary instance of the same pattern exists at line 19.

## Source

`DiscountRepository.findDiscountCentsForSku(String sku)` returns `Long` (boxed, nullable). The interface documents: "Returns null when no discount is configured for the given sku."

## Fix

Change the return type of `findDiscountCentsForSku` to `Optional<Long>` and update both callers to handle the absence explicitly:

```java
package evalcases;

import java.util.Optional;

public interface DiscountRepository {
    // Returns empty Optional when no discount is configured for the given sku.
    Optional<Long> findDiscountCentsForSku(String sku);
}
```

```java
package evalcases;

public class PricingService {
    private final DiscountRepository discounts;

    public PricingService(DiscountRepository discounts) {
        this.discounts = discounts;
    }

    public long applyDiscount(String sku, long priceCents) {
        long discountCents = discounts.findDiscountCentsForSku(sku).orElse(0L);
        long discounted = priceCents - discountCents;
        return Math.max(discounted, 0L);
    }

    public boolean isDiscountApplied(String sku) {
        long discountCents = discounts.findDiscountCentsForSku(sku).orElse(0L);
        return discountCents > 0;
    }
}
```

## Explanation

The fix makes absence explicit by changing the producer's return type from `Long` (where null is ambiguous) to `Optional<Long>` (where absence is semantically clear). Each call site invokes `.orElse(0L)` to provide a safe default value (no discount) when the repository returns an empty Optional. This eliminates the invisible unboxing of null at lines 13 and 19, converting a runtime crash into a predictable, controlled behavior. The fix preserves the original logic: when no discount is configured, the price remains unchanged (treated as a 0-cent discount).

## Behaviour changes

- When `DiscountRepository.findDiscountCentsForSku()` returns empty (no discount configured), both methods now treat it as a 0-cent discount and proceed normally, rather than crashing with a `NullPointerException`.
- `applyDiscount()` returns the full original price (no reduction) when no discount is configured.
- `isDiscountApplied()` returns `false` when no discount is configured.
- Callers of `DiscountRepository` must now handle the `Optional` return type explicitly, making the optional nature of the discount visible at the call site.
