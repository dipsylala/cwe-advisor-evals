## Verdict

Confirmed. Real, exploitable null pointer dereference.

## Source

`DiscountRepository.findDiscountCentsForSku(String sku)` is documented (in `DiscountRepository.java`) to return `null` when no discount is configured for the given SKU. This is a legitimate, contractual absent-value case, not an edge case that should never occur — any SKU with no configured discount produces `null`.

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
        long discount = 0L;
        if (discountCents != null) {
            discount = discountCents;
        }
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

`findDiscountCentsForSku` returns the boxed type `Long` specifically because it can legitimately report "no discount configured" as `null`. The original `applyDiscount` used the result directly in `priceCents - discountCents`, an arithmetic expression that forces unboxing (`discountCents.longValue()`); for any SKU without a configured discount this throws `NullPointerException` with no `.` in the source line to hint at the dereference. The fix reads the producer's contract (a documented nullable return, not a bug to fix upstream) and handles the absence at the point the value is obtained: when `discountCents` is `null`, "no discount" is treated as a discount of `0`, which is the natural default matching the method's own `Math.max(discounted, 0L)` floor — no discount reduces the price by zero rather than crashing. The `if (discountCents != null)` guard means the unboxing assignment `discount = discountCents;` only executes on the branch already proven non-null, so it is not the ternary-unboxing hazard the guidance warns about (both branches of a `cond ? Long : long` ternary are type-unified and can unbox the untaken side's static type; a plain `if` avoids that entirely).

The sibling call site `isDiscountApplied` shared the same producer and had the identical defect: `discountCents > 0` unboxes unconditionally. Per the guidance's "audit sibling call sites" step, it is fixed the same way, using short-circuit `&&` so `discountCents > 0` is only evaluated once `discountCents != null` has already been confirmed true — a SKU with no discount now correctly reports "not applied" instead of throwing.

`DiscountRepository.java` is unchanged: its contract (a nullable return documented in a comment) is a legitimate optional-lookup pattern, and the defect was entirely in how the two consumers handled that contract, not in the producer itself.

## Behaviour changes

- `applyDiscount(sku, priceCents)`: for a SKU with no configured discount, previously threw `NullPointerException`; now returns `priceCents` unchanged (subject to the existing `Math.max(discounted, 0L)` floor), i.e. no discount is applied.
- `isDiscountApplied(sku)`: for a SKU with no configured discount, previously threw `NullPointerException`; now returns `false`.
- No change for any SKU that has a configured discount — both methods behave exactly as before in that case.

**Check performed:** copied `PricingService.java` and `DiscountRepository.java` into a scratch directory and compiled the fixed `PricingService.java` against the unmodified sibling interface with `javac -Xlint:all evalcases/DiscountRepository.java evalcases/PricingService.java`. Compiled cleanly with no errors or warnings.
