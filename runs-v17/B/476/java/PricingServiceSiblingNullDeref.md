## Verdict

**CONFIRMED - Real null pointer dereference vulnerability**

The finding is valid. `DiscountRepository.findDiscountCentsForSku()` returns `Long` (boxed) and is documented to return null when no discount is configured. Line 13 performs arithmetic with this potentially-null value, triggering implicit unboxing and a `NullPointerException`.

A secondary vulnerability exists on line 19 in the sibling method `isDiscountApplied()` with the same pattern.

## Source

**Vulnerable code:**

```java
public long applyDiscount(String sku, long priceCents) {
    Long discountCents = discounts.findDiscountCentsForSku(sku);  // Can return null
    // SAST FINDING: CWE-476 (NULL Pointer Dereference) reported here. Sink is the next statement.
    long discounted = priceCents - discountCents;                 // Unboxing null Long throws NPE
    return Math.max(discounted, 0L);
}

public boolean isDiscountApplied(String sku) {
    Long discountCents = discounts.findDiscountCentsForSku(sku);  // Can return null
    return discountCents > 0;                                     // Unboxing null Long throws NPE
}
```

**Data flow:**

1. `DiscountRepository.findDiscountCentsForSku(sku)` returns `Long` with documented null return on cache miss
2. Result assigned to `discountCents` (boxed `Long` type)
3. Line 13: `priceCents - discountCents` attempts subtraction of primitive `long` and boxed `Long`
4. Java applies binary numeric promotion, unboxing the `Long` to primitive `long`
5. If `discountCents` is null, unboxing throws `NullPointerException`
6. Line 19 has identical unboxing in comparison: `discountCents > 0`

**Producer contract:**

The interface explicitly documents: "Returns null when no discount is configured for the given sku."

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
        // Handle null discount - treat missing discount as 0 cents
        long discount = discountCents != null ? discountCents : 0L;
        long discounted = priceCents - discount;
        return Math.max(discounted, 0L);
    }

    public boolean isDiscountApplied(String sku) {
        Long discountCents = discounts.findDiscountCentsForSku(sku);
        // Handle null discount - if no discount is configured, return false
        return discountCents != null && discountCents > 0;
    }
}
```

## Explanation

The fix prevents null pointer dereference by explicitly handling the documented null case before unboxing:

1. **Line 13 (primary finding):** Introduced an intermediate variable `discount` with ternary operator that tests for null: `long discount = discountCents != null ? discountCents : 0L;`. This converts the null case to a concrete zero-discount value before the arithmetic operation, eliminating the unboxing of null.

2. **Line 19 (sibling):** Added explicit null check in the boolean condition: `return discountCents != null && discountCents > 0;`. The null check happens first (short-circuit evaluation), preventing unboxing when null.

The semantics are preserved:
- If no discount is configured (null), the code treats it as a 0-cent discount, returning the original price
- The `isDiscountApplied()` method correctly returns false when no discount is configured

This follows the CWE-476 Java guidance to "make absence explicit at the point the value is obtained" rather than adding a runtime guard only at the crash site. Both call paths that receive the potentially-null value now handle it safely.

**Compilation check:** The fixed code compiles successfully with `javac` without errors or warnings.

## Behaviour changes

1. **applyDiscount method:** When `findDiscountCentsForSku()` returns null (no discount configured), the method now returns the original `priceCents` unchanged, rather than crashing with `NullPointerException`. This is the intended behavior - missing discount configuration should result in no discount being applied.

2. **isDiscountApplied method:** When `findDiscountCentsForSku()` returns null, the method now returns `false` (no discount applied), rather than crashing. Previously, any attempt to check this would crash; now it cleanly indicates no discount is active.

3. **Non-breaking:** When `findDiscountCentsForSku()` returns a non-null value, both methods behave identically to the original code - no change to the happy path.

