## Verdict

Confirmed. Line 13 unboxes a nullable `Long` without a null check, causing `NullPointerException` when `discounts.findDiscountCentsForSku(sku)` returns null. The same sink pattern appears at line 19 in a sibling method. Both require fixes.

## Source

`DiscountRepository.findDiscountCentsForSku(sku)` returns nullable `Long` (documented: "Returns null when no discount is configured for the given sku").

## Fix

**Original code (line 10–15):**
```java
public long applyDiscount(String sku, long priceCents) {
    Long discountCents = discounts.findDiscountCentsForSku(sku);
    // SAST FINDING: CWE-476 (NULL Pointer Dereference) reported here. Sink is the next statement.
    long discounted = priceCents - discountCents;
    return Math.max(discounted, 0L);
}
```

**Fixed code:**
```java
public long applyDiscount(String sku, long priceCents) {
    Long discountCents = discounts.findDiscountCentsForSku(sku);
    if (discountCents == null) {
        discountCents = 0L;
    }
    long discounted = priceCents - discountCents;
    return Math.max(discounted, 0L);
}
```

**Sibling method - Original code (line 17–20):**
```java
public boolean isDiscountApplied(String sku) {
    Long discountCents = discounts.findDiscountCentsForSku(sku);
    return discountCents > 0;
}
```

**Sibling method - Fixed code:**
```java
public boolean isDiscountApplied(String sku) {
    Long discountCents = discounts.findDiscountCentsForSku(sku);
    return discountCents != null && discountCents > 0;
}
```

## Explanation

The unboxing of `Long` to primitive `long` in arithmetic (line 13) and comparison (line 19) is an implicit dereference. When the repository returns null, Java attempts to unbox a null reference, throwing `NullPointerException` immediately.

The fix makes absence explicit at the point the nullable value is obtained. In `applyDiscount()`, a null discount is treated as no discount (0 cents), a safe default that preserves the method's contract. In `isDiscountApplied()`, the short-circuit check `discountCents != null &&` prevents dereferencing null and correctly returns false when no discount is configured.

Both fixes follow the Java guidance principle: handle the absence where the null-capable value is produced, not only where the first crash was observed. The DiscountRepository contract (nullable return) is not changed; instead, both callers now handle the absence explicitly.

## Behaviour changes

- `applyDiscount()` with an unconfigured SKU now applies 0 discount instead of crashing.
- `isDiscountApplied()` with an unconfigured SKU now returns false instead of crashing.
- No change to the behaviour when a discount is configured; the discount is applied correctly in both cases.
