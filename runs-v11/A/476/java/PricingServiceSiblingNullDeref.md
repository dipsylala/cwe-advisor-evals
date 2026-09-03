## Verdict

The finding is a valid CWE-476 NULL Pointer Dereference. The `discountCents` variable, returned from `discounts.findDiscountCentsForSku(sku)`, is a nullable `Long` wrapper type. When used in the arithmetic operation at line 13 (`priceCents - discountCents`), auto-unboxing will throw a `NullPointerException` if the value is null.

## Source

```java
public long applyDiscount(String sku, long priceCents) {
    Long discountCents = discounts.findDiscountCentsForSku(sku);
    // SAST FINDING: CWE-476 (NULL Pointer Dereference) reported here. Sink is the next statement.
    long discounted = priceCents - discountCents;
    return Math.max(discounted, 0L);
}

public boolean isDiscountApplied(String sku) {
    Long discountCents = discounts.findDiscountCentsForSku(sku);
    return discountCents > 0;
}
```

## Fix

```java
public long applyDiscount(String sku, long priceCents) {
    Long discountCents = discounts.findDiscountCentsForSku(sku);
    if (discountCents == null) {
        discountCents = 0L;
    }
    long discounted = priceCents - discountCents;
    return Math.max(discounted, 0L);
}

public boolean isDiscountApplied(String sku) {
    Long discountCents = discounts.findDiscountCentsForSku(sku);
    return discountCents != null && discountCents > 0;
}
```

Alternatively, if using Java 9+, the ternary operator can be more concise:

```java
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
```

## Explanation

The interface `DiscountRepository` explicitly documents that `findDiscountCentsForSku(String sku)` returns null when no discount is configured for a given SKU. The `discountCents` variable must be null-checked before any operation that requires unboxing the `Long` wrapper to a primitive `long`.

In `applyDiscount`, the null-check replaces the null value with `0L`, treating the absence of a discount as zero discount—a semantically sound default. In `isDiscountApplied`, the short-circuit AND operator (`&&`) safely handles the null case: if `discountCents` is null, the comparison `discountCents > 0` is never reached, preventing auto-unboxing of a null value.
