## Verdict

Exploitable. Null pointer dereference confirmed via unboxing of nullable `Long` boxed wrapper type in arithmetic and comparison operations.

## Source

**File**: `evals/cases/476/java/PricingServiceSiblingNullDeref/DiscountRepository.java`

```java
public interface DiscountRepository {
    // Returns null when no discount is configured for the given sku.
    Long findDiscountCentsForSku(String sku);
}
```

The interface's return type `Long` (nullable boxed wrapper) is documented to return null on cache miss. No compile-time constraint prevents null.

## Fix

**Primary fix**: Change the producer interface and implementations to return `Optional<Long>`, making nullability explicit and enforceable.

**File 1**: `DiscountRepository.java`

**Vulnerable code:**
```java
public interface DiscountRepository {
    // Returns null when no discount is configured for the given sku.
    Long findDiscountCentsForSku(String sku);
}
```

**Fixed code:**
```java
import java.util.Optional;

public interface DiscountRepository {
    // Returns an empty Optional when no discount is configured for the given sku.
    Optional<Long> findDiscountCentsForSku(String sku);
}
```

**File 2**: `PricingService.java`

**Vulnerable code:**
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

**Fixed code:**
```java
public long applyDiscount(String sku, long priceCents) {
    long discountCents = discounts.findDiscountCentsForSku(sku).orElse(0L);
    long discounted = priceCents - discountCents;
    return Math.max(discounted, 0L);
}

public boolean isDiscountApplied(String sku) {
    long discountCents = discounts.findDiscountCentsForSku(sku).orElse(0L);
    return discountCents > 0;
}
```

## Explanation

The `DiscountRepository.findDiscountCentsForSku()` method returns a nullable `Long` (boxed wrapper type), documented to return null when no discount is configured. Both call sites in `PricingService` unbox this value for arithmetic and comparison operations without checking for null first, causing `NullPointerException` when the repository returns null.

The fix changes the producer to return `Optional<Long>`, which makes nullability explicit and requires the caller to handle absence explicitly. At each call site, `.orElse(0L)` provides a documented default (no discount applies). This converts an invisible unboxing dereference into a visible, type-safe operation that the compiler can check. The `Optional` return type also surfaces the case at every call site through the type system rather than relying on documentation or code review.

The default value `0L` is chosen because a missing discount is logically equivalent to a zero-discount (no deduction), allowing the business logic to proceed correctly: `applyDiscount` calculates `priceCents - 0L` and `isDiscountApplied` returns `0L > 0` (false).

## Behaviour changes

**Change 1**: Return type change in interface (`Long` → `Optional<Long>`)
- **Reason**: Makes nullability explicit and compile-time checked; prevents implicit unboxing of null
- **Impact**: Callers are forced to handle the Optional, eliminating the invisible dereference

**Change 2**: Call site variables change from `Long` to `long` primitive in both methods
- **Reason**: Eliminates the possibility of unboxing null by making the variable primitive-typed; `.orElse(0L)` guarantees a non-null `long` value is assigned
- **Impact**: No behavior change at runtime—arithmetic and comparisons work as intended; the default value (0L) is semantically correct for "no discount"

**Change 3**: Explicit default value `.orElse(0L)` supplied at each call site
- **Reason**: Documents the intended behavior when discount is absent (treat as zero discount)
- **Impact**: None—the business logic remains unchanged; code is now explicit about the absence case
