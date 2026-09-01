## Verdict

**Confirmed.** Line 14 unboxes the result of `Map.get()` without checking for absence. When the SKU is not in the reservation map, `Map.get()` returns null, and the implicit unboxing to primitive `int` throws `NullPointerException`.

## Source

`reservedBySku.get(sku)` at line 14 can return null when the key is not found in the map. The assignment to primitive `int reserved` triggers implicit unboxing, which fails on null.

## Fix

Replace `Map.get()` with `Map.getOrDefault()` to provide an explicit safe default:

```java
public int availableToPromise(String sku, int onHand) {
    int reserved = reservedBySku.getOrDefault(sku, 0);
    return onHand - reserved;
}
```

## Explanation

`Map.get(key)` returns null when the key is absent, which unboxes unsafely to a primitive int. `Map.getOrDefault(key, 0)` eliminates the null by returning the default value 0 when the SKU is not in the reservation map, matching the semantic intent (a missing entry means nothing is reserved). This is the Java-specific safe pattern for map lookups that flow into arithmetic operations without an explicit null check.

## Behaviour changes

**Before the fix:** When a SKU has no reservation entry, the method throws `NullPointerException`, crashing the operation with an unhandled 500 error.

**After the fix:** When a SKU has no reservation entry, `getOrDefault(sku, 0)` returns 0, and the method correctly computes available-to-promise as `onHand - 0`, returning the full on-hand quantity as available. The method no longer throws for missing reservations.
