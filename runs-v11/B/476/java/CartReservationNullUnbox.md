## Verdict

Real issue. NULL unboxing at line 14 when the SKU key is absent from the reservation map.

## Source

`reservedBySku.get(sku)` returns `null` when the key is not present. The assignment to primitive `int reserved` triggers unboxing of the null reference, throwing `NullPointerException`.

## Fix

Replace `reservedBySku.get(sku)` with `reservedBySku.getOrDefault(sku, 0)`:

```java
public int availableToPromise(String sku, int onHand) {
    int reserved = reservedBySku.getOrDefault(sku, 0);
    return onHand - reserved;
}
```

## Explanation

`Map.get()` returns `null` to signal a missing key. When that result is assigned directly to a primitive type, Java unboxes the `null` reference and throws `NullPointerException`. The fix uses `getOrDefault()` to supply an explicit fallback value (`0`) when the key is absent, eliminating the null dereference. This is semantically correct: a SKU with no reservation should count as `0` reserved units. The method's return type and contract are unchanged.

## Behaviour changes

When the provided SKU is not in the `reservedBySku` map:
- **Before**: Throws `NullPointerException` at line 14.
- **After**: Returns `onHand` (treating the missing SKU as having `0` reserved units).

When the SKU exists in the map: Behavior is identical to the original.
