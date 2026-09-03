## Verdict
VULNERABLE

## Source
Line 14: `int reserved = reservedBySku.get(sku);`

The `Map.get()` method returns a nullable `Integer` object. When a key is not found, it returns `null`. Assigning this directly to an `int` primitive triggers auto-unboxing, which throws a `NullPointerException` when the value is `null`.

## Fix
```java
int reserved = reservedBySku.getOrDefault(sku, 0);
return onHand - reserved;
```

Replace `get()` with `getOrDefault()`, providing a default value of `0` when the SKU is not found in the reservation map.

## Explanation
The vulnerability occurs because `Map.get(key)` can return `null`, and unboxing `null` to an `int` primitive causes a `NullPointerException` at runtime.

The fix uses `getOrDefault(sku, 0)`, which safely returns `0` when the SKU has no reservation record. This eliminates the null dereference while semantically expressing the intended behavior: if a SKU is not reserved, treat it as having `0` reserved units.

Alternative approaches include explicit null-checking (`if (reserved == null) reserved = 0;`) or using `Optional`, but `getOrDefault()` is the most concise and idiomatic solution for this scenario.
