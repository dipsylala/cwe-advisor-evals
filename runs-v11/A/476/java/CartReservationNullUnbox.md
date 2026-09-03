## Verdict
Confirmed. Unboxing a nullable value from `Map.get()` causes NULL pointer dereference when the key is absent.

## Source
Line 14:
```java
int reserved = reservedBySku.get(sku);
```

`Map.get(sku)` returns `Integer` (boxed type) and returns `null` when the key is not present. Auto-unboxing `null` to `int` raises `NullPointerException`.

## Fix
Replace line 14 with:
```java
int reserved = reservedBySku.getOrDefault(sku, 0);
```

This safely retrieves the reserved count for the SKU, defaulting to 0 (no reservation) when the key is absent.

## Explanation
`Map.get()` returns the boxed type `Integer`, which can be `null`. When Java auto-unboxes the result to assign it to the primitive `int`, a null value cannot be converted and throws `NullPointerException`. Using `getOrDefault()` avoids this by providing a fallback value (0) when the key is not found, matching the domain logic that treats a missing reservation as zero reserved units.
