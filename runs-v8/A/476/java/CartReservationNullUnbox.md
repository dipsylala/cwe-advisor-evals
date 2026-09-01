## Verdict
NULL pointer dereference via unsafe unboxing. Map.get() returns null when the key is absent, and assigning null to int reserved attempts to unbox null, causing a NullPointerException.

## Source
Line 14: `int reserved = reservedBySku.get(sku);`

The Map.get(sku) call can return null if sku is not in the map. Assigning this null result to the primitive int type forces unboxing, which dereferences the null pointer.

## Fix
Replace line 14 with:
```java
int reserved = reservedBySku.getOrDefault(sku, 0);
```

This ensures a non-null default value (0) is used when the sku key is absent, eliminating the null dereference.

## Explanation
Map.get() returns null for missing keys. The assignment to a primitive int implicitly calls unboxing on the Integer return type, which crashes when the reference is null.

Using getOrDefault(sku, 0) avoids null entirely by providing a default value. This assumes that a missing SKU means zero reserved units, which aligns with the method's logic: if nothing is reserved, the available-to-promise quantity equals the on-hand quantity.
