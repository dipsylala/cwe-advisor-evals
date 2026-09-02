## Verdict
Confirmed. The code at line 14 attempts to unbox a potentially null value returned by `Map.get()` into an int primitive.

## Source
Line 14: `int reserved = reservedBySku.get(sku);`

The `Map.get()` method returns `null` when the specified key is not found in the map. Since `reservedBySku` is a `Map<String, Integer>`, `get()` returns an `Integer` object or `null`. Assigning this directly to an `int` primitive triggers auto-unboxing, which fails with a NullPointerException if the value is null.

## Fix
```java
int reserved = reservedBySku.getOrDefault(sku, 0);
return onHand - reserved;
```

Alternatively, if a null check is preferred:
```java
Integer reservedObj = reservedBySku.get(sku);
int reserved = (reservedObj != null) ? reservedObj : 0;
return onHand - reserved;
```

## Explanation
The vulnerability occurs because `Map.get()` can return null, and Java's auto-unboxing from `Integer` to `int` throws a NullPointerException when the source value is null. Using `getOrDefault()` is the idiomatic solution—it safely returns a default value (0, meaning no reservation) when the SKU is not found in the map. This prevents the null dereference and correctly handles the case where a product has no reservation: the full quantity on hand is available to promise.
