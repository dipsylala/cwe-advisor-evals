## Verdict

Exploitable. The data flow is clear: `Map.get(sku)` returns `Integer | null`, and the assignment to primitive `int reserved` unboxes the returned value without a null check, causing `NullPointerException` when the key is absent.

## Source

`reservedBySku.get(sku)` in the `availableToPromise` method. The `Map<String, Integer>` holds reserved quantities by SKU, and the `get()` method returns `null` when the SKU key is not present in the map.

## Fix

**Vulnerable code:**
```java
int reserved = reservedBySku.get(sku);
```

**Fixed code:**
```java
int reserved = reservedBySku.getOrDefault(sku, 0);
```

## Explanation

The `Map.get()` method returns `null` when the key is absent. Java's unboxing of `null Integer` to primitive `int` is an invisible dereference that throws `NullPointerException`. The fix replaces `get()` with `getOrDefault(sku, 0)`, which returns 0 when the SKU is not in the map—the correct semantic for "no items reserved for this SKU." This eliminates the null pointer dereference and handles the absent-key case with the safe default value.

## Behaviour changes

The original code throws `NullPointerException` when a SKU is not present in `reservedBySku`. The fixed code returns `onHand - 0` in that case, allowing the calculation to succeed. This is the correct behaviour for the business logic: if a SKU has no reservation entry, zero items are reserved, so the full on-hand quantity is available to promise. No other contract changes.
