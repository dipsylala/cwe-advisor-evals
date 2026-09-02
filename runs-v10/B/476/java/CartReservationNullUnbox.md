## Verdict

Exploitable.

## Source

The `reservedBySky` map parameter, which may not contain the queried SKU. When `Map.get(sku)` is called on a missing key, it returns `null`.

## Fix

**Vulnerable code (line 14):**
```java
int reserved = reservedBySky.get(sku);
```

**Fixed code:**
```java
int reserved = reservedBySky.getOrDefault(sku, 0);
```

## Explanation

The vulnerability occurs when `Map.get()` returns `null` for a missing key, and that null is assigned to a primitive `int` variable. Java's automatic unboxing converts the null `Integer` reference to a primitive, causing a `NullPointerException` at the assignment. 

The fix uses `getOrDefault(sku, 0)` instead of `get(sku)`. This is semantically correct: if a SKU has no reservation in the map, the reserved quantity is 0. This prevents the unboxing of null and provides a sensible default that aligns with the business logic—unreserved inventory has zero reservations.

## Behaviour changes

When a SKU is not found in the `reservedBySky` map:
- **Original**: Throws `NullPointerException`
- **Fixed**: Returns `onHand - 0`, which equals `onHand` (the full on-hand quantity is available to promise)

This is the correct semantic behavior: an absent reservation implies zero reserved units, so all on-hand inventory is available for commitment. The fix prevents the crash and replaces it with valid, predictable business logic.
