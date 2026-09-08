## Verdict

Exploitable. Confidence: high.

- cwe_id: CWE-476
- location: `CartReservationNullUnbox.java`, line 14
- source: `reservedBySku.get(sku)` (a `Map<String, Integer>` lookup that returns `null` when `sku` has no entry)
- sink: `int reserved = reservedBySku.get(sku);` - unboxing the `Integer` result into a primitive `int`

## Source

`reservedBySku` is a `Map<String, Integer>` supplied to the constructor and stored as-is. `availableToPromise(sku, onHand)` calls `reservedBySku.get(sku)`. `Map.get` returns `null` whenever the key is absent, and here the caller passes an arbitrary `sku` string with no guarantee it was ever inserted into the map (no reservation was made for that SKU). That `null` is assigned directly to a primitive `int` local, which the compiler unboxes with `Integer.intValue()` - an invisible dereference with no `.` in the source to flag it. When `sku` has no entry, this throws `NullPointerException` at line 14 before line 15 ever runs.

## Fix

### File: CartReservationNullUnbox.java

```java
package evalcases;

import java.util.Map;

public class CartReservationNullUnbox {
    private final Map<String, Integer> reservedBySku;

    public CartReservationNullUnbox(Map<String, Integer> reservedBySku) {
        this.reservedBySku = reservedBySku;
    }

    public int availableToPromise(String sku, int onHand) {
        // A SKU with no entry has no reservation against it, so treat it as zero reserved
        // rather than unboxing a null Integer from Map.get().
        int reserved = reservedBySku.getOrDefault(sku, 0);
        return onHand - reserved;
    }
}
```

## Explanation

The unsafe pattern was an ambiguous `Map.get` result flowing straight into unboxing arithmetic: for this map, "no entry for `sku`" and "zero units reserved for `sku`" mean the same thing in the domain, so the null case is not an error condition that needs to be rejected - it needs an explicit, documented default. Replacing `reservedBySku.get(sku)` with `reservedBySku.getOrDefault(sku, 0)` supplies that default at the exact point the value is obtained, so a SKU with no reservation entry resolves to a reserved quantity of `0` instead of throwing. This is a producer-contract fix rather than a guard around the crash site: the ambiguity between "absent" and "present and mapped to null" is resolved once, here, rather than deferred to a null check the caller would otherwise have to repeat.

## Behaviour changes

- For any `sku` with no entry in `reservedBySku`, `availableToPromise` now returns `onHand` (i.e. `onHand - 0`) instead of throwing `NullPointerException`. This is the intended fix, not a side effect: an unreserved SKU has zero units reserved, so this value is the correct answer rather than a masked failure.
- For any `sku` that does have an entry, behaviour is unchanged - `getOrDefault` returns the mapped value exactly as `get` did.
- No other difference from the original: same signature, same arguments, same arithmetic, same field.

Verification: compiled the fixed file standalone with `javac` (JDK on PATH) into a scratch output directory - compiled cleanly with no errors or warnings. `Map.getOrDefault(Object, V)` is a standard `java.util.Map` method (Java 8+), used here with the same generic types (`String`, `Integer`) already declared on the field, so no new import is required.
