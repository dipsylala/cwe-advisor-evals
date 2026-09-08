## Verdict

Confirmed. `reservedBySku.get(sku)` returns a `Map<String, Integer>` lookup result that is `null` whenever `sku` has no reservation entry. The assignment `int reserved = reservedBySku.get(sku)` auto-unboxes that `Integer` to `int`, and unboxing a `null` reference throws `NullPointerException`. This is a real, reachable NPE for any SKU that has not been reserved (the common case for a product with no cart reservations), not just a theoretical edge case.

## Source

`reservedBySku.get(sku)` in `CartReservationNullUnbox.availableToPromise(String, int)`, line 14 of `CartReservationNullUnbox.java`. `reservedBySku` is a `Map<String, Integer>` supplied via the constructor with no non-null or completeness guarantee, so any key absent from the map (or explicitly mapped to `null`) produces a `null` result from `get`, which is dereferenced (unboxed) on the same line and again used at the sink on line 15.

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
        int reserved = reservedBySku.getOrDefault(sku, 0);
        return onHand - reserved;
    }
}
```

## Explanation

`Map.getOrDefault(sku, 0)` replaces `get(sku)` so a SKU with no reservation entry resolves to `0` instead of `null`, removing the auto-unboxing NPE at its source rather than adding a null check after the fact. Zero is the correct default here: "no entry" and "zero units reserved" are the same business state, so `availableToPromise` still returns `onHand` unchanged for an unreserved SKU, matching the method's existing contract. This also covers the case where the map explicitly stores a `null` value for a key only if the map implementation treats a missing key and a `null`-valued key the same way for `getOrDefault`; standard `HashMap`/`Map.of` usage here only exercises the "key absent" path, which `getOrDefault` fixes directly. No other behavior changes: the method signature, arguments, and return calculation are untouched.
