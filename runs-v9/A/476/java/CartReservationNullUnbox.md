## Verdict

Confirmed. `reservedBySku.get(sku)` returns a `java.lang.Integer`, which is `null` whenever `sku` has no entry in the map. Assigning that `null` to the primitive local `int reserved` forces autounboxing (`Integer.intValue()`), which throws `NullPointerException` for any SKU that has not been reserved.

## Source

`reservedBySku` is a `Map<String, Integer>` supplied to the constructor by the caller; it is not guaranteed to contain an entry for every `sku` passed to `availableToPromise`. `Map.get` returns `null` for a missing key by contract, so any SKU without a prior reservation is an untrusted/absent value flowing directly into the unboxing sink.

## Fix

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

Replacing `Map.get(sku)` with `Map.getOrDefault(sku, 0)` removes the possibility of a `null` reaching the autounboxing assignment: when `sku` is absent, `getOrDefault` returns the supplied default (`0`) directly as the boxed value that gets unboxed, instead of `null`. Zero is the correct default here because "no entry" means "nothing currently reserved for that SKU," so `availableToPromise` degrades to `onHand - 0`, i.e. the full on-hand quantity is available, which matches the method's intent. This is a one-line change that eliminates the NPE at its source rather than adding a null check further down, and it keeps the method's return type and calling contract unchanged. If a missing SKU should instead be treated as an error condition (e.g., the caller must always pre-register reservations), use `Map.get` followed by an explicit null check that throws a descriptive `IllegalArgumentException` instead of silently defaulting to zero — but for a lookup table of accumulated reservations, "absent" and "zero reserved" are naturally equivalent, so `getOrDefault` is the more precise and minimal fix.
