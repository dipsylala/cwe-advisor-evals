## Verdict
Confirmed. The code at line 14 calls `Map.get(sku)`, which returns `null` when the key is not found. Unboxing `null` to a primitive `int` causes a `NullPointerException`.

## Source
`CartReservationNullUnbox.java`, line 14: `int reserved = reservedBySku.get(sku);`

When `sku` is not a key in `reservedBySku`, `get()` returns `null`. Java's automatic unboxing of a `null` Integer to primitive `int` throws `NullPointerException`.

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
Replace `get()` with `getOrDefault(sku, 0)`. When a SKU has no reservation entry, `getOrDefault()` returns the default value `0` instead of `null`, eliminating the null dereference. This is safe because a missing reservation implies zero reserved units, which is the correct business logic: available stock is on-hand inventory minus reserved units, and if nothing is reserved, nothing is subtracted.
