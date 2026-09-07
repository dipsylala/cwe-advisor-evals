## Verdict
exploitable

## Source
`reservedBySku.get(sku)` on line 14 of CartReservationNullUnbox.java. The `Map.get()` method returns `null` when a key is not present in the map. This null value is then implicitly unboxed to a primitive `int` via the assignment `int reserved = reservedBySku.get(sku)`, triggering a `NullPointerException`.

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
The vulnerability stems from an implicit unboxing operation that occurs when assigning the result of `Map.get()` to a primitive `int`. The `Map.get()` method returns `null` when the specified key is not found, and attempting to unbox a null `Integer` to a primitive `int` throws a `NullPointerException`. The fix replaces `get(sku)` with `getOrDefault(sku, 0)`, which returns the associated value if present or a default value of 0 if the key is absent. This eliminates the null dereference and provides semantically correct behavior: if a SKU has no entry in the reserved inventory map, it means zero items are reserved for that SKU, so all on-hand inventory is available to promise.

## Behaviour changes
none
