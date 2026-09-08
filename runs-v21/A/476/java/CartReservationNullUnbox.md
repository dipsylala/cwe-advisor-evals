## Verdict
CONFIRMED

## Source
The vulnerability is in `CartReservationNullUnbox.java` at line 14. The `Map.get(sku)` method returns an `Integer` (boxed type) which can be `null`. The assignment to the primitive `int` variable `reserved` triggers auto-unboxing of a null value, causing a `NullPointerException` at runtime when the key is not present in the map.

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
Replace `Map.get(sku)` with `Map.getOrDefault(sku, 0)`. The `getOrDefault()` method returns the mapped value if present, or the provided default value (0) if the key is absent. This eliminates the null value and its subsequent auto-unboxing, preventing the `NullPointerException`. A default of 0 reserved units is the appropriate sentinel for a SKU with no reservation in the map.
