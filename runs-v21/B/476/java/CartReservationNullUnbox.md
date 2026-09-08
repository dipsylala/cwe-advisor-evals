## Verdict

**Real vulnerability confirmed.** Line 14 performs unboxing of a nullable `Integer` from `Map.get()`, which throws `NullPointerException` when the SKU is not found in the map.

## Source

The `reservedBySku` field is a `Map<String, Integer>` initialized from constructor arguments. The vulnerability occurs when `availableToPromise()` queries a SKU that does not exist in the map.

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

The fix replaces `reservedBySku.get(sku)` with `reservedBySku.getOrDefault(sku, 0)`. When a SKU is not found in the map, `getOrDefault()` returns the provided default value (0) instead of `null`, eliminating the unboxing of null. This aligns with the business logic: a SKU with no reservation record has zero reserved units. The method continues to return the correct available-to-promise value in all cases: when the SKU is reserved and when it is not.

## Behaviour changes

**When the SKU is found:** No change. The method returns `onHand` minus the reserved count exactly as before.

**When the SKU is not found:** The original code threw `NullPointerException` (undefined/crashed). The fixed code returns `onHand` minus 0, treating an absent reservation as "no units reserved" and allowing the calculation to complete normally. This is the intended business behavior: unknown SKUs default to zero reservation.
