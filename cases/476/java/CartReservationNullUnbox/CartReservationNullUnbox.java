package evalcases;

import java.util.Map;

public class CartReservationNullUnbox {
    private final Map<String, Integer> reservedBySku;

    public CartReservationNullUnbox(Map<String, Integer> reservedBySku) {
        this.reservedBySku = reservedBySku;
    }

    public int availableToPromise(String sku, int onHand) {
        // SAST FINDING: CWE-476 (NULL Pointer Dereference) reported here. Sink is the next statement.
        int reserved = reservedBySku.get(sku);
        return onHand - reserved;
    }
}
