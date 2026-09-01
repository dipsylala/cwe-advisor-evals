package cases.csrf;

import java.util.UUID;

public class BillingService {
    public BillingResult queueCardUpdate(String customerId, String token) {
        return new BillingResult("queued", UUID.randomUUID().toString());
    }
}
