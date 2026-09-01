package cases.csrf;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BillingController {
    private final BillingService billingService;

    public BillingController(BillingService billingService) {
        this.billingService = billingService;
    }

    @PatchMapping("/api/billing/card")
    public ResponseEntity<BillingResult> updateCard(@RequestBody CardUpdateRequest request) {
        BillingResult result = billingService.queueCardUpdate(request.customerId(), request.token());
        return ResponseEntity.ok(result);
    }
}

record CardUpdateRequest(String customerId, String token) {}
record BillingResult(String status, String requestId) {}
