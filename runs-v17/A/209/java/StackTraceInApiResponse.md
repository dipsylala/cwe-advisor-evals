## Verdict

The finding is confirmed. Line 18 returns exception details to the API client, exposing sensitive information about the parsing failure.

## Source

The `catch` block on line 16-18 returns `e.getMessage()` directly in the HTTP response body. The `NumberFormatException` message can contain details about the raw input or internal validation logic that should not be exposed to untrusted clients.

## Fix

### File: StackTraceInApiResponse.java

```java
package evalcases;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StackTraceInApiResponse {

    @GetMapping("/api/orders/lookup")
    public ResponseEntity<String> lookupOrder(@RequestParam("orderId") String orderId) {
        try {
            int id = Integer.parseInt(orderId);
            return ResponseEntity.ok("Order status for " + id + ": SHIPPED");
        } catch (NumberFormatException e) {
            // SAST FINDING: CWE-209 (Generation of Error Message Containing Sensitive Information) reported here. Sink is the next statement.
            return ResponseEntity.badRequest().body("Invalid order ID format");
        }
    }
}
```

## Explanation

CWE-209 requires that error messages returned to clients must not expose sensitive or implementation-specific details. The exception message from `Integer.parseInt()` can reveal information about how the application parses input or what values were rejected.

The fix replaces the exception message with a generic, user-friendly error message that does not leak internal details. If detailed logging is needed for debugging, the exception should be logged internally (not shown in this fix since logging infrastructure is not part of the vulnerability scope), but the client response must remain generic.
