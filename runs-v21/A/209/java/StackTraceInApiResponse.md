## Verdict
CONFIRMED: CWE-209 vulnerability at line 18. The code returns `e.getMessage()` directly in an HTTP response, exposing the exception's raw error message to clients.

## Source
```java
catch (NumberFormatException e) {
    return ResponseEntity.badRequest().body(e.getMessage());
}
```

The `e.getMessage()` returns exception details (e.g., "For input string: \"abc\"") that can leak information about the application's internal behavior and parsing logic to API consumers.

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
            return ResponseEntity.badRequest().body("Invalid order ID format");
        }
    }
}
```

## Explanation
The fix replaces the exception message with a generic, user-friendly error response. This prevents leaking internal exception details while still communicating a meaningful error to the client. The exception itself can be logged server-side for debugging without exposing it in the API response.
