## Verdict

CONFIRMED. The application exposes exception messages to clients, violating CWE-209. Line 18 returns `e.getMessage()` directly in the HTTP response body instead of a generic, user-facing error message.

## Source

The `orderId` parameter is attacker-controlled and parsed as an integer at line 14. When parsing fails, the resulting `NumberFormatException` is caught at line 16.

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
            // Fixed: return generic error message instead of e.getMessage()
            return ResponseEntity.badRequest().body("Invalid order ID");
        }
    }
}
```

## Explanation

The fix replaces the exception message exposure with a generic, server-controlled error message that describes the caller's mistake ("Invalid order ID") rather than exposing internal application details. The client learns only what went wrong with their input, not how the application processes it. The full exception details should be logged server-side for debugging, which can be added later via `@ControllerAdvice` if needed for application-wide consistency.

## Behaviour changes

- **Changed**: The HTTP response body now returns `"Invalid order ID"` instead of the exception message.
- **Unchanged**: HTTP status code remains 400 (bad request), response type remains String, and the parsing logic remains the same.
- **Risk elimination**: The application no longer exposes exception class names, internal error details, or the format of invalid inputs to clients.
