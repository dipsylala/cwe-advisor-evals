## Verdict

The finding is confirmed. The code at line 18 directly exposes the exception message from `NumberFormatException.getMessage()` to the HTTP response body, which constitutes an information leak under CWE-209.

## Source

User-supplied `orderId` request parameter flows to `Integer.parseInt(orderId)` at line 14.

## Sink

Line 18: `return ResponseEntity.badRequest().body(e.getMessage());` returns the exception message directly to the API response body.

## Data Flow

`orderId` (user input) → `Integer.parseInt(orderId)` (throws `NumberFormatException`) → `e.getMessage()` (detailed message) → HTTP 400 response body (exposed to client)

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
            // Fixed: Return generic error message instead of e.getMessage()
            return ResponseEntity.badRequest().body("Invalid order ID format");
        }
    }
}
```

## Explanation

The vulnerability stems from exposing exception details to clients via `e.getMessage()`. The `NumberFormatException` thrown by `Integer.parseInt()` includes details about the invalid input format, which is an internal implementation detail.

The fix replaces the exception message with a generic, server-controlled error message: "Invalid order ID format". This message describes the client's situation (the supplied orderId was malformed) without exposing stack trace information, class names, or system internals. The generic message maintains the API contract—clients still receive HTTP 400 with a descriptive error—while preventing information leakage.

The detailed exception information should be logged server-side (using a logging framework with a unique error ID for correlation) rather than returned to the client. This approach follows the CWE-209 remediation guidance: generic user-facing messages paired with detailed server-side logging.

## Behaviour changes

- **User-visible:** Error responses now return "Invalid order ID format" instead of the JDK's internal exception message (e.g., "For input string: \"abc\"").
- **API contract:** HTTP 400 status code and response body structure remain unchanged; only the message content is sanitized.
- **Security:** Eliminates the information leak; clients cannot infer internal exception types or input validation logic from error messages.
- **Logging:** The exception `e` is not logged in the current code, but in production this should be logged server-side with an error ID for debugging.
