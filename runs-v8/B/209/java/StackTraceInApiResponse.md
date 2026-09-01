## Verdict

CONFIRMED. Line 18 exposes `NumberFormatException.getMessage()` in the HTTP response body, violating CWE-209: the exception message leaks internal application details to untrusted users.

## Source

**File:** `StackTraceInApiResponse.java`  
**Line:** 18  
**Code:**
```java
return ResponseEntity.badRequest().body(e.getMessage());
```

The `catch` block returns the exception message directly to the client. For `NumberFormatException`, this reveals what the parsing operation was attempting and how it failed, leaking information about the application's internal error handling.

## Fix

```java
package evalcases;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StackTraceInApiResponse {
    private static final Logger logger = LoggerFactory.getLogger(StackTraceInApiResponse.class);

    @GetMapping("/api/orders/lookup")
    public ResponseEntity<String> lookupOrder(@RequestParam("orderId") String orderId) {
        try {
            int id = Integer.parseInt(orderId);
            return ResponseEntity.ok("Order status for " + id + ": SHIPPED");
        } catch (NumberFormatException e) {
            logger.error("Invalid order ID provided: {}", orderId, e);
            return ResponseEntity.badRequest().body("Invalid request");
        }
    }
}
```

**Changes:**
- Added `Logger` field to capture exception details server-side
- Log the full exception stack trace with context (the invalid `orderId` value)
- Return a generic error message `"Invalid request"` instead of `e.getMessage()`

## Explanation

CWE-209 mandates that error messages returned to clients must be generic and never expose implementation details. The original code violates this by exposing the exception message directly.

The fix implements the primary defence recommended in the CWE-209 Java guidance:
1. **Generic client message:** Clients receive only `"Invalid request"`, which describes their situation without revealing how the application parses input or validates it.
2. **Server-side logging:** The full exception and context (the malformed `orderId` value) are logged with `logger.error()`, preserving diagnostic information for operations and debugging.
3. **Centralization path:** This pattern is compatible with Spring's `@ControllerAdvice` migration; the same logging + generic-message pattern scales across all endpoints.

## Behaviour changes

**User-visible:**
- Clients previously received error messages like `"For input string: \"abc\""` when passing a non-integer order ID; they now receive the generic message `"Invalid request"`.
- HTTP status code remains `400 Bad Request` (unchanged).

**Server-side (not visible to users):**
- The server now logs `[ERROR] Invalid order ID provided: abc` followed by the full `NumberFormatException` stack trace, enabling debugging and monitoring of invalid input attempts.
- Logs include the actual invalid value, allowing detection of attack patterns without exposing those patterns to attackers.
