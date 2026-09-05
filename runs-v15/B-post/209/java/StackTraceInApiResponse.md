## Verdict

Exploitable. The exception message from `NumberFormatException` is returned directly to the client, exposing internal implementation details about the application's parsing logic.

## Source

The vulnerability originates at line 12 with the user-supplied `orderId` parameter from the HTTP request. Line 14 passes this untrusted input to `Integer.parseInt()`, which throws `NumberFormatException` with a detailed message when the input is not a valid integer. Line 18 (the sink) returns this detailed exception message directly in the HTTP response body via `e.getMessage()`, exposing the error details to the client.

## Fix

**Vulnerable code:**
```java
@GetMapping("/api/orders/lookup")
public ResponseEntity<String> lookupOrder(@RequestParam("orderId") String orderId) {
    try {
        int id = Integer.parseInt(orderId);
        return ResponseEntity.ok("Order status for " + id + ": SHIPPED");
    } catch (NumberFormatException e) {
        // VULNERABLE: Exception message exposed to client
        return ResponseEntity.badRequest().body(e.getMessage());
    }
}
```

**Fixed code:**
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
            logger.error("Invalid order ID provided", e);
            return ResponseEntity.badRequest().body("Invalid order ID");
        }
    }
}
```

## Explanation

The fix eliminates the information leak by replacing the exception message with a generic, user-facing error message. The detailed exception information (`e.getMessage()`) is now logged server-side using SLF4J, preserving the diagnostic data for developers and operations while keeping the HTTP response opaque to clients. This follows CWE-209 remediation guidance: centralize exception handling to return generic messages to users while logging full exception details server-side. The client receives only "Invalid order ID", which describes their mistake without revealing that an integer parse was attempted or what the invalid input was.

## Behaviour changes

**Added import**: `org.slf4j.Logger`, `org.slf4j.LoggerFactory` - both from SLF4J, which is a standard dependency in Spring Boot projects.

**Added field**: `private static final Logger logger = LoggerFactory.getLogger(StackTraceInApiResponse.class);` - creates a logger instance for the class.

**Changed error response**: The HTTP response body changed from `e.getMessage()` (e.g., `"For input string: \"abc\""`) to the generic string `"Invalid order ID"`. This is the intended difference to close the weakness.

**Added logging**: The exception is now logged server-side with `logger.error("Invalid order ID provided", e);`, capturing the full stack trace for debugging. This preserves operational visibility while preventing information leakage.

**No change to HTTP status code**: The response remains `badRequest()` (HTTP 400), maintaining the same client-facing contract for error handling.
