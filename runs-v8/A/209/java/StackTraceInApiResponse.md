## Verdict

The finding is confirmed. Line 18 returns the exception message directly to the HTTP client, exposing details about input parsing failures that can reveal application internals.

## Source

Line 18 in the exception handler:
```java
return ResponseEntity.badRequest().body(e.getMessage());
```

When `Integer.parseInt(orderId)` fails, the `NumberFormatException.getMessage()` contains text like `"For input string: \"abc\""`, which discloses the invalid input format and parsing internals to the client.

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
            logger.warn("Invalid order ID provided: {}", orderId, e);
            return ResponseEntity.badRequest().body("Invalid order ID format");
        }
    }
}
```

## Explanation

The fix replaces the exception message with a generic, user-safe error string. The detailed exception (including the invalid input) is logged server-side with `logger.warn()` for debugging and monitoring, but never sent to the client. This prevents exposure of parsing internals while preserving the ability to diagnose issues during development and in production logs.
