## Verdict

Confirmed. `lookupOrder` returns `e.getMessage()` from a caught `NumberFormatException` directly in the HTTP response body. `NumberFormatException`'s message echoes the raw input verbatim (`For input string: "<orderId>"`), and for other exception types a message can carry internal details such as class names, file paths, or SQL fragments. Either way, exception internals are being sent to the API caller instead of being confined to server-side logs.

## Source

- File: `StackTraceInApiResponse.java`
- Sink: line 18, `ResponseEntity.badRequest().body(e.getMessage())` inside the `catch (NumberFormatException e)` block starting at line 16.
- Flow: `orderId` (attacker-controlled `@RequestParam`) -> `Integer.parseInt(orderId)` throws -> caught exception's `getMessage()` -> written straight into the HTTP response body returned to the client.

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

    private static final Logger log = LoggerFactory.getLogger(StackTraceInApiResponse.class);

    @GetMapping("/api/orders/lookup")
    public ResponseEntity<String> lookupOrder(@RequestParam("orderId") String orderId) {
        try {
            int id = Integer.parseInt(orderId);
            return ResponseEntity.ok("Order status for " + id + ": SHIPPED");
        } catch (NumberFormatException e) {
            log.warn("Invalid orderId supplied to /api/orders/lookup", e);
            return ResponseEntity.badRequest().body("Invalid orderId");
        }
    }
}
```

## Explanation

The exception's detail message is no longer placed in the response body. It is logged server-side via SLF4J (`log.warn(..., e)`, which captures the full stack trace in the log record) so operators retain diagnostic detail, while the client receives a fixed, generic message (`"Invalid orderId"`) that confirms the request was malformed without disclosing input echoes, internal state, or implementation details. This keeps the same control flow and HTTP status (`400 Bad Request`) so the API contract for callers is unchanged - only the leaked message content is replaced. If callers need a stable machine-readable error code for this case, a fixed error code/enum value can be added to the body instead of any exception-derived text.
