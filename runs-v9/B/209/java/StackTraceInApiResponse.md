## Verdict

Exploitable. CWE-209 confirmed.

- **Location:** `StackTraceInApiResponse.java`, line 18 (`ResponseEntity.badRequest().body(e.getMessage())`)
- **Confidence:** high

## Source

`orderId`, the `@RequestParam` bound in `lookupOrder(@RequestParam("orderId") String orderId)` on the public `GET /api/orders/lookup` endpoint. It is attacker-controlled and flows unmodified into `Integer.parseInt(orderId)`.

## Fix

Vulnerable code:

```java
} catch (NumberFormatException e) {
    // SAST FINDING: CWE-209 (Generation of Error Message Containing Sensitive Information) reported here. Sink is the next statement.
    return ResponseEntity.badRequest().body(e.getMessage());
}
```

Fixed code:

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
            log.warn("Rejected order lookup: orderId parameter was not a valid integer", e);
            return ResponseEntity.badRequest().body("Invalid order ID");
        }
    }
}
```

## Explanation

The catch block returned `e.getMessage()` from `NumberFormatException` directly in the HTTP response body, exposing exception-internal detail (the exact parser failure text, e.g. `For input string: "abc"`) straight from an unauthenticated endpoint - the taint-sink pattern the Java CWE-209 guidance calls out explicitly (`ex.getMessage()` in response body). The fix replaces the response body with a fixed, generic, server-controlled message (`"Invalid order ID"`) that describes the caller's situation without echoing any exception-derived text, and moves the full exception (including its message and stack trace) to server-side logging via SLF4J so the detail is still available for debugging/correlation but is no longer client-visible. The HTTP status code (400, via `badRequest()`) is left unchanged since it is already the correct, non-leaking signal for this failure.

## Behaviour changes

- Response body on invalid `orderId` changes from the raw `NumberFormatException` message to the fixed string `"Invalid order ID"`. This is the intended effect of the fix: it removes the only channel through which exception-internal detail reached the client.
- Added a server-side `log.warn(...)` call recording the exception (message and stack trace) for the invalid-input case. This is new output, but it exists to preserve the diagnostic detail that the fix removes from the client-visible response, per the guidance's instruction to log detailed errors server-side.
- Added a package-private static `Logger` field (SLF4J `LoggerFactory.getLogger`) to support the above logging call. No other fields, methods, or control flow changed.
- HTTP status code (400 Bad Request) and the success-path response (`200 OK` with `"Order status for " + id + ": SHIPPED"`) are unchanged.
