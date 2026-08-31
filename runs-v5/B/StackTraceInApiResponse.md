## Verdict

exploitable (confidence: high)

## Source

- **Source**: `orderId`, the `@RequestParam("orderId") String orderId` value on `GET /api/orders/lookup` (attacker-controlled HTTP query parameter).
- **Sink**: `ResponseEntity.badRequest().body(e.getMessage())` at line 18, inside the `catch (NumberFormatException e)` block that fires when `Integer.parseInt(orderId)` (line 14) fails to parse.
- **Flow**: the raw query parameter is passed directly into `Integer.parseInt`; on failure the JDK-generated exception message (`"For input string: \"<value>\""`, which echoes the raw input back and names the JDK's own internal format string) is written straight into the HTTP response body with no filtering, logging, or transformation in between.

## Fix

No third-party library is needed for this fix; it is a code-level change only. No dependency/version bump applies.

**Vulnerable code:**

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
            return ResponseEntity.badRequest().body(e.getMessage());
        }
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

    private static final Logger log = LoggerFactory.getLogger(StackTraceInApiResponse.class);

    @GetMapping("/api/orders/lookup")
    public ResponseEntity<String> lookupOrder(@RequestParam("orderId") String orderId) {
        try {
            int id = Integer.parseInt(orderId);
            return ResponseEntity.ok("Order status for " + id + ": SHIPPED");
        } catch (NumberFormatException e) {
            log.warn("Rejected order lookup: orderId parameter was not a valid integer", e);
            return ResponseEntity.badRequest().body("Invalid order ID format");
        }
    }
}
```

## Explanation

The handler passed the raw `NumberFormatException` message straight back to the client, which echoes the attacker's own input alongside JDK-internal wording ("For input string: ...") describing the application's parsing implementation rather than a fact about the caller's request. The fix replaces the response body with a fixed, server-controlled generic message ("Invalid order ID format") per the CWE-209 guidance's core principle of separating user-facing messages from internal diagnostic detail, and adds server-side logging (via SLF4j, already on the Spring Boot classpath) so the original exception - including its message and stack trace - remains available for debugging without leaving the trust boundary. The HTTP status code (400, via `badRequest()`) is unchanged, so clients that branch on status still work identically; only the leaking body content changed.

## Behaviour changes

- **Response body on invalid `orderId` changes from the raw exception message to a fixed generic string.** This is the fix itself - required to close the CWE-209 finding. Any client parsing the old message text (rather than the 400 status) would need to be updated, but no such contract should be relied upon for an error body.
- **A new SLF4j logger field and a `log.warn(...)` call were added.** This implements the guidance's "log detailed errors server-side for debugging and monitoring" principle so the diagnostic detail removed from the response is not lost entirely. `org.slf4j:slf4j-api` is a transitive dependency of `spring-boot-starter-web` (via Logback), so no new dependency is introduced; this assumes the project uses the standard Spring Boot logging stack, which the Spring MVC annotations already in the file make the best-supported assumption for this codebase.
- No other change: status code, success-path behavior, method signature, and control flow are all unchanged.
