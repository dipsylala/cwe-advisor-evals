## Verdict

exploitable

- **cwe_id**: CWE-209
- **location**: `StackTraceInApiResponse.java`, line 18 (sink); source at line 12 (`orderId` request parameter)
- **confidence**: high

## Source

`@RequestParam("orderId") String orderId` on the `lookupOrder` handler (line 12) is fully attacker-controlled input from the HTTP query string.

Flow: `orderId` is passed unvalidated to `Integer.parseInt(orderId)` (line 14). Any non-numeric value throws `NumberFormatException`, whose message is built by the JDK as `For input string: "<the raw orderId value>"`. That exception is caught at line 16 and its message is written directly into the HTTP response body at line 18 (`ResponseEntity.badRequest().body(e.getMessage())`), with no intervening validation, sanitization, or generic-message substitution. The path is direct and unbroken, so the finding is exploitable: a caller can trivially observe how their raw input is echoed back inside a JDK-generated diagnostic string, and in a real deployment the same catch-all pattern is what carries genuinely sensitive detail (SQL error text, file paths, nested cause chains) once other exception types are added to this handler or others like it.

**Sink contract (`ResponseEntity.badRequest().body(...)`):**
- **Returns**: an HTTP 400 response whose body is whatever `String` is passed in; callers read the body as the client-facing error text.
- **Discards**: nothing currently — the exception is not logged anywhere, so the only place its detail exists today is the client-visible response.
- **Arguments left implicit**: none beyond the body string itself; no headers or content-type are set beyond Spring's default.
- **Failure behaviour**: this branch only runs on `NumberFormatException`; the method has no other failure path today.

## Fix

### File: StackTraceInApiResponse.java

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
            log.warn("Rejected non-numeric orderId parameter", e);
            return ResponseEntity.badRequest().body("Invalid order ID");
        }
    }
}
```

## Explanation

The fix replaces the reflected `e.getMessage()` body with a fixed, server-controlled string (`"Invalid order ID"`) so the client-facing 400 response no longer carries any part of the raw input or the JDK's internal exception-message format. The full exception, including its message and stack trace, is now captured server-side via an SLF4J `Logger.warn(String, Throwable)` call before the generic response is returned, preserving the diagnostic detail for developers without exposing it to the caller. This directly follows the CWE-209 Java guidance's primary defence (generic client messages, full detail logged server-side) and its explicit instruction to trace the message-building chain rather than assume a short catch block is safe.

## Behaviour changes

- **Response body text changed** from the raw `NumberFormatException` message (e.g. `For input string: "abc"`) to the fixed string `"Invalid order ID"` — this is the intended fix; it removes the only channel through which caller input and JDK-internal phrasing were reflected back.
- **HTTP status code unchanged**: still `400 Bad Request` via `ResponseEntity.badRequest()` — no change to how clients distinguish this error from others.
- **Added server-side logging** (`log.warn(...)` with the exception passed as the `Throwable` argument) — new side effect, not present before. Justified by the CWE-209 guidance's requirement to log full exception details server-side once they are removed from the response, so the diagnostic information is not lost, only relocated. This assumes a logging destination (console/file via the application's Logback/SLF4J binding) is configured, which is the Spring Boot default and requires no new dependency.
- **Added imports** `org.slf4j.Logger` and `org.slf4j.LoggerFactory` and one new field (`log`) — required to perform the server-side logging described above; no other class members changed.
- No change to the method signature, the success path (lines 14-15 logic unchanged aside from being left as-is), or any caller of this handler.

**Assumptions**: `org.slf4j` (Logger/LoggerFactory) is on the runtime classpath. This is not verified directly in this single-file case (no build manifest is present to inspect), but SLF4J is a transitive dependency of every `spring-boot-starter` (via `spring-boot-starter-logging`), and this class already depends on `spring-boot`-family annotations (`@RestController`, `@GetMapping`), so the assumption is treated as low-risk; confidence is not lowered below high on this basis alone since the alternative (writing `System.err`) would be a worse pattern for a Spring application.

**Verification**: `javac` was run against both the original and the fixed file in isolation (no project classpath/build file is present in the case directory). Both produce identical categories of "package does not exist" / "cannot find symbol" errors for the pre-existing Spring imports (`org.springframework.*`), confirming those failures are a classpath artifact of the isolated case file, not a defect. The fixed file's only *additional* diagnostics are the same class of error for the two new `org.slf4j` imports, for the same reason (no dependency jars on the ad hoc compile classpath) — no new syntax or structural errors were introduced beyond that. Manual review confirms: the method signature is unchanged, the one caller relationship (Spring's dispatcher invoking `lookupOrder`) is unaffected, and every new symbol (`Logger`, `LoggerFactory`, `log`) is used consistently with the standard SLF4J API (`LoggerFactory.getLogger(Class)`, `Logger.warn(String, Throwable)`).
