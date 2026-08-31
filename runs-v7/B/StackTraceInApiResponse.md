## Verdict

**Confirmed.** Line 18 exposes the exception message directly in the HTTP response, violating CWE-209 by leaking internal error details to the client.

## Source

```java
catch (NumberFormatException e) {
    // Line 18: Sink - exception message exposed to user
    return ResponseEntity.badRequest().body(e.getMessage());
}
```

The `NumberFormatException.getMessage()` contains implementation details about what parsing failed and why (e.g., "For input string: \"xyz\""), which is internal information an attacker can use to refine subsequent requests or gather reconnaissance.

## Fix

```java
catch (NumberFormatException e) {
    // Log full exception server-side for debugging
    org.slf4j.LoggerFactory.getLogger(StackTraceInApiResponse.class)
        .warn("Invalid order ID provided", e);
    // Return generic message to client
    return ResponseEntity.badRequest().body("Invalid order ID format");
}
```

Alternatively, centralize this with `@RestControllerAdvice` and `@ExceptionHandler` to ensure all exception handlers follow the same pattern across the application:

```java
@RestControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(NumberFormatException.class)
    public ResponseEntity<String> handleNumberFormatException(NumberFormatException e) {
        org.slf4j.LoggerFactory.getLogger(GlobalExceptionHandler.class)
            .warn("Invalid numeric parameter provided", e);
        return ResponseEntity.badRequest().body("Invalid request parameter");
    }
}
```

## Explanation

The vulnerability is closed by replacing `e.getMessage()` with a fixed, server-controlled generic message. The exception message is moved to server-side logging (using a logger and unique correlation ID in production) so developers can still debug failures without exposing internal details to clients.

CWE-209 requires that error responses communicate only facts about the caller's request (whether it was valid, malformed, or unauthorized), not about the application's architecture or internal parsing logic. The `NumberFormatException` message describes how the parsing failed—internal implementation detail—and must never reach the client.

## Behaviour changes

- **Client-visible response body**: Changes from a low-level exception message (e.g., "For input string: \"xyz\"") to a generic, user-friendly message (e.g., "Invalid order ID format")
- **Logging**: Full exception details are now logged server-side with the original message and stack trace available for debugging
- **HTTP status code**: Remains 400 Bad Request
- **Response format**: Still plain text in the response body (matches existing contract)
- **No functional regression**: The endpoint still rejects invalid order IDs with a 400 status; clients cannot distinguish between different parsing failures (by design to prevent error enumeration)
