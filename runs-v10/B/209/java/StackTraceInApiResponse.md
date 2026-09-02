## Verdict

**Confirmed exploitable.** The application exposes exception detail through `e.getMessage()` in the HTTP response body, violating CWE-209.

## Source

User-supplied request parameter `orderId` (line 12) passed to `Integer.parseInt()` which throws `NumberFormatException` on invalid input.

## Fix

**Vulnerable code (line 18):**
```java
return ResponseEntity.badRequest().body(e.getMessage());
```

**Fixed code:**
```java
// Log the detailed exception server-side for debugging
logger.warn("Invalid order ID parameter", e);

// Return generic error message to client
return ResponseEntity.badRequest().body("Invalid order ID format");
```

Or, using `@RestControllerAdvice` for centralized handling (recommended):

```java
@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(NumberFormatException.class)
    public ResponseEntity<String> handleNumberFormatException(NumberFormatException e) {
        logger.warn("Invalid number format in request", e);
        return ResponseEntity.badRequest().body("Invalid request format");
    }
}
```

Then simplify the controller:
```java
@GetMapping("/api/orders/lookup")
public ResponseEntity<String> lookupOrder(@RequestParam("orderId") String orderId) {
    int id = Integer.parseInt(orderId);
    return ResponseEntity.ok("Order status for " + id + ": SHIPPED");
}
```

## Explanation

The original code returns `e.getMessage()` directly to the client, which exposes internal exception details. For `NumberFormatException`, this typically includes the invalid input value and format expectations, leaking information about the application's internal validation logic.

The fix replaces the raw exception message with a generic, developer-controlled message ("Invalid order ID format" or "Invalid request format") while logging the full exception details server-side where only authorized personnel can access them. This satisfies both the user's need for feedback (they know the request was malformed) and the security requirement to hide implementation details.

The `@RestControllerAdvice` approach is preferred because it centralizes exception handling across all endpoints, ensuring consistency and preventing similar issues elsewhere.

## Behaviour changes

- Exception message no longer exposed to client: `e.getMessage()` is replaced with a static generic string.
- Full exception detail now logged server-side via `logger.warn()` instead of discarded.
- HTTP status code unchanged: still `400 Bad Request`.
- Response body changed from dynamic exception message to fixed generic message.
