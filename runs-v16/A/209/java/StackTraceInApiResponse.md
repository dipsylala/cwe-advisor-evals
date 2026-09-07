## Verdict
CONFIRMED

## Source
Line 18 returns `e.getMessage()` from a `NumberFormatException` directly in the HTTP response body. Exception messages can expose implementation details and internal state that should not be visible to clients.

## Fix
Replace the exception message return with a generic error message, and log the exception for internal debugging:

```java
@GetMapping("/api/orders/lookup")
public ResponseEntity<String> lookupOrder(@RequestParam("orderId") String orderId) {
    try {
        int id = Integer.parseInt(orderId);
        return ResponseEntity.ok("Order status for " + id + ": SHIPPED");
    } catch (NumberFormatException e) {
        // Log the exception for internal debugging
        logger.warn("Invalid order ID provided", e);
        // Return a generic error message to the client
        return ResponseEntity.badRequest().body("Invalid order ID format");
    }
}
```

Add a logger field to the class:
```java
private static final Logger logger = LoggerFactory.getLogger(StackTraceInApiResponse.class);
```

## Explanation
CWE-209 occurs when error messages containing sensitive information are exposed to end users. Exception messages from standard library classes often reveal implementation details—for `NumberFormatException`, this can expose the exact input format or internal parsing logic. The fix separates error handling into two paths: (1) log the exception internally with full details for debugging, and (2) return a generic, user-safe message to the client. This maintains debuggability for developers while preventing information disclosure to potential attackers.
