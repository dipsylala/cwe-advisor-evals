## Verdict
CWE-209 confirmed. Line 18 returns the exception message directly to the API response, exposing internal error details to the client.

## Source
Line 18:
```java
return ResponseEntity.badRequest().body(e.getMessage());
```

The `catch` block captures a `NumberFormatException` and returns its message as the HTTP response body. Exception messages can leak information about internal implementation, library versions, or data structures.

## Fix
```java
@GetMapping("/api/orders/lookup")
public ResponseEntity<String> lookupOrder(@RequestParam("orderId") String orderId) {
    try {
        int id = Integer.parseInt(orderId);
        return ResponseEntity.ok("Order status for " + id + ": SHIPPED");
    } catch (NumberFormatException e) {
        // Log the full exception internally for debugging
        logger.debug("Invalid order ID provided", e);
        // Return a generic error message to the client
        return ResponseEntity.badRequest().body("Invalid order ID format");
    }
}
```

Alternatively, for a REST API, return a structured error response:
```java
return ResponseEntity.badRequest()
    .body(new ErrorResponse("Invalid order ID format", "ORDER_ID_INVALID"));
```

## Explanation
The fix separates internal error handling from client-facing messages. The exception is logged locally with its full details for debugging purposes, while the API response returns only a generic, user-safe message that does not expose exception internals. This prevents information disclosure while maintaining debuggability for developers.
