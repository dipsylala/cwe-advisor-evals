## Verdict
The application returns exception messages directly in API responses, exposing internal system details to clients. Line 18 returns `e.getMessage()` from a `NumberFormatException`, which can leak implementation information.

## Source
The exception originates from `Integer.parseInt(orderId)` at line 14 when the request parameter `orderId` contains non-numeric input. The taint flows directly into the response body at line 18.

## Fix
Replace the exception message exposure with a generic client-facing error message, and log the actual exception server-side for debugging:

```java
@GetMapping("/api/orders/lookup")
public ResponseEntity<String> lookupOrder(@RequestParam("orderId") String orderId) {
    try {
        int id = Integer.parseInt(orderId);
        return ResponseEntity.ok("Order status for " + id + ": SHIPPED");
    } catch (NumberFormatException e) {
        logger.warn("Invalid order ID received", e);
        return ResponseEntity.badRequest().body("Invalid order ID format");
    }
}
```

## Explanation
The fix removes sensitive information from the API response by replacing `e.getMessage()` with a generic error message. The original exception is still captured via `logger.warn()`, preserving it for server-side debugging and monitoring without exposing details to clients. This prevents attackers from learning about the application's parsing logic or internal error handling through error messages.
