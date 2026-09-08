## Verdict
exploitable

## Source
`NumberFormatException e` caught from `Integer.parseInt(orderId)` at line 14.

## Fix

### File: StackTraceInApiResponse.java

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
            // Return generic error message instead of exposing exception details
            return ResponseEntity.badRequest().body("Invalid order ID");
        }
    }
}
```

## Explanation
The original code at line 18 returned `e.getMessage()` directly in the HTTP response body, exposing the exception's message to the API client. The `NumberFormatException.getMessage()` includes details like "For input string: \"abc\"", which leaks information about the application's exception handling and input validation logic. The fix replaces this with a generic, server-controlled error message "Invalid order ID" that describes the user's situation without exposing internal exception details. The message is derived from the CWE-209 guidance: return only generic error messages to clients while maintaining the same HTTP status code (400 Bad Request). Detailed exception information should be logged server-side for debugging purposes.

## Behaviour changes
The HTTP response body changed from returning the dynamic exception message (e.g., "For input string: \"invalid\"") to a fixed generic message ("Invalid order ID"). This is the intended security fix and does not alter the method's contract: it still returns a 400 Bad Request status with a String body. No additional logging is added in this minimal fix, though production code should implement server-side logging of full exception details using a centralized exception handler (`@RestControllerAdvice` with `@ExceptionHandler`) for proper audit trails. The method's return type, signature, and control flow remain identical.

