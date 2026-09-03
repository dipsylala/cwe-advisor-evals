## Verdict

Exploitable

## Source

User input from `@RequestParam("orderId")` on line 12, which flows to the exception handler.

## Fix

**Vulnerable code (line 18):**
```java
return ResponseEntity.badRequest().body(e.getMessage());
```

**Fixed code (lines 17-19):**
```java
} catch (NumberFormatException e) {
    return ResponseEntity.badRequest().body("Invalid order ID format");
}
```

**Alternative with server-side logging (recommended):**
```java
} catch (NumberFormatException e) {
    // Log detailed error server-side for debugging
    logger.warn("Invalid order ID provided: {}", orderId, e);
    // Return generic message to client
    return ResponseEntity.badRequest().body("Invalid order ID format");
}
```

## Explanation

The vulnerability occurs at line 18 where `e.getMessage()` from the `NumberFormatException` is returned directly to the HTTP client. When `Integer.parseInt()` fails on user input, the exception message includes details about what input caused the error (e.g., `"For input string: \"abc\""`), which is returned to the client. This exposes internal implementation details that could be used for reconnaissance or to refine attacks.

The fix replaces the exception message with a generic error response that describes the user's situation ("Invalid order ID format") without revealing what specifically failed or what the application's internal error handling looks like. Server-side logging preserves the detailed error information for debugging and monitoring while keeping the client-facing API response minimal and safe. This follows CWE-209 best practices: never expose exception details to clients, log them server-side, and return only generic messages derived from a fixed server-controlled contract.

## Behaviour changes

None beyond closing the weakness. The HTTP response body changes from `"For input string: \"<user-input>\""` to `"Invalid order ID format"`, and the status code remains 400 (Bad Request). The function signature and return type (`ResponseEntity<String>`) remain unchanged. If server-side logging is added, the logger call has no effect on the API contract — it is purely for operational observability and does not alter the response sent to the client.
