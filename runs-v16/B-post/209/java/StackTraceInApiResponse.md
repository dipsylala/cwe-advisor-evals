## Verdict

Exploitable. The exception message from `NumberFormatException` is returned directly to the HTTP response body, exposing internal error details to an attacker. An invalid `orderId` parameter (e.g., a non-numeric string) triggers the exception, and the message "For input string: \"<value>\"" is visible to the client.

## Source

`NumberFormatException e` at line 14, thrown by `Integer.parseInt(orderId)`. The `orderId` parameter is user-controlled via the `@RequestParam` annotation, making it an untrusted source.

## Fix

**Vulnerable code (line 18):**
```java
return ResponseEntity.badRequest().body(e.getMessage());
```

**Fixed code:**
```java
catch (NumberFormatException e) {
    logger.warn("Invalid orderId parameter", e);
    return ResponseEntity.badRequest().body("Invalid order ID format");
}
```

Add a logger field to the class (using SLF4J, which is included in Spring Boot):
```java
private static final Logger logger = LoggerFactory.getLogger(StackTraceInApiResponse.class);
```

And import:
```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
```

## Explanation

The fix replaces the exception message with a generic error message ("Invalid order ID format") returned to the client. The detailed exception (which would reveal the application expects an integer) is logged server-side with full context for debugging. This eliminates the information leak while preserving the application's ability to diagnose parsing failures in logs. The generic message does not expose internal implementation details or parsing logic to untrusted clients.

## Behaviour changes

1. **Response body:** Changed from exception message (e.g., "For input string: \"abc\"") to generic string ("Invalid order ID format"). This prevents clients from learning about the expected input format or internal error details.

2. **Server-side logging:** Added a `logger.warn()` call to record the detailed exception server-side. The original code had no logging, so this is an addition that enables debugging and monitoring. The log message includes the exception stack trace, allowing developers to diagnose parsing failures without exposing the details to clients.

3. **Status code:** Unchanged - remains 400 (Bad Request) in both versions.

4. **HTTP headers and timing:** Unchanged - response timing and headers remain identical.
