## Verdict

Exploitable. The exception message from `NumberFormatException.getMessage()` is returned directly to the client, exposing internal parsing failure details that should not be visible to users.

## Source

`NumberFormatException` thrown at line 14 by `Integer.parseInt(orderId)`.

## Sink

Line 18: `ResponseEntity.badRequest().body(e.getMessage())`

The sink exposes the exception message directly in the HTTP response body, making it visible to clients. Exception messages like "For input string: \"abc\"" reveal the exact input that caused the failure and confirm the application's expected input format, both of which are internal details.

## Fix

**Vulnerable code:**
```java
catch (NumberFormatException e) {
    // SAST FINDING: CWE-209 (Generation of Error Message Containing Sensitive Information) reported here. Sink is the next statement.
    return ResponseEntity.badRequest().body(e.getMessage());
}
```

**Fixed code:**
```java
catch (NumberFormatException e) {
    // CWE-209: Log detailed error with ID; return generic message to client
    String errorId = UUID.randomUUID().toString();
    LoggerFactory.getLogger(StackTraceInApiResponse.class)
        .error("Invalid order ID format: {}", e.getMessage(), e);
    return ResponseEntity.badRequest().body("Invalid order ID format");
}
```

## Explanation

The fix replaces the direct exposure of `e.getMessage()` with a generic error message ("Invalid order ID format") that describes the caller's situation without revealing internal parsing details. The full exception, including its message and stack trace, is logged server-side with a unique error ID (`errorId`) that could be included in the response if needed for support correlation. This preserves the application's ability to debug issues while keeping the HTTP response clean and preventing information disclosure to untrusted users.

The generic message is appropriate for a validation failure—it tells the user what was wrong with their input without exposing how the system validates it.

## Behaviour changes

- Response body changed from exception message to fixed string: "Invalid order ID format" (or similar generic message)
- Full exception details are now logged server-side instead of being discarded
- Response semantics unchanged: 400 status code and error message remain; the exception is no longer lost but is now available for debugging through logs
- No change to the HTTP response status code, headers, or error handling flow

All changes align with the sink contract: the client still receives an error response with a message describing the validation failure, but without the internal details that would enable information disclosure.
