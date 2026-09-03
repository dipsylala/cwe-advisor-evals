## Verdict
CONFIRMED

## Source
`lookupOrder()` method catches `NumberFormatException` and returns its message directly to the API client without sanitization.

## Fix
Replace line 18:
```java
return ResponseEntity.badRequest().body(e.getMessage());
```

With:
```java
// Log the full exception for debugging/monitoring
System.err.println("Failed to parse orderId: " + orderId);
e.printStackTrace();
// Return a generic error message to the client
return ResponseEntity.badRequest().body("Invalid order ID format");
```

Or, using a proper logger (if SLF4J/Log4j is available):
```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// In class field:
private static final Logger logger = LoggerFactory.getLogger(StackTraceInApiResponse.class);

// In catch block:
logger.error("Failed to parse orderId: {}", orderId, e);
return ResponseEntity.badRequest().body("Invalid order ID format");
```

## Explanation
The original code exposes the exception message (`e.getMessage()`) to the API client. Exception messages can contain implementation details, data type information, or internal validation logic that helps attackers craft more targeted exploits. This violates CWE-209's principle of not generating error messages containing sensitive information.

The fix separates concerns: sensitive diagnostic information is logged internally for debugging, troubleshooting, and security monitoring, while a generic, non-revealing message is returned to the client. This preserves debuggability while protecting against information disclosure.
