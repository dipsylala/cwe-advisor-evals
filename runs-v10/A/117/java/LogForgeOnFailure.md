## Verdict
The code logs untrusted user input directly without neutralization, allowing log forging through newline/carriage return injection.

## Source
The vulnerability source is at line 14: `String username = request.getParameter("user");`

The untrusted `username` value flows directly to line 25.

## Fix
Change line 25 from:
```java
logger.error("Login failed for " + username, e);
```

to:
```java
logger.error("Login failed for {}", username, e);
```

This uses SLF4J's parameterized logging, which automatically neutralizes special characters in the username when formatting the log output, preventing newline/carriage return injection that could forge log entries.

## Explanation
CWE-117 occurs when user-controlled data is logged without neutralization. An attacker who controls the username parameter can inject newline (`\n`) or carriage return (`\r`) characters to forge log entries—for example, injecting `admin\nLOGIN_SUCCEEDED_FOR_admin` to make the logs falsely appear to show a successful login. 

The fix uses SLF4J's parameterized placeholder (`{}`) pattern, which is already used correctly on line 19 for the success case. This approach defers message formatting to the logging framework, which safely handles special characters and prevents injection. Using string concatenation (line 25 before the fix) bypasses this protection and exposes the concatenated message directly to the logger.
