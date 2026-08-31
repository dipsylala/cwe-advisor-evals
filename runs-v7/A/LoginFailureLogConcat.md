## Verdict

**Real issue.** User-controlled `username` from the request is concatenated directly into a log message via string interpolation. This enables log injection attacks where an attacker can inject newline characters or other delimiters to forge log entries, hide malicious actions, or break log parsing.

## Source

The `username` parameter at line 18 is bound directly from user-submitted form data via `[FromForm]` with no validation. It flows unsanitized into the log message at line 23.

## Fix

Replace string interpolation with structured logging using the `ILogger` overload that accepts a format string and parameter placeholders:

```csharp
_logger.LogWarning("Failed login attempt for user: {Username}", username);
```

This treats `username` as structured data, not as part of the log message template. The logging framework will escape or safely serialize the parameter value, preventing injection of control characters or log delimiters.

## Explanation

CWE-117 occurs when attacker-controlled data is concatenated into log output without sanitization. Using `$"...{username}"` interpolates the raw value into the message string, allowing injection attacks—for example, a username like `admin\nFailed login attempt for user: admin` would forge a fake log entry.

Structured logging in .NET (using format placeholders like `{Username}` with separate parameters) is the idiomatic fix. The logging provider automatically handles escaping and ensures the value is recorded as a distinct field, not as raw text in the message. This preserves security, improves log parsing, and enables structured queries on the injected value.
