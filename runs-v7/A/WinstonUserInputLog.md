## Verdict

CWE-117 confirmed. The application logs user-supplied input directly into a log message via string interpolation without sanitization, enabling log injection attacks that could obscure security events or introduce false entries into audit trails.

## Source

Line 19 receives `username` from `req.body.username` (line 14) and passes it unsanitized into a log message:

```javascript
logger.info(`Failed login attempt for user: ${username}`);
```

An attacker can inject newlines, special characters, or structured data to manipulate log output.

## Fix

Use Winston's structured logging API with metadata parameters instead of string interpolation:

```javascript
logger.info('Failed login attempt', { username });
```

Alternatively, for richer context:

```javascript
logger.info('Failed login attempt for user', { userId: username, timestamp: new Date().toISOString() });
```

This separates the log message template from the untrusted data, preventing log injection regardless of the input content.

## Explanation

Structured logging treats user data as metadata fields rather than as part of the message string. Winston serializes these fields safely according to its configured format, preventing injection attacks. The attacker's input cannot alter the log structure or introduce fake entries, even if it contains newlines, quotes, or special characters. This approach also improves log parsability and allows filtering/searching by field values.
