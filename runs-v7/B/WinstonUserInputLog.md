## Verdict
exploitable

## Source
`req.body.username` (line 14) - untrusted HTTP request parameter

## Fix

**Vulnerable code (line 19):**
```javascript
logger.info(`Failed login attempt for user: ${username}`);
```

**Fixed code:**
```javascript
logger.info('Failed login attempt', { username });
```

## Explanation

The vulnerability is log injection through direct string interpolation of untrusted user input. The original code embeds the username directly into the log message template, allowing an attacker to inject newlines or Unicode line separators (U+0085, U+2028, U+2029) to forge additional log entries or hide malicious activity. The fix passes the username as a separate structured field in winston's metadata object rather than interpolating it into the message string. Winston's JSON serializer will then encode the field value, automatically escaping ASCII control characters (0x00-0x1F) and quote/backslash through JSON.stringify, preventing the attacker-controlled input from breaking out of the log record structure.

## Behaviour changes

The logger.info call signature changes from a single template string argument to a message string plus a metadata object. Winston's logging output will now include the username as a structured field (e.g., `{"message": "Failed login attempt", "username": "..."}`) rather than embedded in the message text. This is a format change that aligns with structured logging best practices and allows aggregation and analysis tools to process the username as a separate field, improving log quality and auditability. The contract of the logger sink is preserved: the call still produces a single log entry with the same semantic information, and the transport configuration determines the final output format.
