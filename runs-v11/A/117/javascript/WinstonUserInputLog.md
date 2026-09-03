## Verdict
**Vulnerable:** Yes. The `username` parameter is user-controlled input passed unsanitized directly into a log message via string interpolation, enabling log injection attacks.

## Source
Line 19 in `WinstonUserInputLog.js` logs unsanitized user input:
```javascript
logger.info(`Failed login attempt for user: ${username}`);
```

The `username` originates from `req.body.username` (line 14), under attacker control through the JSON POST request body.

## Fix
Use Winston's metadata parameter to separate user data from the log message, preventing injection via control characters:

```javascript
logger.info('Failed login attempt', { username: username });
```

Alternatively, if inline formatting is required, strip newlines and carriage returns:

```javascript
const sanitizedUsername = username.replace(/[\r\n]/g, '');
logger.info(`Failed login attempt for user: ${sanitizedUsername}`);
```

## Explanation
Log injection attacks exploit unsanitized user input in log output to forge log entries, hide attack traces, or inject commands if logs are parsed downstream. CWE-117 requires neutralizing untrusted input before it reaches log sinks.

Winston's structured logging (metadata approach) is preferred because it treats the username as data, not as part of the format string, preventing any injected newlines or control characters from being interpreted as log structure. The sanitization approach removes the most common injection vector (newline insertion) but does not fully prevent all log manipulation—structured logging is the robust solution.
