## Verdict
Real. User-controlled input from `r.URL.Query().Get("username")` is logged without sanitization, enabling log injection attacks.

## Source
Line 14 in `loginHandler`:
```go
log.Printf("Failed login attempt for user: %s", username)
```

The `username` parameter originates from untrusted HTTP request query parameters and flows directly into the log output.

## Fix
Replace line 14 with sanitized output:
```go
log.Printf("Failed login attempt for user: %s", strings.ReplaceAll(strings.ReplaceAll(username, "\n", ""), "\r", ""))
```

Or use `strconv.Quote` to escape all special characters:
```go
log.Printf("Failed login attempt for user: %s", strconv.Quote(username))
```

The imports must include `"strings"` or `"strconv"` respectively at the top of the file.

## Explanation
Log injection occurs when an attacker supplies a username containing newlines (`\n`) or carriage returns (`\r`). These characters are passed through to the log output, allowing the attacker to forge log entries that appear to come from other events or users. By removing or escaping these control characters before logging, the log entry cannot be split across multiple lines, preventing forgery. The `strings.ReplaceAll` approach removes the problematic characters entirely, while `strconv.Quote` provides a more general escaping mechanism that also handles other special characters and makes the escaped nature of the input visible in logs.
