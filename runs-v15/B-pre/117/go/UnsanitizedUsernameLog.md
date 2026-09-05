## Verdict

**Confirmed.** The vulnerability is real and exploitable as reported.

## Source

Untrusted user input originates from the HTTP query parameter at line 10:
```
username := r.URL.Query().Get("username")
```

An attacker controls the value of `username` directly through the HTTP GET request, e.g. `/login?username=attacker%0Aadmin%20logged%20in`.

## Fix

Replace the legacy `log.Printf` call with structured logging using Go's `log/slog` package, passing the username as a typed attribute instead of concatenating it into the message string:

**Current (vulnerable) code at line 14:**
```go
log.Printf("Failed login attempt for user: %s", username)
```

**Fixed code:**
```go
import "log/slog"

slog.Error("Failed login attempt", slog.String("user", username))
```

Also add the import statement at the top of the file if `slog` is not already imported.

## Explanation

The fix eliminates log injection by migrating from the legacy `log` package to Go's `log/slog` structured logging (Go 1.21+). When untrusted data is passed as a structured attribute using `slog.String()`, the slog handlers (both the default `TextHandler` and `JSONHandler`) automatically escape all ASCII control characters (including newlines U+000A and carriage returns U+000D) in attribute values. This prevents an attacker-supplied username containing `\n` or `\r\n` from forging new log entries or hiding malicious activity.

By moving the username from the message string (where it would be concatenated raw) to a structured attribute (where it is properly escaped), we ensure that characters like newlines appear as escaped sequences in the output rather than actual line breaks, defeating log injection attacks.

## Behaviour changes

**Before:** A username containing `admin\nSuccessful login for admin` would forge a fake log entry appearing to show a successful login.

**After:** The same input is logged as an escaped sequence, appearing as data within a single log entry (e.g., `user="admin\nSuccessful login for admin"` or with proper escaping), making the injection attempt visible to auditors rather than creating a forged entry.

**Log output example:**

Before fix (injectable):
```
Failed login attempt for user: attacker
Successful login for admin
```

After fix (escaped):
```
time=2025-01-15T10:30:45.123Z level=ERROR msg="Failed login attempt" user="attacker\nSuccessful login for admin"
```

The legitimate error message is logged as intended, but any injected control characters are now visible as escaped sequences, preventing log tampering.
