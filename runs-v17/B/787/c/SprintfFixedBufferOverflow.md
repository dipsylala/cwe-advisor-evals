## Verdict

CONFIRMED. Out-of-bounds write vulnerability at line 16. The `sprintf()` function performs no bounds checking on the destination buffer. An attacker-controlled combination of `timestamp`, `username`, and `message` inputs can overflow the 64-byte `line` buffer and corrupt adjacent memory.

## Source

**Location**: SprintfFixedBufferOverflow.c, line 16 (sink)

**Data flow**:
- **Source**: Three parameters with no length constraints arrive from authenticated request handlers: `const char *timestamp`, `const char *username`, `const char *message`
- **Sink**: `sprintf(line, "[%s] %s: %s", timestamp, username, message)` writes to a fixed 64-byte stack buffer
- **Vulnerability**: No validation that the formatted output fits within 64 bytes

**Exploitability**: The comment explicitly states that `username` and `message` are "attacker-controlled in length." Even without the attacker control, `timestamp` is formatted by `strftime()` with a fixed pattern, `username` could be a display name of arbitrary length, and `message` is free-text status. The three fields formatted with separators (`"[%s] %s: %s"`) easily exceed 64 bytes.

## Fix

### File: SprintfFixedBufferOverflow.c

```c
#include <stdio.h>
#include <string.h>
#include <time.h>

/*
 * Appends one formatted audit-log entry to the shared log file.
 * username and message come from the authenticated request handler
 * and are attacker-controlled in length (a display name and a free-text
 * status message respectively); timestamp is generated locally.
 */
int log_user_action(const char *timestamp, const char *username, const char *message)
{
    char line[64];

    // Fixed: Use snprintf with explicit buffer size and validate return value
    int written = snprintf(line, sizeof(line), "[%s] %s: %s", timestamp, username, message);
    if (written < 0 || (size_t)written >= sizeof(line)) {
        return -1;  // Truncation or encoding error detected
    }

    FILE *fp = fopen("audit.log", "a");
    if (fp == NULL) {
        return -1;
    }

    fputs(line, fp);
    fputc('\n', fp);
    fclose(fp);
    return 0;
}

int main(void)
{
    time_t now = time(NULL);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", localtime(&now));

    /* In the real service these come from request fields with no length cap. */
    const char *username = "alice";
    const char *message = "logged in successfully";

    return log_user_action(timestamp, username, message);
}
```

## Explanation

The original code uses `sprintf()`, which has no bounds checking and writes to the destination buffer without verifying that the formatted output fits. This is the fundamental cause of CWE-787 out-of-bounds write.

The fix replaces `sprintf()` with `snprintf()`, which takes an explicit destination buffer size (`sizeof(line)`, 64 bytes) as its second argument and guarantees never to write more than that many bytes to the destination. The function returns the number of characters that would have been written if space were unlimited, or a negative value on an encoding error.

The return value check `if (written < 0 || (size_t)written >= sizeof(line))` implements the exact validation pattern recommended in the CWE-787/C guidance:
- `written < 0` catches encoding errors
- `(size_t)written >= sizeof(line)` detects truncation: if the formatted string is 64 bytes or longer, it did not fit in the buffer and was truncated

When the check fails, the function returns -1 to signal to the caller that the log entry could not be safely written and was discarded rather than allowing buffer corruption.

This replaces an exploitable unbounded write with a size-enforced operation, closing the CWE-787 vulnerability.

## Behaviour changes

- **Functional change**: When the formatted log line is 64 bytes or longer (e.g., long username or message), the line is now discarded and the function returns -1, rather than writing past the buffer boundary.
- **Caller impact**: Code calling `log_user_action()` can now detect overflow conditions by checking for the -1 return value and decide whether to retry with shorter input, log an error, or reject the request.
- **Memory safety**: The stack buffer is no longer vulnerable to out-of-bounds write; a sufficiently long input will trigger truncation detection and rejection rather than corruption.
- **Log behavior**: Truncated or oversized entries are not written to the audit log (intentional safety), which is preferable to logging corrupted memory. The calling code should log or report the failure of `log_user_action()`.
