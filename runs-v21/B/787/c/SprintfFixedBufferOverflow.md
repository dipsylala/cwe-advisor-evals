## Verdict
Out-of-bounds write confirmed. The `sprintf()` call at line 16 writes attacker-controlled `username` and `message` into a fixed 64-byte buffer with no bounds checking, allowing overflow into adjacent stack memory. Use `snprintf()` with explicit size and return-value checks to enforce bounds.

## Source
Line 16: `sprintf(line, "[%s] %s: %s", timestamp, username, message);`

The `username` and `message` parameters (comment at lines 7-8) are attacker-controlled in length and arrive unconstrained from the request handler. The destination `line` buffer (line 13) is fixed at 64 bytes. The format string concatenates timestamp, username, and message with decorations (`"[%s] %s: %s"` = 10 characters overhead), leaving only ~54 bytes for the three values. A hostile username or message longer than available space overwrites the stack.

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

    // Use snprintf with explicit buffer size and check return value for truncation.
    int written = snprintf(line, sizeof(line), "[%s] %s: %s", timestamp, username, message);
    if (written < 0 || (size_t)written >= sizeof(line)) {
        // Truncation or encoding error; reject the entry rather than write partial/corrupted data.
        return -1;
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

The vulnerable code uses `sprintf()`, which has no destination size limit and writes whatever the format expansion produces into the fixed 64-byte `line` buffer. Since `username` and `message` are attacker-controlled and unconstrained, a sufficiently long value overflows the buffer and corrupts adjacent stack memory.

The fix replaces `sprintf()` with `snprintf()`, which takes an explicit destination buffer size (`sizeof(line)`) and truncates the formatted output if it exceeds capacity. The return value is checked: `snprintf()` returns the number of characters that would have been written had the buffer been large enough. If the return value is negative (encoding error) or if the cast-to-unsigned return value is >= `sizeof(line)` (truncation occurred), the entry is rejected and the function returns -1 to signal an error. This prevents truncated or corrupted audit records from being written and closes the out-of-bounds write.

## Behaviour changes

- The function now returns -1 if the formatted log line would not fit in the 64-byte buffer, including when `username` or `message` are longer than the available space.
- Oversized or malicious inputs that previously would overflow the buffer are now rejected.
- The caller can detect the error via the -1 return value and take appropriate action (retry with a larger buffer, log the rejection, or alert).
- Normal-length inputs (within the 64-byte total) continue to work as before; no change to the happy path.
