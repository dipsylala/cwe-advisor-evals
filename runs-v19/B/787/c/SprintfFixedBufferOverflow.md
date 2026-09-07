## Verdict
exploitable

## Source
`timestamp`, `username`, and `message` parameters — attacker-controlled string lengths from the authenticated request handler.

## Sink
`sprintf(line, "[%s] %s: %s", timestamp, username, message)` at line 16. The sink writes formatted output to a fixed 64-byte stack buffer with no bounds checking.

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

    int written = snprintf(line, sizeof(line), "[%s] %s: %s", timestamp, username, message);
    if (written < 0 || (size_t)written >= sizeof(line)) {
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
The original code used `sprintf`, which performs unbounded formatted output into a fixed 64-byte buffer. If the combined length of the format string literal (8 bytes for `"[%s] %s: %s"`), the timestamp, username, and message exceeds the buffer capacity, the write will overflow into adjacent stack memory. The fix replaces `sprintf` with `snprintf`, which takes the destination buffer size as an explicit parameter and truncates output if it would exceed that size. The return value is checked: a negative value indicates an encoding error, and a value >= sizeof(line) indicates the formatted string would have been truncated. On either condition, the function returns -1 to signal failure to the caller, preventing truncated or malformed audit entries from being written.

## Behaviour changes
**New return value**: The function now returns -1 if the formatted output would not fit entirely in the 64-byte buffer or if an encoding error occurs during formatting. The original code would silently overflow the buffer and return 0, indicating success. The new behaviour preserves the return type and existing success case (return 0 when formatting completes without truncation), but surfaces truncation as an error condition rather than proceeding silently. This is appropriate for audit logging: detecting truncation allows the caller to log the event separately or enlarge the buffer, rather than writing a corrupted entry.

**Arguments**: The format string invocation and parameter list are unchanged; `snprintf` accepts the same argument signature as `sprintf` with the addition of the required size parameter.

**Discards**: None. `snprintf` returns the same value as `sprintf` (the formatted length) and produces the same output in the buffer when it fits.

**Sink contract**: The file I/O contract (`fopen`, `fputs`, `fputc`, `fclose`) remains unchanged. When `snprintf` succeeds, `line` contains a properly NUL-terminated string that `fputs` can safely write.
