## Verdict

CONFIRMED. Line 16 uses `sprintf()` to format an unbounded combination of attacker-controlled strings (`timestamp`, `username`, `message`) into a fixed 64-byte buffer (`line`). When the combined formatted string exceeds 63 bytes, the write overflows the buffer boundary.

## Source

E:/Github/cwe-advisor/evals/cases/787/c/SprintfFixedBufferOverflow/SprintfFixedBufferOverflow.c, line 16.

The sink is the `sprintf()` call which writes without a length limit. The buffer (`line`) is too small to safely contain the formatted output when the three input strings are of realistic length.

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

    // SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
    snprintf(line, sizeof(line), "[%s] %s: %s", timestamp, username, message);

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

The fix replaces `sprintf()` with `snprintf()`, passing the buffer size as the second argument. `snprintf()` respects the size limit and guarantees that at most `sizeof(line) - 1` bytes are written (the remaining byte holds the null terminator), preventing the overflow.

Any formatted string that would exceed the buffer is truncated to fit safely. This is the standard C protection against format string buffer overflows when writing to fixed-size buffers.
