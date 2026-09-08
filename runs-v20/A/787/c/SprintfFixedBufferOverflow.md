## Verdict

Confirmed. `sprintf(line, "[%s] %s: %s", timestamp, username, message)` writes into a fixed 64-byte stack buffer (`char line[64]`) with no length limit on `username` or `message`. Both are documented as attacker-controlled with no length cap, so any request whose display name and status message together with the fixed literal text (`"[] : "`) and the timestamp exceed 63 characters overflows `line` and corrupts adjacent stack memory (return address, saved registers, other locals) — a classic stack-based buffer overflow (CWE-787 / CWE-121).

## Source

`username` and `message`, passed into `log_user_action` in `SprintfFixedBufferOverflow.c` line 16. Per the file's own comment, in the real service these originate from authenticated request fields with no length cap (a display name and a free-text status message); `main`'s literal values are only a harness stand-in for that unbounded input. `timestamp` is locally generated and bounded (`strftime` into a 32-byte buffer) so it is not the risk driver.

## Fix

### File: SprintfFixedBufferOverflow.c
```c
#include <stdio.h>
#include <stdlib.h>
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
    int needed = snprintf(NULL, 0, "[%s] %s: %s", timestamp, username, message);
    if (needed < 0) {
        return -1;
    }

    char *line = malloc((size_t)needed + 1);
    if (line == NULL) {
        return -1;
    }

    snprintf(line, (size_t)needed + 1, "[%s] %s: %s", timestamp, username, message);

    FILE *fp = fopen("audit.log", "a");
    if (fp == NULL) {
        free(line);
        return -1;
    }

    fputs(line, fp);
    fputc('\n', fp);
    fclose(fp);
    free(line);
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

`sprintf` performs no bounds checking, so any format that can exceed the destination buffer's size is an out-of-bounds write once the inputs are long enough. Because `username` and `message` are explicitly unbounded, no fixed-size stack buffer is safe here regardless of how large it is made — a larger fixed size only raises the input length needed to trigger the overflow, it does not remove the defect.

The fix first calls `snprintf(NULL, 0, ...)`, which performs no writes but returns the exact number of characters the formatted string would occupy (excluding the terminating NUL), per the C99/C11 standard's a defined behavior of `snprintf` shared with `vsnprintf`. That length is used to `malloc` a buffer sized to fit the actual content plus the NUL terminator, and the second `snprintf` call writes the real content into that buffer with its size passed as the limit, so even if the two calls somehow disagreed, no overflow could occur. This removes the fixed-capacity assumption entirely rather than picking a larger arbitrary bound, which matters because both attacker-controlled fields have no defined maximum length. The allocated buffer is freed on every exit path (including the new `fopen` failure path) to avoid a leak introduced by switching from a stack buffer to a heap one.

This differs from simply switching to `snprintf(line, sizeof(line), ...)` on the original fixed buffer: that would stop the overflow but silently truncate any audit entry whose username/message combination exceeds 63 characters, corrupting the log record instead of corrupting memory. Since the buffer is now sized to the actual content, no truncation occurs and the full audit entry is always preserved.
