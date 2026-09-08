## Verdict
VULNERABLE

## Source
The vulnerability is on line 16 of SprintfFixedBufferOverflow.c: the use of `sprintf()` to format data into a fixed 64-byte buffer without size checking. The function receives attacker-controlled `username` and `message` parameters of unbounded length, which are incorporated directly into the format string output. If the formatted result exceeds 64 bytes, the write overflows the stack buffer.

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
Replace `sprintf()` with `snprintf()` and supply the buffer size as the second parameter. The `snprintf()` function enforces a maximum write length, truncating the output if necessary rather than overflowing the buffer. Using `sizeof(line)` ensures the size limit matches the actual buffer allocation; if the buffer size changes, the limit updates automatically.

The fix is a direct substitution on line 16: `snprintf(line, sizeof(line), "[%s] %s: %s", timestamp, username, message);`. This prevents the out-of-bounds write regardless of the length of the attacker-supplied `username` and `message` strings.
